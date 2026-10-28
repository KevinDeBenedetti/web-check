"""Scan management endpoints."""

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import cast

import structlog
from api.database import get_session, get_session_context
from api.models import CheckResult, Finding, ScanRequest, ScanResponse
from api.models.db_models import Scan
from api.models.findings import Severity
from api.models.reports import AggregatedFinding, ScanComparison, ScanFindings, ScanSummary
from api.models.results import ScanCategory, ScanStatus
from api.services import db_service
from api.services.catalog import get_module, resolve_modules
from api.services.compare import compare_findings
from api.services.exporters import (
    EXPORT_EXTENSIONS,
    EXPORT_MEDIA_TYPES,
    ExportFormat,
    export_scan,
)
from api.services.findings import aggregate_findings, compute_score, severity_counts
from api.services.log_streamer import log_streamer
from api.services.scope import check_scope
from api.utils.config import get_settings
from api.utils.security import ScanId, validate_target
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()
router = APIRouter()

# Strong references to running background scans (see asyncio.create_task docs).
_background_tasks: set[asyncio.Task[None]] = set()


@router.post("/start", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest, session: AsyncSession = Depends(get_session)
) -> ScanResponse:
    """
    Start a comprehensive security scan.

    The target must be an http(s) URL inside the scope configured by
    ALLOWED_DOMAINS and must not point to a private network. Modules run one
    after the other; each result is stored as soon as it is available. Follow
    progress with `GET /api/scans/{scan_id}/logs` (SSE).
    """
    if not request.target.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Target must start with http:// or https://")

    decision = check_scope(request.target, get_settings().get_allowed_domains())
    if not decision.allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Target {decision.hostname or request.target!r} is outside the allowed scope. "
                "Add it to ALLOWED_DOMAINS to scan it."
            ),
        )

    # SSRF guard: internal hostnames and non-public IPs, also after DNS resolution.
    target = await validate_target(request.target)

    try:
        modules = resolve_modules(request.modules, request.profile)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # Random suffix: two scans started in the same second must not collide.
    scan_id = f"{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"

    scan = await db_service.create_scan(
        session=session,
        scan_id=scan_id,
        target=target,
        modules=modules,
        timeout=request.timeout,
    )

    # Record logs from now on so clients connecting later can replay them.
    log_streamer.register(scan_id)

    # Keep a strong reference: the event loop only holds weak refs to tasks.
    task = asyncio.create_task(
        _run_scans(scan_id, target, modules, request.timeout), name=f"scan-{scan_id}"
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return _to_scan_response(scan, [])


@router.get("", response_model=list[ScanResponse])
async def list_scans(session: AsyncSession = Depends(get_session)) -> list[ScanResponse]:
    """List the 100 most recent scans, newest first."""
    scans = await db_service.list_scans(session, limit=100)
    return [_to_scan_response(scan, await _load_results(session, scan.scan_id)) for scan in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: ScanId, session: AsyncSession = Depends(get_session)
) -> ScanResponse:
    """Get the status and results of a scan."""
    scan = await _get_scan_or_404(session, scan_id)
    return _to_scan_response(scan, await _load_results(session, scan_id))


@router.get("/{scan_id}/findings", response_model=ScanFindings)
async def get_scan_findings(
    scan_id: ScanId, session: AsyncSession = Depends(get_session)
) -> ScanFindings:
    """Get the findings of a scan, deduplicated across modules and sorted by severity."""
    scan = await _get_scan_or_404(session, scan_id)
    results = await _load_results(session, scan_id)
    findings = aggregate_findings(results)
    return ScanFindings(summary=_summary(scan, findings), findings=findings)


@router.get("/{base_id}/compare/{head_id}", response_model=ScanComparison)
async def compare_scans(
    base_id: ScanId, head_id: ScanId, session: AsyncSession = Depends(get_session)
) -> ScanComparison:
    """Compare a baseline scan with a later one: new, fixed and unchanged findings."""
    base_scan = await _get_scan_or_404(session, base_id)
    head_scan = await _get_scan_or_404(session, head_id)
    base_findings = aggregate_findings(await _load_results(session, base_id))
    head_findings = aggregate_findings(await _load_results(session, head_id))

    new, fixed, unchanged = compare_findings(base_findings, head_findings)
    base = _summary(base_scan, base_findings)
    head = _summary(head_scan, head_findings)
    return ScanComparison(
        base=base,
        head=head,
        score_delta=head.score - base.score,
        new=new,
        fixed=fixed,
        unchanged=unchanged,
    )


@router.get("/{scan_id}/export")
async def export_scan_report(
    scan_id: ScanId,
    fmt: ExportFormat = Query("json", alias="format", description="json, markdown or sarif"),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Download a scan report as JSON, Markdown or SARIF 2.1.0."""
    scan = await _get_scan_or_404(session, scan_id)
    results = await _load_results(session, scan_id)
    findings = aggregate_findings(results)
    body = export_scan(_to_scan_response(scan, results, findings), findings, fmt)
    filename = f"web-check-{scan_id}.{EXPORT_EXTENSIONS[fmt]}"
    return Response(
        content=body,
        media_type=EXPORT_MEDIA_TYPES[fmt],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/logs")
async def stream_scan_logs(
    scan_id: ScanId, session: AsyncSession = Depends(get_session)
) -> StreamingResponse:
    """
    Stream real-time logs for a scan using Server-Sent Events (SSE).

    Clients that connect late first receive the logs emitted so far, then live
    updates about scan progress, container logs and completion status.
    """
    finished_status: str | None = None
    if not log_streamer.is_tracked(scan_id):
        scan = await db_service.get_scan(session, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        finished_status = scan.status

    return StreamingResponse(
        log_streamer.subscribe(scan_id, finished_status=finished_status),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _get_scan_or_404(session: AsyncSession, scan_id: str) -> Scan:
    scan = await db_service.get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def _load_results(session: AsyncSession, scan_id: str) -> list[CheckResult]:
    """Load the stored module results of a scan as CheckResult models."""
    results_with_findings = await db_service.get_scan_results(session, scan_id)
    return [
        CheckResult(
            module=scan_result.module,
            category=cast(ScanCategory, scan_result.category),
            target=scan_result.target,
            timestamp=scan_result.timestamp,
            duration_ms=scan_result.duration_ms,
            status=cast(ScanStatus, scan_result.status),
            data=scan_result.data,
            findings=[
                Finding(
                    severity=cast(Severity, f.severity),
                    title=f.title,
                    description=f.description,
                    reference=f.reference,
                    cve=f.cve,
                    cvss_score=f.cvss_score,
                    remediation=f.remediation,
                )
                for f in findings
            ],
            error=scan_result.error,
        )
        for scan_result, findings in results_with_findings
    ]


def _to_scan_response(
    scan: Scan,
    results: list[CheckResult],
    findings: list[AggregatedFinding] | None = None,
) -> ScanResponse:
    if findings is None:
        findings = aggregate_findings(results)
    return ScanResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        status=cast(ScanStatus, scan.status),
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        modules=scan.modules,
        score=compute_score(findings),
        severity_counts=severity_counts(findings),
        results=results,
    )


def _summary(scan: Scan, findings: list[AggregatedFinding]) -> ScanSummary:
    return ScanSummary(
        scan_id=scan.scan_id,
        target=scan.target,
        status=cast(ScanStatus, scan.status),
        started_at=scan.started_at,
        score=compute_score(findings),
        severity_counts=severity_counts(findings),
    )


def _module_runners(scan_id: str) -> dict[str, Callable[[str, int], Awaitable[CheckResult]]]:
    """Map module ids (see api.services.catalog) to their scanner coroutines."""
    from api.services.dns_enum import run_dns_enum
    from api.services.headers_scanner import run_headers_scan
    from api.services.nikto import run_nikto_scan
    from api.services.nuclei import run_nuclei_scan
    from api.services.sqlmap_scanner import run_sqlmap_scan
    from api.services.sslyze_scanner import run_sslyze_scan
    from api.services.wapiti_scanner import run_wapiti_scan
    from api.services.xsstrike_scanner import run_xsstrike_scan
    from api.services.zap_native import run_zap_scan

    return {
        # In-process checks only need a short HTTP/DNS timeout.
        "headers": lambda t, timeout: run_headers_scan(t, min(timeout, 60)),
        "dns": lambda t, timeout: run_dns_enum(t, min(timeout, 60)),
        "nuclei": lambda t, timeout: run_nuclei_scan(t, timeout),
        "nikto": lambda t, timeout: run_nikto_scan(t, timeout),
        "zap": lambda t, timeout: run_zap_scan(t, timeout, scan_id),
        "testssl": lambda t, timeout: run_sslyze_scan(t, timeout, scan_id),
        "sqlmap": lambda t, timeout: run_sqlmap_scan(t, timeout, scan_id),
        "wapiti": lambda t, timeout: run_wapiti_scan(t, timeout, scan_id),
        "xsstrike": lambda t, timeout: run_xsstrike_scan(t, timeout, scan_id),
    }


def _error_result(module: str, target: str, error: str, started: float) -> CheckResult:
    """CheckResult for a module that raised instead of returning a result."""
    info = get_module(module)
    return CheckResult(
        module=module,
        category=info.category if info else "quick",
        target=target,
        duration_ms=int((time.monotonic() - started) * 1000),
        status="error",
        error=error,
    )


async def _run_scans(scan_id: str, target: str, modules: list[str], timeout: int) -> None:
    """Run the modules one after the other, storing each result as it completes."""
    runners = _module_runners(scan_id)
    succeeded = 0
    final_status: ScanStatus = "error"

    try:
        await log_streamer.send_log(
            scan_id,
            {
                "type": "info",
                "message": f"Starting scan with modules: {', '.join(modules)}",
                "modules": modules,
            },
        )

        for module in modules:
            await log_streamer.send_log(
                scan_id,
                {
                    "type": "docker",
                    "event": "module_started",
                    "module": module,
                    "message": f"Running {module}...",
                },
            )

            started = time.monotonic()
            try:
                result = await runners[module](target, timeout)
                # Some scanners name themselves differently (testssl -> "sslyze",
                # dns -> "dns_enum"); store results under the requested module id.
                result = result.model_copy(update={"module": module})
            except Exception as e:
                logger.exception("scan_module_failed", scan_id=scan_id, module=module)
                result = _error_result(module, target, str(e), started)

            if result.status == "success":
                succeeded += 1
                log_type, message = "success", f"{module} completed"
            else:
                log_type = "error" if result.status == "error" else "warning"
                message = f"{module} finished with status {result.status}"
                if result.error:
                    message += f": {result.error}"

            # Store before announcing it, so clients refreshing on this event see the result.
            async with get_session_context() as session:
                await db_service.save_scan_result(session, scan_id, result)

            await log_streamer.send_log(
                scan_id,
                {
                    "type": log_type,
                    "event": "module_completed",
                    "module": module,
                    "message": message,
                    "findings_count": len(result.findings),
                    "status": result.status,
                    "duration_ms": result.duration_ms,
                },
            )

        final_status = "success" if succeeded or not modules else "error"
    except Exception as e:
        logger.exception("scan_failed", scan_id=scan_id)
        await log_streamer.send_log(scan_id, {"type": "error", "message": f"Scan failed: {e}"})
    finally:
        # Always leave the scan in a terminal state, even on unexpected errors.
        try:
            async with get_session_context() as session:
                await db_service.update_scan_status(session, scan_id, final_status)
        except Exception:
            logger.exception("scan_status_update_failed", scan_id=scan_id)
        await log_streamer.complete(scan_id, final_status)
