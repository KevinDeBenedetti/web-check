"""Scan management endpoints."""

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import cast

import structlog
from api.database import get_session, get_session_context
from api.models.results import (
    DEFAULT_SCAN_MODULES,
    CheckResult,
    ScanRequest,
    ScanResponse,
    ScanStatus,
)
from api.services import db_service
from api.services.log_streamer import log_streamer
from api.utils.security import validate_target
from fastapi import APIRouter, Depends, HTTPException
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

    Runs the selected modules in the background and tracks progress.
    Follow progress with `GET /api/scans/{scan_id}/logs` (SSE).
    """
    target = await validate_target(request.target, require_scheme=False)
    request = request.model_copy(update={"target": target})
    scan_id = str(uuid.uuid4())

    # Create scan in database
    scan = await db_service.create_scan(
        session=session,
        scan_id=scan_id,
        target=request.target,
        modules=list(request.modules or DEFAULT_SCAN_MODULES),
        timeout=request.timeout,
    )

    # Record logs from now on so clients connecting later can replay them.
    log_streamer.register(scan_id)

    # Keep a strong reference: the event loop only holds weak refs to tasks.
    task = asyncio.create_task(_run_scans(scan_id, request), name=f"scan-{scan_id}")
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    return ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="running",
        started_at=scan.started_at,
        results=[],
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str, session: AsyncSession = Depends(get_session)
) -> ScanResponse:
    """Get the status and results of a scan."""
    scan = await db_service.get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get results
    results_with_findings = await db_service.get_scan_results(session, scan_id)

    # Convert to CheckResult objects
    check_results: list[CheckResult] = []
    for scan_result, findings in results_with_findings:
        from api.models import Finding
        from api.models.findings import Severity
        from api.models.results import ScanCategory, ScanStatus

        check_results.append(
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
                    )
                    for f in findings
                ],
                error=scan_result.error,
            )
        )

    return ScanResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        status=cast("ScanStatus", scan.status),
        started_at=scan.started_at,
        results=check_results,
    )


@router.get("", response_model=list[ScanResponse])
async def list_scans(session: AsyncSession = Depends(get_session)) -> list[ScanResponse]:
    """List all scans."""
    scans = await db_service.list_scans(session, limit=100)

    scan_responses: list[ScanResponse] = []
    for scan in scans:
        results_with_findings = await db_service.get_scan_results(session, scan.scan_id)

        check_results: list[CheckResult] = []
        for scan_result, findings in results_with_findings:
            from api.models import Finding
            from api.models.findings import Severity
            from api.models.results import ScanCategory, ScanStatus

            check_results.append(
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
                        )
                        for f in findings
                    ],
                    error=scan_result.error,
                )
            )

        scan_responses.append(
            ScanResponse(
                scan_id=scan.scan_id,
                target=scan.target,
                status=cast("ScanStatus", scan.status),
                started_at=scan.started_at,
                results=check_results,
            )
        )

    return scan_responses


@router.get("/{scan_id}/logs")
async def stream_scan_logs(
    scan_id: str, session: AsyncSession = Depends(get_session)
) -> StreamingResponse:
    """
    Stream real-time logs for a scan using Server-Sent Events (SSE).

    Clients receive the logs emitted since the scan started, then live updates
    about scan progress, container logs, and completion status.
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


def _module_runners(scan_id: str) -> dict[str, Callable[[str, int], Awaitable[CheckResult]]]:
    """Map module names (see ScanModule) to their scanner coroutines."""
    from api.services.nikto import run_nikto_scan
    from api.services.nuclei import run_nuclei_scan
    from api.services.sqlmap_scanner import run_sqlmap_scan
    from api.services.sslyze_scanner import run_sslyze_scan
    from api.services.wapiti_scanner import run_wapiti_scan
    from api.services.xsstrike_scanner import run_xsstrike_scan
    from api.services.zap_native import run_zap_scan

    return {
        "nuclei": lambda t, timeout: run_nuclei_scan(t, timeout),
        "nikto": lambda t, timeout: run_nikto_scan(t, timeout),
        "zap": lambda t, timeout: run_zap_scan(t, timeout, scan_id),
        "testssl": lambda t, timeout: run_sslyze_scan(t, timeout, scan_id),
        "sqlmap": lambda t, timeout: run_sqlmap_scan(t, timeout, scan_id),
        "wapiti": lambda t, timeout: run_wapiti_scan(t, timeout, scan_id),
        "xsstrike": lambda t, timeout: run_xsstrike_scan(t, timeout, scan_id),
    }


def _error_result(module: str, target: str, error: str) -> CheckResult:
    """CheckResult for a module that raised instead of returning a result."""
    return CheckResult(
        module=module,
        category="security",
        target=target,
        duration_ms=0,
        status="error",
        error=error,
    )


def _overall_status(results: list[CheckResult]) -> ScanStatus:
    """A scan succeeds if at least one module succeeded."""
    return "success" if any(r.status == "success" for r in results) else "error"


async def _run_scans(scan_id: str, request: ScanRequest) -> None:
    """Run scans in background, persisting each module's result as it completes."""
    modules = request.modules or DEFAULT_SCAN_MODULES
    runners = _module_runners(scan_id)
    results: list[CheckResult] = []
    final_status: ScanStatus = "error"

    try:
        await log_streamer.send_log(
            scan_id,
            {"type": "info", "message": f"Starting scan with modules: {', '.join(modules)}"},
        )

        # Run scans sequentially to show progress
        for module in modules:
            await log_streamer.send_log(
                scan_id,
                {"type": "docker", "module": module, "message": f"Running {module}..."},
            )

            try:
                result = await runners[module](request.target, request.timeout)
            except Exception as e:
                logger.exception("scan_module_failed", scan_id=scan_id, module=module)
                result = _error_result(module, request.target, str(e))

            results.append(result)
            async with get_session_context() as session:
                await db_service.save_scan_result(session, scan_id, result)

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "success" if result.status == "success" else "error",
                    "module": module,
                    "message": f"{module} scan finished: {result.status}",
                    "findings_count": len(result.findings),
                    "status": result.status,
                },
            )

        final_status = _overall_status(results)

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
