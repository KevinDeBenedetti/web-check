"""Scan management endpoints."""

import asyncio
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_session
from api.models.results import CheckResult, ScanRequest, ScanResponse
from api.services import db_service

router = APIRouter()


@router.post("/start", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest, session: AsyncSession = Depends(get_session)
) -> ScanResponse:
    """
    Start a comprehensive security scan.

    Runs multiple scanners in parallel and tracks progress.
    """
    scan_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")

    # Create scan in database
    await db_service.create_scan(
        session=session,
        scan_id=scan_id,
        target=request.target,
        modules=request.modules,
        timeout=request.timeout,
    )

    scan_response = ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="running",
        started_at=datetime.now(UTC),
        results=[],
    )

    # Start scans in background
    asyncio.create_task(_run_scans(scan_id, request))

    return scan_response


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


@router.get("/", response_model=list[ScanResponse])
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


async def _run_scans(scan_id: str, request: ScanRequest) -> None:
    """Run scans in background and update results in database."""
    from api.database import get_session_context
    from api.services.nikto import run_nikto_scan
    from api.services.nuclei import run_nuclei_scan
    from api.services.zap import run_zap_scan

    modules = request.modules or ["nuclei", "nikto", "zap"]
    results: list[CheckResult] = []

    # Run scans based on requested modules
    tasks: list[Any] = []
    if "nuclei" in modules:
        tasks.append(run_nuclei_scan(request.target, request.timeout))
    if "nikto" in modules:
        tasks.append(run_nikto_scan(request.target, request.timeout))
    if "zap" in modules:
        tasks.append(run_zap_scan(request.target, request.timeout))

    # Execute all scans in parallel
    if tasks:
        scan_results = await asyncio.gather(*tasks, return_exceptions=False)
        results = [r for r in scan_results if isinstance(r, CheckResult)]

    # Save results to database
    async with get_session_context() as session:
        for result in results:
            await db_service.save_scan_result(session, scan_id, result)

        # Update scan status
        await db_service.update_scan_status(session, scan_id, "success")
