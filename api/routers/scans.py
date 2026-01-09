"""Scan management endpoints."""

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException

from api.models.results import CheckResult, ScanRequest, ScanResponse

router = APIRouter()


# In-memory store for scan results (use Redis in production)
_active_scans: dict[str, ScanResponse] = {}


@router.post("/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest) -> ScanResponse:
    """
    Start a comprehensive security scan.

    Runs multiple scanners in parallel and tracks progress.
    """
    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    scan_response = ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="running",
        started_at=datetime.now(timezone.utc),
        results=[],
    )

    _active_scans[scan_id] = scan_response

    # Start scans in background
    asyncio.create_task(_run_scans(scan_id, request))

    return scan_response


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str) -> ScanResponse:
    """Get the status and results of a scan."""
    if scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    return _active_scans[scan_id]


@router.get("/", response_model=list[ScanResponse])
async def list_scans() -> list[ScanResponse]:
    """List all scans."""
    return list(_active_scans.values())


async def _run_scans(scan_id: str, request: ScanRequest) -> None:
    """Run scans in background and update results."""
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

    # Update scan status
    if scan_id in _active_scans:
        _active_scans[scan_id].results = results
        _active_scans[scan_id].status = "success"
