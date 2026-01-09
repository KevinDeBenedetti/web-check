"""Database operations for scans and results."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models import CheckResult
from api.models.db_models import Finding, Scan, ScanResult


async def create_scan(
    session: AsyncSession,
    scan_id: str,
    target: str,
    modules: list[str] | None = None,
    timeout: int = 300,
) -> Scan:
    """
    Create a new scan record.

    Args:
        session: Database session
        scan_id: Unique scan identifier
        target: Target URL
        modules: List of modules to run
        timeout: Timeout in seconds

    Returns:
        Created Scan object
    """
    scan = Scan(
        scan_id=scan_id,
        target=target,
        status="running",
        started_at=datetime.now(UTC),
        modules=modules,
        timeout=timeout,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def update_scan_status(
    session: AsyncSession,
    scan_id: str,
    status: str,
) -> None:
    """
    Update scan status.

    Args:
        session: Database session
        scan_id: Scan identifier
        status: New status
    """
    result = await session.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if scan:
        scan.status = status
        if status in ("success", "error", "timeout"):
            scan.completed_at = datetime.now(UTC)
        await session.commit()


async def get_scan(session: AsyncSession, scan_id: str) -> Scan | None:
    """
    Get scan by ID.

    Args:
        session: Database session
        scan_id: Scan identifier

    Returns:
        Scan object or None
    """
    result = await session.execute(select(Scan).where(Scan.scan_id == scan_id))
    return result.scalar_one_or_none()


async def list_scans(session: AsyncSession, limit: int = 100) -> list[Scan]:
    """
    List recent scans.

    Args:
        session: Database session
        limit: Maximum number of scans to return

    Returns:
        List of Scan objects
    """
    result = await session.execute(select(Scan).order_by(Scan.started_at.desc()).limit(limit))
    return list(result.scalars().all())


async def save_scan_result(
    session: AsyncSession, scan_id: str, check_result: CheckResult
) -> ScanResult:
    """
    Save a scan result with its findings.

    Args:
        session: Database session
        scan_id: Scan identifier
        check_result: CheckResult object from scanner

    Returns:
        Created ScanResult object
    """
    scan_result = ScanResult(
        scan_id=scan_id,
        module=check_result.module,
        category=check_result.category,
        target=check_result.target,
        timestamp=check_result.timestamp,
        duration_ms=check_result.duration_ms,
        status=check_result.status,
        data=check_result.data,
        error=check_result.error,
    )
    session.add(scan_result)
    await session.flush()  # Get the ID

    # Save findings
    for finding in check_result.findings:
        db_finding = Finding(
            scan_result_id=scan_result.id,
            scan_id=scan_id,
            severity=finding.severity,
            title=finding.title,
            description=finding.description,
            reference=finding.reference,
            cve=finding.cve,
            cvss_score=finding.cvss_score,
        )
        session.add(db_finding)

    await session.commit()
    await session.refresh(scan_result)
    return scan_result


async def get_scan_results(
    session: AsyncSession, scan_id: str
) -> list[tuple[ScanResult, list[Finding]]]:
    """
    Get all results for a scan with their findings.

    Args:
        session: Database session
        scan_id: Scan identifier

    Returns:
        List of tuples (ScanResult, list of findings)
    """
    result = await session.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    scan_results = list(result.scalars().all())

    results_with_findings: list[tuple[ScanResult, list[Finding]]] = []
    for scan_result in scan_results:
        findings_result = await session.execute(
            select(Finding).where(Finding.scan_result_id == scan_result.id)
        )
        findings: list[Finding] = list(findings_result.scalars().all())
        results_with_findings.append((scan_result, findings))

    return results_with_findings
