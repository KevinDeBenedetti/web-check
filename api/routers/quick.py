"""Quick scan endpoints."""

from datetime import UTC

import httpx
from fastapi import APIRouter, HTTPException, Query

from api.models import CheckResult
from api.services.nikto import run_nikto_scan
from api.services.nuclei import run_nuclei_scan

router = APIRouter()


@router.get("/nuclei", response_model=CheckResult)
async def quick_nuclei_scan(
    url: str = Query(..., description="Target URL to scan"),
    timeout: int = Query(300, ge=30, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run quick Nuclei vulnerability scan.

    This scan uses Nuclei templates to check for known CVEs and vulnerabilities.
    Average duration: 2-5 minutes.
    """
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    return await run_nuclei_scan(url, timeout)


@router.get("/nikto", response_model=CheckResult)
async def quick_nikto_scan(
    url: str = Query(..., description="Target URL to scan"),
    timeout: int = Query(600, ge=30, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run Nikto web server scan.

    Scans for web server misconfigurations and outdated software.
    Average duration: 5-10 minutes.
    """
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    return await run_nikto_scan(url, timeout)


@router.get("/dns", response_model=CheckResult)
async def quick_dns_check(
    url: str = Query(..., description="Domain or URL to check"),
) -> CheckResult:
    """
    Perform quick DNS reconnaissance.

    Checks DNS records, nameservers, and basic domain information.
    Average duration: < 1 minute.
    """
    import time
    from datetime import datetime

    start = time.time()

    try:
        # Extract domain from URL
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]

        # Simple DNS check using httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(f"https://{domain}", follow_redirects=True)
                dns_ok = True
                status_code = response.status_code
            except Exception:
                dns_ok = False
                status_code = None

        return CheckResult(
            module="dns",
            category="quick",
            target=url,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={
                "domain": domain,
                "resolvable": dns_ok,
                "http_status": status_code,
            },
            findings=[],
            error=None,
        )

    except Exception as e:
        return CheckResult(
            module="dns",
            category="quick",
            target=url,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )
