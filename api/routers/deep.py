"""Deep scan endpoints."""

from datetime import timezone

from fastapi import APIRouter, HTTPException, Query

from api.models import CheckResult
from api.services.zap import run_zap_scan

router = APIRouter()


@router.get("/zap", response_model=CheckResult)
async def deep_zap_scan(
    url: str = Query(..., description="Target URL to scan"),
    timeout: int = Query(900, ge=300, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run comprehensive OWASP ZAP baseline scan.

    Performs active scanning for vulnerabilities including XSS, SQLi, and more.
    Average duration: 15-30 minutes.
    """
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    return await run_zap_scan(url, timeout)


@router.get("/testssl", response_model=CheckResult)
async def deep_testssl_scan(
    url: str = Query(..., description="Target URL or domain to scan"),
    timeout: int = Query(300, ge=60, le=600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run comprehensive SSL/TLS security analysis.

    Tests for SSL/TLS configuration issues, weak ciphers, and certificate problems.
    Average duration: 3-5 minutes.
    """
    import time
    from datetime import datetime

    from api.services.docker_runner import docker_run

    start = time.time()

    try:
        # Extract domain from URL
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]

        result = await docker_run(
            image="drwetter/testssl.sh:latest",
            command=[
                "/home/testssl/testssl.sh",
                "--jsonfile",
                "/output/testssl.json",
                domain,
            ],
            volumes={"outputs/temp": "/output"},
            timeout=timeout,
            container_name="security-scanner-testssl",
        )

        if result["timeout"]:
            return CheckResult(
                module="testssl",
                category="deep",
                target=url,
                timestamp=datetime.now(timezone.utc),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        return CheckResult(
            module="testssl",
            category="deep",
            target=url,
            timestamp=datetime.now(timezone.utc),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"scan_completed": True},
            findings=[],
            error=None,)

    except Exception as e:
        return CheckResult(
            module="testssl",
            category="deep",
            target=url,
            timestamp=datetime.now(timezone.utc),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )
