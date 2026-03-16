"""Deep scan endpoints."""

from fastapi import APIRouter, HTTPException, Query

from api.models import CheckResult
from api.services.sslyze_scanner import run_sslyze_scan
from api.services.zap_native import run_zap_scan

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


@router.get("/sslyze", response_model=CheckResult)
async def deep_sslyze_scan(
    url: str = Query(..., description="Target URL or domain to scan"),
    timeout: int = Query(300, ge=60, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run comprehensive SSL/TLS security analysis using SSLyze.

    Tests for SSL/TLS configuration issues, weak ciphers, and certificate problems.
    Average duration: 1-3 minutes.
    """
    if not url.startswith(("http://", "https://")) and ":" not in url:
        # If just a domain, assume HTTPS
        url = f"https://{url}"

    return await run_sslyze_scan(url, timeout)
