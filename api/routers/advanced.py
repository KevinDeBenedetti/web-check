"""Advanced security scanning endpoints (SQLMap, Wapiti, XSStrike)."""

from fastapi import APIRouter, Query

from api.models import CheckResult
from api.services.sqlmap_scanner import run_sqlmap_scan
from api.services.wapiti_scanner import run_wapiti_scan
from api.services.xsstrike_scanner import run_xsstrike_scan

router = APIRouter()


@router.get("/sqlmap", response_model=CheckResult)
async def scan_with_sqlmap(
    url: str = Query(..., description="Target URL to scan for SQL injection"),
    timeout: int = Query(900, ge=60, le=1800, description="Timeout in seconds (default: 900)"),
) -> CheckResult:
    """
    Run SQLMap SQL injection scanner.

    This is a powerful SQL injection detection tool that can:
    - Detect various SQL injection types
    - Enumerate databases
    - Extract data from vulnerable applications

    **Average duration**: 10-15 minutes
    **Recommended for**: Testing applications with database interactions
    """
    return await run_sqlmap_scan(url, timeout)


@router.get("/wapiti", response_model=CheckResult)
async def scan_with_wapiti(
    url: str = Query(..., description="Target URL to scan for web vulnerabilities"),
    timeout: int = Query(600, ge=60, le=1800, description="Timeout in seconds (default: 600)"),
) -> CheckResult:
    """
    Run Wapiti web vulnerability scanner.

    Wapiti is a comprehensive web application security scanner that detects:
    - SQL injections
    - XSS vulnerabilities
    - File disclosure issues
    - Command execution vulnerabilities
    - CRLF injections

    **Average duration**: 5-10 minutes
    **Recommended for**: Comprehensive web application testing
    """
    return await run_wapiti_scan(url, timeout)


@router.get("/xsstrike", response_model=CheckResult)
async def scan_with_xsstrike(
    url: str = Query(..., description="Target URL to scan for XSS vulnerabilities"),
    timeout: int = Query(300, ge=30, le=900, description="Timeout in seconds (default: 300)"),
) -> CheckResult:
    """
    Run XSStrike XSS detection scanner.

    XSStrike is an advanced XSS detection suite that can:
    - Detect reflected and DOM-based XSS
    - Crawl target URLs
    - Test various XSS payloads
    - Bypass WAF filters

    **Average duration**: 3-5 minutes
    **Recommended for**: Focused XSS vulnerability testing
    """
    return await run_xsstrike_scan(url, timeout)
