"""Quick scan endpoints."""

import time
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import urlparse

import httpx
from api.models import CheckResult
from api.services.dns_enum import run_dns_enum
from api.services.headers_scanner import run_headers_scan
from api.services.nikto import run_nikto_scan
from api.services.nuclei import run_nuclei_scan
from api.utils.config import get_settings
from api.utils.security import is_allowed_host, target_host, target_url
from fastapi import APIRouter, Depends, Query
from httpx_secure import httpx_ssrf_protection

router = APIRouter()


@router.get("/nuclei", response_model=CheckResult)
async def quick_nuclei_scan(
    url: str = Depends(target_url),
    timeout: int = Query(300, ge=30, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run quick Nuclei vulnerability scan.

    This scan uses Nuclei templates to check for known CVEs and vulnerabilities.
    Average duration: 2-5 minutes.
    """
    return await run_nuclei_scan(url, timeout)


@router.get("/nikto", response_model=CheckResult)
async def quick_nikto_scan(
    url: str = Depends(target_url),
    timeout: int = Query(600, ge=30, le=3600, description="Timeout in seconds"),
) -> CheckResult:
    """
    Run Nikto web server scan.

    Scans for web server misconfigurations and outdated software.
    Average duration: 5-10 minutes.
    """
    return await run_nikto_scan(url, timeout)


@router.get("/dns", response_model=CheckResult)
async def quick_dns_check(url: str = Depends(target_host)) -> CheckResult:
    """
    Perform quick DNS reconnaissance.

    Checks DNS records, nameservers, and basic domain information.
    Average duration: < 1 minute.
    """
    start = time.time()
    domain = urlparse(url).hostname or ""
    allowed_domains = get_settings().get_allowed_domains()

    def _ssrf_validator(hostname: str, ip: IPv4Address | IPv6Address, port: int) -> bool:
        return is_allowed_host(hostname, allowed_domains)

    try:
        # Build URL using only the validated domain; httpx-secure re-checks the
        # resolved IP at connection time (DNS rebinding protection).
        validated_url = f"https://{domain}/"
        base_client = httpx.AsyncClient(timeout=10.0)
        async with httpx_ssrf_protection(
            base_client,
            custom_validator=_ssrf_validator,
            dns_cache_size=1000,
            dns_cache_ttl=600,
        ) as client:
            try:
                # Do not follow redirects to avoid being redirected to unintended hosts.
                response = await client.get(validated_url, follow_redirects=False)
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


@router.get("/headers", response_model=CheckResult)
async def quick_headers_scan(
    url: str = Depends(target_url),
    timeout: int = Query(30, ge=5, le=120, description="Timeout in seconds"),
) -> CheckResult:
    """
    Scan HTTP security headers.

    Checks for missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, etc.),
    CORS policy, cookie flags, and server information disclosure.
    Average duration: < 5 seconds.
    """
    return await run_headers_scan(url, timeout)


@router.get("/dns-enum", response_model=CheckResult)
async def quick_dns_enum(
    url: str = Depends(target_host),
    timeout: int = Query(30, ge=5, le=120, description="Timeout in seconds"),
) -> CheckResult:
    """
    Full DNS record enumeration.

    Enumerates A, AAAA, MX, NS, TXT, SOA, CNAME records and checks email security
    controls (SPF, DMARC, DKIM) and zone transfer exposure.
    Average duration: < 15 seconds.
    """
    return await run_dns_enum(url, timeout)
