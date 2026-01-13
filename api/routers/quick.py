"""Quick scan endpoints."""

from datetime import UTC
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, Query
from httpx_secure import httpx_ssrf_protection

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

    def _extract_hostname(value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname
        # Fallback: treat input as bare hostname/domain
        # Strip any path portion if present
        return value.split("/")[0]

    # Domains that this endpoint is allowed to contact.
    # Replace or extend this tuple with the domains that are acceptable in your deployment.
    ALLOWED_DOMAINS = ("example.com",)

    def _custom_ssrf_validator(hostname: str, ip: IPv4Address | IPv6Address, port: int) -> bool:
        """
        Custom validator for httpx-secure SSRF protection.

        Args:
            hostname: The hostname being accessed
            ip: The resolved IP address
            port: The port being accessed

        Returns:
            True if the request should be allowed, False otherwise
        """
        # Check if hostname is in the allow-list
        hostname_lc = hostname.lower().strip(".")

        for allowed_domain in ALLOWED_DOMAINS:
            allowed_domain_lc = allowed_domain.lower().strip(".")
            if hostname_lc == allowed_domain_lc or hostname_lc.endswith("." + allowed_domain_lc):
                return True

        return False

    def _is_allowed_domain(hostname: str) -> bool:
        """
        Check if hostname is allowed for DNS checks.

        This function enforces that the hostname is not internal/localhost and
        that it matches the configured allow-list in ALLOWED_DOMAINS, either
        as an exact match or as a subdomain.
        """
        # Basic validation: ensure hostname is not empty and doesn't contain suspicious patterns
        if not hostname or len(hostname) > 253:
            return False

        hostname_lc = hostname.lower().strip(".")

        # Reject localhost variations
        localhost_variations = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if hostname_lc in localhost_variations:
            return False

        # Reject internal domain suffixes
        internal_suffixes = (".local", ".internal", ".localhost")
        if any(hostname_lc.endswith(suffix) for suffix in internal_suffixes):
            return False

        # Enforce allow-list: hostname must be equal to or a subdomain of one of ALLOWED_DOMAINS
        allowed = False
        for allowed_domain in ALLOWED_DOMAINS:
            allowed_domain_lc = allowed_domain.lower().strip(".")
            if hostname_lc == allowed_domain_lc or hostname_lc.endswith("." + allowed_domain_lc):
                allowed = True
                break

        return allowed

    try:
        # Extract and validate domain from URL or hostname
        domain = _extract_hostname(url)
        if not domain:
            raise HTTPException(status_code=400, detail="A non-empty domain or URL is required")

        # Validate hostname before making any network request
        if not _is_allowed_domain(domain):
            raise HTTPException(
                status_code=400,
                detail="Target domain is not allowed",
            )

        # Build URL using only the validated domain to prevent SSRF
        validated_url = f"https://{domain}/"

        # Simple DNS check using httpx with SSRF protection
        base_client = httpx.AsyncClient(timeout=10.0)
        async with httpx_ssrf_protection(
            base_client,
            custom_validator=_custom_ssrf_validator,
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

    except HTTPException:
        # Re-raise HTTP errors (validation failures) directly
        raise

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
