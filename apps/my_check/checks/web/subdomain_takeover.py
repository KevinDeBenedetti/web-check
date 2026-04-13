"""Subdomain takeover detection check."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import dns.resolver
import httpx
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

# Known services vulnerable to subdomain takeover.
VULNERABLE_CNAME_SUFFIXES: list[str] = [
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "s3-website",
    "cloudfront.net",
    "azurewebsites.net",
    "blob.core.windows.net",
    "cloudapp.net",
    "trafficmanager.net",
    "myshopify.com",
    "desk.com",
    "zendesk.com",
    "fastly.net",
    "ghost.io",
    "helpjuice.com",
    "helpscoutdocs.com",
    "unbouncepages.com",
    "cargocollective.com",
    "feedpress.me",
    "freshdesk.com",
    "tumblr.com",
]

# Error body fingerprints that indicate a dangling CNAME.
TAKEOVER_FINGERPRINTS: list[str] = [
    "There isn't a GitHub Pages site here.",
    "No such app",
    "NoSuchBucket",
    "Bad Request: ERROR: The request could not be satisfied",
    "The specified bucket does not exist",
    "Repository not found",
    "No settings were found for this company",
    "Whatever you were looking for doesn't currently exist",
    "is not a registered InCloud YouTrack",
    "Domain is not configured",
]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target.split("/")[0].split(":")[0]


def _resolve_cnames(domain: str) -> list[str]:
    """Return the CNAME chain for *domain*, if any."""
    cnames: list[str] = []
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cnames.append(str(rdata.target).rstrip("."))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except Exception as exc:
        logger.debug("CNAME resolution error for %s: %s", domain, exc)
    return cnames


def _matches_vulnerable_service(cname: str) -> str | None:
    """Return the matching vulnerable suffix if the CNAME is a known target."""
    lower = cname.lower()
    for suffix in VULNERABLE_CNAME_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return None


async def _probe_for_takeover(domain: str) -> tuple[bool, str | None]:
    """Try to fetch the domain over HTTP(S) and look for error fingerprints."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)
                body = resp.text[:4096]
                for fingerprint in TAKEOVER_FINGERPRINTS:
                    if fingerprint.lower() in body.lower():
                        return True, fingerprint
        except Exception:
            # Connection failure to a known-vulnerable CNAME is itself suspicious
            return True, f"Connection to {url} failed (possible dangling CNAME)"
    return False, None


@dataclass(slots=True)
class SubdomainTakeoverCheck:
    """Detect potential subdomain takeover via dangling CNAME records."""

    id: str = "web-subdomain-takeover"
    name: str = "Subdomain Takeover"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, str)
        domain = _extract_domain(target)

        cnames = _resolve_cnames(domain)

        details: dict = {
            "domain": domain,
            "cnames": cnames,
            "vulnerable_service": None,
            "takeover_indicator": None,
        }

        if not cnames:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="No CNAME record found — not susceptible to subdomain takeover",
                details=details,
            )

        # Check each CNAME against the vulnerable-service list
        for cname in cnames:
            matched_service = _matches_vulnerable_service(cname)
            if matched_service:
                details["vulnerable_service"] = matched_service
                is_takeover, indicator = await _probe_for_takeover(domain)
                details["takeover_indicator"] = indicator

                if is_takeover:
                    return CheckResult(
                        status=CheckStatus.FAIL,
                        score=0,
                        message=(
                            f"Potential subdomain takeover: CNAME {cname} "
                            f"points to {matched_service}"
                        ),
                        details=details,
                        remediation=(
                            f"Remove the dangling CNAME record for {domain} or "
                            f"reclaim the resource on {matched_service}."
                        ),
                    )

                return CheckResult(
                    status=CheckStatus.WARN,
                    score=70,
                    message=(
                        f"CNAME points to potentially vulnerable service ({matched_service}) "
                        "but resource appears claimed"
                    ),
                    details=details,
                    remediation=(
                        f"Verify ownership of the {matched_service} resource for {domain}."
                    ),
                )

        return CheckResult(
            status=CheckStatus.PASS,
            score=100,
            message=f"CNAME exists ({', '.join(cnames)}) but points to non-vulnerable service",
            details=details,
        )
