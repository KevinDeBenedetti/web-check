"""Security headers check."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

SECURITY_HEADERS: list[str] = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Permissions-Policy",
    "Referrer-Policy",
]

POINTS_PER_HEADER = 100 // len(SECURITY_HEADERS)  # ~16


@dataclass(slots=True)
class HeadersCheck:
    """Verify the presence of recommended security response headers."""

    id: str = "web-headers"
    name: str = "Security Headers"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, str)

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(15.0),
                verify=False,
            ) as client:
                resp = await client.get(target)
        except Exception as exc:
            logger.debug("HTTP request failed for %s: %s", target, exc)
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Could not fetch headers from {target}",
                details={"error": str(exc)},
                remediation="Ensure the target URL is reachable.",
            )

        details: dict[str, str] = {}
        present_count = 0

        for header in SECURITY_HEADERS:
            value = resp.headers.get(header)
            if value:
                details[header] = value
                present_count += 1
            else:
                details[header] = "MISSING"

        score = min(present_count * POINTS_PER_HEADER, 100)
        missing = [h for h in SECURITY_HEADERS if details[h] == "MISSING"]

        if not missing:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="All recommended security headers are present",
                details=details,
            )

        status = CheckStatus.WARN if present_count >= 3 else CheckStatus.FAIL
        remediation = "Add the following security headers: " + ", ".join(missing)

        return CheckResult(
            status=status,
            score=score,
            message=f"{present_count}/{len(SECURITY_HEADERS)} security headers present",
            details=details,
            remediation=remediation,
        )
