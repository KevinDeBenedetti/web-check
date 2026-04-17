"""Security headers check."""

from __future__ import annotations

import logging
import re
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

# Validation rules: header → (valid_regex_or_set, issue_if_invalid)
_HSTS_MIN_AGE = 31536000  # 1 year
_VALID_XFO = {"DENY", "SAMEORIGIN"}
_VALID_XCTO = {"nosniff"}
_VALID_REFERRER = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
_RECOMMENDED_REFERRER = {"strict-origin-when-cross-origin", "no-referrer", "same-origin"}


def _validate_header(name: str, value: str) -> str | None:
    """Return an issue string if the header value is weak/invalid, else None."""
    if name == "Strict-Transport-Security":
        match = re.search(r"max-age=(\d+)", value)
        if not match:
            return "HSTS missing max-age directive"
        age = int(match.group(1))
        if age < _HSTS_MIN_AGE:
            return f"HSTS max-age={age} is below recommended {_HSTS_MIN_AGE} (1 year)"
        return None

    if name == "X-Frame-Options":
        if value.upper() not in _VALID_XFO:
            return f"X-Frame-Options value '{value}' is not DENY or SAMEORIGIN"
        return None

    if name == "X-Content-Type-Options":
        if value.lower() not in _VALID_XCTO:
            return f"X-Content-Type-Options should be 'nosniff', got '{value}'"
        return None

    if name == "Referrer-Policy":
        policies = {p.strip().lower() for p in value.split(",")}
        unknown = policies - _VALID_REFERRER
        if unknown:
            return f"Unknown Referrer-Policy value(s): {', '.join(unknown)}"
        if not policies & _RECOMMENDED_REFERRER:
            return f"Referrer-Policy '{value}' is permissive — consider strict-origin-when-cross-origin"
        return None

    return None


@dataclass(slots=True)
class HeadersCheck:
    """Verify the presence of recommended security response headers."""

    id: str = "web-headers"
    name: str = "Security Headers"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, str):
            raise TypeError(f"Expected str URL, got {type(target).__name__}")

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
        validation_issues: list[str] = []

        for header in SECURITY_HEADERS:
            value = resp.headers.get(header)
            if value:
                details[header] = value
                present_count += 1
                issue = _validate_header(header, value)
                if issue:
                    validation_issues.append(issue)
                    details[header] += f" ⚠ {issue}"
            else:
                details[header] = "MISSING"

        score = min(present_count * POINTS_PER_HEADER, 100)
        # Deduct for misconfigured values
        score = max(0, score - len(validation_issues) * 5)
        missing = [h for h in SECURITY_HEADERS if details[h] == "MISSING"]

        if not missing and not validation_issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="All recommended security headers are present",
                details=details,
            )

        status = CheckStatus.WARN if present_count >= 3 else CheckStatus.FAIL
        parts: list[str] = []
        if missing:
            parts.append("Add the following security headers: " + ", ".join(missing) + ".")
        if validation_issues:
            parts.append("Fix: " + "; ".join(validation_issues) + ".")
        remediation = " ".join(parts)

        return CheckResult(
            status=status,
            score=score,
            message=f"{present_count}/{len(SECURITY_HEADERS)} security headers present",
            details=details,
            remediation=remediation,
        )
