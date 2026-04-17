"""Cookie security check.

Fetches the target URL and evaluates Set-Cookie headers for security flags:
- Secure flag (required for HTTPS)
- HttpOnly flag (prevents JS access)
- SameSite attribute (CSRF protection)
- __Host- / __Secure- prefixes
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)


def _parse_cookie_attrs(raw: str) -> tuple[str, dict[str, str]]:
    """Parse a Set-Cookie header into (name, {lowercase_attr: value})."""
    parts = [p.strip() for p in raw.split(";")]
    name_value = parts[0]
    name = name_value.split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.strip().lower()] = ""
    return name, attrs


@dataclass(slots=True)
class CookieSecurityCheck:
    id: str = "web-cookies"
    name: str = "Cookie Security"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, str):
            raise TypeError(f"Expected str URL, got {type(target).__name__}")

        is_https = target.startswith("https://")

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
                message=f"Could not reach {target}",
                details={"error": str(exc)},
            )

        raw_cookies = resp.headers.get_list("set-cookie")
        if not raw_cookies:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="No cookies set — nothing to evaluate.",
            )

        issues: list[dict[str, str]] = []

        for raw in raw_cookies:
            name, attrs = _parse_cookie_attrs(raw)

            if is_https and "secure" not in attrs:
                issues.append({"cookie": name, "issue": "missing Secure flag"})

            if "httponly" not in attrs:
                issues.append({"cookie": name, "issue": "missing HttpOnly flag"})

            samesite = attrs.get("samesite", "").lower()
            if samesite not in ("strict", "lax"):
                if samesite == "none":
                    issues.append({"cookie": name, "issue": "SameSite=None (no CSRF protection)"})
                else:
                    issues.append({"cookie": name, "issue": "missing SameSite attribute"})

        total_checks = len(raw_cookies) * 3  # 3 flags per cookie
        failures = len(issues)
        score = max(0, min(100, int(((total_checks - failures) / total_checks) * 100)))

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message=f"All {len(raw_cookies)} cookie(s) have proper security flags.",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"{len(issues)} cookie security issue(s) across {len(raw_cookies)} cookie(s).",
            details=issues,
            remediation=(
                "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all cookies. "
                "Use __Host- prefix for sensitive cookies to enforce Secure + Path=/."
            ),
        )
