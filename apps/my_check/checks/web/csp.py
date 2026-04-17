"""Content Security Policy (CSP) analysis check.

Fetches the CSP header and evaluates it for common misconfigurations:
- Missing CSP entirely
- Usage of 'unsafe-inline' or 'unsafe-eval'
- Overly permissive sources (wildcard *)
- Missing key directives (default-src, script-src, object-src)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

# Directives that should ideally be present in a strong CSP.
_KEY_DIRECTIVES = ("default-src", "script-src", "object-src")

# Tokens that weaken CSP significantly.
_UNSAFE_TOKENS = ("'unsafe-inline'", "'unsafe-eval'", "data:", "blob:")


def _parse_csp(raw: str) -> dict[str, list[str]]:
    """Parse a CSP header string into a dict of directive → values."""
    directives: dict[str, list[str]] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        values = tokens[1:] if len(tokens) > 1 else []
        directives[name] = values
    return directives


@dataclass(slots=True)
class CspCheck:
    id: str = "web-csp"
    name: str = "Content Security Policy"
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
                message=f"Could not reach {target}",
                details={"error": str(exc)},
            )

        raw_csp = resp.headers.get("Content-Security-Policy", "")
        raw_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")

        if not raw_csp and not raw_ro:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message="No Content-Security-Policy header found.",
                remediation=(
                    "Add a Content-Security-Policy header. Start with a restrictive "
                    "policy like: default-src 'self'; script-src 'self'; object-src 'none'"
                ),
            )

        # Prefer enforcing CSP; fall back to report-only for analysis.
        is_report_only = not raw_csp
        csp_raw = raw_csp or raw_ro
        directives = _parse_csp(csp_raw)

        issues: list[dict[str, str]] = []
        score = 100

        if is_report_only:
            issues.append({"issue": "CSP is report-only (not enforced)", "severity": "medium"})
            score -= 20

        # Check for key directives
        for directive in _KEY_DIRECTIVES:
            if directive not in directives:
                # default-src covers missing directives
                if directive != "default-src" and "default-src" in directives:
                    continue
                issues.append({"issue": f"Missing '{directive}' directive", "severity": "medium"})
                score -= 10

        # Check for unsafe tokens
        for directive, values in directives.items():
            for token in _UNSAFE_TOKENS:
                if token in values:
                    issues.append(
                        {
                            "issue": f"'{token}' in {directive}",
                            "severity": "high" if token in ("'unsafe-eval'",) else "medium",
                        }
                    )
                    score -= 15 if token == "'unsafe-eval'" else 10

        # Check for wildcard sources
        for directive, values in directives.items():
            if "*" in values:
                issues.append({"issue": f"Wildcard '*' in {directive}", "severity": "high"})
                score -= 15

        score = max(0, min(100, score))

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="Content Security Policy is well-configured.",
                details={"csp": csp_raw, "directives": list(directives.keys())},
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"CSP has {len(issues)} issue(s).",
            details=issues,
            remediation=(
                "Tighten CSP: remove 'unsafe-inline'/'unsafe-eval', avoid wildcards, "
                "set 'object-src none', and ensure default-src is restrictive."
            ),
        )
