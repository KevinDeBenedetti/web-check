"""CORS misconfiguration check.

Sends requests with an Origin header and evaluates the
Access-Control-Allow-Origin response for risky configurations:
- Wildcard (*) with credentials
- Reflection of arbitrary origins
- Null origin allowed
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

_TEST_ORIGINS = [
    "https://evil.example.com",
    "null",
]


@dataclass(slots=True)
class CorsCheck:
    id: str = "web-cors"
    name: str = "CORS Configuration"
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
                # First: baseline request without Origin
                base_resp = await client.get(target)
                acao = base_resp.headers.get("Access-Control-Allow-Origin", "")
                acac = base_resp.headers.get("Access-Control-Allow-Credentials", "")

                issues: list[dict[str, str]] = []
                score = 100

                # Check wildcard with credentials
                if acao == "*" and acac.lower() == "true":
                    issues.append(
                        {
                            "issue": "Wildcard ACAO (*) with Allow-Credentials: true",
                            "severity": "critical",
                        }
                    )
                    score -= 40

                # Test origin reflection
                for origin in _TEST_ORIGINS:
                    resp = await client.get(target, headers={"Origin": origin})
                    reflected = resp.headers.get("Access-Control-Allow-Origin", "")
                    creds = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if reflected == origin and origin == "null":
                        issues.append(
                            {
                                "issue": "null origin is reflected in ACAO",
                                "severity": "high",
                            }
                        )
                        score -= 25
                    elif reflected == origin and origin != "null":
                        issues.append(
                            {
                                "issue": f"Arbitrary origin '{origin}' reflected in ACAO",
                                "severity": "high",
                            }
                        )
                        score -= 30
                        if creds.lower() == "true":
                            issues.append(
                                {
                                    "issue": "Reflected origin + Allow-Credentials: true",
                                    "severity": "critical",
                                }
                            )
                            score -= 20

        except Exception as exc:
            logger.debug("HTTP request failed for %s: %s", target, exc)
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Could not reach {target}",
                details={"error": str(exc)},
            )

        score = max(0, min(100, score))

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="CORS configuration looks safe.",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"Found {len(issues)} CORS issue(s).",
            details=issues,
            remediation=(
                "Avoid reflecting arbitrary origins. Never combine wildcard (*) "
                "with credentials. Use a strict allowlist of trusted origins."
            ),
        )
