"""Redirect chain analysis check."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

MAX_HOPS = 10


@dataclass(slots=True)
class RedirectsCheck:
    """Follow the redirect chain and detect HTTP↔HTTPS transitions."""

    id: str = "web-redirects"
    name: str = "Redirect Chain"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, str)

        chain: list[dict[str, str | int]] = []
        current_url = target
        has_upgrade = False
        has_downgrade = False

        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(15.0),
                verify=False,
            ) as client:
                for _ in range(MAX_HOPS):
                    resp = await client.get(current_url)

                    if resp.is_redirect:
                        location = resp.headers.get("location", "")
                        chain.append(
                            {
                                "url": str(resp.url),
                                "status_code": resp.status_code,
                                "location": location,
                            }
                        )

                        # Detect HTTP ↔ HTTPS transitions
                        if str(resp.url).startswith("http://") and location.startswith("https://"):
                            has_upgrade = True
                        elif str(resp.url).startswith("https://") and location.startswith(
                            "http://"
                        ):
                            has_downgrade = True

                        current_url = location
                    else:
                        # Final destination
                        chain.append(
                            {
                                "url": str(resp.url),
                                "status_code": resp.status_code,
                                "location": None,
                            }
                        )
                        break
                else:
                    return CheckResult(
                        status=CheckStatus.FAIL,
                        score=0,
                        message=f"Too many redirects (>{MAX_HOPS})",
                        details={"chain": chain},
                        remediation="Reduce the number of redirects in the chain.",
                    )

        except Exception as exc:
            logger.debug("Redirect check failed for %s: %s", target, exc)
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Could not follow redirects for {target}",
                details={"error": str(exc)},
                remediation="Ensure the target URL is reachable.",
            )

        details = {
            "chain": chain,
            "total_hops": len(chain) - 1,
            "http_to_https_upgrade": has_upgrade,
            "https_to_http_downgrade": has_downgrade,
        }

        if has_downgrade:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message="HTTPS → HTTP downgrade detected in redirect chain",
                details=details,
                remediation="Remove the HTTPS to HTTP downgrade. All redirects should stay on HTTPS.",
            )

        final_url = str(chain[-1]["url"]) if chain else target

        if has_upgrade:
            return CheckResult(
                status=CheckStatus.WARN,
                score=50,
                message="HTTP → HTTPS upgrade redirect detected",
                details=details,
                remediation=(
                    "Serve the site directly over HTTPS instead of redirecting from HTTP. "
                    "Consider enabling HSTS."
                ),
            )

        if final_url.startswith("https://"):
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="Clean HTTPS with no problematic redirects",
                details=details,
            )

        return CheckResult(
            status=CheckStatus.WARN,
            score=50,
            message="Final destination is not HTTPS",
            details=details,
            remediation="Configure the server to serve content over HTTPS.",
        )
