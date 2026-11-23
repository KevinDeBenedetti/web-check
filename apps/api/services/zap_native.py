"""OWASP ZAP scanning service using native Python API."""

import asyncio
import threading
import time
from datetime import UTC, datetime
from typing import Any

import structlog
from api.models import CheckResult, Finding
from api.utils.config import get_settings
from zapv2 import ZAPv2

logger = structlog.get_logger()

# Seconds allowed beyond the module timeout before the scan is abandoned: the
# stop/alerts calls that end a scan need a moment once the budget is spent.
DEADLINE_MARGIN = 30.0
# Timeout of the initial request to the target through the ZAP proxy. zapv2 sends
# its API calls without one (and offers no way to set it), so the outer deadline
# in run_zap_scan is what bounds a hung daemon.
REQUEST_TIMEOUT = 60.0


def _get_zap_client() -> ZAPv2:
    """Get ZAP client instance (host, port and API key come from settings)."""
    settings = get_settings()
    proxy = f"http://{settings.zap_host}:{settings.zap_port}"
    apikey = settings.zap_api_key.get_secret_value() if settings.zap_api_key else None
    return ZAPv2(apikey=apikey, proxies={"http": proxy, "https": proxy})


async def run_zap_scan(target: str, timeout: int = 900, scan_id: str | None = None) -> CheckResult:
    """
    Run OWASP ZAP baseline scan against a target using Python API.

    Args:
        target: URL to scan
        timeout: Timeout in seconds
        scan_id: Scan ID for log streaming (optional)

    Returns:
        CheckResult with ZAP findings
    """
    start = time.time()
    findings: list[Finding] = []

    if scan_id:
        from api.services.log_streamer import log_streamer

        await log_streamer.send_log(
            scan_id, {"type": "info", "message": "Connecting to ZAP daemon..."}
        )

    try:
        # Get ZAP client
        zap = _get_zap_client()

        # Set when the deadline passes: a thread that unblocks afterwards stops at
        # the next step instead of starting (or polling) a scan nobody waits for.
        abandoned = threading.Event()

        # Run in thread pool to avoid blocking
        def _run_scan() -> dict[str, Any]:
            # Access the target URL
            logger.info("zap_accessing_url", target=target)
            # Redirects are not followed: this request goes through the ZAP proxy,
            # and a target must not be able to bounce it to ZAP's own API or to an
            # internal host.
            zap.urlopen(target, allow_redirects=False, timeout=REQUEST_TIMEOUT)
            if abandoned.is_set():
                return {"alerts": [], "timed_out": True}

            # Spider scan to discover URLs
            logger.info("zap_starting_spider", target=target)
            spider_id = zap.spider.scan(target)

            # Wait for spider to complete (half the budget), then stop it for real:
            # breaking out of the loop alone leaves ZAP crawling in the background.
            timed_out = False
            while int(zap.spider.status(spider_id)) < 100:
                if abandoned.is_set() or time.time() - start > timeout / 2:
                    logger.warning("zap_spider_timeout", target=target)
                    zap.spider.stop(spider_id)
                    break
                time.sleep(2)

            logger.info("zap_spider_completed", target=target, spider_id=spider_id)
            if abandoned.is_set():
                return {"alerts": [], "timed_out": True}

            # Active scan
            logger.info("zap_starting_active_scan", target=target)
            scan_id_zap = zap.ascan.scan(target)

            # Wait for active scan to complete
            while int(zap.ascan.status(scan_id_zap)) < 100:
                if abandoned.is_set() or time.time() - start > timeout:
                    logger.warning("zap_scan_timeout", target=target)
                    zap.ascan.stop(scan_id_zap)
                    timed_out = True
                    break
                time.sleep(5)

            # Get alerts (partial results when timed out)
            alerts = zap.core.alerts(baseurl=target)
            return {"alerts": alerts, "timed_out": timed_out}

        # Run blocking ZAP operations in thread pool, under a hard deadline: the
        # time checks above only run between polls, so a call that hangs would
        # otherwise keep the scan "running" until the API restarts.
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(_run_scan), timeout=timeout + DEADLINE_MARGIN
            )
        except TimeoutError:
            abandoned.set()
            logger.warning("zap_deadline_exceeded", target=target, timeout=timeout)
            if scan_id:
                from api.services.log_streamer import log_streamer

                await log_streamer.send_log(
                    scan_id,
                    {"type": "warning", "message": "ZAP did not answer before the deadline"},
                )
            return CheckResult(
                module="zap",
                category="deep",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error=f"ZAP did not answer within {timeout:.0f}s (+{DEADLINE_MARGIN:.0f}s margin)",
            )

        # Parse alerts
        alerts = result.get("alerts", [])
        findings = _parse_zap_alerts(alerts)

        logger.info(
            "zap_scan_completed",
            target=target,
            findings_count=len(findings),
            alerts_count=len(alerts),
        )

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "warning" if result["timed_out"] else "success",
                    "message": f"ZAP scan {'timed out' if result['timed_out'] else 'completed'}"
                    f" - {len(findings)} findings",
                },
            )

        return CheckResult(
            module="zap",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="timeout" if result["timed_out"] else "success",
            data={"alerts_count": len(alerts), "partial": result["timed_out"]},
            findings=findings,
            error="Scan timed out (partial results)" if result["timed_out"] else None,
        )

    except Exception as e:
        error_msg = str(e)

        # Provide clearer error messages
        if "Unable to connect to proxy" in error_msg or "Max retries exceeded" in error_msg:
            error_msg = "ZAP daemon is not accessible. Please ensure the ZAP container is running and healthy."
        elif "not permitted" in error_msg:
            error_msg = "ZAP API access denied. If the ZAP daemon runs with an API key, set ZAP_API_KEY to it."

        logger.error("zap_scan_failed", target=target, error=error_msg)

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id, {"type": "error", "message": f"ZAP scan failed: {error_msg}"}
            )

        return CheckResult(
            module="zap",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=error_msg,
        )


def _parse_zap_alerts(alerts: list[dict[str, Any]]) -> list[Finding]:
    """
    Parse ZAP alerts into Finding objects.

    Args:
        alerts: List of ZAP alert dictionaries

    Returns:
        List of Finding objects
    """
    findings: list[Finding] = []

    # ZAP risk levels: 0=Info, 1=Low, 2=Medium, 3=High
    risk_to_severity = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
    }

    for alert in alerts:
        severity = risk_to_severity.get(str(alert.get("risk", "0")), "info")

        finding = Finding(
            severity=severity,  # type: ignore
            title=alert.get("alert", "Unknown"),
            description=alert.get("description", ""),
            reference=alert.get("reference", None),
            cve=alert.get("cweid", None),
            cvss_score=None,  # ZAP doesn't provide CVSS directly
        )
        findings.append(finding)

    return findings
