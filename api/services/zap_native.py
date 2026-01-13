"""OWASP ZAP scanning service using native Python API."""

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

import structlog
from zapv2 import ZAPv2

from api.models import CheckResult, Finding

logger = structlog.get_logger()

# ZAP daemon configuration
ZAP_HOST = "zap"  # Container name in docker-compose
ZAP_PORT = 8090
ZAP_API_KEY = ""  # No API key needed (api.disablekey=true)


def _get_zap_client() -> ZAPv2:
    """Get ZAP client instance."""
    return ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": f"http://{ZAP_HOST}:{ZAP_PORT}",
            "https": f"http://{ZAP_HOST}:{ZAP_PORT}",
        },
    )


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

        # Run in thread pool to avoid blocking
        def _run_scan() -> dict[str, Any]:
            # Access the target URL
            logger.info("zap_accessing_url", target=target)
            zap.urlopen(target)

            # Spider scan to discover URLs
            logger.info("zap_starting_spider", target=target)
            spider_id = zap.spider.scan(target)

            # Wait for spider to complete
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(2)
                if time.time() - start > timeout / 2:  # Use half timeout for spider
                    break

            logger.info("zap_spider_completed", target=target, spider_id=spider_id)

            # Active scan
            logger.info("zap_starting_active_scan", target=target)
            scan_id_zap = zap.ascan.scan(target)

            # Wait for active scan to complete
            while int(zap.ascan.status(scan_id_zap)) < 100:
                time.sleep(5)
                if time.time() - start > timeout:
                    logger.warning("zap_scan_timeout", target=target)
                    break

            # Get alerts
            alerts = zap.core.alerts(baseurl=target)
            return {"alerts": alerts}

        # Run blocking ZAP operations in thread pool
        result = await asyncio.to_thread(_run_scan)

        if time.time() - start >= timeout:
            return CheckResult(
                module="zap",
                category="deep",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
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
                    "type": "success",
                    "message": f"ZAP scan completed - {len(findings)} findings",
                },
            )

        return CheckResult(
            module="zap",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"alerts_count": len(alerts)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        error_msg = str(e)

        # Provide clearer error messages
        if "Unable to connect to proxy" in error_msg or "Max retries exceeded" in error_msg:
            error_msg = "ZAP daemon is not accessible. Please ensure the ZAP container is running and healthy."
        elif "not permitted" in error_msg:
            error_msg = "ZAP API access denied. The container needs to be restarted with proper API permissions."

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
            error=str(e),
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
