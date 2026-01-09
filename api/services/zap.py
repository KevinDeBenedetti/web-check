"""ZAP (OWASP Zed Attack Proxy) scanning service."""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from api.models import CheckResult, Finding
from api.services.docker_runner import docker_run, load_json_output

logger = structlog.get_logger()


async def run_zap_scan(target: str, timeout: int = 900) -> CheckResult:
    """
    Run OWASP ZAP baseline scan against a target.

    Args:
        target: URL to scan
        timeout: Timeout in seconds

    Returns:
        CheckResult with ZAP findings
    """
    start = time.time()
    findings: list[Finding] = []

    output_dir = Path("outputs/temp")
    output_dir.mkdir(parents=True, exist_ok=True)
    json_output = output_dir / f"zap_{int(time.time())}.json"

    try:
        result = await docker_run(
            image="zaproxy/zap-stable:latest",
            command=[
                "zap-baseline.py",
                "-t",
                target,
                "-r",
                "/zap/wrk/zap.html",
                "-J",
                "/zap/wrk/zap.json",
                "-I",  # Ignore warning on missing TLS certificate
            ],
            volumes={str(output_dir.absolute()): "/zap/wrk"},
            timeout=timeout,
        )

        if result["timeout"]:
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

        # Parse JSON output
        data = await load_json_output(json_output)
        if data:
            findings = _parse_zap_output(data)

        return CheckResult(
            module="zap",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"alerts": len(findings)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        logger.error("zap_scan_failed", target=target, error=str(e))
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
    finally:
        # Cleanup temp files
        for temp_file in output_dir.glob("zap_*"):
            temp_file.unlink()


def _parse_zap_output(data: dict[str, Any]) -> list[Finding]:
    """Parse ZAP JSON output into Finding objects."""
    findings: list[Finding] = []

    site: list[Any] = data.get("site", [])
    if not site:
        return findings

    for site_data in site:
        alerts: list[dict[str, Any]] = site_data.get("alerts", [])
        for alert in alerts:
            risk: str = str(alert.get("riskcode", "0"))
            severity_map = {
                "3": "high",
                "2": "medium",
                "1": "low",
                "0": "info",
            }
            severity = severity_map.get(risk, "info")

            finding = Finding(
                severity=severity,  # type: ignore[arg-type]
                title=str(alert.get("alert", "ZAP Alert")),
                description=str(alert.get("desc", "No description available")),
                reference=str(alert.get("reference")) if alert.get("reference") else None,
                cve=str(alert.get("cweid")) if alert.get("cweid") else None,
                cvss_score=None,
            )
            findings.append(finding)

    return findings
