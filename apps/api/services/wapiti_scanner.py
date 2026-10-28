"""Wapiti web vulnerability scanner service."""

import time
from datetime import UTC, datetime
from pathlib import Path

import structlog
from api.models import CheckResult, Finding, Severity
from api.services.docker_runner import load_json_output, run_process, unique_output_name

logger = structlog.get_logger()


async def run_wapiti_scan(
    target: str, timeout: int = 600, scan_id: str | None = None
) -> CheckResult:
    """
    Run Wapiti web vulnerability scanner against a target using Python library.

    Args:
        target: URL to scan
        timeout: Timeout in seconds
        scan_id: Scan ID for log streaming (optional)

    Returns:
        CheckResult with Wapiti findings
    """
    start = time.time()
    findings: list[Finding] = []

    # Output directory
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / unique_output_name("wapiti", "json")

    if scan_id:
        from api.services.log_streamer import log_streamer

        await log_streamer.send_log(
            scan_id, {"type": "info", "message": f"Starting Wapiti scan on {target}"}
        )

    try:
        # Run wapiti-getcookie then wapiti using subprocess
        cmd = [
            "wapiti",
            "-u",
            target,
            "-f",
            "json",
            "-o",
            str(output_file),
            "--flush-session",
            "--scope",
            "url",
        ]

        result = await run_process(cmd, timeout=timeout)
        if result["timeout"]:
            return CheckResult(
                module="wapiti",
                category="security",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        # Parse the JSON report; a report the API cannot read fails the module
        # (ToolOutputError) instead of passing as "no findings".
        wapiti_data = await load_json_output(output_file, tool="wapiti")
        if wapiti_data is not None:
            vulnerabilities = wapiti_data.get("vulnerabilities", {})
            for vuln_type, vuln_list in vulnerabilities.items():
                for vuln in vuln_list:
                    severity_str = _map_wapiti_severity(vuln.get("level", 1))
                    findings.append(
                        Finding(
                            severity=severity_str,
                            title=f"Wapiti: {vuln_type}",
                            description=vuln.get("info", "No description available"),
                            reference=vuln.get("wstg", [None])[0] if vuln.get("wstg") else None,
                            cve=vuln.get("cve", [None])[0] if vuln.get("cve") else None,
                            cvss_score=_severity_to_cvss(severity_str),
                        )
                    )

        logger.info(
            "wapiti_scan_completed",
            target=target,
            findings_count=len(findings),
        )

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "success",
                    "message": f"Wapiti scan completed - {len(findings)} vulnerabilities found",
                },
            )

        return CheckResult(
            module="wapiti",
            category="security",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"findings_count": len(findings)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        error_msg = str(e)
        logger.error("wapiti_scan_failed", target=target, error=error_msg)

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id, {"type": "error", "message": f"Wapiti scan failed: {error_msg}"}
            )

        return CheckResult(
            module="wapiti",
            category="security",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=error_msg,
        )
    finally:
        # The findings are in the database: the raw report is not kept.
        if output_file.exists():
            output_file.unlink()


def _map_wapiti_severity(level: int) -> "Severity":
    """Map Wapiti severity level to our severity levels."""
    if level == 3:
        return "critical"
    elif level == 2:
        return "high"
    elif level == 1:
        return "medium"
    else:
        return "low"


def _severity_to_cvss(severity: str) -> float:
    """Convert severity to approximate CVSS score."""
    mapping = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 3.0,
        "info": 0.0,
    }
    return mapping.get(severity, 0.0)
