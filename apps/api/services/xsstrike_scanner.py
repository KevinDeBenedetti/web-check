"""XSStrike XSS vulnerability scanner service."""

import time
from datetime import UTC, datetime
from pathlib import Path

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import run_process, unique_output_name, write_private_file

logger = structlog.get_logger()


async def run_xsstrike_scan(
    target: str, timeout: int = 300, scan_id: str | None = None
) -> CheckResult:
    """
    Run XSStrike XSS vulnerability scanner against a target using subprocess.

    Args:
        target: URL to scan for XSS vulnerabilities
        timeout: Timeout in seconds
        scan_id: Scan ID for log streaming (optional)

    Returns:
        CheckResult with XSStrike findings
    """
    start = time.time()
    findings: list[Finding] = []

    # Output directory
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / unique_output_name("xsstrike", "txt")

    if scan_id:
        from api.services.log_streamer import log_streamer

        await log_streamer.send_log(
            scan_id, {"type": "info", "message": f"Starting XSS scan on {target}"}
        )

    try:
        # XSStrike needs to be cloned from GitHub and run as Python script
        # Check if xsstrike exists in /opt/xsstrike
        xsstrike_path = Path("/opt/xsstrike/xsstrike.py")

        if not xsstrike_path.exists():
            return CheckResult(
                module="xsstrike",
                category="security",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="error",
                data=None,
                findings=[],
                error="XSStrike not installed at /opt/xsstrike. Please clone from https://github.com/s0md3v/XSStrike.git",
            )

        cmd = [
            "python3",
            str(xsstrike_path),
            "-u",
            target,
            "--crawl",
        ]

        result = await run_process(cmd, timeout=timeout)
        if result["timeout"]:
            return CheckResult(
                module="xsstrike",
                category="security",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )
        stdout: str = result["stdout"]

        # Keep the raw output for manual inspection; it may quote data from the target.
        write_private_file(output_file, stdout)

        # Parse output
        if "XSS" in stdout and "detected" in stdout.lower():
            # Count XSS findings
            xss_count = stdout.lower().count("xss")

            findings.append(
                Finding(
                    severity="high",
                    title="Cross-Site Scripting (XSS) Vulnerability Detected",
                    description=f"XSStrike detected {xss_count} potential XSS vulnerability points in the target application.",
                    reference="https://owasp.org/www-community/attacks/xss/",
                    cve=None,
                    cvss_score=7.5,
                )
            )

        # Look for specific vulnerability types
        if "reflected" in stdout.lower():
            findings.append(
                Finding(
                    severity="high",
                    title="Reflected XSS Vulnerability",
                    description="Reflected XSS vulnerability detected where user input is immediately returned by the application.",
                    reference="https://owasp.org/www-community/attacks/xss/#reflected-xss-attacks",
                    cve=None,
                    cvss_score=7.0,
                )
            )

        logger.info(
            "xsstrike_scan_completed",
            target=target,
            findings_count=len(findings),
        )

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "success",
                    "message": f"XSStrike scan completed with {len(findings)} findings",
                },
            )

        return CheckResult(
            module="xsstrike",
            category="security",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"output_file": str(output_file)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        logger.error("xsstrike_scan_failed", target=target, error=str(e))

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id, {"type": "error", "message": f"XSStrike scan error: {e}"}
            )

        return CheckResult(
            module="xsstrike",
            category="security",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )
