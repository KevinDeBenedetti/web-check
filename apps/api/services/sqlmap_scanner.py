"""SQLMap scanning service for SQL injection detection."""

import time
from datetime import UTC, datetime
from pathlib import Path

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import run_process, unique_output_name, write_private_file

logger = structlog.get_logger()


async def run_sqlmap_scan(
    target: str, timeout: int = 900, scan_id: str | None = None
) -> CheckResult:
    """
    Run SQLMap SQL injection scanner against a target using Python library.

    Args:
        target: URL to scan for SQL injection
        timeout: Timeout in seconds
        scan_id: Scan ID for log streaming (optional)

    Returns:
        CheckResult with SQLMap findings
    """
    start = time.time()
    findings: list[Finding] = []

    # Output directory
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / unique_output_name("sqlmap", "txt")

    if scan_id:
        from api.services.log_streamer import log_streamer

        await log_streamer.send_log(
            scan_id, {"type": "info", "message": f"Starting SQL injection scan on {target}"}
        )

    try:
        # Run sqlmap as subprocess since it's a command-line tool
        cmd = [
            "sqlmap",
            "-u",
            target,
            "--batch",
            "--random-agent",
            "--level=1",
            "--risk=1",
            "--flush-session",
            "--output-dir",
            str(output_dir.absolute()),
        ]

        result = await run_process(cmd, timeout=timeout)
        if result["timeout"]:
            return CheckResult(
                module="sqlmap",
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
        if "sqlmap identified the following injection" in stdout.lower():
            findings.append(
                Finding(
                    severity="critical",
                    title="SQL Injection Vulnerability Detected",
                    description="SQLMap detected SQL injection vulnerabilities in the target application.",
                    reference="https://owasp.org/www-community/attacks/SQL_Injection",
                    cve=None,
                    cvss_score=9.8,
                )
            )

        if "parameter" in stdout.lower() and "injectable" in stdout.lower():
            # Extract injectable parameters
            lines = stdout.split("\n")
            for line in lines:
                if "Parameter:" in line and "is vulnerable" in line.lower():
                    findings.append(
                        Finding(
                            severity="high",
                            title="Injectable Parameter Found",
                            description=line.strip(),
                            reference="https://owasp.org/www-community/attacks/SQL_Injection",
                            cve=None,
                            cvss_score=8.5,
                        )
                    )

        logger.info(
            "sqlmap_scan_completed",
            target=target,
            findings_count=len(findings),
        )

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "success",
                    "message": f"SQLMap scan completed - {len(findings)} vulnerabilities found",
                },
            )

        return CheckResult(
            module="sqlmap",
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
        logger.error("sqlmap_scan_failed", target=target, error=error_msg)

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id, {"type": "error", "message": f"SQLMap scan failed: {error_msg}"}
            )

        return CheckResult(
            module="sqlmap",
            category="security",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=error_msg,
        )
