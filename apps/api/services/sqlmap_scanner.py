"""SQLMap scanning service for SQL injection detection."""

import re
import time
from datetime import UTC, datetime
from pathlib import Path

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import (
    exit_code_error,
    run_process,
    unique_output_name,
    write_private_file,
)

logger = structlog.get_logger()

_SQLI_REFERENCE = "https://owasp.org/www-community/attacks/SQL_Injection"
# sqlmap's summary of what it confirmed, printed once per run:
#   sqlmap identified the following injection point(s) with a total of 53 HTTP(s) requests:
#   ---
#   Parameter: id (GET)
#       Type: boolean-based blind
#       Title: AND boolean-based blind - WHERE or HAVING clause
#       Payload: id=1 AND 3784=3784
#   ---
_INJECTION_SUMMARY = re.compile(
    r"sqlmap identified the following injection point\(s\)[^\n]*\n---\n(.*?)\n---", re.S
)
_PARAMETER = re.compile(r"^Parameter: (?P<name>.+?) \((?P<place>[^)]+)\)\s*$")
_FIELD = re.compile(r"^\s+(?P<key>Type|Title|Payload): (?P<value>.*)$")
_DBMS = re.compile(r"^back-end DBMS: (.+)$", re.M)


def parse_sqlmap_output(stdout: str) -> list[Finding]:
    """One critical finding per parameter in sqlmap's injection-point summary.

    A clean run has no summary ("all tested parameters do not appear to be
    injectable" is only a log line), so it yields no finding.
    """
    summary = _INJECTION_SUMMARY.search(stdout.replace("\r\n", "\n"))
    if not summary:
        return []
    dbms = _DBMS.search(stdout)

    parameters: list[tuple[str, str, list[dict[str, str]]]] = []
    for line in summary.group(1).splitlines():
        if match := _PARAMETER.match(line):
            parameters.append((match["name"], match["place"], []))
        elif (match := _FIELD.match(line)) and parameters:
            techniques = parameters[-1][2]
            if match["key"] == "Type" or not techniques:
                techniques.append({})
            techniques[-1][match["key"]] = match["value"].strip()

    findings: list[Finding] = []
    for name, place, techniques in parameters:
        lines = [f"sqlmap confirmed SQL injection in the {place} parameter '{name}'."]
        if dbms:
            lines.append(f"Back-end DBMS: {dbms.group(1).strip()}")
        for technique in techniques:
            lines.append(
                f"- {technique.get('Type', 'unknown')}: {technique.get('Title', '')}".rstrip(": ")
            )
            if payload := technique.get("Payload"):
                lines.append(f"  Payload: {payload}")
        findings.append(
            Finding(
                severity="critical",
                title=f"SQL injection in {place} parameter '{name}'",
                description="\n".join(lines),
                reference=_SQLI_REFERENCE,
                cvss_score=9.8,
                remediation="Use parameterised queries (prepared statements) for every value "
                "that reaches the database; never build SQL by string concatenation.",
            )
        )
    return findings


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
        if error := exit_code_error(result, "sqlmap"):
            return CheckResult(
                module="sqlmap",
                category="security",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="error",
                data=None,
                findings=[],
                error=error,
            )

        stdout: str = result["stdout"]

        # Keep the raw output for manual inspection; it may quote data from the target.
        write_private_file(output_file, stdout)

        findings = parse_sqlmap_output(stdout)

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
