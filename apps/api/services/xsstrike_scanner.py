"""XSStrike XSS vulnerability scanner service."""

import re
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import (
    exit_code_error,
    run_process,
    unique_output_name,
    write_private_file,
)

logger = structlog.get_logger()

# Cloned at a pinned commit by the Dockerfile.
XSSTRIKE_SCRIPT = Path("/opt/xsstrike/xsstrike.py")

_XSS_REFERENCE = "https://owasp.org/www-community/attacks/xss/"
# What XSStrike's crawl mode logs for a hit (modes/crawl.py, logger.vuln → "[++]"):
#   [++] Vulnerable webpage: http://host/search
#   [++] Vector for q: <payload>
# Its progress display uses carriage returns, so a marker can follow other text
# on the same physical line.
_VULNERABLE_PAGE = re.compile(r"\[\+\+\] Vulnerable webpage: (\S+)")
_VECTOR = re.compile(r"\[\+\+\] Vector for ([^:]+): (.*?)\s*$")


def parse_xsstrike_output(stdout: str) -> list[Finding]:
    """One finding per (page, parameter) XSStrike reported a working vector for.

    XSStrike's verdict rests on reflection heuristics: on an HTML-escaped page it
    can still report a vector, so findings say "possible" and ask for confirmation.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    page = ""
    for line in stdout.replace("\r", "\n").splitlines():
        if match := _VULNERABLE_PAGE.search(line):
            page = match.group(1)
        elif (match := _VECTOR.search(line)) and page:
            parameter, vector = match.group(1).strip(), match.group(2)
            if (page, parameter) in seen:
                continue
            seen.add((page, parameter))
            path = urlsplit(page).path or "/"
            findings.append(
                Finding(
                    severity="high",
                    title=f"Possible XSS in parameter '{parameter}' ({path})",
                    description=(
                        f"XSStrike reported a working vector for the parameter '{parameter}' "
                        f"on {page}.\nVector: {vector}\n"
                        "XSStrike can also flag reflections the page escapes: confirm the "
                        "vector in a browser before treating it as exploitable."
                    ),
                    reference=_XSS_REFERENCE,
                    remediation="Encode the parameter for its output context (HTML, attribute, "
                    "JavaScript, URL) and add a restrictive Content-Security-Policy.",
                )
            )
    return findings


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
        xsstrike_path = XSSTRIKE_SCRIPT

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
        if error := exit_code_error(result, "xsstrike"):
            return CheckResult(
                module="xsstrike",
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

        findings = parse_xsstrike_output(stdout)

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
