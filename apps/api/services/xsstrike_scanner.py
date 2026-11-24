"""XSStrike XSS vulnerability scanner service."""

import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx
import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import (
    exit_code_error,
    run_process,
    unique_output_name,
    write_private_file,
)
from api.utils.security import ssrf_guarded_client

logger = structlog.get_logger()

# Cloned at a pinned commit by the Dockerfile.
XSSTRIKE_SCRIPT = Path("/opt/xsstrike/xsstrike.py")

_XSS_REFERENCE = "https://owasp.org/www-community/attacks/xss/"
_XSS_REMEDIATION = (
    "Encode the parameter for its output context (HTML, attribute, "
    "JavaScript, URL) and add a restrictive Content-Security-Policy."
)
# Seconds allowed for the request that confirms one reported vector.
_CONFIRM_TIMEOUT = 15.0
# What XSStrike's crawl mode logs for a hit (modes/crawl.py, logger.vuln → "[++]"):
#   [++] Vulnerable webpage: http://host/search
#   [++] Vector for q: <payload>
# Its progress display uses carriage returns, so a marker can follow other text
# on the same physical line.
_VULNERABLE_PAGE = re.compile(r"\[\+\+\] Vulnerable webpage: (\S+)")
_VECTOR = re.compile(r"\[\+\+\] Vector for ([^:]+): (.*?)\s*$")


@dataclass(frozen=True, slots=True)
class XssReport:
    """A vector XSStrike reported as working for one parameter of one page."""

    page: str
    parameter: str
    vector: str

    @property
    def payload(self) -> str:
        """The parameter value as XSStrike sent it: the printed vector, verbatim.

        XSStrike's requester passes it as `requests.get(url, params=...)`, which
        encodes it, so a `+` or `%0a` in the vector reaches the page literally.
        """
        return self.vector


def parse_xsstrike_reports(stdout: str) -> list[XssReport]:
    """One report per (page, parameter) XSStrike reported a working vector for."""
    reports: list[XssReport] = []
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
            reports.append(XssReport(page=page, parameter=parameter, vector=vector))
    return reports


def _path(report: XssReport) -> str:
    return urlsplit(report.page).path or "/"


def _finding(severity: Literal["high", "info"], title: str, description: str) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        description=description,
        reference=_XSS_REFERENCE,
        remediation=_XSS_REMEDIATION,
    )


def _not_confirmed(report: XssReport, why: str) -> Finding:
    return _finding(
        "info",
        f"Unconfirmed XSS report for parameter '{report.parameter}' ({_path(report)})",
        f"XSStrike reported a working vector for the parameter '{report.parameter}' "
        f"on {report.page}, but {why}\nVector: {report.vector}",
    )


def _unconfirmed_finding(report: XssReport) -> Finding:
    """XSStrike's own verdict, which rests on reflection heuristics."""
    return _finding(
        "high",
        f"Possible XSS in parameter '{report.parameter}' ({_path(report)})",
        f"XSStrike reported a working vector for the parameter '{report.parameter}' "
        f"on {report.page}.\nVector: {report.vector}\n"
        "XSStrike can also flag reflections the page escapes: confirm the "
        "vector in a browser before treating it as exploitable.",
    )


def parse_xsstrike_output(stdout: str) -> list[Finding]:
    """XSStrike's reports as findings, before confirmation (see confirm_xss_reports).

    XSStrike's verdict rests on reflection heuristics: on an HTML-escaped page it
    can still report a vector, so these findings say "possible".
    """
    return [_unconfirmed_finding(report) for report in parse_xsstrike_reports(stdout)]


async def _confirm(report: XssReport, client: httpx.AsyncClient) -> Finding:
    """Request the page once with the vector: high only if it comes back verbatim."""
    try:
        url = httpx.URL(report.page).copy_merge_params({report.parameter: report.payload})
        response = await client.get(url)
    except (httpx.HTTPError, ValueError) as e:
        return _not_confirmed(
            report, f"it could not be checked ({type(e).__name__}): confirm it in a browser."
        )

    if report.payload in response.text:
        return _finding(
            "high",
            f"XSS in parameter '{report.parameter}' ({_path(report)})",
            f"The page {report.page} returns the parameter '{report.parameter}' "
            "unescaped: the vector XSStrike reported comes back as sent.\n"
            f"Vector: {report.vector}",
        )
    return _not_confirmed(
        report,
        f"a GET request with it got it back escaped or not at all (HTTP "
        f"{response.status_code}): likely a false positive. A form that only accepts "
        "POST is not covered by this check.",
    )


async def confirm_xss_reports(reports: list[XssReport], client: httpx.AsyncClient) -> list[Finding]:
    """One finding per report: high when the vector reflects unescaped, info otherwise."""
    return [await _confirm(report, client) for report in reports]


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

        reports = parse_xsstrike_reports(stdout)
        if reports:
            # Checked like the API's own requests (ALLOWED_DOMAINS, public addresses
            # only): a page the guard refuses is reported as info, not requested.
            async with ssrf_guarded_client(
                timeout=_CONFIRM_TIMEOUT,
                follow_redirects=True,
                verify=False,  # noqa: S501 — we're auditing, not trusting
            ) as client:
                findings = await confirm_xss_reports(reports, client)

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
