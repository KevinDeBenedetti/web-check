"""FFUF directory and file fuzzing service."""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import (
    docker_run,
    exit_code_error,
    load_json_output,
    unique_output_name,
)

logger = structlog.get_logger()

# Status codes reported as a discovered path (-mc).
MATCH_CODES = "200,204,301,302,307,401,403"
_REFERENCE = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/"
    "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
    "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
)


def fuzz_url(target: str) -> str:
    """The URL ffuf requests: the target's path followed by the FUZZ keyword.

    The query string and fragment are dropped: appending to the raw URL would put
    FUZZ inside them (``https://x/?a=b/FUZZ``).
    """
    parts = urlsplit(target)
    path = parts.path.rstrip("/") + "/FUZZ"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def parse_ffuf_report(report: dict[str, Any]) -> list[Finding]:
    """One informational finding per path ffuf matched."""
    findings: list[Finding] = []
    for match in report.get("results") or []:
        if not isinstance(match, dict):
            continue
        url = str(match.get("url") or "")
        path = urlsplit(url).path or "/"
        status = match.get("status")
        details = [f"URL: {url}", f"HTTP status: {status}", f"Length: {match.get('length')}"]
        if match.get("content-type"):
            details.append(f"Content type: {match['content-type']}")
        if match.get("redirectlocation"):
            details.append(f"Redirects to: {match['redirectlocation']}")
        findings.append(
            Finding(
                severity="info",
                title=f"Discovered path: {path} (HTTP {status})",
                description="\n".join(details),
                reference=_REFERENCE,
                remediation="Check that this path is meant to be public; remove or protect it otherwise.",
            )
        )
    return findings


def _result(
    target: str, start: float, status: str, findings: list[Finding], **extra: Any
) -> CheckResult:
    return CheckResult(
        module="ffuf",
        category="security",
        target=target,
        timestamp=datetime.now(UTC),
        duration_ms=int((time.time() - start) * 1000),
        status=status,  # ty: ignore[invalid-argument-type]
        findings=findings,
        **extra,
    )


async def run_ffuf_scan(target: str, wordlist: str, timeout: int = 600) -> CheckResult:
    """
    Fuzz directories and files under the target's path with a validated wordlist.

    Args:
        target: Validated target URL
        wordlist: Validated wordlist filename (see api.utils.security.validate_wordlist)
        timeout: Timeout in seconds

    Returns:
        CheckResult with one finding per discovered path
    """
    start = time.time()
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / unique_output_name("ffuf", "json")

    try:
        result = await docker_run(
            image="secsi/ffuf:2.3.0",
            command=[
                "ffuf",
                "-u",
                fuzz_url(target),
                "-w",
                f"/wordlists/{wordlist}",
                "-o",
                f"/output/{output_file.name}",
                "-of",
                "json",
                "-mc",
                MATCH_CODES,
                "-s",
            ],
            timeout=timeout,
            container_name="security-scanner-ffuf",
        )

        if result["timeout"]:
            return _result(target, start, "timeout", [], error="Scan timed out")
        if error := exit_code_error(result, "ffuf"):
            return _result(target, start, "error", [], error=error)

        report = await load_json_output(output_file, tool="ffuf")
        if report is None:
            # ffuf writes its report even without matches: no file means it did not run.
            return _result(target, start, "error", [], error="ffuf wrote no report")

        findings = parse_ffuf_report(report)
        logger.info("ffuf_scan_completed", target=target, findings_count=len(findings))
        return _result(
            target,
            start,
            "success",
            findings,
            data={"wordlist": wordlist, "matches": len(findings)},
        )

    except Exception as e:
        logger.error("ffuf_scan_failed", target=target, error=str(e))
        return _result(target, start, "error", [], error=str(e))
    finally:
        # The findings are returned to the caller: the raw report is not kept.
        if output_file.exists():
            output_file.unlink()
