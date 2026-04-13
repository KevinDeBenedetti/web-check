"""Nikto scanning service."""

import re
import time
from datetime import UTC, datetime

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import docker_run

logger = structlog.get_logger()


async def run_nikto_scan(target: str, timeout: int = 600) -> CheckResult:
    """
    Run Nikto web server scanner against a target.

    Args:
        target: URL or domain to scan
        timeout: Timeout in seconds

    Returns:
        CheckResult with Nikto findings
    """
    start = time.time()
    findings: list[Finding] = []

    # Use shared volume mounted in docker-compose
    output_filename = f"nikto_{int(time.time())}.html"

    try:
        result = await docker_run(
            image="alpine/nikto:latest",
            command=[
                "perl",
                "/nikto/nikto.pl",
                "-h",
                target,
                "-output",
                f"/output/{output_filename}",
                "-Format",
                "html",
            ],
            timeout=timeout,
            container_name="security-scanner-nikto",
        )

        if result["timeout"]:
            return CheckResult(
                module="nikto",
                category="quick",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        if result["exit_code"] == -1:
            return CheckResult(
                module="nikto",
                category="quick",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="error",
                data=None,
                findings=[],
                error=f"Docker exec failed: {result['stderr']}",
            )

        # Parse Nikto output from stderr/stdout
        output = result["stdout"] + "\n" + result["stderr"]
        findings = _parse_nikto_output(output)

        logger.info(
            "nikto_scan_completed",
            target=target,
            findings_count=len(findings),
            exit_code=result["exit_code"],
        )

        return CheckResult(
            module="nikto",
            category="quick",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"findings_count": len(findings)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        logger.error("nikto_scan_failed", target=target, error=str(e))
        return CheckResult(
            module="nikto",
            category="quick",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )


def _parse_nikto_output(output: str) -> list[Finding]:
    """Parse Nikto output into Finding objects."""
    findings: list[Finding] = []

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue

        description = line[1:].strip()
        if (
            not description
            or description.startswith("Target ")
            or description.startswith("Start Time")
            or description.startswith("---")
        ):
            continue

        # Extract OSVDB reference if present (e.g. "OSVDB-3233: ...")
        osvdb_ref: str | None = None
        osvdb_match = re.match(r"^(OSVDB-\d+):\s*", description)
        if osvdb_match:
            osvdb_ref = osvdb_match.group(1)
            description = description[osvdb_match.end() :]

        # Build a short title from the first meaningful sentence / clause
        title = _nikto_title_from_description(description)

        # Determine severity based on keywords
        severity = "info"
        desc_lower = description.lower()
        if any(
            kw in desc_lower
            for kw in ["vulnerability", "exploit", "critical", "heartbleed", "shellshock"]
        ):
            severity = "high"
        elif any(
            kw in desc_lower
            for kw in [
                "outdated",
                "misconfiguration",
                "warning",
                "vulnerable",
                "injection",
                "xss",
                "sql",
            ]
        ):
            severity = "medium"

        reference = (
            f"https://www.oswdb.org/vulndb/{osvdb_ref}"
            if osvdb_ref and osvdb_ref != "OSVDB-0"
            else "https://cirt.net/nikto2"
        )
        cve = osvdb_ref if osvdb_ref and osvdb_ref != "OSVDB-0" else None

        findings.append(
            Finding(
                severity=severity,
                title=title,
                description=description,
                reference=reference,
                cve=cve,
                cvss_score=None,
            )
        )

    return findings


def _nikto_title_from_description(description: str) -> str:
    """Derive a short title from a Nikto finding description."""
    import re as _re

    # Strip URI prefix like "/path HTTP method: description"
    uri_prefix = _re.match(r"^/\S+\s+[A-Z]+:\s*", description)
    if uri_prefix:
        rest = description[uri_prefix.end() :]
        title = rest[:80].split(".")[0].split(",")[0].strip()
        return title if title else description[:80]
    # First sentence / up to first period or 80 chars
    first = description.split(".")[0].strip()
    return (first[:80] + "…") if len(first) > 80 else first or description[:80]
