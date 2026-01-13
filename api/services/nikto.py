"""Nikto scanning service."""

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

    # Nikto findings typically start with "+"
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("+"):
            # Remove the + prefix
            description = line[1:].strip()

            # Determine severity based on keywords
            severity = "info"
            if any(
                keyword in description.lower()
                for keyword in ["vulnerability", "exploit", "critical"]
            ):
                severity = "high"
            elif any(
                keyword in description.lower()
                for keyword in ["outdated", "misconfiguration", "warning"]
            ):
                severity = "medium"

            finding = Finding(
                severity=severity,
                title="Nikto Finding",
                description=description,
                reference="https://cirt.net/nikto2",
                cve=None,
                cvss_score=None,
            )
            findings.append(finding)

    return findings
