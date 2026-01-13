"""Nuclei scanning service."""

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from api.models import CheckResult, Finding
from api.services.docker_runner import docker_run, load_jsonl_output

logger = structlog.get_logger()


async def run_nuclei_scan(target: str, timeout: int = 300) -> CheckResult:
    """
    Run Nuclei vulnerability scanner against a target.

    Args:
        target: URL or domain to scan
        timeout: Timeout in seconds

    Returns:
        CheckResult with Nuclei findings
    """
    start = time.time()
    findings: list[Finding] = []

    # Use shared volume mounted in docker-compose
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"nuclei_{int(time.time())}.json"
    output_filename = output_file.name

    try:
        result = await docker_run(
            image="projectdiscovery/nuclei:latest",
            command=[
                "nuclei",
                "-u",
                target,
                "-severity",
                "critical,high,medium",
                "-jsonl",
                "-o",
                f"/output/{output_filename}",
            ],
            timeout=timeout,
            container_name="security-scanner-nuclei",
        )

        if result["timeout"]:
            return CheckResult(
                module="nuclei",
                category="quick",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="timeout",
                data=None,
                findings=[],
                error="Scan timed out",
            )

        # Parse JSONL output
        data = await load_jsonl_output(output_file)
        if data:
            findings = _parse_nuclei_output(data)
            logger.info(
                "nuclei_scan_completed",
                target=target,
                findings_count=len(findings),
                exit_code=result["exit_code"],
            )
        else:
            # No output file means no vulnerabilities found (normal behavior)
            logger.info(
                "nuclei_scan_completed_no_findings",
                target=target,
                exit_code=result["exit_code"],
            )

        return CheckResult(
            module="nuclei",
            category="quick",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"templates_matched": len(findings)},
            findings=findings,
            error=None,
        )

    except Exception as e:
        logger.error("nuclei_scan_failed", target=target, error=str(e))
        return CheckResult(
            module="nuclei",
            category="quick",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(e),
        )
    finally:
        # Cleanup temp file
        if output_file.exists():
            output_file.unlink()


def _parse_nuclei_output(data: list[dict[str, Any]]) -> list[Finding]:
    """Parse Nuclei JSONL output into Finding objects."""
    findings: list[Finding] = []

    # data is now a list from load_jsonl_output
    items = data

    for item in items:
        if not item or not hasattr(item, "get"):
            continue

        info: dict[str, Any] = item.get("info", {})
        severity_str: str = str(info.get("severity", "info")).lower()

        finding = Finding(
            severity=severity_str
            if severity_str in ["critical", "high", "medium", "low", "info"]
            else "info",  # type: ignore[arg-type]
            title=str(info.get("name", "Nuclei Finding")),
            description=str(info.get("description", "No description available")),
            reference=str(info.get("reference")) if info.get("reference") else None,
            cve=str(item.get("matched-at")) if "CVE" in str(item.get("template-id", "")) else None,
            cvss_score=None,
        )
        findings.append(finding)

    return findings
