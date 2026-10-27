"""Nuclei scanning service."""

import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from api.models import CheckResult, Finding
from api.services.docker_runner import docker_run, load_jsonl_output, unique_output_name

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
    output_file = output_dir / unique_output_name("nuclei", "json")
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

        if result["exit_code"] == -1:
            return CheckResult(
                module="nuclei",
                category="quick",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="error",
                data=None,
                findings=[],
                error=f"Docker exec failed: {result['stderr']}",
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

    for item in data:
        if not item or not isinstance(item, dict):
            continue

        info: dict[str, Any] = item.get("info") or {}
        classification: dict[str, Any] = info.get("classification") or {}
        severity_str: str = str(info.get("severity", "info")).lower()

        description = str(info.get("description") or "No description available").strip()
        if matched_at := item.get("matched-at"):
            description = f"{description}\n\nMatched at: {matched_at}"

        finding = Finding(
            severity=(
                severity_str
                if severity_str in ["critical", "high", "medium", "low", "info"]
                else "info"
            ),
            title=str(info.get("name", "Nuclei Finding")),
            description=description,
            reference=_first(info.get("reference")),
            cve=_parse_cve(classification.get("cve-id"), str(item.get("template-id", ""))),
            cvss_score=_parse_cvss(classification.get("cvss-score")),
        )
        findings.append(finding)

    return findings


def _first(value: Any) -> str | None:
    """Return the first non-empty entry of a nuclei string-or-list field."""
    if isinstance(value, list):
        value = next((v for v in value if v), None)
    return str(value) if value else None


def _parse_cve(cve_ids: Any, template_id: str) -> str | None:
    """Extract CVE id(s) from classification.cve-id, falling back to a CVE template id."""
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    if isinstance(cve_ids, list):
        cves = [str(c).upper() for c in cve_ids if c]
        if cves:
            return ", ".join(cves)
    if re.fullmatch(r"cve-\d{4}-\d{4,}", template_id, flags=re.IGNORECASE):
        return template_id.upper()
    return None


def _parse_cvss(value: Any) -> float | None:
    """Return a CVSS score in [0, 10], or None."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None
