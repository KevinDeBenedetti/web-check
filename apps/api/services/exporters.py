"""Export a scan report as JSON, Markdown or SARIF 2.1.0."""

import json
from typing import Any, Literal

from api.models import ScanResponse
from api.models.reports import AggregatedFinding
from api.services.findings import SEVERITY_ORDER

ExportFormat = Literal["json", "markdown", "sarif"]

EXPORT_MEDIA_TYPES: dict[str, str] = {
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "sarif": "application/sarif+json",
}
EXPORT_EXTENSIONS: dict[str, str] = {"json": "json", "markdown": "md", "sarif": "sarif"}

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
# GitHub code scanning reads this property to rank security alerts.
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


def export_json(scan: ScanResponse, findings: list[AggregatedFinding]) -> str:
    """Full scan with raw module results and deduplicated findings."""
    document = {
        "scan": scan.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def export_markdown(scan: ScanResponse, findings: list[AggregatedFinding]) -> str:
    """Human-readable report, suitable for a ticket or a pull request."""
    lines = [
        f"# Web-Check report — {scan.target}",
        "",
        f"- Scan: `{scan.scan_id}`",
        f"- Started: {scan.started_at.isoformat()}",
        f"- Status: {scan.status}",
        f"- Score: **{scan.score if scan.score is not None else '—'}/100**",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    counts = scan.severity_counts or {}
    lines += [f"| {severity} | {counts.get(severity, 0)} |" for severity in SEVERITY_ORDER]

    lines += ["", "## Findings", ""]
    if not findings:
        lines += ["No findings.", ""]
    for finding in findings:
        lines += [
            f"### [{finding.severity.upper()}] {finding.title}",
            "",
            f"_Sources: {', '.join(finding.sources)}_",
            "",
            finding.description.strip(),
            "",
        ]
        if finding.remediation:
            lines += [f"**Remediation:** {finding.remediation.strip()}", ""]
        if finding.cve:
            lines += [f"**CVE:** {finding.cve}", ""]
        if finding.reference:
            lines += [f"Reference: {finding.reference}", ""]

    lines += ["## Modules", "", "| Module | Status | Duration | Findings |", "|---|---|---|---|"]
    for result in scan.results:
        lines.append(
            f"| {_md_cell(result.module)} | {result.status} | "
            f"{result.duration_ms / 1000:.1f} s | {len(result.findings)} |"
        )
    return "\n".join(lines) + "\n"


def export_sarif(scan: ScanResponse, findings: list[AggregatedFinding]) -> str:
    """SARIF 2.1.0 document, one rule per deduplicated finding."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule: dict[str, Any] = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "tags": ["security", *finding.sources],
            },
        }
        if finding.reference:
            rule["helpUri"] = finding.reference
        if finding.remediation:
            rule["help"] = {"text": finding.remediation}
        rules.append(rule)
        results.append(
            {
                "ruleId": finding.id,
                "level": _SARIF_LEVELS[finding.severity],
                "message": {"text": f"{finding.title} ({scan.target})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": scan.target}}}],
                "properties": {"severity": finding.severity, "sources": finding.sources},
            }
        )

    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "web-check",
                        "informationUri": "https://github.com/KevinDeBenedetti/web-check",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"web-check/{scan.scan_id}"},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


_EXPORTERS = {"json": export_json, "markdown": export_markdown, "sarif": export_sarif}


def export_scan(scan: ScanResponse, findings: list[AggregatedFinding], fmt: ExportFormat) -> str:
    """Render a scan in the requested format."""
    return _EXPORTERS[fmt](scan, findings)
