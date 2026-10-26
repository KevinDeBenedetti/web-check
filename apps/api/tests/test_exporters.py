"""Tests for JSON, Markdown and SARIF exports."""

import json
from datetime import UTC, datetime

from api.models import CheckResult, Finding, ScanResponse
from api.services.exporters import export_scan
from api.services.findings import aggregate_findings, compute_score, severity_counts


def _scan() -> tuple[ScanResponse, list]:
    results = [
        CheckResult(
            module="headers",
            category="quick",
            target="https://example.com",
            duration_ms=1200,
            status="success",
            findings=[
                Finding(
                    severity="high",
                    title="Cookie without Secure flag",
                    description="The session cookie can be sent over HTTP.",
                    reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie",
                    remediation="Add the Secure attribute.",
                ),
                Finding(severity="low", title="Missing Referrer-Policy", description="Not set."),
            ],
        )
    ]
    findings = aggregate_findings(results)
    scan = ScanResponse(
        scan_id="20261026-104200-abcd",
        target="https://example.com",
        status="success",
        started_at=datetime(2026, 10, 26, 10, 42, tzinfo=UTC),
        modules=["headers"],
        score=compute_score(findings),
        severity_counts=severity_counts(findings),
        results=results,
    )
    return scan, findings


def test_export_json_contains_scan_and_findings() -> None:
    scan, findings = _scan()
    document = json.loads(export_scan(scan, findings, "json"))
    assert document["scan"]["scan_id"] == scan.scan_id
    assert [f["title"] for f in document["findings"]] == [
        "Cookie without Secure flag",
        "Missing Referrer-Policy",
    ]


def test_export_markdown() -> None:
    scan, findings = _scan()
    markdown = export_scan(scan, findings, "markdown")
    assert markdown.startswith("# Web-Check report — https://example.com")
    assert "Score: **89/100**" in markdown
    assert "### [HIGH] Cookie without Secure flag" in markdown
    assert "**Remediation:** Add the Secure attribute." in markdown
    assert "| headers | success | 1.2 s | 2 |" in markdown


def test_export_sarif() -> None:
    scan, findings = _scan()
    document = json.loads(export_scan(scan, findings, "sarif"))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [f.id for f in findings]
    assert [result["level"] for result in run["results"]] == ["error", "note"]
    assert run["tool"]["driver"]["rules"][0]["help"] == {"text": "Add the Secure attribute."}
