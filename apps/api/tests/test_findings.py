"""Tests for finding deduplication, scoring and comparison."""

from api.models import CheckResult, Finding
from api.models.findings import Severity
from api.services.compare import compare_findings
from api.services.findings import aggregate_findings, compute_score, finding_id, severity_counts


def _finding(title: str, severity: Severity = "medium", **kwargs) -> Finding:
    return Finding(severity=severity, title=title, description=f"{title} description", **kwargs)


def _result(module: str, findings: list[Finding]) -> CheckResult:
    return CheckResult(
        module=module,
        category="quick",
        target="https://example.com",
        duration_ms=10,
        status="success",
        findings=findings,
    )


def test_aggregate_merges_same_title_across_modules() -> None:
    results = [
        _result("headers", [_finding("Missing HSTS", "medium", remediation="Add HSTS")]),
        _result("nikto", [_finding("  missing   hsts ", "high", reference="https://ref")]),
    ]
    [finding] = aggregate_findings(results)
    assert finding.severity == "high"
    assert finding.sources == ["headers", "nikto"]
    assert finding.remediation == "Add HSTS"
    assert finding.reference == "https://ref"
    assert finding.id == finding_id("Missing HSTS")


def test_aggregate_sorts_by_severity_then_title() -> None:
    results = [
        _result(
            "nuclei",
            [_finding("b", "low"), _finding("a", "low"), _finding("z", "critical")],
        )
    ]
    assert [f.title for f in aggregate_findings(results)] == ["z", "a", "b"]


def test_score_and_counts() -> None:
    findings = aggregate_findings(
        [
            _result(
                "nuclei", [_finding("c", "critical"), _finding("h", "high"), _finding("i", "info")]
            )
        ]
    )
    assert compute_score(findings) == 65
    assert severity_counts(findings) == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1}


def test_score_never_goes_below_zero() -> None:
    findings = aggregate_findings(
        [_result("nuclei", [_finding(f"c{i}", "critical") for i in range(6)])]
    )
    assert compute_score(findings) == 0


def test_compare_findings() -> None:
    base = aggregate_findings([_result("headers", [_finding("kept"), _finding("fixed")])])
    head = aggregate_findings([_result("headers", [_finding("kept"), _finding("new")])])
    new, fixed, unchanged = compare_findings(base, head)
    assert [f.title for f in new] == ["new"]
    assert [f.title for f in fixed] == ["fixed"]
    assert [f.title for f in unchanged] == ["kept"]
