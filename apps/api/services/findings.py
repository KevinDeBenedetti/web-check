"""Deduplicate findings reported by several modules and score them."""

import hashlib
import re
from collections.abc import Iterable

from api.models import CheckResult, Finding
from api.models.reports import AggregatedFinding

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}

# Points removed from a perfect score of 100 for each deduplicated finding.
SEVERITY_PENALTY: dict[str, int] = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

_WHITESPACE = re.compile(r"\s+")


def finding_key(title: str) -> str:
    """Normalise a finding title so the same issue from two modules collapses."""
    return _WHITESPACE.sub(" ", title).strip().casefold()


def finding_id(title: str) -> str:
    """Stable short identifier for a finding title."""
    return hashlib.sha1(finding_key(title).encode(), usedforsecurity=False).hexdigest()[:12]


def _merge(target: AggregatedFinding, finding: Finding, module: str) -> None:
    if _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[target.severity]:
        target.severity = finding.severity
    if module not in target.sources:
        target.sources.append(module)
    target.reference = target.reference or finding.reference
    target.cve = target.cve or finding.cve
    target.remediation = target.remediation or finding.remediation
    if finding.cvss_score is not None and (
        target.cvss_score is None or finding.cvss_score > target.cvss_score
    ):
        target.cvss_score = finding.cvss_score


def aggregate_findings(results: Iterable[CheckResult]) -> list[AggregatedFinding]:
    """Merge findings with the same title, keeping the highest severity.

    The result is sorted by severity (critical first), then title.
    """
    merged: dict[str, AggregatedFinding] = {}
    for result in results:
        for finding in result.findings:
            key = finding_key(finding.title)
            existing = merged.get(key)
            if existing is None:
                merged[key] = AggregatedFinding(
                    id=finding_id(finding.title),
                    severity=finding.severity,
                    title=finding.title.strip(),
                    description=finding.description,
                    reference=finding.reference,
                    cve=finding.cve,
                    cvss_score=finding.cvss_score,
                    remediation=finding.remediation,
                    sources=[result.module],
                )
            else:
                _merge(existing, finding, result.module)
    return sorted(merged.values(), key=lambda f: (_SEVERITY_RANK[f.severity], f.title.casefold()))


def severity_counts(findings: Iterable[AggregatedFinding]) -> dict[str, int]:
    """Count findings per severity, with every severity present."""
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def compute_score(findings: Iterable[AggregatedFinding]) -> int:
    """Score from 0 to 100: 100 minus a penalty per finding severity."""
    penalty = sum(SEVERITY_PENALTY[finding.severity] for finding in findings)
    return max(0, 100 - penalty)
