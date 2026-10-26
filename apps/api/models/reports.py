"""Report models: deduplicated findings, scan summaries and comparisons."""

from datetime import datetime

from api.models.findings import Severity
from api.models.results import ScanStatus
from pydantic import BaseModel, Field


class AggregatedFinding(BaseModel):
    """A finding deduplicated across the modules that reported it."""

    id: str = Field(..., description="Stable identifier derived from the normalised title")
    severity: Severity = Field(..., description="Highest severity reported by any source")
    title: str
    description: str
    reference: str | None = None
    cve: str | None = None
    cvss_score: float | None = None
    remediation: str | None = None
    sources: list[str] = Field(default_factory=list, description="Modules that reported it")


class ScanSummary(BaseModel):
    """Headline numbers for one scan."""

    scan_id: str
    target: str
    status: ScanStatus
    started_at: datetime
    score: int = Field(..., ge=0, le=100)
    severity_counts: dict[str, int]


class ScanFindings(BaseModel):
    """Deduplicated findings of a scan."""

    summary: ScanSummary
    findings: list[AggregatedFinding]


class ScanComparison(BaseModel):
    """Differences between a baseline scan and a later scan."""

    base: ScanSummary
    head: ScanSummary
    score_delta: int
    new: list[AggregatedFinding] = Field(default_factory=list)
    fixed: list[AggregatedFinding] = Field(default_factory=list)
    unchanged: list[AggregatedFinding] = Field(default_factory=list)
