"""Result models for security scans."""

from datetime import UTC, datetime
from typing import Any, Literal

from api.models.findings import Finding
from api.utils.text import clean_text
from pydantic import BaseModel, Field, field_validator

ScanStatus = Literal["success", "error", "timeout", "running"]
# scans.target / scan_results.target are VARCHAR(500); the target also becomes a
# command-line argument of every scanner.
MAX_TARGET_LENGTH = 500
# Error messages are built from scanner output: bounded before storage and streaming.
MAX_ERROR_LENGTH = 2000
ScanCategory = Literal["quick", "deep", "security"]
# Keep in sync with api.services.catalog.MODULES (checked by the test suite).
ScanModule = Literal[
    "headers", "dns", "testssl", "nuclei", "nikto", "zap", "wapiti", "sqlmap", "xsstrike"
]
DEFAULT_SCAN_MODULES: list[ScanModule] = ["nuclei", "nikto", "zap"]


class CheckResult(BaseModel):
    """Result from a security check."""

    module: str = Field(..., description="Name of the scanning module")
    category: ScanCategory = Field(..., description="Category of the scan")
    target: str = Field(..., description="Target URL or domain")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the scan was performed",
    )
    duration_ms: int = Field(..., ge=0, description="Scan duration in milliseconds")
    status: ScanStatus = Field(..., description="Status of the scan")
    data: dict[str, Any] | None = Field(None, description="Raw scan data and metadata")
    findings: list[Finding] = Field(
        default_factory=list, description="Security findings discovered"
    )
    error: str | None = Field(None, description="Error message if scan failed")

    @field_validator("error")
    @classmethod
    def _clean_error(cls, value: str | None) -> str | None:
        return clean_text(value, MAX_ERROR_LENGTH) if value is not None else None

    model_config = {
        "json_schema_extra": {
            "example": {
                "module": "nuclei",
                "category": "quick",
                "target": "https://example.com",
                "timestamp": "2026-01-09T12:00:00",
                "duration_ms": 5432,
                "status": "success",
                "data": {"templates_matched": 3},
                "findings": [
                    {
                        "severity": "medium",
                        "title": "X-Frame-Options Header Missing",
                        "description": "The X-Frame-Options header is not set...",
                        "reference": "https://owasp.org/www-community/controls/X-Frame-Options",
                    }
                ],
                "error": None,
            }
        }
    }


class ScanRequest(BaseModel):
    """Request to start a security scan."""

    target: str = Field(
        ..., max_length=MAX_TARGET_LENGTH, description="Target URL or domain to scan"
    )
    modules: list[ScanModule] | None = Field(
        None,
        min_length=1,
        max_length=32,
        description="Modules to run (see /api/catalog); takes precedence over `profile`",
    )
    profile: str | None = Field(
        None,
        max_length=64,
        description="Scan profile (see /api/catalog); ignored when modules are given",
    )
    timeout: int = Field(300, ge=1, le=3600, description="Timeout in seconds per module")

    model_config = {
        "json_schema_extra": {
            "example": {
                "target": "https://example.com",
                "modules": ["nuclei", "nikto"],
                "timeout": 300,
            }
        }
    }


class ScanResponse(BaseModel):
    """Response after starting a scan."""

    scan_id: str = Field(..., description="Unique identifier for this scan")
    target: str = Field(..., description="Target being scanned")
    status: ScanStatus = Field(..., description="Current status of the scan")
    started_at: datetime = Field(..., description="When the scan started")
    completed_at: datetime | None = Field(None, description="When the scan finished")
    modules: list[str] | None = Field(None, description="Modules requested for this scan")
    score: int | None = Field(
        None, ge=0, le=100, description="Score computed from the deduplicated findings"
    )
    severity_counts: dict[str, int] = Field(
        default_factory=dict, description="Deduplicated findings per severity"
    )
    results: list[CheckResult] = Field(default_factory=list, description="Available results so far")

    model_config = {
        "json_schema_extra": {
            "example": {
                "scan_id": "20260109-120000",
                "target": "https://example.com",
                "status": "running",
                "started_at": "2026-01-09T12:00:00",
                "results": [],
            }
        }
    }
