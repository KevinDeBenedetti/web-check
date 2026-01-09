"""Result models for security scans."""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from api.models.findings import Finding

ScanStatus = Literal["success", "error", "timeout", "running"]
ScanCategory = Literal["quick", "deep", "security"]


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
        default_factory=lambda: [], description="Security findings discovered"
    )
    error: str | None = Field(None, description="Error message if scan failed")

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

    target: str = Field(..., description="Target URL or domain to scan")
    modules: list[str] | None = Field(None, description="Specific modules to run (default: all)")
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
    results: list[CheckResult] = Field(
        default_factory=lambda: [], description="Available results so far"
    )

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
