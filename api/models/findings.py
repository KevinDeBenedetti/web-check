"""Finding models for security scan results."""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    """Security finding from a scan."""

    severity: Severity = Field(..., description="Severity level of the finding")
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description of the finding")
    reference: str | None = Field(None, description="URL or reference for more information")
    cve: str | None = Field(None, description="CVE identifier if applicable")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score if applicable")

    model_config = {
        "json_schema_extra": {
            "example": {
                "severity": "high",
                "title": "SQL Injection Vulnerability",
                "description": "The application is vulnerable to SQL injection...",
                "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                "cve": "CVE-2023-12345",
                "cvss_score": 8.5,
            }
        }
    }
