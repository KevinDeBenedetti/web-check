"""Finding models for security scan results."""

from typing import Literal

from api.utils.text import clean_text, safe_reference
from pydantic import BaseModel, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]

# Caps follow the findings table (title, reference: VARCHAR(500); cve: VARCHAR(255)).
# SQLite does not enforce them, so the model does.
MAX_TITLE_LENGTH = 500
MAX_REFERENCE_LENGTH = 500
MAX_CVE_LENGTH = 255
MAX_TEXT_LENGTH = 20_000


class Finding(BaseModel):
    """Security finding from a scan.

    Every text field comes from a scanner's output: it is cleaned of control
    characters and capped here, the one place all scanners (and the rows read back
    from the database) go through.
    """

    severity: Severity = Field(..., description="Severity level of the finding")
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description of the finding")
    reference: str | None = Field(None, description="URL or reference for more information")
    cve: str | None = Field(None, description="CVE identifier if applicable")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score if applicable")
    remediation: str | None = Field(None, description="Recommended remediation steps")

    @field_validator("title")
    @classmethod
    def _clean_title(cls, value: str) -> str:
        return clean_text(value, MAX_TITLE_LENGTH) or "Untitled finding"

    @field_validator("description")
    @classmethod
    def _clean_description(cls, value: str) -> str:
        return clean_text(value, MAX_TEXT_LENGTH)

    @field_validator("remediation")
    @classmethod
    def _clean_remediation(cls, value: str | None) -> str | None:
        return clean_text(value, MAX_TEXT_LENGTH) if value is not None else None

    @field_validator("cve")
    @classmethod
    def _clean_cve(cls, value: str | None) -> str | None:
        return clean_text(value, MAX_CVE_LENGTH) if value is not None else None

    @field_validator("reference")
    @classmethod
    def _clean_reference(cls, value: str | None) -> str | None:
        return safe_reference(value, MAX_REFERENCE_LENGTH)

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
