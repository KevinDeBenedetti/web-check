"""Tests for Pydantic models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from api.models import Finding, CheckResult, ScanRequest


def test_finding_model():
    """Test Finding model validation."""
    finding = Finding(
        severity="high",
        title="Test Finding",
        description="This is a test finding",
        reference="https://example.com",
    )

    assert finding.severity == "high"
    assert finding.title == "Test Finding"
    assert finding.cve is None


def test_finding_invalid_severity():
    """Test that invalid severity is rejected."""
    with pytest.raises(ValidationError):
        Finding(
            severity="invalid",
            title="Test",
            description="Test",
        )


def test_check_result_model():
    """Test CheckResult model validation."""
    result = CheckResult(
        module="test",
        category="quick",
        target="https://example.com",
        timestamp=datetime.utcnow(),
        duration_ms=1000,
        status="success",
        data={"test": "data"},
        findings=[],
    )

    assert result.module == "test"
    assert result.category == "quick"
    assert result.status == "success"


def test_scan_request_model():
    """Test ScanRequest model validation."""
    request = ScanRequest(
        target="https://example.com",
        modules=["nuclei", "nikto"],
        timeout=300,
    )

    assert request.target == "https://example.com"
    assert len(request.modules) == 2
    assert request.timeout == 300


def test_scan_request_timeout_validation():
    """Test that invalid timeout is rejected."""
    with pytest.raises(ValidationError):
        ScanRequest(
            target="https://example.com",
            timeout=5000,  # Too high
        )
