"""Tests for scope rules and the /api/scope endpoints."""

import pytest
from api.main import app
from api.services.scope import check_scope, extract_hostname, matches_rule
from httpx import ASGITransport, AsyncClient


@pytest.mark.parametrize(
    ("target", "hostname"),
    [
        ("https://Example.com/path?q=1", "example.com"),
        ("http://app.example.com:8080", "app.example.com"),
        ("example.com", "example.com"),
        ("http://[::1]:3000/", "::1"),
        ("", None),
        ("https://", None),
    ],
)
def test_extract_hostname(target: str, hostname: str | None) -> None:
    assert extract_hostname(target) == hostname


@pytest.mark.parametrize(
    ("hostname", "rule", "expected"),
    [
        ("example.com", "example.com", True),
        ("api.example.com", "example.com", True),
        ("badexample.com", "example.com", False),
        ("example.com", "*.example.com", False),
        ("api.example.com", "*.example.com", True),
        ("example.com", "  ", False),
    ],
)
def test_matches_rule(hostname: str, rule: str, expected: bool) -> None:
    assert matches_rule(hostname, rule) is expected


def test_check_scope_returns_matching_rule() -> None:
    decision = check_scope("https://www.example.com", ["other.org", "example.com"])
    assert decision.allowed
    assert decision.matched_rule == "example.com"


def test_check_scope_rejects_unknown_host() -> None:
    decision = check_scope("https://example.org", ["example.com"])
    assert not decision.allowed
    assert decision.hostname == "example.org"


@pytest.mark.asyncio
async def test_read_scope(allowed_domains: list[str]) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/scope")
    assert response.status_code == 200
    assert response.json() == {"rules": allowed_domains, "source": "ALLOWED_DOMAINS"}


@pytest.mark.asyncio
async def test_check_target_scope(allowed_domains: list[str]) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        allowed = await client.post("/api/scope/check", json={"target": "https://app.staging.test"})
        denied = await client.post("/api/scope/check", json={"target": "https://evil.test"})
    assert allowed.json()["allowed"] is True
    assert allowed.json()["matched_rule"] == "*.staging.test"
    assert denied.json()["allowed"] is False
    assert denied.json()["hostname"] == "evil.test"
