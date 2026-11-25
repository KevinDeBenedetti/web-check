"""Tests for Web-Check Security Scanner."""

import os

import pytest
from httpx import ASGITransport, AsyncClient

# Ensure test-friendly ALLOWED_DOMAINS before importing the app
# (the router reads settings at module-import time via lru_cache).
os.environ["ALLOWED_DOMAINS"] = "example.com"

from api.utils.config import get_settings  # noqa: E402

get_settings.cache_clear()

import httpx  # noqa: E402
from api.main import app  # noqa: E402
from api.routers import quick  # noqa: E402
from api.utils import security  # noqa: E402


@pytest.fixture
def test_url() -> str:
    """Test URL for scans."""
    return "https://example.com"


@pytest.mark.asyncio
async def test_root_endpoint():
    """Test root endpoint returns API information."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Web-Check Security Scanner"
        assert "version" in data


@pytest.mark.asyncio
async def test_health_check():
    """Test health check endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


def _fake_https(monkeypatch: pytest.MonkeyPatch, answer) -> list[str]:
    """Answer the endpoint's HTTPS request with *answer*; returns the URLs it requested."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return answer(request)

    def fake_client(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(quick, "ssrf_guarded_client", fake_client)
    return requested


@pytest.mark.asyncio
async def test_dns_check(test_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Quick DNS check: the addresses the domain resolves to, then its HTTPS answer (faked)."""
    requested = _fake_https(monkeypatch, lambda request: httpx.Response(204))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/dns", params={"url": test_url})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "dns"
        assert data["category"] == "quick"
        assert data["target"] == test_url
        assert data["status"] == "success"
        assert data["data"] == {
            "domain": "example.com",
            "resolvable": True,
            "addresses": ["93.184.215.14"],
            "https_reachable": True,
            "http_status": 204,
        }
    assert requested == ["https://example.com/"]


@pytest.mark.asyncio
async def test_dns_check_reports_a_domain_that_resolves_without_serving_https(
    test_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _fake_https(monkeypatch, refuse)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        data = (await client.get("/api/quick/dns", params={"url": test_url})).json()

    assert data["status"] == "success"
    assert data["data"] == {
        "domain": "example.com",
        "resolvable": True,
        "addresses": ["93.184.215.14"],
        "https_reachable": False,
        "http_status": None,
    }


@pytest.mark.asyncio
async def test_dns_check_reports_a_domain_that_does_not_resolve(
    test_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_answer(hostname: str) -> list:
        return []

    monkeypatch.setattr(security, "_resolve", no_answer)
    requested = _fake_https(monkeypatch, lambda request: httpx.Response(204))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        data = (await client.get("/api/quick/dns", params={"url": test_url})).json()

    assert data["status"] == "success"
    assert data["data"] == {
        "domain": "example.com",
        "resolvable": False,
        "addresses": [],
        "https_reachable": False,
        "http_status": None,
    }
    assert requested == []  # nothing to connect to


@pytest.mark.asyncio
async def test_dns_check_ssrf_localhost_protection():
    """Test SSRF protection against localhost requests."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test localhost variations
        localhost_urls = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://0.0.0.0",
        ]
        for url in localhost_urls:
            response = await client.get("/api/quick/dns", params={"url": url})
            assert response.status_code == 400
            assert "not allowed" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_dns_check_ssrf_internal_domain_protection():
    """Test SSRF protection against internal domains."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test internal domain suffixes
        internal_urls = [
            "http://server.local",
            "http://api.internal",
            "http://service.localhost",
        ]
        for url in internal_urls:
            response = await client.get("/api/quick/dns", params={"url": url})
            assert response.status_code == 400
            assert "not allowed" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_dns_check_ssrf_private_ip_protection():
    """Test SSRF protection against private IP addresses."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test private IP ranges
        private_ips = [
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
        ]
        for url in private_ips:
            response = await client.get("/api/quick/dns", params={"url": url})
            assert response.status_code == 400
            # Could be rejected either by domain validation or IP validation
            assert response.status_code == 400


@pytest.mark.asyncio
async def test_invalid_url():
    """Test that invalid URLs are rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nuclei", params={"url": "not-a-valid-url"})
        assert response.status_code == 400
