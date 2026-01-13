"""Tests for Web-Check Security Scanner."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


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


@pytest.mark.asyncio
async def test_dns_check(test_url: str) -> None:
    """Test quick DNS check."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/dns", params={"url": test_url})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "dns"
        assert data["category"] == "quick"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error"]


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
