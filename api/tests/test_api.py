"""Tests for Vigil Security Scanner."""

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
        assert data["name"] == "Vigil Security Scanner"
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
async def test_invalid_url():
    """Test that invalid URLs are rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nuclei", params={"url": "not-a-valid-url"})
        assert response.status_code == 400
