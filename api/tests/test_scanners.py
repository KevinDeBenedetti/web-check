"""Tests for security scanner endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.fixture
def test_url() -> str:
    """Test URL for scans."""
    return "https://example.com"


@pytest.mark.slow
@pytest.mark.asyncio
async def test_nuclei_scan_endpoint(test_url: str) -> None:
    """Test Nuclei scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nuclei", params={"url": test_url, "timeout": 60})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "nuclei"
        assert data["category"] == "quick"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_nuclei_scan_invalid_url() -> None:
    """Test Nuclei scanner rejects invalid URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nuclei", params={"url": "not-a-url"})
        assert response.status_code == 400


@pytest.mark.slow
@pytest.mark.asyncio
async def test_nikto_scan_endpoint(test_url: str) -> None:
    """Test Nikto scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nikto", params={"url": test_url, "timeout": 60})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "nikto"
        assert data["category"] == "quick"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_nikto_scan_invalid_url() -> None:
    """Test Nikto scanner rejects invalid URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nikto", params={"url": "ftp://example.com"})
        assert response.status_code == 400


@pytest.mark.slow
@pytest.mark.asyncio
async def test_zap_scan_endpoint(test_url: str) -> None:
    """Test OWASP ZAP scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/deep/zap", params={"url": test_url, "timeout": 300})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "zap"
        assert data["category"] == "deep"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_zap_scan_invalid_url() -> None:
    """Test ZAP scanner rejects invalid URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/deep/zap", params={"url": "invalid"})
        assert response.status_code == 400


@pytest.mark.slow
@pytest.mark.asyncio
async def test_sslyze_scan_endpoint(test_url: str) -> None:
    """Test SSLyze scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/deep/sslyze", params={"url": test_url, "timeout": 60})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "sslyze"
        assert data["category"] == "deep"
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.slow
@pytest.mark.asyncio
async def test_sslyze_scan_auto_https() -> None:
    """Test SSLyze automatically adds https:// to domain."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/deep/sslyze", params={"url": "example.com", "timeout": 60}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "sslyze"


@pytest.mark.slow
@pytest.mark.asyncio
async def test_sqlmap_scan_endpoint(test_url: str) -> None:
    """Test SQLMap scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/advanced/sqlmap", params={"url": test_url, "timeout": 60})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "sqlmap"
        assert data["category"] == "security"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.slow
@pytest.mark.asyncio
async def test_wapiti_scan_endpoint(test_url: str) -> None:
    """Test Wapiti scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/advanced/wapiti", params={"url": test_url, "timeout": 60})
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "wapiti"
        assert data["category"] == "security"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.slow
@pytest.mark.asyncio
async def test_xsstrike_scan_endpoint(test_url: str) -> None:
    """Test XSStrike scanner endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/advanced/xsstrike", params={"url": test_url, "timeout": 60}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["module"] == "xsstrike"
        assert data["category"] == "security"
        assert data["target"] == test_url
        assert data["status"] in ["success", "error", "timeout"]
        assert "findings" in data
        assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_scanner_timeout_validation() -> None:
    """Test that scanners validate timeout parameter."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Timeout too low
        response = await client.get(
            "/api/quick/nuclei", params={"url": "https://example.com", "timeout": 10}
        )
        assert response.status_code == 422  # Validation error

        # Timeout too high
        response = await client.get(
            "/api/quick/nuclei", params={"url": "https://example.com", "timeout": 5000}
        )
        assert response.status_code == 422  # Validation error
