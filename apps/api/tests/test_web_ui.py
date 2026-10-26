"""Tests for serving the built web UI."""

from pathlib import Path

import pytest
from api.main import app
from api.routers import web_ui
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def dist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>web-check</title>")
    (tmp_path / "assets" / "app.js").write_text("console.log('ok')")
    monkeypatch.setattr(web_ui, "get_web_dist", lambda: tmp_path)
    return tmp_path


async def _get(path: str):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path)


@pytest.mark.asyncio
async def test_serves_assets(dist: Path) -> None:
    response = await _get("/ui/assets/app.js")
    assert response.status_code == 200
    assert response.text == "console.log('ok')"


@pytest.mark.asyncio
async def test_client_routes_fall_back_to_index(dist: Path) -> None:
    response = await _get("/ui/scans/20261026-104200-abcd")
    assert response.status_code == 200
    assert "<title>web-check</title>" in response.text


@pytest.mark.asyncio
async def test_path_traversal_falls_back_to_index(dist: Path) -> None:
    (dist.parent / "secret.txt").write_text("secret")
    response = await _get("/ui/..%2Fsecret.txt")
    assert "secret" not in response.text


@pytest.mark.asyncio
async def test_ui_root_redirects_with_trailing_slash() -> None:
    response = await _get("/ui")
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"


@pytest.mark.asyncio
async def test_missing_build_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_ui, "get_web_dist", lambda: None)
    response = await _get("/ui/")
    assert response.status_code == 404
