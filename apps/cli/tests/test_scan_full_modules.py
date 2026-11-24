"""`scan full` accepts exactly the modules listed by the API catalog (GET /api/catalog)."""

from pathlib import Path
from typing import Any

import pytest
from cli.commands import scan as scan_cmd
from cli.main import app
from typer.testing import CliRunner

CATALOG_IDS = ["headers", "dns", "testssl", "nuclei", "future_module"]


class CatalogClient:
    """Fake API: a catalog with a module the CLI has never heard of, and recorded posts."""

    posted: list[dict] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def get(self, endpoint: str, **params: Any) -> dict:
        if endpoint == "/api/catalog":
            return {
                "modules": [{"id": module_id} for module_id in CATALOG_IDS],
                "profiles": [],
                "default_profile": "standard",
            }
        return {
            "scan_id": "s1",
            "target": "https://example.com",
            "status": "success",
            "results": [],
        }

    def post(self, endpoint: str, json: dict | None = None, **params: Any) -> dict:
        CatalogClient.posted.append(json or {})
        return {"scan_id": "s1", "status": "running"}

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan_cmd, "APIClient", CatalogClient)
    monkeypatch.setattr(scan_cmd.time, "sleep", lambda seconds: None)
    CatalogClient.posted = []


def _full(*args: str):
    return CliRunner().invoke(app, ["scan", "full", "https://example.com", *args])


def test_modules_listed_by_the_catalog_are_accepted() -> None:
    result = _full("--modules", "headers,dns,future_module")

    assert result.exit_code == 0, result.output
    assert CatalogClient.posted[0]["modules"] == ["headers", "dns", "future_module"]


def test_all_runs_every_catalog_module() -> None:
    result = _full("--all")

    assert result.exit_code == 0, result.output
    assert CatalogClient.posted[0]["modules"] == CATALOG_IDS


def test_a_module_missing_from_the_catalog_is_refused() -> None:
    result = _full("--modules", "nuclei,xsstrike")

    assert result.exit_code == 1
    assert "Unknown module(s): xsstrike" in result.output
    assert "future_module" in result.output, "the error should list the catalog's modules"
    assert CatalogClient.posted == [], "no scan should start"


def test_an_unreadable_catalog_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self, endpoint: str, **params: Any) -> dict:
        raise RuntimeError("401 Unauthorized")

    monkeypatch.setattr(CatalogClient, "get", refuse)

    result = _full("--modules", "nuclei")

    assert result.exit_code == 1
    assert "Could not read the module catalog" in result.output
    assert "401 Unauthorized" in result.output
    assert CatalogClient.posted == []
