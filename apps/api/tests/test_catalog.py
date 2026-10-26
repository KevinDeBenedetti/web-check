"""Tests for the module and profile catalog."""

import pytest
from api.main import app
from api.services.catalog import (
    LEGACY_DEFAULT_MODULES,
    MODULES,
    PROFILES,
    get_module,
    resolve_modules,
)
from httpx import ASGITransport, AsyncClient


def test_profiles_only_reference_known_modules() -> None:
    for profile in PROFILES:
        assert all(get_module(module) for module in profile.modules), profile.id


def test_passive_profiles_have_no_intrusive_module() -> None:
    for profile_id in ("quick", "standard"):
        profile = next(p for p in PROFILES if p.id == profile_id)
        modules = [get_module(module_id) for module_id in profile.modules]
        assert not any(module.intrusive for module in modules if module is not None)


def test_resolve_modules_prefers_explicit_modules() -> None:
    assert resolve_modules(["nikto", "nuclei", "nikto"], "full") == ["nikto", "nuclei"]


def test_resolve_modules_from_profile() -> None:
    assert resolve_modules(None, "quick") == ["headers", "dns", "testssl"]


def test_resolve_modules_defaults_to_legacy_modules() -> None:
    assert resolve_modules(None, None) == LEGACY_DEFAULT_MODULES


@pytest.mark.parametrize(("modules", "profile"), [(["nope"], None), (None, "nope")])
def test_resolve_modules_rejects_unknown_values(modules: list[str] | None, profile: str | None):
    with pytest.raises(ValueError):
        resolve_modules(modules, profile)


@pytest.mark.asyncio
async def test_read_catalog() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/catalog")
    assert response.status_code == 200
    data = response.json()
    assert [m["id"] for m in data["modules"]] == [m.id for m in MODULES]
    assert data["default_profile"] in {p["id"] for p in data["profiles"]}
