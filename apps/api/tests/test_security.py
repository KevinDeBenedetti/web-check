"""Tests for scan target validation (SSRF guard) and API key authentication."""

import ipaddress

import pytest
from api.main import app
from api.utils import security
from api.utils.config import Settings, get_settings
from api.utils.security import validate_target, validate_wordlist
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

PUBLIC_IP = ipaddress.ip_address("93.184.215.14")


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Resolve every hostname to a public IP unless overridden in the returned map."""
    overrides: dict[str, list] = {}

    async def _resolve(hostname: str) -> list:
        return overrides.get(hostname, [PUBLIC_IP])

    monkeypatch.setattr(security, "_resolve", _resolve)
    return overrides


@pytest.fixture
def settings() -> Settings:
    return Settings(allowed_domains="example.com,test.org", allow_private_targets=False)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "http://example.com:8080/path?q=1",
        "https://sub.example.com",
        "https://deep.sub.test.org/",
    ],
)
async def test_validate_target_accepts_allowlisted(target: str, settings: Settings) -> None:
    assert await validate_target(target, settings=settings) == target


async def test_validate_target_bare_domain(settings: Settings) -> None:
    assert (
        await validate_target("example.com", require_scheme=False, settings=settings)
        == "https://example.com"
    )
    with pytest.raises(HTTPException) as exc:
        await validate_target("example.com", settings=settings)
    assert exc.value.status_code == 400


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "https://notexample.com",  # suffix trick
        "https://example.com.evil.net",
        "https://evil.net",
        "http://localhost",
        "http://service.localhost",
        "http://server.local",
        "http://api.internal",
        "http://zap:8090",  # docker service name
        "http://nuclei",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254/latest/meta-data/",
        "https://user:pass@example.com",
        "https://example.com:notaport",
        "https://",
    ],
)
async def test_validate_target_rejects(target: str, settings: Settings) -> None:
    with pytest.raises(HTTPException) as exc:
        await validate_target(target, settings=settings)
    assert exc.value.status_code == 400


async def test_validate_target_rejects_private_resolution(
    settings: Settings, fake_dns: dict[str, list]
) -> None:
    fake_dns["internal.example.com"] = [PUBLIC_IP, ipaddress.ip_address("10.1.2.3")]
    with pytest.raises(HTTPException) as exc:
        await validate_target("https://internal.example.com", settings=settings)
    assert "non-public" in exc.value.detail


async def test_validate_target_unresolvable_is_allowed(
    settings: Settings, fake_dns: dict[str, list]
) -> None:
    # Resolution failures are left to the scanner (it will report an error).
    fake_dns["nxdomain.example.com"] = []
    assert await validate_target("https://nxdomain.example.com", settings=settings)


async def test_allow_private_targets(fake_dns: dict[str, list]) -> None:
    lab = Settings(allowed_domains="lab.test,10.0.0.5", allow_private_targets=True)
    fake_dns["app.lab.test"] = [ipaddress.ip_address("10.0.0.5")]
    assert await validate_target("http://app.lab.test", settings=lab)
    assert await validate_target("http://10.0.0.5", settings=lab)
    # The allowlist and blocked names still apply.
    for target in ("http://10.0.0.6", "http://localhost"):
        with pytest.raises(HTTPException):
            await validate_target(target, settings=lab)


@pytest.mark.parametrize("name", ["common.txt", "big-list_v2.txt"])
def test_validate_wordlist_ok(name: str) -> None:
    assert validate_wordlist(name) == name


@pytest.mark.parametrize(
    "name", ["../../etc/passwd", "/etc/passwd", "sub/common.txt", "common", ".hidden.txt", ""]
)
def test_validate_wordlist_rejects(name: str) -> None:
    with pytest.raises(HTTPException):
        validate_wordlist(name)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

SCAN_ENDPOINTS = [
    "/api/quick/nuclei",
    "/api/quick/nikto",
    "/api/quick/dns",
    "/api/quick/headers",
    "/api/quick/dns-enum",
    "/api/deep/zap",
    "/api/deep/sslyze",
    "/api/security/ffuf",
    "/api/security/sqlmap",
    "/api/advanced/sqlmap",
    "/api/advanced/wapiti",
    "/api/advanced/xsstrike",
]


@pytest.mark.parametrize("path", SCAN_ENDPOINTS)
@pytest.mark.parametrize(
    "target", ["http://zap:8090", "http://169.254.169.254", "https://evil.net"]
)
async def test_endpoints_reject_disallowed_targets(
    client: AsyncClient, path: str, target: str
) -> None:
    response = await client.get(path, params={"url": target})
    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"].lower()


async def test_ffuf_rejects_wordlist_traversal(client: AsyncClient) -> None:
    response = await client.get(
        "/api/security/ffuf",
        params={"url": "https://example.com", "wordlist": "../../etc/passwd"},
    )
    assert response.status_code == 400


async def test_start_scan_rejects_disallowed_target(
    client: AsyncClient, fake_dns: dict[str, list]
) -> None:
    # Outside ALLOWED_DOMAINS: refused by the scope check.
    outside = await client.post("/api/scans/start", json={"target": "http://10.0.0.1"})
    assert outside.status_code == 403
    # In scope but resolving to a private network: refused by the SSRF guard.
    fake_dns["example.com"] = [ipaddress.ip_address("10.0.0.1")]
    private = await client.post("/api/scans/start", json={"target": "https://example.com"})
    assert private.status_code == 400


async def test_api_key_enforced(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "api_key", SecretStr("s3cret"))

    assert (await client.get("/api/health")).status_code == 200

    missing = await client.get("/api/quick/nuclei", params={"url": "https://evil.net"})
    assert missing.status_code == 401
    wrong = await client.get(
        "/api/quick/nuclei", params={"url": "https://evil.net"}, headers={"X-API-Key": "nope"}
    )
    assert wrong.status_code == 401
    assert (await client.get("/api/scans", headers={"X-API-Key": "nope"})).status_code == 401

    # Correct key: request reaches target validation.
    ok = await client.get(
        "/api/quick/nuclei", params={"url": "https://evil.net"}, headers={"X-API-Key": "s3cret"}
    )
    assert ok.status_code == 400
    # Never read from the URL: it would land in access logs, proxies and browser history.
    assert (await client.get("/api/catalog", params={"api_key": "s3cret"})).status_code == 401
