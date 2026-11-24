"""Tests for security scanner endpoints."""

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from api.main import app
from api.models import CheckResult, ScanCategory
from api.routers import advanced, deep, quick
from api.services.sslyze_scanner import _parse_sslyze_results
from httpx import ASGITransport, AsyncClient
from sslyze.plugins.certificate_info.trust_stores.trust_store import PathValidationResult
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum


@pytest.fixture
def test_url() -> str:
    """Test URL for scans."""
    return "https://example.com"


# Endpoint, router module, the scanner function it calls, the module and category
# of the result. The scanners are faked: they would scan the target for real.
_SCANNER_ENDPOINTS = [
    ("/api/quick/nuclei", quick, "run_nuclei_scan", "nuclei", "quick"),
    ("/api/quick/nikto", quick, "run_nikto_scan", "nikto", "quick"),
    ("/api/deep/zap", deep, "run_zap_scan", "zap", "deep"),
    ("/api/deep/sslyze", deep, "run_sslyze_scan", "sslyze", "deep"),
    ("/api/advanced/sqlmap", advanced, "run_sqlmap_scan", "sqlmap", "security"),
    ("/api/advanced/wapiti", advanced, "run_wapiti_scan", "wapiti", "security"),
    ("/api/advanced/xsstrike", advanced, "run_xsstrike_scan", "xsstrike", "security"),
]


@pytest.mark.parametrize(
    ("endpoint", "router", "scanner", "module", "category"),
    _SCANNER_ENDPOINTS,
    ids=[module for _, _, _, module, _ in _SCANNER_ENDPOINTS],
)
async def test_a_scanner_endpoint_runs_its_scanner_on_the_target(
    monkeypatch: pytest.MonkeyPatch,
    test_url: str,
    endpoint: str,
    router: ModuleType,
    scanner: str,
    module: str,
    category: ScanCategory,
) -> None:
    calls: list[tuple[str, int]] = []

    async def fake_scan(url: str, timeout: int) -> CheckResult:
        calls.append((url, timeout))
        return CheckResult(
            module=module, category=category, target=url, duration_ms=0, status="success"
        )

    monkeypatch.setattr(router, scanner, fake_scan)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(endpoint, params={"url": test_url, "timeout": 300})

    assert response.status_code == 200, response.text
    assert calls == [(test_url, 300)]
    data = response.json()
    assert (data["module"], data["category"], data["target"]) == (module, category, test_url)
    assert data["findings"] == []


async def test_sslyze_takes_a_bare_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sslyze endpoint is given a host: a bare domain is accepted."""
    calls: list[str] = []

    async def fake_scan(url: str, timeout: int) -> CheckResult:
        calls.append(url)
        return CheckResult(
            module="sslyze", category="deep", target=url, duration_ms=0, status="success"
        )

    monkeypatch.setattr(deep, "run_sslyze_scan", fake_scan)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/deep/sslyze", params={"url": "example.com"})

    assert response.status_code == 200, response.text
    assert calls == ["https://example.com"]


@pytest.mark.asyncio
async def test_nuclei_scan_invalid_url() -> None:
    """Test Nuclei scanner rejects invalid URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nuclei", params={"url": "not-a-url"})
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_nikto_scan_invalid_url() -> None:
    """Test Nikto scanner rejects invalid URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/quick/nikto", params={"url": "ftp://example.com"})
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_zap_scan_invalid_url() -> None:
    """Test ZAP scanner rejects invalid URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/deep/zap", params={"url": "invalid"})
        assert response.status_code == 400


def test_sslyze_parser_reports_untrusted_certificate_chain() -> None:
    """A failed path validation becomes a finding carrying sslyze's error message."""
    not_run = SimpleNamespace(status=ScanCommandAttemptStatusEnum.NOT_SCHEDULED, result=None)
    validation = PathValidationResult(
        trust_store=SimpleNamespace(name="Mozilla"),  # ty: ignore[invalid-argument-type]
        verified_certificate_chain=None,
        validation_error="self-signed certificate",
    )
    certificate_info = SimpleNamespace(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        result=SimpleNamespace(
            certificate_deployments=[SimpleNamespace(path_validation_results=[validation])]
        ),
    )
    scan_result = SimpleNamespace(
        ssl_2_0_cipher_suites=not_run,
        ssl_3_0_cipher_suites=not_run,
        tls_1_0_cipher_suites=not_run,
        tls_1_1_cipher_suites=not_run,
        heartbleed=not_run,
        openssl_ccs_injection=not_run,
        certificate_info=certificate_info,
    )

    findings = _parse_sslyze_results(scan_result, "example.com")

    assert [f.title for f in findings] == ["Invalid Certificate Chain"]
    assert "self-signed certificate" in findings[0].description


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


def test_nikto_parser_skips_run_status_lines() -> None:
    """Nikto 2.6 console output: only lines about the target become findings."""
    from api.services.nikto import _parse_nikto_output

    output = "\n".join(
        [
            "- Nikto v2.6.1",
            "---------------------------------------------------------------------------",
            "+ Target IP:          203.0.113.10",
            "+ Target Hostname:    example.com",
            "+ Target Port:        443",
            "+ Platform:           Linux",
            "+ Start Time:         2026-11-23 10:00:00 (GMT0)",
            "+ WARNING: Net::SSL does not support SAN extraction. Use Net::SSLeay instead.",
            "+ /: The X-Content-Type-Options header is not set.",
            "+ End Time:           2026-11-23 10:05:00 (GMT0) (300 seconds)",
            "+ 1 host(s) tested",
            "+ 8102 requests made in 300 seconds",
        ]
    )
    findings = _parse_nikto_output(output)

    assert len(findings) == 1
    assert "X-Content-Type-Options" in findings[0].description


def test_wapiti_executable_is_installed() -> None:
    """The wapiti module runs the `wapiti` executable: it must ship with the project."""
    import shutil
    from importlib.metadata import entry_points

    assert entry_points(group="console_scripts", name="wapiti"), "wapiti3 is not installed"
    assert shutil.which("wapiti") or shutil.which("wapiti", path=str(Path(sys.executable).parent))
