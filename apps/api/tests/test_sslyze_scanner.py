"""run_sslyze_scan with sslyze's Scanner faked: the request it builds and its outcomes."""

import threading
from types import SimpleNamespace
from typing import Any

import pytest
from api.services import sslyze_scanner
from api.services.sslyze_scanner import run_sslyze_scan
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.models import ServerScanRequest, ServerScanStatusEnum
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum

# The target is this machine: sslyze resolves the host when the request is built.
TARGET = "https://localhost:8443"


def _attempt(**result: Any) -> SimpleNamespace:
    return SimpleNamespace(
        status=ScanCommandAttemptStatusEnum.COMPLETED, result=SimpleNamespace(**result)
    )


def _server_result(**overrides: Any) -> SimpleNamespace:
    """A completed scan of a server that only accepts TLS 1.0 among the old protocols."""
    refused = _attempt(accepted_cipher_suites=[])
    scan_result = SimpleNamespace(
        ssl_2_0_cipher_suites=refused,
        ssl_3_0_cipher_suites=refused,
        tls_1_0_cipher_suites=_attempt(accepted_cipher_suites=["TLS_RSA_WITH_AES_128_CBC_SHA"]),
        tls_1_1_cipher_suites=refused,
        heartbleed=_attempt(is_vulnerable_to_heartbleed=False),
        openssl_ccs_injection=_attempt(is_vulnerable_to_ccs_injection=False),
        certificate_info=_attempt(certificate_deployments=[]),
    )
    fields: dict[str, Any] = {
        "scan_status": ServerScanStatusEnum.COMPLETED,
        "connectivity_error_trace": None,
        "scan_result": scan_result,
    }
    return SimpleNamespace(**(fields | overrides))


def _fake_scanner(monkeypatch: pytest.MonkeyPatch, get_results: Any) -> list[ServerScanRequest]:
    """Replace sslyze's Scanner; returns the scan requests it was given."""
    queued: list[ServerScanRequest] = []

    class FakeScanner:
        def queue_scans(self, requests: list[ServerScanRequest]) -> None:
            queued.extend(requests)

        def get_results(self) -> Any:
            return get_results()

    monkeypatch.setattr(sslyze_scanner, "Scanner", FakeScanner)
    return queued


async def test_a_completed_scan_becomes_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    queued = _fake_scanner(monkeypatch, lambda: iter([_server_result()]))

    result = await run_sslyze_scan(TARGET, timeout=30)

    assert (result.module, result.category, result.target) == ("sslyze", "deep", TARGET)
    assert result.status == "success"
    assert result.data == {"hostname": "localhost", "port": 8443}
    assert [finding.title for finding in result.findings] == ["TLS 1.0 Enabled"]

    [request] = queued
    assert (request.server_location.hostname, request.server_location.port) == ("localhost", 8443)
    # Every command the result parser reads is asked for.
    assert request.scan_commands >= {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
        ScanCommand.OPENSSL_CCS_INJECTION,
    }


async def test_the_port_defaults_to_443(monkeypatch: pytest.MonkeyPatch) -> None:
    queued = _fake_scanner(monkeypatch, lambda: iter([_server_result()]))

    result = await run_sslyze_scan("localhost", timeout=30)

    assert result.data == {"hostname": "localhost", "port": 443}
    assert queued[0].server_location.port == 443


async def test_a_server_that_cannot_be_reached_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreachable = _server_result(
        scan_status=ServerScanStatusEnum.ERROR_NO_CONNECTIVITY,
        connectivity_error_trace="ConnectionRefusedError: [Errno 61] Connection refused",
        scan_result=None,
    )
    _fake_scanner(monkeypatch, lambda: iter([unreachable]))

    result = await run_sslyze_scan(TARGET, timeout=30)

    assert result.status == "error"
    assert result.findings == []
    assert result.error == (
        "Could not connect: ConnectionRefusedError: [Errno 61] Connection refused"
    )


async def test_a_scanner_that_returns_nothing_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_scanner(monkeypatch, lambda: iter([]))

    result = await run_sslyze_scan(TARGET, timeout=30)

    assert (result.status, result.error) == ("error", "No scan results returned")


async def test_a_scan_that_outlasts_the_timeout_is_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()

    def never_finishes() -> Any:
        release.wait(timeout=10)
        return iter([])

    _fake_scanner(monkeypatch, never_finishes)
    try:
        result = await run_sslyze_scan(TARGET, timeout=0)
    finally:
        release.set()  # let the worker thread end

    assert (result.status, result.error) == ("timeout", "Scan timed out")
    assert result.findings == []


async def test_a_refused_connection_is_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused() -> Any:
        raise ConnectionRefusedError("[Errno 61] Connection refused")

    _fake_scanner(monkeypatch, refused)

    result = await run_sslyze_scan(TARGET, timeout=30)

    assert result.status == "error"
    assert result.error == ("Connection refused by localhost:8443. SSL/TLS port may not be open.")
