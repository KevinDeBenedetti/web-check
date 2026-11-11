"""Boundary tests: untrusted input and scanner output can neither escape nor exhaust the API.

Each test drives a real entry point (HTTP endpoint, scanner coroutine, subprocess
runner) and checks the absence of the side effect, not only the error.
"""

import asyncio
import json
import socket
import stat
import sys
import time
from collections.abc import AsyncGenerator, Callable
from pathlib import Path

import pytest
from api.main import app
from api.models import CheckResult, Finding
from api.routers import web_ui
from api.services.docker_runner import (
    ToolOutputError,
    load_json_output,
    load_jsonl_output,
    run_process,
    write_private_file,
)
from api.services.headers_scanner import run_headers_scan
from api.services.zap_native import run_zap_scan
from api.utils.config import (
    HARD_MAX_TOOL_FILE_BYTES,
    HARD_MAX_TOOL_OUTPUT_BYTES,
    Settings,
    get_settings,
)
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr, ValidationError

Handler = Callable[[str], tuple[str, list[tuple[str, str]], bytes]]


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


async def _serve(handler: Handler) -> tuple[asyncio.AbstractServer, int]:
    """Minimal HTTP/1.1 server on 127.0.0.1; ``handler(path)`` returns status, headers, body."""

    async def _on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line.split():
            # httpx-secure's address probe: a TCP connect with no HTTP request.
            writer.close()
            return
        while await reader.readline() not in (b"\r\n", b"\n", b""):
            pass
        path = request_line.split()[1].decode()
        status, headers, body = handler(path)
        head = f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n"
        head += "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n"
        writer.write(head.encode() + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(_on_connection, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# Bounded configuration
# ---------------------------------------------------------------------------


def test_settings_reject_unbounded_tool_limits() -> None:
    with pytest.raises(ValidationError):
        Settings(tool_output_max_bytes=0)
    with pytest.raises(ValidationError):
        Settings(tool_output_max_bytes=HARD_MAX_TOOL_OUTPUT_BYTES + 1)
    with pytest.raises(ValidationError):
        Settings(tool_file_max_bytes=HARD_MAX_TOOL_FILE_BYTES + 1)


# ---------------------------------------------------------------------------
# Input bounds at the HTTP boundary
# ---------------------------------------------------------------------------


async def test_oversized_targets_are_rejected_before_any_validation(client: AsyncClient) -> None:
    long_url = "https://example.com/" + "a" * 600
    assert (await client.post("/api/scans/start", json={"target": long_url})).status_code == 422
    assert (await client.get("/api/quick/headers", params={"url": long_url})).status_code == 422


@pytest.mark.parametrize("scan_id", ['a"b', "x" * 51, ".hidden", "a b", "%00"])
async def test_malformed_scan_ids_are_rejected(client: AsyncClient, scan_id: str) -> None:
    assert (await client.get(f"/api/scans/{scan_id}/export")).status_code == 422
    assert (await client.get(f"/api/scans/{scan_id}/logs")).status_code == 422


# ---------------------------------------------------------------------------
# Subprocess output: bounded, decoded leniently, deadline enforced
# ---------------------------------------------------------------------------


async def test_run_process_bounds_output_and_replaces_invalid_bytes() -> None:
    script = (
        "import sys; sys.stdout.buffer.write(b'\\xff' + b'a' * 100000); "
        "sys.stderr.write('warn'); sys.exit(3)"
    )
    result = await run_process([sys.executable, "-c", script], timeout=30, output_limit=4096)

    assert result["exit_code"] == 3
    assert result["truncated"] and not result["timeout"]
    assert result["stdout"].startswith("�" + "a" * 4095)
    assert "[output truncated: 100001 bytes produced, 4096 kept]" in result["stdout"]
    assert result["stderr"] == "warn"


async def test_run_process_kills_the_child_on_timeout(tmp_path: Path) -> None:
    marker = tmp_path / "ran-to-completion"
    script = f"import time, pathlib; time.sleep(1.5); pathlib.Path({str(marker)!r}).write_text('x')"
    started = time.monotonic()

    result = await run_process([sys.executable, "-c", script], timeout=0.3, output_limit=4096)

    assert result["timeout"] and result["exit_code"] == -1
    assert time.monotonic() - started < 1.5
    await asyncio.sleep(1.6)
    assert not marker.exists()


# ---------------------------------------------------------------------------
# Scanner result files: size limit, malformed data is a failure
# ---------------------------------------------------------------------------


async def test_output_files_beyond_the_limit_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "tool_file_max_bytes", 1024)
    big = tmp_path / "big.json"
    big.write_bytes(b"{" + b" " * 2000 + b"}")

    with pytest.raises(ToolOutputError, match="wapiti: output file is 2002 bytes"):
        await load_json_output(big, tool="wapiti")
    with pytest.raises(ToolOutputError, match="nuclei"):
        await load_jsonl_output(big, tool="nuclei")


async def test_malformed_output_files_are_refused(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "list.json").write_text("[1, 2]")
    (tmp_path / "bad.jsonl").write_text('{"ok": 1}\nnot json\n')

    with pytest.raises(ToolOutputError, match="wapiti: invalid JSON output"):
        await load_json_output(tmp_path / "bad.json", tool="wapiti")
    with pytest.raises(ToolOutputError, match="not an object"):
        await load_json_output(tmp_path / "list.json", tool="wapiti")
    with pytest.raises(ToolOutputError, match="nuclei: invalid JSON on line 2"):
        await load_jsonl_output(tmp_path / "bad.jsonl", tool="nuclei")
    assert await load_json_output(tmp_path / "missing.json") is None
    assert await load_jsonl_output(tmp_path / "missing.jsonl") == []


def test_private_files_are_owner_only_and_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "sqlmap_output.txt"
    write_private_file(path, "first")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_private_file(path, "second")
    assert path.read_text() == "first"


# ---------------------------------------------------------------------------
# Findings: scanner text is sanitised when the model is built
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    ["javascript:alert(1)", "data:text/html,x", "ftp://example.com/x", "//example.com", "nope", ""],
)
def test_finding_drops_references_that_are_not_http_urls(reference: str) -> None:
    finding = Finding(severity="low", title="t", description="d", reference=reference)
    assert finding.reference is None


def test_finding_keeps_http_references_and_strips_control_characters() -> None:
    finding = Finding(
        severity="low",
        title="\x1b[31mTitle\x1b[0m\r\n",
        description="line\r\nnext\x00",
        reference=" https://owasp.org/x ",
        cve="CVE-2026-1\x07",
        remediation="\x9bfix",
    )
    assert finding.title == "[31mTitle[0m"
    assert finding.description == "line\nnext"
    assert finding.reference == "https://owasp.org/x"
    assert finding.cve == "CVE-2026-1"
    assert finding.remediation == "fix"


def test_finding_text_is_capped() -> None:
    finding = Finding(
        severity="low", title="t" * 1000, description="d", reference="https://x/" + "y" * 600
    )
    assert len(finding.title) == 500 and finding.title.endswith("…")
    assert finding.reference is None
    assert Finding(severity="low", title="\x00", description="d").title == "Untitled finding"


def test_check_result_error_is_bounded() -> None:
    result = CheckResult(
        module="nuclei",
        category="quick",
        target="https://example.com",
        duration_ms=1,
        status="error",
        error="\x1b[2Jboom " * 1000,
    )
    assert result.error is not None
    assert len(result.error) == 2000 and "\x1b" not in result.error


# ---------------------------------------------------------------------------
# Outbound HTTP: destination checked on every hop, at connect time
# ---------------------------------------------------------------------------


async def test_headers_scan_refuses_non_public_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def handler(path: str) -> tuple[str, list[tuple[str, str]], bytes]:
        seen.append(path)
        return "200 OK", [], b"hello"

    server, port = await _serve(handler)
    settings = get_settings()
    monkeypatch.setattr(settings, "allow_private_targets", False)
    monkeypatch.setattr(settings, "allowed_domains", "localhost,127.0.0.1")
    try:
        result = await run_headers_scan(f"http://127.0.0.1:{port}/", timeout=5)
    finally:
        server.close()
        await server.wait_closed()

    assert result.status == "error"
    assert seen == []


async def test_headers_scan_refuses_redirect_outside_allowed_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    port_holder: dict[str, int] = {}

    def handler(path: str) -> tuple[str, list[tuple[str, str]], bytes]:
        seen.append(path)
        if path == "/":
            location = f"http://127.0.0.1:{port_holder['port']}/private"
            return "302 Found", [("Location", location)], b""
        return "200 OK", [], b"secret"

    server, port = await _serve(handler)
    port_holder["port"] = port
    settings = get_settings()
    # Lab mode: private addresses are allowed, the allowlist still applies to every hop.
    monkeypatch.setattr(settings, "allow_private_targets", True)
    monkeypatch.setattr(settings, "allowed_domains", "localhost")
    try:
        result = await run_headers_scan(f"http://localhost:{port}/", timeout=5)
    finally:
        server.close()
        await server.wait_closed()

    assert result.status == "error"
    assert seen == ["/"]  # the redirect target was never requested


# ---------------------------------------------------------------------------
# Credentials never leave their boundary
# ---------------------------------------------------------------------------


async def test_zap_failure_never_exposes_the_api_key(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    sentinel = "zap-key-sentinel-7f3a9c"
    settings = get_settings()
    monkeypatch.setattr(settings, "zap_host", "127.0.0.1")
    monkeypatch.setattr(settings, "zap_port", _free_port())
    monkeypatch.setattr(settings, "zap_api_key", SecretStr(sentinel))

    result = await run_zap_scan("https://example.com", timeout=5)
    captured = capfd.readouterr()

    assert result.status == "error"
    assert sentinel not in json.dumps(result.model_dump(mode="json"))
    assert sentinel not in captured.out + captured.err


# ---------------------------------------------------------------------------
# Static files: nothing outside the built UI directory is served
# ---------------------------------------------------------------------------


async def test_web_ui_never_serves_files_outside_dist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: AsyncClient
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<title>web-check</title>")
    (dist / "link.txt").symlink_to(outside)
    monkeypatch.setattr(web_ui, "get_web_dist", lambda: dist)

    for path in ("/ui/link.txt", "/ui/assets/..%2F..%2Foutside.txt", "/ui/%2E%2E/outside.txt"):
        response = await client.get(path)
        assert "secret" not in response.text, path
