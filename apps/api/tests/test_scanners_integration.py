"""Opt-in: run each real scanner once, against a server this test starts on 127.0.0.1.

Deselected by default (``-m "not integration"`` in pyproject.toml); run it with
``make test-integration`` after upgrading a scanner. It fails when a tool no longer
accepts the arguments its service passes, and never touches a real site.

sqlmap, wapiti and sslyze run on this machine. Nuclei and Nikto run in their
containers (``make start``) and are skipped when those are not running; from there
the test site is ``host.docker.internal``: Docker Desktop provides that name, and
docker-compose.yml maps it to the host on Docker Engine (Linux). There the
containers reach the host through its bridge address, so the site they scan
listens on every interface for the length of the test; the others stay on loopback.
"""

import datetime
import http.server
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from api.services.nikto import run_nikto_scan
from api.services.nuclei import run_nuclei_scan
from api.services.sqlmap_scanner import run_sqlmap_scan
from api.services.sslyze_scanner import run_sslyze_scan
from api.services.wapiti_scanner import run_wapiti_scan
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = pytest.mark.integration

_PAGE = b"""<!doctype html>
<html><head><title>web-check integration target</title></head>
<body><a href="/?id=1">item</a>
<form action="/" method="get"><input name="id" value="1"><input type="submit"></form>
</body></html>
"""


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server's naming)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()
        self.wfile.write(_PAGE)

    do_HEAD = do_GET  # noqa: N815

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        pass  # scanners cut connections and send malformed requests on purpose


def _serve(server: http.server.HTTPServer) -> Iterator[int]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def http_port() -> Iterator[int]:
    """Port of a one-page HTTP site on 127.0.0.1."""
    yield from _serve(_QuietServer(("127.0.0.1", 0), _Page))


@pytest.fixture
def container_http_port() -> Iterator[int]:
    """Port of the same site on every interface, for the scanners in containers."""
    yield from _serve(_QuietServer(("0.0.0.0", 0), _Page))  # noqa: S104 (see the docstring)


def _self_signed_certificate(path: Path) -> None:
    """Write a private key and a certificate for localhost, valid for one day."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        + certificate.public_bytes(serialization.Encoding.PEM)
    )


@pytest.fixture
def https_port(tmp_path: Path) -> Iterator[int]:
    """Port of the same site over TLS, with a self-signed certificate."""
    certificate = tmp_path / "localhost.crt"
    _self_signed_certificate(certificate)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate)
    server = _QuietServer(("127.0.0.1", 0), _Page)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    yield from _serve(server)


def _needs_executable(name: str) -> None:
    if shutil.which(name) is None:
        pytest.skip(f"{name} is not installed (make install)")


def _needs_container(name: str) -> None:
    try:
        state = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        state = ""
    if state != "true":
        pytest.skip(f"the {name} container is not running (make start)")


def _run_in(directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep what a tool writes (./outputs, its session files under ~) in *directory*."""
    monkeypatch.chdir(directory)
    monkeypatch.setenv("HOME", str(directory))


async def test_sqlmap_accepts_its_arguments(
    http_port: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _needs_executable("sqlmap")
    _run_in(tmp_path, monkeypatch)

    result = await run_sqlmap_scan(f"http://127.0.0.1:{http_port}/?id=1", timeout=300)

    assert result.status == "success", result.error
    assert result.findings == []  # the page ignores its parameter


async def test_wapiti_accepts_its_arguments(
    http_port: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _needs_executable("wapiti")
    _run_in(tmp_path, monkeypatch)

    result = await run_wapiti_scan(f"http://127.0.0.1:{http_port}/", timeout=300)

    assert result.status == "success", result.error


async def test_sslyze_scans_a_tls_server(https_port: int) -> None:
    result = await run_sslyze_scan(f"https://localhost:{https_port}", timeout=120)

    assert result.status == "success", result.error
    assert result.data == {"hostname": "localhost", "port": https_port}
    # The self-signed certificate is the one thing every sslyze release must report.
    assert "Invalid Certificate Chain" in [finding.title for finding in result.findings]


async def test_nuclei_accepts_its_arguments(container_http_port: int) -> None:
    _needs_container("security-scanner-nuclei")

    result = await run_nuclei_scan(
        f"http://host.docker.internal:{container_http_port}/", timeout=600
    )

    assert result.status == "success", result.error


async def test_nikto_accepts_its_arguments(container_http_port: int) -> None:
    _needs_container("security-scanner-nikto")

    result = await run_nikto_scan(
        f"http://host.docker.internal:{container_http_port}/", timeout=600
    )

    assert result.status == "success", result.error
