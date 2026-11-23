"""web-tls against local TLS servers on a non-default port, with certificates made here."""

import datetime
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from my_check.checks.web.tls import TlsCheck
from my_check.types import CheckStatus


def _self_signed(directory: Path, *, days_valid: int) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    not_after = now + datetime.timedelta(days=days_valid)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(min(now, not_after) - datetime.timedelta(days=30))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _serve_tls(cert: Path, key: Path) -> tuple[int, threading.Event]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()

    def loop() -> None:
        with listener:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                try:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except (ssl.SSLError, OSError):
                    pass  # the client refused the certificate: expected for the chain check

    threading.Thread(target=loop, daemon=True).start()
    return listener.getsockname()[1], stop


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator:
    stops: list[threading.Event] = []

    def start(days_valid: int) -> int:
        directory = tmp_path / str(days_valid)
        directory.mkdir()
        port, stop = _serve_tls(*_self_signed(directory, days_valid=days_valid))
        stops.append(stop)
        return port

    yield start
    for stop in stops:
        stop.set()


async def test_uses_the_port_of_the_url_and_reports_an_untrusted_chain(tls_server) -> None:
    port = tls_server(days_valid=90)

    result = await TlsCheck().run(f"https://localhost:{port}/")

    # Reached the server on its own port (not 443) and read its certificate,
    # then graded the self-signed chain separately.
    assert result.status == CheckStatus.WARN
    assert result.message == "Certificate chain validation failed"
    assert result.details["port"] == port
    assert result.details["chain_valid"] is False
    assert 88 <= result.details["days_until_expiry"] <= 90


async def test_an_expired_certificate_is_reported_as_expired(tls_server) -> None:
    port = tls_server(days_valid=-3)

    result = await TlsCheck().run(f"https://localhost:{port}")

    assert result.status == CheckStatus.FAIL
    assert "has expired" in result.message
