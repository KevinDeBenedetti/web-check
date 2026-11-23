"""TLS certificate validation check."""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)


def _target_address(target: str) -> tuple[str, int]:
    """Host and TLS port of a URL or bare domain (`host:8443` keeps its port)."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = parsed.hostname or target.split("/")[0].split(":")[0]
    try:
        port = parsed.port or 443
    except ValueError:
        port = 443
    return hostname, port


def _get_certificate(hostname: str, port: int = 443, timeout: float = 10.0) -> x509.Certificate:
    """Fetch the server's certificate *without* verifying it.

    Verification happens separately (_check_chain): a verifying handshake would
    refuse an expired or self-signed certificate before the check could say so.
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise ssl.SSLError("No certificate returned by server")
            return x509.load_der_x509_certificate(der)


def _days_until_expiry(cert: x509.Certificate) -> int:
    """Return the number of days until the certificate expires (negative once expired)."""
    delta = cert.not_valid_after_utc - datetime.datetime.now(datetime.UTC)
    return delta.days


def _name(name: x509.Name) -> dict[str, str]:
    return {attribute.rfc4514_attribute_name: str(attribute.value) for attribute in name}


def _check_chain(hostname: str, port: int = 443, timeout: float = 10.0) -> bool:
    """Validate the full certificate chain against system trust store."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except ssl.SSLError:
        return False


def _has_ct_scts(cert: x509.Certificate) -> bool:
    """True when the certificate embeds Certificate Transparency SCTs."""
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
    except x509.ExtensionNotFound:
        return False
    return True


@dataclass(slots=True)
class TlsCheck:
    """Validate TLS certificate expiry, chain trust, and CT indicators."""

    id: str = "web-tls"
    name: str = "TLS Certificate"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, str):
            raise TypeError(f"Expected str URL, got {type(target).__name__}")
        hostname, port = _target_address(target)

        try:
            cert = _get_certificate(hostname, port)
        except Exception as exc:
            logger.debug("TLS connection failed for %s:%s: %s", hostname, port, exc)
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Could not establish TLS connection to {hostname}:{port}",
                details={"error": str(exc)},
                remediation="Ensure the server supports TLS and the certificate is valid.",
            )

        days_left = _days_until_expiry(cert)
        chain_ok = _check_chain(hostname, port)
        ct_ok = _has_ct_scts(cert)

        details = {
            "hostname": hostname,
            "port": port,
            "issuer": _name(cert.issuer),
            "subject": _name(cert.subject),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "days_until_expiry": days_left,
            "chain_valid": chain_ok,
            "ct_scts_present": ct_ok,
        }

        if days_left < 0:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Certificate for {hostname} has expired ({-days_left} days ago)",
                details=details,
                remediation="Renew the TLS certificate immediately.",
            )

        if days_left < 7:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=30,
                message=f"Certificate expires in {days_left} days",
                details=details,
                remediation="Renew the TLS certificate within the next few days.",
            )

        if days_left < 30:
            return CheckResult(
                status=CheckStatus.WARN,
                score=70,
                message=f"Certificate expires in {days_left} days",
                details=details,
                remediation="Plan certificate renewal soon.",
            )

        if not chain_ok:
            return CheckResult(
                status=CheckStatus.WARN,
                score=70,
                message="Certificate chain validation failed",
                details=details,
                remediation=(
                    "Ensure the server sends a complete certificate chain "
                    "including all intermediate certificates."
                ),
            )

        return CheckResult(
            status=CheckStatus.PASS,
            score=100,
            message=f"TLS certificate valid for {days_left} days",
            details=details,
        )
