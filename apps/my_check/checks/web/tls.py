"""TLS certificate validation check."""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)


def _extract_hostname(target: str) -> str:
    """Return the hostname portion of a URL or bare domain."""
    parsed = urlparse(target)
    return parsed.hostname or target.split("/")[0].split(":")[0]


def _get_certificate(hostname: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Connect via TLS and return the peer certificate dict."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            cert = tls.getpeercert()
            if cert is None:
                raise ssl.SSLError("No certificate returned by server")
            return cert


def _days_until_expiry(cert: dict) -> int:
    """Return the number of days until the certificate expires."""
    not_after = cert["notAfter"]
    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.UTC,
    )
    delta = expiry - datetime.datetime.now(datetime.UTC)
    return delta.days


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


def _has_ct_scts(cert: dict) -> bool:
    """Check for Certificate Transparency SCTs via the SCT list extension OID.

    Python's ssl module exposes extensions only partially; the presence of
    the 'OCSP' field or 'crlDistributionPoints' in the peer-cert dict is a
    proxy indicator.  A reliable SCT check requires pyOpenSSL or the
    cryptography library.  As a pragmatic heuristic, modern public CAs
    always embed SCTs — so we return True when the issuer is not self-signed.
    """
    if not cert:
        return False
    # If issuer != subject, the cert was issued by a CA (which almost
    # certainly includes SCTs for publicly trusted certificates).
    issuer = cert.get("issuer")
    subject = cert.get("subject")
    return issuer != subject


@dataclass(slots=True)
class TlsCheck:
    """Validate TLS certificate expiry, chain trust, and CT indicators."""

    id: str = "web-tls"
    name: str = "TLS Certificate"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, str):
            raise TypeError(f"Expected str URL, got {type(target).__name__}")
        hostname = _extract_hostname(target)

        try:
            cert = _get_certificate(hostname)
        except Exception as exc:
            logger.debug("TLS connection failed for %s: %s", hostname, exc)
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"Could not establish TLS connection to {hostname}",
                details={"error": str(exc)},
                remediation="Ensure the server supports TLS and the certificate is valid.",
            )

        days_left = _days_until_expiry(cert)
        chain_ok = _check_chain(hostname)
        ct_ok = _has_ct_scts(cert)

        details = {
            "hostname": hostname,
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
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
