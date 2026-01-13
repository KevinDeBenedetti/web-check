"""SSLyze SSL/TLS scanning service using native Python library."""

import asyncio
import time
from datetime import UTC, datetime

import structlog
from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

from api.models import CheckResult, Finding

logger = structlog.get_logger()


async def run_sslyze_scan(
    target: str, timeout: int = 300, scan_id: str | None = None
) -> CheckResult:
    """
    Run SSLyze SSL/TLS analysis using native Python library.

    Args:
        target: URL or domain to scan
        timeout: Timeout in seconds
        scan_id: Scan ID for log streaming (optional)

    Returns:
        CheckResult with SSL/TLS findings
    """
    start = time.time()
    findings: list[Finding] = []

    # Extract domain from URL
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    port = 443

    # Handle domain:port format
    if ":" in domain:
        domain, port_str = domain.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443

    if scan_id:
        from api.services.log_streamer import log_streamer

        await log_streamer.send_log(
            scan_id, {"type": "info", "message": f"Starting SSL/TLS scan for {domain}:{port}"}
        )

    try:
        # Run SSLyze in thread pool (it's synchronous)
        def _run_scan() -> dict:
            # Create scan request
            server_location = ServerNetworkLocation(hostname=domain, port=port)

            # Define scan commands to run
            scan_request = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.SESSION_RENEGOTIATION,
                },
            )

            # Queue and run scan
            scanner = Scanner()
            scanner.queue_scans([scan_request])

            # Get results (blocks until complete)
            for server_scan_result in scanner.get_results():
                return {"result": server_scan_result}

            return {}

        # Run with timeout
        result = await asyncio.wait_for(asyncio.to_thread(_run_scan), timeout=timeout)

        server_scan_result = result.get("result")

        if not server_scan_result:
            return CheckResult(
                module="sslyze",
                category="deep",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="error",
                data=None,
                findings=[],
                error="No scan results returned",
            )

        # Check connectivity
        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            error_msg = f"Could not connect: {server_scan_result.connectivity_error_trace}"
            logger.error("sslyze_connectivity_error", domain=domain, error=error_msg)

            return CheckResult(
                module="sslyze",
                category="deep",
                target=target,
                timestamp=datetime.now(UTC),
                duration_ms=int((time.time() - start) * 1000),
                status="error",
                data=None,
                findings=[],
                error=error_msg,
            )

        # Parse results
        scan_result = server_scan_result.scan_result
        assert scan_result

        findings = _parse_sslyze_results(scan_result, domain)

        logger.info("sslyze_scan_completed", domain=domain, findings_count=len(findings))

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id,
                {
                    "type": "success",
                    "message": f"SSL/TLS scan completed - {len(findings)} findings",
                },
            )

        return CheckResult(
            module="sslyze",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="success",
            data={"hostname": domain, "port": port},
            findings=findings,
            error=None,
        )

    except TimeoutError:
        logger.warning("sslyze_timeout", domain=domain)

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id, {"type": "warning", "message": "SSL/TLS scan timed out"}
            )

        return CheckResult(
            module="sslyze",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="timeout",
            data=None,
            findings=[],
            error="Scan timed out",
        )

    except Exception as e:
        error_msg = str(e)

        # Provide clearer error messages
        if "Could not resolve" in error_msg:
            error_msg = f"DNS resolution failed for '{domain}'. Please verify the domain name is correct."
        elif "timed out" in error_msg.lower():
            error_msg = f"Connection to {domain}:{port} timed out. The server may be down or blocking connections."
        elif "Connection refused" in error_msg:
            error_msg = f"Connection refused by {domain}:{port}. SSL/TLS port may not be open."

        logger.error("sslyze_scan_failed", domain=domain, error=error_msg)

        if scan_id:
            from api.services.log_streamer import log_streamer

            await log_streamer.send_log(
                scan_id, {"type": "error", "message": f"SSL/TLS scan failed: {error_msg}"}
            )

        return CheckResult(
            module="sslyze",
            category="deep",
            target=target,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=error_msg,
        )


def _parse_sslyze_results(scan_result, domain: str) -> list[Finding]:
    """Parse SSLyze scan results into Finding objects."""
    findings: list[Finding] = []

    # Check for SSL 2.0 support (critical vulnerability)
    ssl2_attempt = scan_result.ssl_2_0_cipher_suites
    if (
        ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and ssl2_attempt.result
        and ssl2_attempt.result.accepted_cipher_suites
    ):
        findings.append(
            Finding(
                severity="critical",
                title="SSL 2.0 Enabled",
                description=f"Server supports deprecated SSL 2.0 protocol with {len(ssl2_attempt.result.accepted_cipher_suites)} cipher suites",
                reference="https://tools.ietf.org/html/rfc6176",
                cve="CWE-327",
                cvss_score=7.5,
            )
        )

    # Check for SSL 3.0 support (high vulnerability - POODLE)
    ssl3_attempt = scan_result.ssl_3_0_cipher_suites
    if (
        ssl3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and ssl3_attempt.result
        and ssl3_attempt.result.accepted_cipher_suites
    ):
        findings.append(
            Finding(
                severity="high",
                title="SSL 3.0 Enabled (POODLE)",
                description=f"Server supports deprecated SSL 3.0 protocol with {len(ssl3_attempt.result.accepted_cipher_suites)} cipher suites",
                reference="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566",
                cve="CVE-2014-3566",
                cvss_score=3.4,
            )
        )

    # Check for TLS 1.0 support (medium - deprecated)
    tls10_attempt = scan_result.tls_1_0_cipher_suites
    if (
        tls10_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and tls10_attempt.result
        and tls10_attempt.result.accepted_cipher_suites
    ):
        findings.append(
            Finding(
                severity="medium",
                title="TLS 1.0 Enabled",
                description=f"Server supports deprecated TLS 1.0 protocol with {len(tls10_attempt.result.accepted_cipher_suites)} cipher suites",
                reference="https://tools.ietf.org/html/rfc8996",
                cve="CWE-327",
                cvss_score=5.0,
            )
        )

    # Check for TLS 1.1 support (medium - deprecated)
    tls11_attempt = scan_result.tls_1_1_cipher_suites
    if (
        tls11_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and tls11_attempt.result
        and tls11_attempt.result.accepted_cipher_suites
    ):
        findings.append(
            Finding(
                severity="medium",
                title="TLS 1.1 Enabled",
                description=f"Server supports deprecated TLS 1.1 protocol with {len(tls11_attempt.result.accepted_cipher_suites)} cipher suites",
                reference="https://tools.ietf.org/html/rfc8996",
                cve="CWE-327",
                cvss_score=5.0,
            )
        )

    # Check for Heartbleed vulnerability
    heartbleed_attempt = scan_result.heartbleed
    if (
        heartbleed_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and heartbleed_attempt.result
        and heartbleed_attempt.result.is_vulnerable_to_heartbleed
    ):
        findings.append(
            Finding(
                severity="critical",
                title="Heartbleed Vulnerability",
                description="Server is vulnerable to the Heartbleed attack (CVE-2014-0160)",
                reference="https://heartbleed.com/",
                cve="CVE-2014-0160",
                cvss_score=7.5,
            )
        )

    # Check for OpenSSL CCS Injection
    ccs_attempt = scan_result.openssl_ccs_injection
    if (
        ccs_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        and ccs_attempt.result
        and ccs_attempt.result.is_vulnerable_to_ccs_injection
    ):
        findings.append(
            Finding(
                severity="high",
                title="OpenSSL CCS Injection Vulnerability",
                description="Server is vulnerable to CCS Injection attack (CVE-2014-0224)",
                reference="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224",
                cve="CVE-2014-0224",
                cvss_score=6.8,
            )
        )

    # Check certificate validity
    certinfo_attempt = scan_result.certificate_info
    if certinfo_attempt.result:
        cert_result = certinfo_attempt.result
        for cert_deployment in cert_result.certificate_deployments:
            # Check for certificate validation issues
            if cert_deployment.path_validation_results:
                for validation_result in cert_deployment.path_validation_results:
                    if not validation_result.was_validation_successful:
                        findings.append(
                            Finding(
                                severity="high",
                                title="Invalid Certificate Chain",
                                description=f"Certificate validation failed: {validation_result.verify_string or 'Unknown error'}",
                                reference=None,
                                cve="CWE-295",
                                cvss_score=7.4,
                            )
                        )

    return findings
