"""DNS record enumeration service — uses dnspython for full record lookup."""

import time
from datetime import UTC, datetime

import dns.resolver
import dns.reversename
from api.models import CheckResult, Finding

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


async def run_dns_enum(url: str, timeout: int = 30) -> CheckResult:
    """Enumerate DNS records for a domain and check email security controls.

    Checks A/AAAA/MX/NS/TXT/SOA records and validates SPF, DMARC, DKIM presence.
    Does not require Docker — uses dnspython directly.
    """
    from urllib.parse import urlparse

    start = time.time()
    findings: list[Finding] = []

    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    domain = parsed.hostname or url

    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = min(timeout, 10)

    # ── Enumerate all record types ─────────────────────────────────────────────
    for rtype in _RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rtype] = []
        except dns.exception.DNSException:
            records[rtype] = []

    # ── Email security checks ──────────────────────────────────────────────────
    txt_records = records.get("TXT", [])
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
    dmarc_records: list[str] = []
    dkim_found = False

    # DMARC lives at _dmarc.<domain>
    try:
        dmarc_ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [r.to_text() for r in dmarc_ans]
    except dns.exception.DNSException:
        dmarc_records = []

    # DKIM: try common selectors
    for selector in ("default", "google", "mail", "dkim", "k1", "selector1", "selector2"):
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found = True
            break
        except dns.exception.DNSException:
            continue

    # ── Generate findings for email security gaps ──────────────────────────────
    if records.get("MX"):
        # Only check email security if MX records exist (domain receives email)
        if not spf_records:
            findings.append(
                Finding(
                    severity="medium",
                    title="No SPF Record Found",
                    description=(
                        f"The domain `{domain}` has MX records but no SPF TXT record. "
                        "Without SPF, anyone can send email claiming to be from this domain, "
                        "enabling phishing/spoofing attacks."
                    ),
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                    remediation="Add a TXT record: v=spf1 include:your-mail-provider.com ~all",
                )
            )
        elif len(spf_records) > 1:
            findings.append(
                Finding(
                    severity="medium",
                    title="Multiple SPF Records Detected",
                    description=(
                        f"Multiple SPF TXT records found for `{domain}`. "
                        "Having more than one SPF record is invalid per RFC 7208 and causes "
                        "email authentication failures."
                    ),
                    reference="https://www.rfc-editor.org/rfc/rfc7208#section-3.2",
                    remediation="Merge all SPF mechanisms into a single TXT record.",
                )
            )
        else:
            spf_value = spf_records[0].strip('"')
            if "+all" in spf_value:
                findings.append(
                    Finding(
                        severity="high",
                        title="SPF Record Uses +all (Permissive)",
                        description=(
                            f"The SPF record for `{domain}` ends with `+all`, meaning any server "
                            "is authorised to send email for this domain. This effectively negates "
                            "SPF protection."
                        ),
                        reference="https://www.rfc-editor.org/rfc/rfc7208",
                        remediation="Change +all to ~all (softfail) or -all (fail).",
                    )
                )

        if not dmarc_records:
            findings.append(
                Finding(
                    severity="medium",
                    title="No DMARC Record Found",
                    description=(
                        f"No DMARC TXT record found at `_dmarc.{domain}`. "
                        "DMARC specifies how to handle emails that fail SPF/DKIM, "
                        "protecting against spoofing and phishing."
                    ),
                    reference="https://dmarc.org/overview/",
                    remediation=f"Add TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                )
            )
        else:
            dmarc_value = dmarc_records[0].strip('"')
            if "p=none" in dmarc_value.lower():
                findings.append(
                    Finding(
                        severity="low",
                        title="DMARC Policy Set to None (Monitor Only)",
                        description=(
                            f"The DMARC record for `{domain}` uses `p=none`, which only monitors "
                            "without taking action on failing emails. This provides no active protection."
                        ),
                        reference="https://dmarc.org/overview/",
                        remediation="Progress DMARC policy to p=quarantine then p=reject after monitoring.",
                    )
                )

        if not dkim_found:
            findings.append(
                Finding(
                    severity="low",
                    title="No Common DKIM Selector Found",
                    description=(
                        f"No DKIM TXT record was detected for `{domain}` at common selectors "
                        "(default, google, mail, dkim, selector1, selector2). "
                        "DKIM signs outgoing emails to verify they haven't been tampered with."
                    ),
                    reference="https://www.rfc-editor.org/rfc/rfc6376",
                    remediation="Configure DKIM signing in your email provider and publish the public key as a TXT record.",
                )
            )

    # ── Zone transfer check ────────────────────────────────────────────────────
    ns_records = records.get("NS", [])
    for ns in ns_records[:2]:  # Only try first 2 nameservers to keep it fast
        ns_host = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
            if z:
                findings.append(
                    Finding(
                        severity="high",
                        title="DNS Zone Transfer Allowed",
                        description=(
                            f"The nameserver `{ns_host}` allows unauthenticated DNS zone transfers (AXFR) "
                            f"for `{domain}`. This exposes all DNS records to anyone, enabling reconnaissance."
                        ),
                        reference="https://owasp.org/www-community/attacks/DNS_Zone_Transfer",
                        remediation="Restrict AXFR to authorised secondary nameservers only.",
                    )
                )
                break
        except Exception:
            pass  # Zone transfer refused/failed — expected

    duration_ms = int((time.time() - start) * 1000)
    return CheckResult(
        module="dns_enum",
        category="quick",
        target=url,
        timestamp=datetime.now(UTC),
        duration_ms=duration_ms,
        status="success",
        data={
            "domain": domain,
            "records": {k: v for k, v in records.items() if v},
            "spf": spf_records,
            "dmarc": dmarc_records,
            "dkim_found": dkim_found,
            "findings_count": len(findings),
        },
        findings=findings,
        error=None,
    )
