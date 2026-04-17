"""DNS security check (DNSSEC, CAA, SPF, DMARC)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import dns.resolver
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

POINTS_PER_CHECK = 25


def _extract_domain(target: str) -> str:
    """Return the domain from a URL or bare hostname."""
    parsed = urlparse(target)
    return parsed.hostname or target.split("/")[0].split(":")[0]


def _check_dnssec(domain: str) -> dict:
    """Attempt DNSSEC-validated resolution."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        answer = resolver.resolve(domain, "A")
        has_ad = bool(answer.response.flags & dns.flags.AD)
        return {"supported": has_ad, "error": None}
    except Exception as exc:
        return {"supported": False, "error": str(exc)}


def _check_caa(domain: str) -> dict:
    """Look for CAA records."""
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        records = [r.to_text() for r in answers]
        return {"present": True, "records": records}
    except dns.resolver.NoAnswer:
        return {"present": False, "records": []}
    except dns.resolver.NXDOMAIN:
        return {"present": False, "records": [], "error": "NXDOMAIN"}
    except Exception as exc:
        return {"present": False, "records": [], "error": str(exc)}


def _check_spf(domain: str) -> dict:
    """Look for an SPF record in TXT records."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                return {"present": True, "record": txt}
        return {"present": False, "record": None}
    except Exception as exc:
        return {"present": False, "record": None, "error": str(exc)}


def _check_dmarc(domain: str) -> dict:
    """Look for a DMARC record at _dmarc.<domain>."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                return {"present": True, "record": txt}
        return {"present": False, "record": None}
    except Exception as exc:
        return {"present": False, "record": None, "error": str(exc)}


@dataclass(slots=True)
class DnsCheck:
    """Evaluate DNS security posture: DNSSEC, CAA, SPF, and DMARC."""

    id: str = "web-dns"
    name: str = "DNS Security"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, str):
            raise TypeError(f"Expected str URL, got {type(target).__name__}")
        domain = _extract_domain(target)

        dnssec = _check_dnssec(domain)
        caa = _check_caa(domain)
        spf = _check_spf(domain)
        dmarc = _check_dmarc(domain)

        details = {
            "domain": domain,
            "dnssec": dnssec,
            "caa": caa,
            "spf": spf,
            "dmarc": dmarc,
        }

        score = 0
        passed: list[str] = []
        missing: list[str] = []

        if dnssec["supported"]:
            score += POINTS_PER_CHECK
            passed.append("DNSSEC")
        else:
            missing.append("DNSSEC")

        if caa["present"]:
            score += POINTS_PER_CHECK
            passed.append("CAA")
        else:
            missing.append("CAA")

        if spf["present"]:
            score += POINTS_PER_CHECK
            passed.append("SPF")
        else:
            missing.append("SPF")

        if dmarc["present"]:
            score += POINTS_PER_CHECK
            passed.append("DMARC")
        else:
            missing.append("DMARC")

        if score == 100:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="All DNS security features configured",
                details=details,
            )

        status = CheckStatus.WARN if score >= 50 else CheckStatus.FAIL
        remediation = "Configure the following DNS security features: " + ", ".join(missing)

        return CheckResult(
            status=status,
            score=score,
            message=f"DNS security: {', '.join(passed) or 'none'} configured; missing {', '.join(missing)}",
            details=details,
            remediation=remediation,
        )
