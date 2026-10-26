"""Scope checks: decide whether a target may be scanned.

Rules come from ALLOWED_DOMAINS. A plain rule (``example.com``) allows the
domain and all its subdomains; a ``*.`` rule (``*.example.com``) allows
subdomains only.
"""

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """Outcome of a scope check."""

    allowed: bool
    hostname: str | None
    matched_rule: str | None


def extract_hostname(target: str) -> str | None:
    """Return the lower-cased hostname of a URL or bare host, or None if there is none."""
    value = target.strip()
    if not value:
        return None
    parsed = urlparse(value if "://" in value else f"//{value}")
    try:
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    return hostname.lower().strip(".") or None


def matches_rule(hostname: str, rule: str) -> bool:
    """Check a hostname against a single scope rule."""
    rule_lc = rule.strip().lower().strip(".")
    if not rule_lc:
        return False
    if rule_lc.startswith("*."):
        return hostname.endswith(rule_lc[1:])
    return hostname == rule_lc or hostname.endswith("." + rule_lc)


def check_scope(target: str, rules: list[str]) -> ScopeDecision:
    """Check a target against the scope rules; the first matching rule wins."""
    hostname = extract_hostname(target)
    if hostname is None:
        return ScopeDecision(allowed=False, hostname=None, matched_rule=None)
    for rule in rules:
        if matches_rule(hostname, rule):
            return ScopeDecision(allowed=True, hostname=hostname, matched_rule=rule.strip())
    return ScopeDecision(allowed=False, hostname=hostname, matched_rule=None)
