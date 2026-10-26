"""Catalog of scan modules and profiles exposed to clients."""

from api.models.catalog import Catalog, ModuleInfo, ScanProfile

MODULES: tuple[ModuleInfo, ...] = (
    ModuleInfo(
        id="headers",
        name="HTTP security headers",
        description="HSTS, CSP, X-Frame-Options, CORS, cookie flags and server banners",
        category="quick",
        intrusive=False,
        default_timeout=30,
    ),
    ModuleInfo(
        id="dns",
        name="DNS and email security",
        description="DNS records, SPF, DMARC, DKIM and zone transfer exposure",
        category="quick",
        intrusive=False,
        default_timeout=30,
    ),
    ModuleInfo(
        id="testssl",
        name="TLS configuration (SSLyze)",
        description="Protocols, cipher suites and certificate validity",
        category="deep",
        intrusive=False,
        default_timeout=300,
    ),
    ModuleInfo(
        id="nuclei",
        name="Known vulnerabilities (Nuclei)",
        description="CVEs and misconfigurations from community templates",
        category="quick",
        intrusive=False,
        default_timeout=300,
    ),
    ModuleInfo(
        id="nikto",
        name="Web server configuration (Nikto)",
        description="Default files, outdated software and risky HTTP methods",
        category="quick",
        intrusive=False,
        default_timeout=600,
    ),
    ModuleInfo(
        id="zap",
        name="Dynamic analysis (OWASP ZAP)",
        description="Crawls the site then runs ZAP's active scan rules",
        category="deep",
        intrusive=True,
        default_timeout=900,
    ),
    ModuleInfo(
        id="wapiti",
        name="Web application audit (Wapiti)",
        description="Black-box audit of forms and parameters",
        category="security",
        intrusive=True,
        default_timeout=600,
    ),
    ModuleInfo(
        id="sqlmap",
        name="SQL injection testing (SQLMap)",
        description="Tests parameters for SQL injection",
        category="security",
        intrusive=True,
        default_timeout=900,
    ),
    ModuleInfo(
        id="xsstrike",
        name="XSS testing (XSStrike)",
        description="Tests parameters for reflected XSS",
        category="security",
        intrusive=True,
        default_timeout=300,
    ),
)

PROFILES: tuple[ScanProfile, ...] = (
    ScanProfile(
        id="quick",
        name="Quick",
        description="Passive checks only: headers, DNS and TLS",
        modules=["headers", "dns", "testssl"],
    ),
    ScanProfile(
        id="standard",
        name="Standard",
        description="Quick checks plus known vulnerabilities and server configuration",
        modules=["headers", "dns", "testssl", "nuclei", "nikto"],
    ),
    ScanProfile(
        id="full",
        name="Full",
        description="Standard checks plus OWASP ZAP dynamic analysis",
        modules=["headers", "dns", "testssl", "nuclei", "nikto", "zap"],
    ),
)

DEFAULT_PROFILE = "standard"

# Modules run when a request names neither modules nor a profile (historical default).
LEGACY_DEFAULT_MODULES = ["nuclei", "nikto", "zap"]

_MODULES_BY_ID = {module.id: module for module in MODULES}
_PROFILES_BY_ID = {profile.id: profile for profile in PROFILES}


def get_module(module_id: str) -> ModuleInfo | None:
    """Return a module by id."""
    return _MODULES_BY_ID.get(module_id)


def get_profile(profile_id: str) -> ScanProfile | None:
    """Return a profile by id."""
    return _PROFILES_BY_ID.get(profile_id)


def resolve_modules(modules: list[str] | None, profile: str | None) -> list[str]:
    """Resolve the modules to run for a scan request.

    Raises:
        ValueError: if the profile or a module is unknown, or no module is selected.
    """
    if modules:
        selected = list(dict.fromkeys(modules))
    elif profile:
        scan_profile = get_profile(profile)
        if scan_profile is None:
            raise ValueError(f"Unknown profile: {profile}")
        selected = list(scan_profile.modules)
    else:
        selected = list(LEGACY_DEFAULT_MODULES)

    unknown = [module for module in selected if module not in _MODULES_BY_ID]
    if unknown:
        raise ValueError(f"Unknown module(s): {', '.join(unknown)}")
    return selected


def get_catalog() -> Catalog:
    """Return the full catalog."""
    return Catalog(
        modules=list(MODULES),
        profiles=list(PROFILES),
        default_profile=DEFAULT_PROFILE,
    )
