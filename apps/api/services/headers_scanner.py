"""HTTP Security Headers scanner — no Docker dependency, pure httpx."""

import time
from datetime import UTC, datetime

import httpx
from api.models import CheckResult, Finding

# Headers we audit and their OWASP references
_SECURITY_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "description": (
            "The Strict-Transport-Security header is not set. This header tells browsers "
            "to always use HTTPS for the domain, preventing protocol downgrade attacks."
        ),
        "severity": "medium",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "title": "Missing Content Security Policy (CSP)",
        "description": (
            "The Content-Security-Policy header is not set. CSP prevents cross-site scripting (XSS) "
            "and data injection attacks by specifying allowed content sources."
        ),
        "severity": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "recommendation": "Define a strict CSP: Content-Security-Policy: default-src 'self'; ...",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "description": (
            "The X-Frame-Options header is not set. This header prevents clickjacking attacks "
            "by controlling whether the page can be embedded in an iframe."
        ),
        "severity": "medium",
        "reference": "https://owasp.org/www-community/attacks/Clickjacking",
        "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "description": (
            "The X-Content-Type-Options header is not set. Without it, browsers may MIME-sniff "
            "responses and execute malicious content with an unexpected content type."
        ),
        "severity": "low",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "description": (
            "The Referrer-Policy header is not set. Without it, the full referrer URL is sent "
            "to third-party sites, potentially leaking sensitive path/query information."
        ),
        "severity": "low",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy Header",
        "description": (
            "The Permissions-Policy header (formerly Feature-Policy) is not set. "
            "This header controls access to browser features (camera, microphone, geolocation, etc.)."
        ),
        "severity": "info",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "x-xss-protection": {
        "title": "Missing X-XSS-Protection Header",
        "description": (
            "The X-XSS-Protection header is not set. While deprecated in modern browsers, "
            "it provides basic XSS filtering for older clients."
        ),
        "severity": "info",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block  (or omit for modern-only sites)",
    },
    "cache-control": {
        "title": "Missing Cache-Control Header",
        "description": (
            "Cache-Control is not set. Sensitive responses may be cached by browsers or proxies, "
            "potentially exposing data to other users of shared systems."
        ),
        "severity": "info",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
        "recommendation": "For authenticated pages: Cache-Control: no-store, no-cache, must-revalidate",
    },
}

# CORS misconfiguration checks
_CORS_ISSUES = {
    "wildcard_acao": {
        "title": "CORS: Wildcard Access-Control-Allow-Origin",
        "description": (
            "Access-Control-Allow-Origin: * is set, allowing any origin to make cross-site requests. "
            "This may expose sensitive data if combined with credentialed requests."
        ),
        "severity": "medium",
        "reference": "https://portswigger.net/web-security/cors",
        "recommendation": "Restrict CORS to specific trusted origins instead of using wildcard.",
    },
    "credentials_with_wildcard": {
        "title": "CORS: Credentials Allowed with Wildcard Origin",
        "description": (
            "Access-Control-Allow-Credentials: true is set alongside Access-Control-Allow-Origin: *. "
            "Browsers reject this combination, but it may indicate a misconfigured CORS policy."
        ),
        "severity": "high",
        "reference": "https://portswigger.net/web-security/cors",
        "recommendation": "Never combine Allow-Credentials: true with Allow-Origin: *.",
    },
}

# Cookie security checks
_COOKIE_FLAGS = {
    "secure": {
        "title": "Cookie Missing Secure Flag",
        "description": "A cookie is set without the Secure flag, meaning it can be transmitted over HTTP.",
        "severity": "medium",
        "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
        "recommendation": "Add the Secure flag to all cookies: Set-Cookie: name=value; Secure",
    },
    "httponly": {
        "title": "Cookie Missing HttpOnly Flag",
        "description": (
            "A cookie is set without the HttpOnly flag. JavaScript can read this cookie, "
            "making it vulnerable to XSS-based theft."
        ),
        "severity": "medium",
        "reference": "https://owasp.org/www-community/HttpOnly",
        "recommendation": "Add the HttpOnly flag: Set-Cookie: name=value; HttpOnly",
    },
    "samesite": {
        "title": "Cookie Missing SameSite Attribute",
        "description": (
            "A cookie is set without the SameSite attribute. "
            "This may allow cross-site request forgery (CSRF) attacks."
        ),
        "severity": "low",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
        "recommendation": "Add SameSite attribute: Set-Cookie: name=value; SameSite=Strict",
    },
}


async def run_headers_scan(url: str, timeout: int = 30) -> CheckResult:
    """Scan HTTP security headers for the given URL.

    Checks for missing or misconfigured security headers, CORS policies, and cookie flags.
    Does not require Docker — uses httpx directly.
    """
    start = time.time()
    findings: list[Finding] = []
    detected_headers: dict[str, str] = {}
    server_info: str | None = None
    powered_by: str | None = None

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # noqa: S501  — we're auditing, not trusting
        ) as client:
            response = await client.get(url)

        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # Capture a few informational headers
        server_info = response.headers.get("server")
        powered_by = response.headers.get("x-powered-by")
        detected_headers = {k: v for k, v in resp_headers.items() if k in _SECURITY_HEADERS}

        # ── Missing security headers ──────────────────────────────────────────
        for header_name, meta in _SECURITY_HEADERS.items():
            if header_name not in resp_headers:
                findings.append(
                    Finding(
                        severity=meta["severity"],
                        title=meta["title"],
                        description=meta["description"],
                        reference=meta["reference"],
                        cve=None,
                        cvss_score=None,
                        remediation=meta.get("recommendation"),
                    )
                )

        # ── CORS checks ───────────────────────────────────────────────────────
        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            findings.append(Finding(**_build_finding(_CORS_ISSUES["wildcard_acao"])))
            if acac == "true":
                findings.append(
                    Finding(**_build_finding(_CORS_ISSUES["credentials_with_wildcard"]))
                )

        # ── Cookie flag checks ────────────────────────────────────────────────
        cookie_headers = (
            response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        )
        if not cookie_headers:
            raw_cookies = resp_headers.get("set-cookie", "")
            if raw_cookies:
                cookie_headers = [raw_cookies]

        _check_cookies(cookie_headers, findings)

        # ── Information disclosure ─────────────────────────────────────────────
        if server_info:
            # Only flag if version is exposed (e.g., "nginx/1.18.0" not just "nginx")
            if any(char.isdigit() for char in server_info):
                findings.append(
                    Finding(
                        severity="info",
                        title="Server Version Disclosed in Header",
                        description=(
                            f"The Server header discloses version information: `{server_info}`. "
                            "Attackers can use this to identify known vulnerabilities."
                        ),
                        reference="https://owasp.org/www-project-web-security-testing-guide/",
                        remediation="Configure your server to suppress or genericise the Server header.",
                    )
                )

        if powered_by:
            findings.append(
                Finding(
                    severity="info",
                    title="X-Powered-By Header Exposes Technology Stack",
                    description=(
                        f"X-Powered-By: {powered_by} reveals the backend technology. "
                        "Suppress this header to reduce information leakage."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    remediation="Remove the X-Powered-By header in your application/server configuration.",
                )
            )

        duration_ms = int((time.time() - start) * 1000)
        return CheckResult(
            module="headers",
            category="quick",
            target=url,
            timestamp=datetime.now(UTC),
            duration_ms=duration_ms,
            status="success",
            data={
                "url": url,
                "status_code": response.status_code,
                "headers_present": list(detected_headers.keys()),
                "headers_missing": [h for h in _SECURITY_HEADERS if h not in detected_headers],
                "server": server_info,
                "x_powered_by": powered_by,
                "findings_count": len(findings),
            },
            findings=findings,
            error=None,
        )

    except Exception as exc:
        return CheckResult(
            module="headers",
            category="quick",
            target=url,
            timestamp=datetime.now(UTC),
            duration_ms=int((time.time() - start) * 1000),
            status="error",
            data=None,
            findings=[],
            error=str(exc),
        )


def _build_finding(meta: dict) -> dict:
    return {
        "severity": meta["severity"],
        "title": meta["title"],
        "description": meta["description"],
        "reference": meta["reference"],
        "cve": None,
        "cvss_score": None,
        "remediation": meta.get("recommendation"),
    }


def _check_cookies(cookie_headers: list[str], findings: list[Finding]) -> None:
    """Check each Set-Cookie header for missing security flags."""
    seen_secure = False
    seen_httponly = False
    seen_samesite = False

    for cookie in cookie_headers:
        cookie_lower = cookie.lower()
        if "secure" not in cookie_lower and not seen_secure:
            findings.append(Finding(**_build_finding(_COOKIE_FLAGS["secure"])))
            seen_secure = True
        if "httponly" not in cookie_lower and not seen_httponly:
            findings.append(Finding(**_build_finding(_COOKIE_FLAGS["httponly"])))
            seen_httponly = True
        if "samesite" not in cookie_lower and not seen_samesite:
            findings.append(Finding(**_build_finding(_COOKIE_FLAGS["samesite"])))
            seen_samesite = True
