"""Each HTTP-based web check against a local server: one compliant, one non-compliant response."""

from my_check.checks.web.cookies import CookieSecurityCheck
from my_check.checks.web.cors import CorsCheck
from my_check.checks.web.csp import CspCheck
from my_check.checks.web.headers import HeadersCheck
from my_check.checks.web.redirects import RedirectsCheck
from my_check.types import CheckStatus

STRICT_CSP = "default-src 'self'; script-src 'self'; object-src 'none'"
GOOD_HEADERS = [
    ("Content-Security-Policy", STRICT_CSP),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Permissions-Policy", "camera=()"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
]


def _static(headers: list[tuple[str, str]]):
    return lambda path, request: ("200 OK", headers, b"<html></html>")


async def test_headers(http_server) -> None:
    good = await http_server(_static(GOOD_HEADERS))
    bare = await http_server(_static([]))

    assert (await HeadersCheck().run(good + "/")).status == CheckStatus.PASS
    result = await HeadersCheck().run(bare + "/")
    assert result.status == CheckStatus.FAIL and result.message.startswith("0/6")


async def test_csp(http_server) -> None:
    good = await http_server(_static([("Content-Security-Policy", STRICT_CSP)]))
    weak = await http_server(
        _static([("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")])
    )
    missing = await http_server(_static([]))

    assert (await CspCheck().run(good + "/")).status == CheckStatus.PASS
    assert (await CspCheck().run(weak + "/")).status in (CheckStatus.WARN, CheckStatus.FAIL)
    assert (await CspCheck().run(missing + "/")).status == CheckStatus.FAIL


async def test_cors(http_server) -> None:
    safe = await http_server(_static([]))

    def reflecting(path: str, request: dict[str, str]):
        origin = request.get("origin")
        headers = (
            [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            if origin
            else []
        )
        return "200 OK", headers, b""

    reflected = await http_server(reflecting)

    assert (await CorsCheck().run(safe + "/")).status == CheckStatus.PASS
    result = await CorsCheck().run(reflected + "/")
    assert result.status == CheckStatus.FAIL
    assert "evil.example.com" in str(result.details)


async def test_cookies(http_server) -> None:
    good = await http_server(
        _static([("Set-Cookie", "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/")])
    )
    bad = await http_server(_static([("Set-Cookie", "sid=1; Path=/")]))

    assert (await CookieSecurityCheck().run(good + "/")).status == CheckStatus.PASS
    result = await CookieSecurityCheck().run(bad + "/")
    assert result.status != CheckStatus.PASS
    issues = {issue["issue"] for issue in result.details}
    assert {"missing HttpOnly flag", "missing SameSite attribute"} <= issues


async def test_redirects_follow_relative_locations(http_server) -> None:
    def site(path: str, request: dict[str, str]):
        if path == "/":
            return "302 Found", [("Location", "/login")], b""  # relative Location
        return "200 OK", [], b"login"

    base = await http_server(site)
    result = await RedirectsCheck().run(base + "/")

    # Followed to the end (a relative Location used to fail with "Could not follow"),
    # then graded: plain HTTP is a warning.
    assert result.status == CheckStatus.WARN
    assert result.message == "Final destination is not HTTPS"
    assert [hop["url"] for hop in result.details["chain"]] == [base + "/", base + "/login"]
    assert result.details["chain"][0]["location"] == base + "/login"
