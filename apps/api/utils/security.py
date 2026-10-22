"""Request-level security: scan target validation (SSRF guard) and API key auth."""

import asyncio
import ipaddress
import re
import secrets
import socket
from urllib.parse import urlparse

import structlog
from api.utils.config import Settings, get_settings
from fastapi import Depends, Header, HTTPException, Query, status

logger = structlog.get_logger()

_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".home.arpa")
_WORDLIST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.txt$")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _reject(reason: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Target not allowed: {reason}"
    )


def _is_public_ip(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return _is_public_ip(ip.ipv4_mapped)
    return ip.is_global and not ip.is_multicast


def _parse_ip(hostname: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def is_allowed_host(hostname: str, allowed_domains: list[str]) -> bool:
    """Return True if hostname equals, or is a subdomain of, an allowlisted domain."""
    host = hostname.lower().strip(".")
    for domain in allowed_domains:
        domain = domain.lower().strip(".")
        if domain and (host == domain or host.endswith("." + domain)):
            return True
    return False


async def _resolve(hostname: str) -> list[IPAddress]:
    """Resolve hostname to IP addresses. Returns [] if resolution fails."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    ips: list[IPAddress] = []
    for info in infos:
        ip = _parse_ip(str(info[4][0]).split("%", 1)[0])
        if ip is not None:
            ips.append(ip)
    return ips


async def validate_target(
    raw: str, *, require_scheme: bool = True, settings: Settings | None = None
) -> str:
    """
    Validate a user-supplied scan target and return it as a URL.

    Rejects non-HTTP schemes, internal hostnames (localhost, single-label Docker
    service names such as ``zap``, ``*.local``…), non-public IPs and targets outside
    ``ALLOWED_DOMAINS``. Hostnames are resolved and rejected if they point to a
    non-public address, unless ``ALLOW_PRIVATE_TARGETS`` is set.

    Args:
        raw: URL (or bare domain when ``require_scheme`` is False)
        require_scheme: Reject inputs without an explicit http(s):// scheme
        settings: Settings override (defaults to the cached application settings)

    Raises:
        HTTPException: 400 when the target is invalid or not allowed
    """
    settings = settings or get_settings()
    value = raw.strip()

    if "://" not in value:
        if require_scheme:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL must start with http:// or https://",
            )
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must start with http:// or https://",
        )
    try:
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as e:
        raise _reject("malformed URL") from e
    if not hostname or len(hostname) > 253:
        raise _reject("missing or invalid hostname")
    if parsed.username or parsed.password:
        raise _reject("credentials in URL are not supported")

    host = hostname.lower().strip(".")
    allow_private = settings.allow_private_targets
    literal_ip = _parse_ip(host)

    if literal_ip is None:
        if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_SUFFIXES):
            raise _reject("internal hostname")
        if "." not in host and not allow_private:
            raise _reject("single-label hostnames are not allowed")
    elif not allow_private and not _is_public_ip(literal_ip):
        raise _reject("non-public IP address")

    if not is_allowed_host(host, settings.get_allowed_domains()):
        raise _reject("domain is not in ALLOWED_DOMAINS")

    if literal_ip is None and not allow_private:
        resolved = await _resolve(host)
        if any(not _is_public_ip(ip) for ip in resolved):
            logger.warning("target_resolves_to_private_ip", host=host)
            raise _reject("hostname resolves to a non-public IP address")

    return value


async def target_url(url: str = Query(..., description="Target URL to scan")) -> str:
    """FastAPI dependency: validated target URL (scheme required)."""
    return await validate_target(url)


async def target_host(url: str = Query(..., description="Target domain or URL")) -> str:
    """FastAPI dependency: validated target; bare domains are accepted as https://."""
    return await validate_target(url, require_scheme=False)


def validate_wordlist(name: str) -> str:
    """Validate an FFUF wordlist filename (no paths, .txt only)."""
    if not _WORDLIST_RE.fullmatch(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid wordlist name (expected a .txt filename without path)",
        )
    return name


async def require_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    """FastAPI dependency: enforce the X-API-Key header when API_KEY is configured."""
    expected = settings.api_key.get_secret_value() if settings.api_key else ""
    if not expected:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
