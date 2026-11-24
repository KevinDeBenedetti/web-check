"""Suite-wide guard: the tests run offline.

A test that looks up a host other than this machine, or sends to one (TCP connect,
UDP datagram), fails, naming the host, even when the code under test swallows the
error: a scan test must not reach a real site (the scanners would attack it), and
the result must not depend on the network. Fake the client, the scanner run or the
resolver instead.

The guard sees what this Python process does through the socket module. A
subprocess (a scanner binary, docker) or a C extension with its own network code is
out of its reach: fake those at the call that starts them.
"""

import ipaddress
import socket
from collections.abc import Iterator

import pytest

_PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def _is_local(host: object) -> bool:
    """This machine: a loopback or unspecified address, localhost, or no host (a bind)."""
    if isinstance(host, bytes):
        host = host.decode(errors="replace")
    if host is None or host == "":
        return True
    if not isinstance(host, str):
        return False
    name = host.split("%", 1)[0].strip("[]").rstrip(".").lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback or address.is_unspecified


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    reached: list[str] = []

    def guard_lookup(real, what: str):  # noqa: ANN001, ANN202
        def lookup(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
            if not _is_local(host):
                reached.append(f"{what} of {host!r}")
                raise socket.gaierror(
                    socket.EAI_NONAME, f"offline test suite: {host!r} not looked up"
                )
            return real(host, *args, **kwargs)

        return lookup

    def guard_send(real, what: str, address_index: int):  # noqa: ANN001, ANN202
        def send(self: socket.socket, *args):  # noqa: ANN002, ANN202
            address = args[address_index] if len(args) > address_index else None
            inet = self.family in (socket.AF_INET, socket.AF_INET6)
            if inet and isinstance(address, tuple) and not _is_local(address[0]):
                reached.append(f"{what} {address[0]!r}")
                raise ConnectionRefusedError(f"offline test suite: no {what} {address[0]!r}")
            return real(self, *args)

        return send

    for name, what in (
        ("getaddrinfo", "lookup"),
        ("gethostbyname", "lookup"),
        ("gethostbyname_ex", "lookup"),
        ("gethostbyaddr", "reverse lookup"),
    ):
        monkeypatch.setattr(socket, name, guard_lookup(getattr(socket, name), what))
    # connect(address), connect_ex(address); sendto(data, address) or sendto(data, flags, address).
    monkeypatch.setattr(
        socket.socket, "connect", guard_send(socket.socket.connect, "connection to", 0)
    )
    monkeypatch.setattr(
        socket.socket, "connect_ex", guard_send(socket.socket.connect_ex, "connection to", 0)
    )
    real_sendto = socket.socket.sendto

    def sendto(self: socket.socket, *args):  # noqa: ANN002, ANN202
        return guard_send(real_sendto, "datagram to", len(args) - 1)(self, *args)

    monkeypatch.setattr(socket.socket, "sendto", sendto)
    # A proxy would carry the request through a local address, out of the guard's sight.
    for variable in _PROXY_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    yield
    if reached:
        pytest.fail(f"The test reached the network: {', '.join(dict.fromkeys(reached))}.")
