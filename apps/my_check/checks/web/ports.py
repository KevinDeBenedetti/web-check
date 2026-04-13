"""Exposed ports scan check."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext

logger = logging.getLogger(__name__)

DEFAULT_PORTS: list[int] = [80, 443, 8080, 8443, 3000, 9090, 22, 21, 3306, 5432, 6379, 27017]
EXPECTED_PORTS: set[int] = {80, 443}
DANGEROUS_PORTS: set[int] = {22, 21, 3306, 5432, 6379, 27017}
CONNECT_TIMEOUT = 3.0
DEDUCT_PER_UNEXPECTED = 15


def _extract_hostname(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target.split("/")[0].split(":")[0]


async def _check_port(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to *host*:*port* succeeds."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (TimeoutError, OSError):
        return False


@dataclass(slots=True)
class PortsCheck:
    """Scan common TCP ports and flag unexpected or dangerous open ports."""

    id: str = "web-ports"
    name: str = "Exposed Ports"
    category: CheckCategory = CheckCategory.WEB
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, str)
        hostname = _extract_hostname(target)

        tasks = {port: _check_port(hostname, port, CONNECT_TIMEOUT) for port in self.ports}
        results = await asyncio.gather(*tasks.values())
        port_status: dict[int, str] = {}
        open_ports: list[int] = []

        for port, is_open in zip(tasks, results, strict=True):
            port_status[port] = "open" if is_open else "closed"
            if is_open:
                open_ports.append(port)

        unexpected = [p for p in open_ports if p not in EXPECTED_PORTS]
        dangerous_open = [p for p in open_ports if p in DANGEROUS_PORTS]

        score = max(0, 100 - len(unexpected) * DEDUCT_PER_UNEXPECTED)

        details = {
            "hostname": hostname,
            "ports": port_status,
            "open": open_ports,
            "unexpected_open": unexpected,
            "dangerous_open": dangerous_open,
        }

        if dangerous_open:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=score,
                message=f"Dangerous ports open: {', '.join(map(str, dangerous_open))}",
                details=details,
                remediation=(
                    "Close or firewall the following dangerous ports: "
                    + ", ".join(map(str, dangerous_open))
                ),
            )

        if unexpected:
            return CheckResult(
                status=CheckStatus.WARN,
                score=score,
                message=f"Unexpected ports open: {', '.join(map(str, unexpected))}",
                details=details,
                remediation=(
                    "Review and restrict access to unexpected open ports: "
                    + ", ".join(map(str, unexpected))
                ),
            )

        return CheckResult(
            status=CheckStatus.PASS,
            score=100,
            message="Only expected ports (80, 443) are open"
            if open_ports
            else "No scanned ports are open",
            details=details,
        )
