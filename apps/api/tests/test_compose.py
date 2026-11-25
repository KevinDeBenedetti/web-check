"""docker-compose.yml: what the scanner containers need from the host."""

from pathlib import Path

import pytest
import yaml

_COMPOSE = Path(__file__).resolve().parents[3] / "docker-compose.yml"


@pytest.mark.parametrize("service", ["nuclei", "nikto"])
def test_the_scanner_containers_reach_the_host_on_linux_too(service: str) -> None:
    # Docker Desktop defines host.docker.internal; Docker Engine on Linux only does
    # with this entry. The integration test serves its site there.
    services = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))["services"]
    assert "host.docker.internal:host-gateway" in services[service].get("extra_hosts", [])
