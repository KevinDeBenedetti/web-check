"""Tests for the scanner container status."""

import pytest
from api.main import app
from api.services import runtime_status
from httpx import ASGITransport, AsyncClient


class _FakeProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._output = (stdout, stderr)

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._output


@pytest.mark.parametrize(
    ("process", "expected"),
    [
        (_FakeProcess(0, b"running\n"), "running"),
        (_FakeProcess(0, b"exited\n"), "stopped"),
        (_FakeProcess(1, stderr=b"Error: No such object: x"), "missing"),
        (_FakeProcess(1, stderr=b"permission denied"), "unknown"),
    ],
)
@pytest.mark.asyncio
async def test_get_container_state(
    monkeypatch: pytest.MonkeyPatch, process: _FakeProcess, expected: str
) -> None:
    async def fake_exec(*args, **kwargs):
        return process

    monkeypatch.setattr(runtime_status.asyncio, "create_subprocess_exec", fake_exec)
    assert await runtime_status.get_container_state("x") == expected


@pytest.mark.asyncio
async def test_get_container_state_without_docker_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_exec(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(runtime_status.asyncio, "create_subprocess_exec", fake_exec)
    assert await runtime_status.get_container_state("x") == "unknown"


@pytest.mark.asyncio
async def test_read_services(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_state(container: str, timeout: float = 5.0) -> str:
        return "running" if container.endswith("zap") else "missing"

    monkeypatch.setattr(runtime_status, "get_container_state", fake_state)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/services")
    assert response.status_code == 200
    states = {service["id"]: service["state"] for service in response.json()}
    assert states == {
        "api": "running",
        "zap": "running",
        "nuclei": "missing",
        "nikto": "missing",
        "ffuf": "missing",
    }
