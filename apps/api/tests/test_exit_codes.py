"""A scanner that exits non-zero is a failed module, never an empty successful scan."""

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from api.models import CheckResult
from api.services import nikto, nuclei, sqlmap_scanner, wapiti_scanner, xsstrike_scanner
from api.services.docker_runner import exit_code_error

TARGET = "https://example.com"

# (module object, name of the process runner it calls, scanner coroutine)
SCANNERS: list[tuple[object, str, Callable[[str, int], Awaitable[CheckResult]]]] = [
    (sqlmap_scanner, "run_process", sqlmap_scanner.run_sqlmap_scan),
    (xsstrike_scanner, "run_process", xsstrike_scanner.run_xsstrike_scan),
    (wapiti_scanner, "run_process", wapiti_scanner.run_wapiti_scan),
    (nuclei, "docker_run", nuclei.run_nuclei_scan),
    (nikto, "docker_run", nikto.run_nikto_scan),
]
IDS = ["sqlmap", "xsstrike", "wapiti", "nuclei", "nikto"]


def _fake_runner(exit_code: int, stderr: str = "") -> Callable[..., Awaitable[dict]]:
    async def fake(*args, **kwargs) -> dict:
        return {
            "stdout": "",
            "stderr": stderr,
            "exit_code": exit_code,
            "timeout": False,
            "truncated": False,
        }

    return fake


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    script = tmp_path / "xsstrike.py"
    script.write_text("")
    monkeypatch.setattr(xsstrike_scanner, "XSSTRIKE_SCRIPT", script)


@pytest.mark.parametrize(("module", "runner", "scan"), SCANNERS, ids=IDS)
async def test_non_zero_exit_is_an_error(
    module: object, runner: str, scan: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, runner, _fake_runner(2, "fatal: target unreachable"))

    result = await scan(TARGET, 30)

    assert result.status == "error"
    assert result.findings == []
    assert result.error is not None and "exited with code 2" in result.error
    assert "target unreachable" in result.error


@pytest.mark.parametrize(("module", "runner", "scan"), SCANNERS, ids=IDS)
async def test_zero_exit_without_findings_is_a_success(
    module: object, runner: str, scan: Callable, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, runner, _fake_runner(0))

    result = await scan(TARGET, 30)

    assert result.status == "success", result.error
    assert result.findings == []


def test_exit_code_error_keeps_a_bounded_tail() -> None:
    result = {"exit_code": 1, "stderr": "x" * 2000, "stdout": ""}
    message = exit_code_error(result, "sqlmap")
    assert message is not None and message.startswith("sqlmap exited with code 1: ")
    assert len(message) < 600
    assert exit_code_error({"exit_code": 0, "stderr": "warn", "stdout": ""}, "sqlmap") is None
