"""`--sarif` writes the SARIF file CI uploads, whatever the configuration file says."""

import json
from pathlib import Path

import pytest
from my_check import cli
from my_check.types import CheckResult, CheckStatus, Report
from typer.testing import CliRunner


class FakeScheduler:
    def __init__(self, **kwargs) -> None:
        pass

    async def run(self, **kwargs) -> Report:
        result = CheckResult(status=CheckStatus.WARN, score=60, message="HSTS missing")
        return Report(target="https://example.com", results={"web-headers": result})


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MY_CHECK_SARIF", raising=False)
    monkeypatch.setattr(cli, "Scheduler", FakeScheduler)
    # A configuration that turns SARIF off, like the one the repository used to ship.
    (tmp_path / "my-check.config.json").write_text(
        json.dumps({"output": {"formats": ["terminal"], "output_dir": "outputs", "sarif": False}})
    )
    return tmp_path


def test_sarif_flag_writes_the_sarif_file(workdir: Path) -> None:
    result = CliRunner().invoke(cli.app, ["web", "https://example.com", "--sarif"])

    assert result.exit_code == 0, result.output
    sarif = json.loads((workdir / "outputs" / "my-check-results.sarif").read_text())
    assert sarif["version"] == "2.1.0"


def test_without_the_flag_the_configuration_decides(workdir: Path) -> None:
    result = CliRunner().invoke(cli.app, ["web", "https://example.com", "--output", "json"])

    assert result.exit_code == 0, result.output
    assert (workdir / "outputs" / "my-check-results.json").exists()
    assert not (workdir / "outputs" / "my-check-results.sarif").exists()
