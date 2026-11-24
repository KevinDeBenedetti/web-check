"""my-check commands, configuration precedence and the scheduler's timeout."""

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from my_check import cli
from my_check.config import load_config
from my_check.scheduler import Scheduler
from my_check.types import CheckCategory, CheckResult, CheckStatus, K8sContext, Report
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    for name in ("MY_CHECK_OUTPUT", "MY_CHECK_OUTPUT_DIR", "MY_CHECK_SARIF", "MY_CHECK_WEB_TARGET"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "command", [[], ["web"], ["k8s"], ["all"]], ids=lambda c: " ".join(c) or "my-check"
)
def test_every_command_has_help(command: list[str]) -> None:
    result = runner.invoke(cli.app, [*command, "--help"])
    assert result.exit_code == 0, result.output


class FakeScheduler:
    def __init__(self, **kwargs) -> None:
        pass

    async def run(self, **kwargs) -> Report:
        result = CheckResult(status=CheckStatus.PASS, score=100, message="ok")
        return Report(target="https://example.com", results={"web-tls": result})


def _write_config(path: Path, formats: list[str]) -> None:
    path.write_text(json.dumps({"output": {"formats": formats, "output_dir": "outputs"}}))


def test_configured_formats_apply_without_output_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "Scheduler", FakeScheduler)
    _write_config(tmp_path / "my-check.config.json", ["json"])

    assert runner.invoke(cli.app, ["web", "https://example.com"]).exit_code == 0
    assert (tmp_path / "outputs" / "my-check-results.json").exists()


def test_output_flag_overrides_configured_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "Scheduler", FakeScheduler)
    _write_config(tmp_path / "my-check.config.json", ["json"])

    result = runner.invoke(cli.app, ["web", "https://example.com", "--output", "terminal"])

    assert result.exit_code == 0, result.output
    assert not (tmp_path / "outputs" / "my-check-results.json").exists()


def test_config_file_wins_over_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_CHECK_OUTPUT", "html")
    monkeypatch.setenv("MY_CHECK_OUTPUT_DIR", "reports")
    assert load_config().output.formats == ["html"]  # no file: the environment applies

    _write_config(tmp_path / "my-check.config.json", ["json"])
    cfg = load_config()
    assert cfg.output.formats == ["json"]  # the file wins
    assert cfg.output.output_dir == "outputs"


def test_explicit_config_path_is_used(tmp_path: Path) -> None:
    other = tmp_path / "ci.json"
    _write_config(other, ["markdown"])
    assert load_config(other).output.formats == ["markdown"]


@dataclass
class SleepyCheck:
    id: str
    delay: float
    name: str = "sleepy"
    category: CheckCategory = CheckCategory.WEB

    async def run(self, target: str | K8sContext) -> CheckResult:
        await asyncio.sleep(self.delay)
        return CheckResult(status=CheckStatus.PASS, score=100, message="finished")


async def test_scheduler_times_out_slow_checks_and_keeps_fast_results() -> None:
    scheduler = Scheduler(checks=[SleepyCheck("slow", 3.0), SleepyCheck("fast", 0.0)], timeout=0.5)

    started = time.monotonic()
    report = await scheduler.run(target="https://example.com", category=CheckCategory.WEB)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0  # the slow check does not hold the run until it finishes
    assert report.results["slow"].status == CheckStatus.FAIL
    assert "Timed out" in report.results["slow"].message
    assert report.results["fast"].status == CheckStatus.PASS


async def test_an_empty_enabled_list_runs_nothing() -> None:
    report = await Scheduler(checks=[SleepyCheck("a", 0.0)]).run(target="x", enabled_ids=set())
    assert report.results == {}


def test_web_ports_setting_reaches_the_ports_check() -> None:
    from my_check.checks.web.ports import DEFAULT_PORTS
    from my_check.registry import get_web_checks

    def ports_of(checks) -> list[int]:
        return next(check for check in checks if check.id == "web-ports").ports

    assert ports_of(get_web_checks([8080, 9443])) == [8080, 9443]
    # Unset keeps the check's own list, with the database / remote-access ports.
    assert ports_of(get_web_checks(None)) == DEFAULT_PORTS
    assert {22, 3306} <= set(ports_of(get_web_checks(load_config().web.ports)))


class RecordingScheduler(FakeScheduler):
    k8s_ctx: K8sContext | None = None
    timeout: float | None = None

    def __init__(self, **kwargs) -> None:
        RecordingScheduler.timeout = kwargs.get("timeout")

    async def run(self, **kwargs) -> Report:
        RecordingScheduler.k8s_ctx = kwargs.get("k8s_ctx")
        return await super().run(**kwargs)


@pytest.mark.parametrize(
    ("args", "config", "expected"),
    [
        ([], {}, False),
        (["--kube-bench-job"], {}, True),
        ([], {"k8s": {"kube_bench_job": True}}, True),
    ],
    ids=["default", "flag", "config"],
)
def test_kube_bench_job_is_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str], config: dict, expected: bool
) -> None:
    monkeypatch.setattr(cli, "Scheduler", RecordingScheduler)
    (tmp_path / "my-check.config.json").write_text(json.dumps(config))

    assert runner.invoke(cli.app, ["k8s", *args]).exit_code == 0
    assert RecordingScheduler.k8s_ctx is not None
    assert RecordingScheduler.k8s_ctx.kube_bench_job is expected


def test_kube_bench_job_raises_the_check_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "Scheduler", RecordingScheduler)
    (tmp_path / "my-check.config.json").write_text(json.dumps({"k8s": {"timeout": 60}}))

    assert runner.invoke(cli.app, ["k8s"]).exit_code == 0
    assert RecordingScheduler.timeout == 60
    assert runner.invoke(cli.app, ["k8s", "--kube-bench-job"]).exit_code == 0
    assert RecordingScheduler.timeout is not None and RecordingScheduler.timeout >= 300
