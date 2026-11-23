"""The web-check command surface: every command parses, options can follow arguments."""

from pathlib import Path

import pytest
from cli.commands import check as check_cmd
from cli.commands.scan import _display_result
from cli.main import app
from cli.utils.http_client import APIClient
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # CLISettings reads .env from the working directory: never the developer's own.
    monkeypatch.chdir(tmp_path)
    for name in ("WEB_CHECK_CLI_API_URL", "WEB_CHECK_CLI_API_KEY", "ALLOWED_DOMAINS"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["check"],
        ["guide"],
        ["health"],
        ["scan", "nuclei"],
        ["scan", "nikto"],
        ["scan", "quick"],
        ["scan", "ssl"],
        ["scan", "full"],
        ["results", "list"],
        ["results", "show"],
        ["results", "clear"],
        ["config", "show"],
        ["config", "validate"],
        ["domains", "list"],
    ],
    ids=lambda args: " ".join(args) or "web-check",
)
def test_every_command_has_help(args: list[str]) -> None:
    result = runner.invoke(app, [*args, "--help"])
    assert result.exit_code == 0, result.output
    assert "Usage" in result.output


def test_check_accepts_options_after_the_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple] = []
    monkeypatch.setattr(check_cmd, "run_check", lambda url, **kwargs: calls.append((url, kwargs)))

    result = runner.invoke(app, ["check", "example.com", "--skip", "nikto,ssl", "--report"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "https://example.com",
            {"skip_set": {"nikto", "ssl"}, "output_format": "table", "save_report": True},
        )
    ]


def test_client_waits_at_least_as_long_as_the_scan() -> None:
    client = APIClient("http://localhost:8000", timeout=600)
    assert client._timeout_for({"timeout": 900}) == 930
    assert client._timeout_for({"timeout": 30}) == 600
    assert client._timeout_for({}) == 600
    client.close()


def test_scanner_text_with_markup_is_printed_verbatim(capsys: pytest.CaptureFixture[str]) -> None:
    # Text from the scanned site must not be parsed as Rich markup ("[/x]" used to crash).
    _display_result(
        {
            "module": "headers",
            "status": "success",
            "duration_ms": 1,
            "findings": [{"severity": "low", "title": "Server [/x]", "description": "[link=x]y"}],
            "data": {"server": "nginx [/x]"},
        },
        "table",
    )
    output = capsys.readouterr().out
    assert "Server [/x]" in output and "nginx [/x]" in output and "[link=x]y" in output
