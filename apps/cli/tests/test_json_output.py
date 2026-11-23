"""`--output-format json` leaves stdout to the JSON document and still honours `--report`."""

import json
from pathlib import Path
from typing import Any

import pytest
from cli.commands import check as check_cmd
from cli.commands import scan as scan_cmd
from cli.main import app
from typer.testing import CliRunner

RESULT = {"module": "headers", "status": "success", "duration_ms": 5, "findings": [], "data": {}}


class FakeClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def get(self, endpoint: str, **params: Any) -> dict:
        if endpoint.startswith("/api/scans/"):
            return {
                "scan_id": "s1",
                "target": "https://example.com",
                "status": "success",
                "results": [RESULT],
            }
        return dict(RESULT)

    def post(self, endpoint: str, json: dict | None = None, **params: Any) -> dict:
        return {"scan_id": "s1", "status": "running"}

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(check_cmd, "APIClient", FakeClient)
    monkeypatch.setattr(scan_cmd, "APIClient", FakeClient)
    monkeypatch.setattr(scan_cmd.time, "sleep", lambda seconds: None)


def _stdout_json(result) -> dict:
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_check_json_is_parseable_and_writes_the_report(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "check",
            "example.com",
            "--skip",
            "dns,dns_enum,ssl,nuclei,nikto",
            "--output-format",
            "json",
            "--report",
        ],
    )

    document = _stdout_json(result)
    assert document["target"] == "https://example.com"
    assert [step["module"] for step in document["steps"]] == ["headers"]
    assert list((tmp_path / "outputs").glob("*.md")), "--report wrote no report"


def test_scan_full_json_is_parseable_and_writes_the_report(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "full",
            "https://example.com",
            "--modules",
            "nuclei",
            "--output-format",
            "json",
            "--report",
        ],
    )

    assert _stdout_json(result)["scan_id"] == "s1"
    assert list((tmp_path / "outputs").glob("*.md")), "--report wrote no report"
