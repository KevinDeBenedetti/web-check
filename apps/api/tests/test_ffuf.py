"""FFUF fuzzing service: fuzz URL, report parsing, cleanup and failure handling."""

import json
from pathlib import Path

import pytest
from api.services import ffuf_scanner
from api.services.ffuf_scanner import fuzz_url, parse_ffuf_report, run_ffuf_scan

REPORT = {
    "commandline": "ffuf -u https://example.com/FUZZ",
    "time": "2026-11-23T10:00:00Z",
    "results": [
        {
            "input": {"FUZZ": "admin"},
            "status": 403,
            "length": 162,
            "content-type": "text/html",
            "redirectlocation": "",
            "url": "https://example.com/admin",
        },
        {
            "input": {"FUZZ": "old"},
            "status": 301,
            "length": 0,
            "content-type": "",
            "redirectlocation": "https://example.com/old/",
            "url": "https://example.com/old",
        },
    ],
    "config": {},
}


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://example.com", "https://example.com/FUZZ"),
        ("https://example.com/", "https://example.com/FUZZ"),
        ("https://example.com/app/?a=b#top", "https://example.com/app/FUZZ"),
        ("http://example.com:8080/app", "http://example.com:8080/app/FUZZ"),
    ],
)
def test_fuzz_url_appends_the_keyword_to_the_path(target: str, expected: str) -> None:
    assert fuzz_url(target) == expected


def test_parse_ffuf_report_turns_each_match_into_a_finding() -> None:
    findings = parse_ffuf_report(REPORT)

    assert [f.title for f in findings] == [
        "Discovered path: /admin (HTTP 403)",
        "Discovered path: /old (HTTP 301)",
    ]
    assert all(f.severity == "info" for f in findings)
    assert "https://example.com/old/" in findings[1].description


def _fake_docker(monkeypatch: pytest.MonkeyPatch, *, exit_code: int, report: dict | None) -> None:
    async def fake_docker_run(*, command: list[str], **kwargs) -> dict:
        output = command[command.index("-o") + 1]
        if report is not None:
            # The ffuf container writes /output/<name>, bind-mounted from ./outputs.
            (Path("outputs") / Path(output).name).write_text(json.dumps(report))
        return {
            "stdout": "",
            "stderr": "" if exit_code == 0 else "Encountered error(s): connection refused",
            "exit_code": exit_code,
            "timeout": False,
            "truncated": False,
        }

    monkeypatch.setattr(ffuf_scanner, "docker_run", fake_docker_run)


async def test_ffuf_scan_parses_and_deletes_its_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _fake_docker(monkeypatch, exit_code=0, report=REPORT)

    result = await run_ffuf_scan("https://example.com/?q=1", "common.txt", timeout=60)

    assert result.status == "success"
    assert len(result.findings) == 2
    assert list((tmp_path / "outputs").iterdir()) == []


@pytest.mark.parametrize(("exit_code", "report"), [(1, None), (1, REPORT), (0, None)])
async def test_ffuf_failures_are_errors_not_empty_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int, report: dict | None
) -> None:
    monkeypatch.chdir(tmp_path)
    _fake_docker(monkeypatch, exit_code=exit_code, report=report)

    result = await run_ffuf_scan("https://example.com", "common.txt", timeout=60)

    assert result.status == "error"
    assert result.findings == []
    assert list((tmp_path / "outputs").iterdir()) == []
