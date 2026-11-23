"""Reporters with text the scanned target controls: never parsed, never rendered as markup."""

import io
import json
import re
from pathlib import Path

import pytest
from my_check.reporters.html import HtmlReporter
from my_check.reporters.json_reporter import JsonReporter
from my_check.reporters.markdown_reporter import MarkdownReporter
from my_check.reporters.terminal import TerminalReporter
from my_check.types import CheckResult, CheckStatus, Report
from rich.console import Console

HOSTILE = "Server [/x] <img src=x onerror=alert(1)> | `tick` [link=https://evil.example]y[/link]\n# Forged heading"


@pytest.fixture
def report() -> Report:
    result = CheckResult(
        status=CheckStatus.FAIL,
        score=10,
        message=HOSTILE,
        details={"issues": [{"cookie": "sid[/x]", "issue": HOSTILE}]},
        remediation=HOSTILE,
    )
    return Report(
        target="https://example.com/<script>",
        results={"web-cookies": result},
        errors={"web-tls": HOSTILE},
    )


def test_terminal_prints_hostile_text_verbatim(report: Report) -> None:
    out = io.StringIO()
    TerminalReporter(console=Console(file=out, width=400, color_system=None)).emit(report)

    text = out.getvalue()
    assert "Server [/x]" in text and "[link=https://evil.example]y[/link]" in text


def test_html_escapes_hostile_text(report: Report, tmp_path: Path) -> None:
    HtmlReporter(output_dir=tmp_path).emit(report)

    html = (tmp_path / "my-check-report.html").read_text()
    assert "<img src=x" not in html and "<script>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_markdown_escapes_hostile_text(report: Report, tmp_path: Path) -> None:
    MarkdownReporter(output_dir=tmp_path).emit(report)

    md = (tmp_path / "my-check-report.md").read_text()
    # Escaped markup (a backslash before "<img") renders as text; only unescaped is live.
    assert not re.search(r"(?<!\\)<(img|script)", md)
    assert "\n# Forged heading" not in md
    assert not re.search(r"(?<!\\)\[link=", md)
    # A "|" from the target must not open a new table column.
    for line in md.splitlines():
        if "onerror" in line and line.startswith("|"):
            assert "Server \\[/x\\] \\<img" in line and " \\| " in line


def test_json_and_sarif_keep_text_as_data(report: Report, tmp_path: Path) -> None:
    JsonReporter(output_dir=tmp_path, sarif=True).emit(report)

    data = json.loads((tmp_path / "my-check-results.json").read_text())
    sarif = json.loads((tmp_path / "my-check-results.sarif").read_text())
    assert HOSTILE in json.dumps(data, ensure_ascii=False) or HOSTILE.replace(
        "\n", "\\n"
    ) in json.dumps(data)
    assert sarif["version"] == "2.1.0"
