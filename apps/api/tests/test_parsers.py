"""Scanner output parsers, against real output captured from the pinned tool versions.

The fixtures in tests/fixtures were recorded by running sqlmap 1.10.11 and XSStrike
(commit 65dd68a, the one the Dockerfile pins) against a local lab server: a page
with a SQL-injectable parameter, a page reflecting a parameter unescaped, and the
same pages escaped and parameterised. Local paths and ports were scrubbed.
"""

from pathlib import Path

import pytest
from api.services.sqlmap_scanner import parse_sqlmap_output, sqlmap_connection_error
from api.services.xsstrike_scanner import parse_xsstrike_output

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    # Bytes, not read_text(): keeps XSStrike's carriage returns as the scanner sees them.
    return (FIXTURES / name).read_bytes().decode("utf-8")


def test_sqlmap_reports_one_finding_per_injectable_parameter() -> None:
    findings = parse_sqlmap_output(_fixture("sqlmap_vulnerable.txt"))

    assert [f.title for f in findings] == ["SQL injection in GET parameter 'id'"]
    finding = findings[0]
    assert finding.severity == "critical"
    for technique in ("boolean-based blind", "error-based", "time-based blind", "UNION query"):
        assert technique in finding.description
    assert "Back-end DBMS: SQLite" in finding.description


def test_sqlmap_clean_run_has_no_finding() -> None:
    # sqlmap logs "all tested parameters do not appear to be injectable" as CRITICAL.
    assert parse_sqlmap_output(_fixture("sqlmap_clean.txt")) == []


def test_sqlmap_reports_each_parameter_of_a_multi_parameter_block() -> None:
    output = "\n".join(
        [
            "sqlmap identified the following injection point(s) with a total of 90 HTTP(s) requests:",
            "---",
            "Parameter: id (GET)",
            "    Type: boolean-based blind",
            "    Title: AND boolean-based blind - WHERE or HAVING clause",
            "    Payload: id=1 AND 1=1",
            "",
            "Parameter: name (POST)",
            "    Type: time-based blind",
            "    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)",
            "    Payload: name=a AND SLEEP(5)",
            "---",
        ]
    )
    assert [f.title for f in parse_sqlmap_output(output)] == [
        "SQL injection in GET parameter 'id'",
        "SQL injection in POST parameter 'name'",
    ]


def test_xsstrike_reports_the_vulnerable_parameter() -> None:
    findings = parse_xsstrike_output(_fixture("xsstrike_vulnerable.txt"))

    assert [f.title for f in findings] == ["Possible XSS in parameter 'q' (/search)"]
    assert findings[0].severity == "high"
    assert "http://127.0.0.1:8080/search" in findings[0].description


@pytest.mark.parametrize("name", ["xsstrike_clean.txt"])
def test_xsstrike_clean_run_has_no_finding(name: str) -> None:
    output = _fixture(name)
    # The banner always contains "XSStrike": that alone must not produce a finding.
    assert "XSStrike" in output
    assert parse_xsstrike_output(output) == []


def test_xsstrike_waf_and_status_messages_are_not_findings() -> None:
    # Messages XSStrike logs outside a vulnerability report (core/log.py prefixes).
    output = "\n".join(
        [
            "\tXSStrike v3.1.5",
            "[--] WAF detected: CloudFlare",
            "[+] WAF Status: Offline",
            "[--] WAF is dropping suspicious requests.",
            "[!] Reflections found: 1",
        ]
    )
    assert parse_xsstrike_output(output) == []


def test_xsstrike_escaped_reflection_is_reported_as_possible_only() -> None:
    # Recorded against an HTML-escaped page: XSStrike's crawl mode still flags it,
    # so the finding says "possible" and asks for manual confirmation.
    findings = parse_xsstrike_output(_fixture("xsstrike_escaped_false_positive.txt"))
    assert len(findings) == 1
    assert "confirm" in findings[0].description.lower()


def test_sqlmap_unreachable_target_is_a_connection_failure() -> None:
    # Captured from sqlmap 1.10.11 against a closed port: it exits 0 all the same.
    error = sqlmap_connection_error(_fixture("sqlmap_unreachable.txt"))
    assert error is not None and "unable to connect to the target URL" in error
    assert "retry" not in error


@pytest.mark.parametrize("name", ["sqlmap_clean.txt", "sqlmap_vulnerable.txt"])
def test_sqlmap_completed_scans_are_not_connection_failures(name: str) -> None:
    assert sqlmap_connection_error(_fixture(name)) is None


def test_sqlmap_connection_timeout_is_a_failure_but_a_retried_one_is_not() -> None:
    retried = (
        "[10:00:00] [CRITICAL] connection timed out to the target URL. "
        "sqlmap is going to retry the request(s)\n"
        "[10:00:05] [WARNING] all tested parameters do not appear to be injectable.\n"
    )
    assert sqlmap_connection_error(retried) is None
    final = "[10:00:00] [CRITICAL] connection timed out to the target URL\n"
    assert sqlmap_connection_error(final) == "connection timed out to the target URL"


@pytest.mark.parametrize(
    "line",
    [
        "[10:00:00] [CRITICAL] connection reset to the target URL",
        "[10:00:00] [CRITICAL] host 'nowhere.invalid' does not exist",
    ],
)
def test_sqlmap_reset_and_unknown_host_are_connection_failures(line: str) -> None:
    assert sqlmap_connection_error(line + "\n") == line.split("[CRITICAL] ")[1]


def test_sqlmap_completed_scan_wins_over_a_later_connection_loss() -> None:
    output = (
        "[10:00:00] [WARNING] all tested parameters do not appear to be injectable.\n"
        "[10:00:09] [CRITICAL] connection timed out to the target URL\n"
    )
    assert sqlmap_connection_error(output) is None
