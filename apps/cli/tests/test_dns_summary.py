"""The /api/quick/dns result reads the same in the terminal and in the saved report."""

import pytest
from cli.commands.check import _step_hints
from cli.report import _step_detail, dns_addresses, dns_summary


@pytest.mark.parametrize(
    ("data", "summary"),
    [
        ({"resolvable": True, "addresses": ["192.0.2.1"], "http_status": 200}, "HTTP 200"),
        (
            {"resolvable": True, "addresses": ["192.0.2.1"], "http_status": None},
            "resolves, no HTTPS",
        ),
        ({"resolvable": False, "addresses": [], "http_status": None}, "unresolvable"),
        ({}, ""),
    ],
    ids=["answers over HTTPS", "resolves without HTTPS", "does not resolve", "no data"],
)
def test_the_check_command_and_the_report_summarize_dns_alike(data: dict, summary: str) -> None:
    assert dns_summary(data) == summary
    assert _step_detail({"_step": "dns", "data": data}) == summary
    assert _step_hints("dns", {"status": "success", "data": data}).startswith(summary)


def test_addresses_are_joined_or_not_available() -> None:
    assert dns_addresses({"addresses": ["192.0.2.1", "2001:db8::1"]}) == "192.0.2.1, 2001:db8::1"
    assert dns_addresses({"addresses": []}) == "N/A"
    assert dns_addresses({}) == "N/A"
