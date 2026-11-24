"""XSStrike findings stay high only when the reported vector comes back unescaped."""

import html
from pathlib import Path

import httpx
from api.services.xsstrike_scanner import confirm_xss_reports, parse_xsstrike_reports

FIXTURES = Path(__file__).parent / "fixtures"


def _reports(name: str):
    return parse_xsstrike_reports((FIXTURES / name).read_text())


def _client(render) -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return render(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), requests


def _page(value: str) -> httpx.Response:
    return httpx.Response(200, html=f"<html><body>Results for {value}</body></html>")


def test_reports_carry_the_page_parameter_and_payload_as_sent() -> None:
    [report] = _reports("xsstrike_vulnerable.txt")

    assert report.page == "http://127.0.0.1:8080/search"
    assert report.parameter == "q"
    # XSStrike passes the vector to requests' params=, which encodes it: the page
    # receives the printed vector verbatim, %0a and + included.
    assert report.payload == "<D3V/+/OnmoUSEOvER%0a=%0aa=prompt,a()%0dx>v3dm0s"


async def test_an_unescaped_reflection_stays_high() -> None:
    client, requests = _client(lambda request: _page(request.url.params["q"]))
    [report] = _reports("xsstrike_vulnerable.txt")

    async with client:
        [finding] = await confirm_xss_reports([report], client)

    assert requests[0].url.params["q"] == report.payload
    assert requests[0].url.path == "/search"
    assert finding.severity == "high"
    assert finding.title == "XSS in parameter 'q' (/search)"


async def test_an_escaped_reflection_is_lowered_to_info() -> None:
    client, _ = _client(lambda request: _page(html.escape(request.url.params["q"])))

    async with client:
        [finding] = await confirm_xss_reports(
            _reports("xsstrike_escaped_false_positive.txt"), client
        )

    assert finding.severity == "info"
    assert "escaped" in finding.description


async def test_a_page_that_cannot_be_requested_is_lowered_to_info() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client, _ = _client(refuse)

    async with client:
        [finding] = await confirm_xss_reports(_reports("xsstrike_vulnerable.txt"), client)

    assert finding.severity == "info"
    assert "could not be checked" in finding.description
