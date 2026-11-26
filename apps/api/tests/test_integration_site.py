"""The site the scanner integration test serves stays inside the offline suite.

Runs by default, unlike test_scanners_integration.py (marked ``integration``): the
offline guard of ../../../conftest.py fails a test whose site looks this machine
up by name, which the five-minute integration run would otherwise catch last.
"""

import urllib.request

from api.tests.test_scanners_integration import container_http_port  # noqa: F401 (fixture)


def test_the_site_for_the_containers_starts_without_a_host_lookup(
    container_http_port: int,  # noqa: F811 (the imported fixture)
) -> None:
    with urllib.request.urlopen(f"http://127.0.0.1:{container_http_port}/", timeout=5) as page:
        assert page.status == 200
        assert b"web-check integration target" in page.read()
