"""The site the scanner integration test serves stays inside the offline suite.

Runs by default, unlike test_scanners_integration.py (marked ``integration``): the
offline guard of ../../../conftest.py fails a test whose site looks this machine
up by name, which the five-minute integration run would otherwise catch last. It also checks
how that run treats a missing scanner: skipped on a laptop, failed in CI.
"""

import subprocess
import urllib.request
from collections.abc import Callable

import pytest
from api.tests import test_scanners_integration as integration
from api.tests.test_scanners_integration import container_http_port  # noqa: F401 (fixture)


def test_the_site_for_the_containers_starts_without_a_host_lookup(
    container_http_port: int,  # noqa: F811 (the imported fixture)
) -> None:
    with urllib.request.urlopen(f"http://127.0.0.1:{container_http_port}/", timeout=5) as page:
        assert page.status == 200
        assert b"web-check integration target" in page.read()


def _absent_container(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="No such object")


_EACH_SCANNER_CHECK = pytest.mark.parametrize(
    "check",
    [
        lambda: integration._needs_executable("web-check-no-such-tool"),
        lambda: integration._needs_container("web-check-no-such-container"),
    ],
    ids=["executable", "container"],
)


@_EACH_SCANNER_CHECK
def test_a_missing_scanner_skips_by_default(
    check: Callable[[], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(integration.REQUIRED_ENV, raising=False)
    monkeypatch.setattr(integration.subprocess, "run", _absent_container)
    with pytest.raises(pytest.skip.Exception):
        check()


@_EACH_SCANNER_CHECK
def test_a_missing_scanner_fails_when_ci_requires_every_scanner(
    check: Callable[[], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(integration.REQUIRED_ENV, "1")
    monkeypatch.setattr(integration.subprocess, "run", _absent_container)
    with pytest.raises(pytest.fail.Exception, match="not installed|not running"):
        check()
