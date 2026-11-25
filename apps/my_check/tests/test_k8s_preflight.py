"""The connectivity preflight says why the cluster cannot be reached."""

import logging
import ssl
from typing import Any

import pytest
import urllib3
from kubernetes import client
from my_check.checks import k8s
from my_check.checks.k8s import preflight_check
from my_check.types import K8sContext

_URL = "/version/"


def _pool_error(reason: Exception) -> urllib3.exceptions.MaxRetryError:
    """What the Kubernetes client raises once urllib3 has given up on the API server."""
    pool = urllib3.HTTPSConnectionPool(host="127.0.0.1", port=6443)
    return urllib3.exceptions.MaxRetryError(pool, _URL, reason)


def _verification_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    """As the ssl module raises it: the OpenSSL verify code and message set."""
    error = ssl.SSLCertVerificationError(
        1, f"[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message} (_ssl.c:1010)"
    )
    error.verify_code = code
    error.verify_message = message
    return error


def _fail_with(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def get_code(self: Any) -> None:
        raise error

    monkeypatch.setattr(k8s, "_load_client", lambda ctx: None)
    monkeypatch.setattr(client.VersionApi, "get_code", get_code)


def test_a_ca_mismatch_is_explained_and_the_raw_error_kept_for_verbose(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    verification = _verification_error(19, "self-signed certificate in certificate chain")
    _fail_with(monkeypatch, _pool_error(urllib3.exceptions.SSLError(verification)))

    with caplog.at_level(logging.DEBUG, logger="my_check.checks.k8s"):
        message = preflight_check(K8sContext())

    assert message == (
        "Cannot reach cluster: the cluster's certificate is not signed by the CA in the "
        "kubeconfig (was the cluster recreated? refresh the kubeconfig)"
    )
    assert "CERTIFICATE_VERIFY_FAILED" in caplog.text
    assert "HTTPSConnectionPool" in caplog.text


def test_another_verification_failure_names_its_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    verification = _verification_error(10, "certificate has expired")
    _fail_with(monkeypatch, _pool_error(urllib3.exceptions.SSLError(verification)))

    assert preflight_check(K8sContext()) == (
        "Cannot reach cluster: the cluster's certificate failed verification: "
        "certificate has expired (--verbose shows the full error)"
    )


@pytest.mark.parametrize(
    "reason",
    [
        urllib3.exceptions.NewConnectionError(
            None,  # ty: ignore[invalid-argument-type]
            "Failed to establish a new connection: [Errno 61] Connection refused",
        ),
        urllib3.exceptions.ConnectTimeoutError(None, _URL, "Connection to 127.0.0.1 timed out"),
    ],
    ids=["connection refused", "timeout"],
)
def test_other_failures_keep_the_client_error(
    monkeypatch: pytest.MonkeyPatch, reason: Exception
) -> None:
    error = _pool_error(reason)
    _fail_with(monkeypatch, error)

    assert preflight_check(K8sContext()) == f"Cannot reach cluster: {error}"


def test_a_reachable_cluster_has_no_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(k8s, "_load_client", lambda ctx: None)
    monkeypatch.setattr(client.VersionApi, "get_code", lambda self: None)

    assert preflight_check(K8sContext()) is None
