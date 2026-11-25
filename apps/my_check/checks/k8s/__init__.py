"""Kubernetes security checks."""

from __future__ import annotations

import logging
import ssl

import urllib3
from my_check.types import K8sContext

logger = logging.getLogger(__name__)

# Connection/read timeout applied to the K8s API client so checks fail fast
# when the cluster is unreachable (e.g. VPN down) instead of hanging for minutes.
_K8S_CONNECT_TIMEOUT = 10  # seconds
_K8S_READ_TIMEOUT = 30  # seconds


def _load_client(ctx: K8sContext):  # noqa: ANN202 – returns client.ApiClient
    """Load a Kubernetes API client from *ctx*, falling back to in-cluster config."""
    from kubernetes import client
    from kubernetes import config as k8s_config

    configuration = client.Configuration()
    try:
        k8s_config.load_kube_config(
            config_file=ctx.kubeconfig_path,
            context=ctx.context_name,
            client_configuration=configuration,
        )
    except Exception as kubeconfig_error:
        logger.warning("Kubeconfig load failed (%s), trying in-cluster config", kubeconfig_error)
        try:
            k8s_config.load_incluster_config(client_configuration=configuration)
        except Exception as incluster_error:
            # Outside a pod the in-cluster error ("Service host/port is not set")
            # hides the real cause: name both.
            raise RuntimeError(
                f"kubeconfig: {kubeconfig_error}; in-cluster config: {incluster_error}"
            ) from incluster_error

    # Set aggressive timeouts so unreachable clusters fail fast
    configuration.retries = urllib3.Retry(total=1, backoff_factor=0)
    api = client.ApiClient(configuration=configuration)
    api.rest_client.pool_manager.connection_pool_kw["timeout"] = urllib3.Timeout(
        connect=_K8S_CONNECT_TIMEOUT, read=_K8S_READ_TIMEOUT
    )
    return api


# OpenSSL verify codes for a certificate no CA of the kubeconfig vouches for:
# UNABLE_TO_GET_ISSUER_CERT, CERT_SIGNATURE_FAILURE, DEPTH_ZERO_SELF_SIGNED_CERT,
# SELF_SIGNED_CERT_IN_CHAIN, UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
# UNABLE_TO_VERIFY_LEAF_SIGNATURE.
_UNTRUSTED_CA_CODES = {2, 7, 18, 19, 20, 21}


def _verification_error(exc: BaseException) -> ssl.SSLCertVerificationError | None:
    """The certificate verification error behind a client error, if any.

    urllib3 wraps it as MaxRetryError(reason=SSLError(SSLCertVerificationError)).
    """
    seen: set[int] = set()
    pending: list[object] = [exc]
    while pending:
        current = pending.pop()
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return current
        pending += [current.__cause__, current.__context__, getattr(current, "reason", None)]
        pending += list(current.args)
    return None


def _explain(exc: Exception) -> str:
    """One line on why the API server could not be reached."""
    verification = _verification_error(exc)
    if verification is None:
        return str(exc)
    if getattr(verification, "verify_code", None) in _UNTRUSTED_CA_CODES:
        return (
            "the cluster's certificate is not signed by the CA in the kubeconfig "
            "(was the cluster recreated? refresh the kubeconfig)"
        )
    reason = getattr(verification, "verify_message", None)
    detail = f": {reason}" if reason else ""
    return f"the cluster's certificate failed verification{detail} (--verbose shows the full error)"


def preflight_check(ctx: K8sContext) -> str | None:
    """Quick connectivity test. Returns an error message or None if reachable.

    A certificate verification failure is explained in one line; the client's own
    error is logged at debug level (``--verbose``).
    """
    from kubernetes import client

    try:
        api = _load_client(ctx)
        v1 = client.VersionApi(api)
        v1.get_code()
        return None
    except Exception as exc:
        logger.debug("Cluster preflight failed: %s", exc)
        return f"Cannot reach cluster: {_explain(exc)}"
