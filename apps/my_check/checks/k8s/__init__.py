"""Kubernetes security checks."""

from __future__ import annotations

import logging

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
    except Exception:
        logger.warning("Kubeconfig load failed, trying in-cluster config")
        k8s_config.load_incluster_config(client_configuration=configuration)

    # Set aggressive timeouts so unreachable clusters fail fast
    configuration.retries = urllib3.Retry(total=1, backoff_factor=0)
    api = client.ApiClient(configuration=configuration)
    api.rest_client.pool_manager.connection_pool_kw["timeout"] = urllib3.Timeout(
        connect=_K8S_CONNECT_TIMEOUT, read=_K8S_READ_TIMEOUT
    )
    return api


def preflight_check(ctx: K8sContext) -> str | None:
    """Quick connectivity test. Returns an error message or None if reachable."""
    from kubernetes import client

    try:
        api = _load_client(ctx)
        v1 = client.VersionApi(api)
        v1.get_code()
        return None
    except Exception as exc:
        return f"Cannot reach cluster: {exc}"
