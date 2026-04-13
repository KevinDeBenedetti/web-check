"""Kubernetes security checks."""

from __future__ import annotations

from my_check.types import K8sContext


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
        k8s_config.load_incluster_config(client_configuration=configuration)
    return client.ApiClient(configuration=configuration)
