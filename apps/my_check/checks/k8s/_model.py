"""Safe reads of Kubernetes client models.

`metadata`, `spec` and `status` are optional on every model the client returns
(an object fetched with a field selector, or a partial watch event, can lack
them): reading `pod.metadata.name` directly crashes the check on such an object.
"""

from __future__ import annotations

from typing import Any


def name_of(obj: Any) -> str:
    """`metadata.name`, or "" when the object has no metadata."""
    metadata = getattr(obj, "metadata", None)
    return (metadata.name if metadata is not None else None) or ""


def namespace_of(obj: Any) -> str:
    """`metadata.namespace`, or "" for cluster-scoped objects and missing metadata."""
    metadata = getattr(obj, "metadata", None)
    return (metadata.namespace if metadata is not None else None) or ""


def labels_of(obj: Any) -> dict[str, str]:
    """`metadata.labels`, or an empty mapping."""
    metadata = getattr(obj, "metadata", None)
    return (metadata.labels if metadata is not None else None) or {}


def containers_of(pod: Any, *, init: bool = True, ephemeral: bool = False) -> list[Any]:
    """The pod's containers (and init / ephemeral containers), or [] without a spec."""
    spec = getattr(pod, "spec", None)
    if spec is None:
        return []
    containers = list(spec.containers or [])
    if init:
        containers += spec.init_containers or []
    if ephemeral:
        containers += spec.ephemeral_containers or []
    return containers


# Pods my-check itself starts in the cluster (the kube-bench Job) carry this label:
# the checks running alongside skip them, so my-check does not audit its own pod.
MANAGED_BY_LABEL = ("app.kubernetes.io/managed-by", "my-check")


def list_pods(core: Any, namespace: str | None) -> list[Any]:
    """The pods of *namespace* (every namespace when None), my-check's own pods excluded."""
    if namespace:
        pods = core.list_namespaced_pod(namespace).items
    else:
        pods = core.list_pod_for_all_namespaces().items
    key, value = MANAGED_BY_LABEL
    return [pod for pod in pods if labels_of(pod).get(key) != value]
