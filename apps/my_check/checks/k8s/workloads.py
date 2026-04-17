"""Workload Security check."""

from __future__ import annotations

from dataclasses import dataclass

from kubernetes import client
from my_check.checks.k8s import _load_client
from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
)

# Pods matching these labels are expected to run privileged (kernel-level security
# agents, CNI plugins, storage drivers, etc.) — flagging them creates noise.
_PRIVILEGED_ALLOWED_LABELS: dict[str, set[str]] = {
    "app.kubernetes.io/name": {
        "falco",
        "cilium-agent",
        "calico-node",
        "kube-proxy",
        "node-exporter",
        "csi-node-driver",
    },
}

# System namespaces where workloads are managed by the distro, not the user.
_SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})


def _is_privileged_expected(pod: client.V1Pod) -> bool:
    """Return True if this pod is expected to run with elevated privileges."""
    labels = pod.metadata.labels or {}
    for label_key, allowed_values in _PRIVILEGED_ALLOWED_LABELS.items():
        if labels.get(label_key, "") in allowed_values:
            return True
    ns = pod.metadata.namespace or ""
    if ns in _SYSTEM_NAMESPACES:
        return True
    return False


def _check_container_security(
    container: client.V1Container,
    pod_name: str,
    namespace: str,
    *,
    privileged_expected: bool = False,
) -> list[dict[str, str]]:
    """Return a list of security issues for a single container."""
    issues: list[dict[str, str]] = []
    ctx = container.security_context
    cname = container.name

    prefix = f"{namespace}/{pod_name}/{cname}"

    if ctx:
        if ctx.run_as_user == 0 and not privileged_expected:
            issues.append({"pod": prefix, "reason": "runAsUser is 0 (root)"})
        if ctx.run_as_non_root is False and not privileged_expected:
            issues.append({"pod": prefix, "reason": "runAsNonRoot is explicitly false"})
        if ctx.privileged is True and not privileged_expected:
            issues.append({"pod": prefix, "reason": "privileged: true"})
        if ctx.allow_privilege_escalation is True and not privileged_expected:
            issues.append({"pod": prefix, "reason": "allowPrivilegeEscalation: true"})
        if ctx.read_only_root_filesystem is not True and not privileged_expected:
            issues.append({"pod": prefix, "reason": "readOnlyRootFilesystem not set to true"})
    elif not privileged_expected:
        issues.append({"pod": prefix, "reason": "no securityContext defined"})

    resources = container.resources
    if not resources or not resources.limits:
        issues.append({"pod": prefix, "reason": "missing resource limits"})
    if not resources or not resources.requests:
        issues.append({"pod": prefix, "reason": "missing resource requests"})

    return issues


@dataclass(slots=True)
class WorkloadsCheck:
    id: str = "k8s-workloads"
    name: str = "Workload Security"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")
        api_client = _load_client(target)
        core = client.CoreV1Api(api_client)

        if target.namespace:
            pods = core.list_namespaced_pod(target.namespace).items
        else:
            pods = core.list_pod_for_all_namespaces().items

        issues: list[dict[str, str]] = []

        for pod in pods:
            priv_ok = _is_privileged_expected(pod)
            containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
            for container in containers:
                issues.extend(
                    _check_container_security(
                        container,
                        pod.metadata.name,
                        pod.metadata.namespace,
                        privileged_expected=priv_ok,
                    )
                )

        total_containers = sum(
            len(p.spec.containers or []) + len(p.spec.init_containers or []) for p in pods
        )
        if total_containers == 0:
            return CheckResult(
                status=CheckStatus.INFO,
                score=100,
                message="No pods found to evaluate.",
            )

        # Score based on the ratio of clean containers to total containers.
        # Each container can have multiple issue types (security context, limits,
        # requests, etc.) — we count containers with at least one issue.
        containers_with_issues = len({issue["pod"] for issue in issues})
        clean_ratio = max(0, total_containers - containers_with_issues) / total_containers
        score = max(0, min(100, int(clean_ratio * 100)))

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="All workloads follow security best practices.",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"Found {len(issues)} workload security issue(s) across {len(pods)} pod(s).",
            details=issues,
            remediation=(
                "Apply pod security contexts: set runAsNonRoot: true, "
                "readOnlyRootFilesystem: true, drop ALL capabilities, "
                "and define resource limits/requests for every container."
            ),
        )
