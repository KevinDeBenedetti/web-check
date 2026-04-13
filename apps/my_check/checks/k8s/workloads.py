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


def _check_container_security(
    container: client.V1Container,
    pod_name: str,
    namespace: str,
) -> list[dict[str, str]]:
    """Return a list of security issues for a single container."""
    issues: list[dict[str, str]] = []
    ctx = container.security_context
    cname = container.name

    prefix = f"{namespace}/{pod_name}/{cname}"

    if ctx:
        if ctx.run_as_user == 0:
            issues.append({"pod": prefix, "reason": "runAsUser is 0 (root)"})
        if ctx.run_as_non_root is False:
            issues.append({"pod": prefix, "reason": "runAsNonRoot is explicitly false"})
        if ctx.privileged is True:
            issues.append({"pod": prefix, "reason": "privileged: true"})
        if ctx.allow_privilege_escalation is True:
            issues.append({"pod": prefix, "reason": "allowPrivilegeEscalation: true"})
        if ctx.read_only_root_filesystem is not True:
            issues.append({"pod": prefix, "reason": "readOnlyRootFilesystem not set to true"})
    else:
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
        assert isinstance(target, K8sContext)
        api_client = _load_client(target)
        core = client.CoreV1Api(api_client)

        if target.namespace:
            pods = core.list_namespaced_pod(target.namespace).items
        else:
            pods = core.list_pod_for_all_namespaces().items

        issues: list[dict[str, str]] = []

        for pod in pods:
            containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
            for container in containers:
                issues.extend(
                    _check_container_security(
                        container,
                        pod.metadata.name,
                        pod.metadata.namespace,
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

        # Deduct 2 points per issue, floor at 0
        score = max(0, 100 - len(issues) * 2)

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
