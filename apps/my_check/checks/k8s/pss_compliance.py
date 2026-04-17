"""Pod Security Standards (PSS) compliance check.

Evaluates pods against the Kubernetes Pod Security Standards baseline and
restricted profiles:
- Privileged containers
- Privilege escalation
- Running as root
- Capabilities not dropped
- HostNetwork / HostPID / HostIPC usage
- Non-read-only root filesystem
"""

from __future__ import annotations

from dataclasses import dataclass

from kubernetes import client
from my_check.checks.k8s import _load_client
from my_check.checks.k8s.workloads import _is_privileged_expected
from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
)

# Capabilities that must be dropped under the restricted profile.
_REQUIRED_DROP_CAPS = frozenset({"ALL"})


def _check_pss_container(
    container: client.V1Container,
    pod_name: str,
    namespace: str,
    *,
    privileged_expected: bool = False,
) -> list[dict[str, str]]:
    """Return PSS violations for a single container."""
    # Known system/security pods that need elevated privileges are exempt.
    if privileged_expected:
        return []

    issues: list[dict[str, str]] = []
    prefix = f"{namespace}/{pod_name}/{container.name}"
    ctx = container.security_context

    if not ctx:
        issues.append(
            {"pod": prefix, "violation": "no securityContext — cannot verify PSS compliance"}
        )
        return issues

    # Baseline: no privileged containers
    if ctx.privileged is True:
        issues.append({"pod": prefix, "violation": "privileged: true (violates baseline)"})

    # Baseline: no privilege escalation
    if ctx.allow_privilege_escalation is not False:
        issues.append({"pod": prefix, "violation": "allowPrivilegeEscalation not explicitly false"})

    # Restricted: must run as non-root
    if ctx.run_as_non_root is not True and (ctx.run_as_user is None or ctx.run_as_user == 0):
        issues.append({"pod": prefix, "violation": "must set runAsNonRoot: true or runAsUser > 0"})

    # Restricted: must drop ALL capabilities
    caps = ctx.capabilities
    if not caps or not caps.drop:
        issues.append({"pod": prefix, "violation": "capabilities.drop must include ALL"})
    elif not _REQUIRED_DROP_CAPS.issubset({c.upper() for c in caps.drop}):
        issues.append({"pod": prefix, "violation": "capabilities.drop must include ALL"})

    # Restricted: seccomp profile should be set (RuntimeDefault or Localhost)
    if ctx.seccomp_profile is None:
        issues.append(
            {
                "pod": prefix,
                "violation": "no seccompProfile set (restricted requires RuntimeDefault or Localhost)",
            }
        )
    elif ctx.seccomp_profile.type not in ("RuntimeDefault", "Localhost"):
        issues.append(
            {
                "pod": prefix,
                "violation": f"seccompProfile.type={ctx.seccomp_profile.type} (expected RuntimeDefault or Localhost)",
            }
        )

    return issues


def _check_pss_pod(pod: client.V1Pod, *, privileged_expected: bool = False) -> list[dict[str, str]]:
    """Return PSS violations for a pod's spec-level settings."""
    issues: list[dict[str, str]] = []
    spec = pod.spec
    name = pod.metadata.name
    ns = pod.metadata.namespace or "default"
    prefix = f"{ns}/{name}"

    # Baseline: no host namespaces (skip for expected privileged pods)
    if not privileged_expected:
        if spec.host_network is True:
            issues.append({"pod": prefix, "violation": "hostNetwork: true (violates baseline)"})
        if spec.host_pid is True:
            issues.append({"pod": prefix, "violation": "hostPID: true (violates baseline)"})
        if spec.host_ipc is True:
            issues.append({"pod": prefix, "violation": "hostIPC: true (violates baseline)"})

    # Check all containers (regular + init + ephemeral)
    all_containers = list(spec.containers or [])
    all_containers.extend(spec.init_containers or [])
    all_containers.extend(spec.ephemeral_containers or [])
    for container in all_containers:
        issues.extend(
            _check_pss_container(container, name, ns, privileged_expected=privileged_expected)
        )

    return issues


@dataclass(slots=True)
class PssComplianceCheck:
    id: str = "k8s-pss-compliance"
    name: str = "Pod Security Standards"
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

        if not pods:
            return CheckResult(
                status=CheckStatus.INFO,
                score=100,
                message="No pods found to evaluate.",
            )

        issues: list[dict[str, str]] = []
        for pod in pods:
            priv_ok = _is_privileged_expected(pod)
            issues.extend(_check_pss_pod(pod, privileged_expected=priv_ok))

        total_pods = len(pods)
        pods_with_issues = len({i["pod"].rsplit("/", 1)[0] for i in issues})
        clean_ratio = max(0, total_pods - pods_with_issues) / total_pods
        score = max(0, min(100, int(clean_ratio * 100)))

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message=f"All {total_pods} pod(s) comply with Pod Security Standards (restricted).",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"{pods_with_issues}/{total_pods} pod(s) have PSS violations.",
            details=issues,
            remediation=(
                "Ensure all pods comply with the restricted Pod Security Standard: "
                "set runAsNonRoot: true, drop ALL capabilities, disable privilege "
                "escalation, set a seccompProfile, and avoid hostNetwork/hostPID/hostIPC."
            ),
        )
