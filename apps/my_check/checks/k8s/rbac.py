"""RBAC Configuration check."""

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

# System and well-known infrastructure roles that legitimately require wildcard
# verbs — flagging these as issues creates noise without actionable value.
_SYSTEM_ROLE_PREFIXES = (
    "system:",
    "cluster-admin",
    "admin",
    "edit",
    "view",
)

_KNOWN_OPERATOR_SUFFIXES = (
    "-operator",
    "-controller",
    "-manager",
    "-provisioner",
    "-scheduler",
)


def _is_system_role(role_name: str) -> bool:
    """Return True if this role is a known system / operator role."""
    if any(role_name.startswith(p) for p in _SYSTEM_ROLE_PREFIXES):
        return True
    if any(role_name.endswith(s) for s in _KNOWN_OPERATOR_SUFFIXES):
        return True
    return False


@dataclass(slots=True)
class RbacCheck:
    id: str = "k8s-rbac"
    name: str = "RBAC Configuration"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")
        api_client = _load_client(target)
        rbac = client.RbacAuthorizationV1Api(api_client)

        issues: list[dict[str, str]] = []
        score = 100

        # --- wildcard verbs in ClusterRoleBindings ---
        crbs = rbac.list_cluster_role_binding()
        cluster_roles = {cr.metadata.name: cr for cr in rbac.list_cluster_role().items}

        for crb in crbs.items:
            role_name = crb.role_ref.name
            cr = cluster_roles.get(role_name)
            if cr and cr.rules:
                for rule in cr.rules:
                    if rule.verbs and "*" in rule.verbs:
                        if _is_system_role(role_name):
                            # system roles with wildcard are expected — skip
                            continue
                        issues.append(
                            {
                                "type": "wildcard_verbs",
                                "binding": crb.metadata.name,
                                "role": role_name,
                                "remediation": (
                                    f"Replace wildcard verbs in ClusterRole '{role_name}' "
                                    "with explicit verbs (get, list, watch, etc.)."
                                ),
                            }
                        )
                        score = max(0, score - 10)
                        break

        # --- bindings to system:anonymous ---
        for crb in crbs.items:
            if crb.subjects:
                for subj in crb.subjects:
                    if subj.name == "system:anonymous":
                        issues.append(
                            {
                                "type": "anonymous_binding",
                                "binding": crb.metadata.name,
                                "remediation": (
                                    f"Remove ClusterRoleBinding '{crb.metadata.name}' that grants "
                                    "access to system:anonymous."
                                ),
                            }
                        )
                        score = max(0, score - 20)

        # --- namespace-scoped RoleBindings with wildcard verbs ---
        ns_filter = target.namespace
        if ns_filter:
            role_bindings = rbac.list_namespaced_role_binding(ns_filter).items
        else:
            role_bindings = rbac.list_role_binding_for_all_namespaces().items

        for rb in role_bindings:
            role_ref = rb.role_ref
            role_name = role_ref.name
            if _is_system_role(role_name):
                continue
            ns = rb.metadata.namespace or ""
            try:
                if role_ref.kind == "ClusterRole":
                    role_obj = cluster_roles.get(role_name)
                else:
                    role_obj = rbac.read_namespaced_role(role_name, ns)
            except Exception:
                continue
            if role_obj and role_obj.rules:
                for rule in role_obj.rules:
                    if rule.verbs and "*" in rule.verbs:
                        issues.append(
                            {
                                "type": "wildcard_verbs_ns",
                                "namespace": ns,
                                "binding": rb.metadata.name,
                                "role": role_name,
                                "remediation": (
                                    f"Replace wildcard verbs in Role '{role_name}' (ns: {ns}) "
                                    "with explicit verbs (get, list, watch, etc.)."
                                ),
                            }
                        )
                        score = max(0, score - 10)
                        break

        # --- ServiceAccounts with automountServiceAccountToken ---
        core = client.CoreV1Api(api_client)
        ns_filter = target.namespace
        if ns_filter:
            service_accounts = core.list_namespaced_service_account(ns_filter).items
        else:
            service_accounts = core.list_service_account_for_all_namespaces().items

        for sa in service_accounts:
            if sa.automount_service_account_token is True:
                if sa.metadata.name == "default":
                    issues.append(
                        {
                            "type": "automount_token",
                            "namespace": sa.metadata.namespace,
                            "service_account": sa.metadata.name,
                            "remediation": (
                                f"Set automountServiceAccountToken: false on the 'default' "
                                f"ServiceAccount in namespace '{sa.metadata.namespace}'."
                            ),
                        }
                    )
                    score = max(0, score - 5)

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="RBAC configuration looks good — no common misconfigurations found.",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"Found {len(issues)} RBAC issue(s).",
            details=issues,
            remediation="Review each issue listed in details and apply the suggested remediations.",
        )
