"""Network Policies check."""

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

EXCLUDED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})

ADMIN_PATH_PREFIXES = ("/admin", "/dashboard", "/management", "/actuator")


@dataclass(slots=True)
class NetworkPoliciesCheck:
    id: str = "k8s-network-policies"
    name: str = "Network Policies"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")
        api_client = _load_client(target)
        core = client.CoreV1Api(api_client)
        networking = client.NetworkingV1Api(api_client)

        # Gather namespaces to inspect
        if target.namespace:
            namespaces = [target.namespace]
        else:
            ns_list = core.list_namespace()
            namespaces = [
                ns.metadata.name
                for ns in ns_list.items
                if ns.metadata.name not in EXCLUDED_NAMESPACES
            ]

        if not namespaces:
            return CheckResult(
                status=CheckStatus.INFO,
                score=100,
                message="No user namespaces found to evaluate.",
            )

        uncovered: list[str] = []
        no_default_deny: list[str] = []
        no_egress: list[str] = []
        admin_exposure: list[dict[str, str]] = []

        for ns in namespaces:
            policies = networking.list_namespaced_network_policy(ns).items
            if not policies:
                uncovered.append(ns)
                continue

            # Check for default-deny policy (empty podSelector + no ingress/egress rules)
            has_default_deny = False
            has_egress_policy = False
            for pol in policies:
                spec = pol.spec
                if not spec:
                    continue
                # Default deny = empty podSelector with empty ingress/egress
                pod_sel = spec.pod_selector
                is_match_all = not pod_sel or not pod_sel.match_labels
                if is_match_all and spec.policy_types:
                    if "Ingress" in spec.policy_types and not spec.ingress:
                        has_default_deny = True
                    if "Egress" in spec.policy_types and not spec.egress:
                        has_default_deny = True
                if spec.egress is not None:
                    has_egress_policy = True

            if not has_default_deny:
                no_default_deny.append(ns)
            if not has_egress_policy:
                no_egress.append(ns)

        # Check Ingress resources for exposed admin paths
        for ns in namespaces:
            try:
                ingresses = networking.list_namespaced_ingress(ns).items
            except Exception:
                continue
            for ing in ingresses:
                if not ing.spec or not ing.spec.rules:
                    continue
                for rule in ing.spec.rules:
                    if not rule.http or not rule.http.paths:
                        continue
                    for path_entry in rule.http.paths:
                        path = path_entry.path or ""
                        for prefix in ADMIN_PATH_PREFIXES:
                            if path.startswith(prefix):
                                admin_exposure.append(
                                    {
                                        "namespace": ns,
                                        "ingress": ing.metadata.name,
                                        "host": rule.host or "*",
                                        "path": path,
                                    }
                                )

        covered = len(namespaces) - len(uncovered)
        pct = (covered / len(namespaces)) * 100 if namespaces else 100
        score = max(0, min(100, int(pct)))

        # Deductions for missing best practices
        if no_default_deny:
            score = max(0, score - len(no_default_deny) * 3)
        if no_egress:
            score = max(0, score - len(no_egress) * 2)
        if admin_exposure:
            score = max(0, score - len(admin_exposure) * 5)

        issues: dict[str, object] = {}
        if uncovered:
            issues["namespaces_without_policies"] = uncovered
        if no_default_deny:
            issues["namespaces_without_default_deny"] = no_default_deny
        if no_egress:
            issues["namespaces_without_egress_policies"] = no_egress
        if admin_exposure:
            issues["admin_path_exposure"] = admin_exposure

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=score,
                message=f"All {len(namespaces)} namespace(s) have NetworkPolicies configured.",
            )

        messages: list[str] = []
        messages.append(f"{covered}/{len(namespaces)} namespace(s) have NetworkPolicies.")
        if no_default_deny:
            messages.append(f"{len(no_default_deny)} missing default-deny.")
        if no_egress:
            messages.append(f"{len(no_egress)} missing egress policies.")
        if admin_exposure:
            messages.append(f"{len(admin_exposure)} admin-path exposure(s) via Ingress.")

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=" ".join(messages),
            details=issues,
            remediation=(
                "Create default-deny NetworkPolicies for every namespace and "
                "explicitly allow only required traffic. Add egress policies to "
                "control outbound connections. Restrict admin paths in Ingress "
                "resources to internal networks only."
            ),
        )
