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
        assert isinstance(target, K8sContext)
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
        admin_exposure: list[dict[str, str]] = []

        for ns in namespaces:
            policies = networking.list_namespaced_network_policy(ns).items
            if not policies:
                uncovered.append(ns)
                continue

            # Check ingress rules exposing admin paths
            for pol in policies:
                if not pol.spec or not pol.spec.ingress:
                    continue
                for _ingress_rule in pol.spec.ingress:
                    # NetworkPolicy doesn't natively have path rules, but
                    # annotations or labels may hint at it. We inspect metadata
                    # annotations for common ingress-path patterns.
                    annotations = pol.metadata.annotations or {}
                    for key, value in annotations.items():
                        if "path" in key.lower():
                            for prefix in ADMIN_PATH_PREFIXES:
                                if prefix in value:
                                    admin_exposure.append(
                                        {
                                            "namespace": ns,
                                            "policy": pol.metadata.name,
                                            "annotation": f"{key}={value}",
                                        }
                                    )

        covered = len(namespaces) - len(uncovered)
        pct = (covered / len(namespaces)) * 100 if namespaces else 100
        score = max(0, min(100, int(pct)))

        # Additional deduction for admin exposure
        score = max(0, score - len(admin_exposure) * 5)

        issues: dict[str, object] = {}
        if uncovered:
            issues["namespaces_without_policies"] = uncovered
        if admin_exposure:
            issues["admin_path_exposure"] = admin_exposure

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=score,
                message=f"All {len(namespaces)} namespace(s) have NetworkPolicies configured.",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=(
                f"{covered}/{len(namespaces)} namespace(s) have NetworkPolicies. "
                f"{len(admin_exposure)} admin-path exposure(s) detected."
            ),
            details=issues,
            remediation=(
                "Create default-deny NetworkPolicies for every namespace and "
                "explicitly allow only required traffic. Restrict admin paths to "
                "internal networks only."
            ),
        )
