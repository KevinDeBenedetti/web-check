"""Runtime Security check — Falco DaemonSet presence."""

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

FALCO_LABELS = ("app.kubernetes.io/name=falco", "app=falco")


@dataclass(slots=True)
class FalcoCheck:
    id: str = "k8s-falco"
    name: str = "Runtime Security (Falco)"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, K8sContext)
        api_client = _load_client(target)
        apps = client.AppsV1Api(api_client)

        # Search for Falco DaemonSet across all namespaces
        daemon_sets = apps.list_daemon_set_for_all_namespaces().items

        falco_ds = None
        for ds in daemon_sets:
            name = (ds.metadata.name or "").lower()
            labels = ds.metadata.labels or {}
            if "falco" in name or labels.get("app.kubernetes.io/name") == "falco":
                falco_ds = ds
                break

        if falco_ds is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message="Falco DaemonSet not found — no runtime security monitoring detected.",
                remediation=(
                    "Install Falco for runtime threat detection: "
                    "https://falco.org/docs/getting-started/"
                ),
            )

        # Check health: all desired pods should be ready
        status_obj = falco_ds.status
        desired = status_obj.desired_number_scheduled or 0
        ready = status_obj.number_ready or 0

        details = {
            "daemonset": falco_ds.metadata.name,
            "namespace": falco_ds.metadata.namespace,
            "desired": desired,
            "ready": ready,
        }

        if desired == 0:
            return CheckResult(
                status=CheckStatus.WARN,
                score=50,
                message="Falco DaemonSet exists but has 0 desired pods.",
                details=details,
                remediation="Verify Falco DaemonSet scheduling and node selectors.",
            )

        if ready < desired:
            return CheckResult(
                status=CheckStatus.WARN,
                score=int((ready / desired) * 100),
                message=f"Falco: {ready}/{desired} pod(s) ready.",
                details=details,
                remediation="Investigate unhealthy Falco pods with `kubectl describe pod`.",
            )

        return CheckResult(
            status=CheckStatus.PASS,
            score=100,
            message=f"Falco runtime security active — {ready}/{desired} pod(s) ready.",
            details=details,
        )
