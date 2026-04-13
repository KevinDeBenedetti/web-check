"""Secrets Management check."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from kubernetes import client
from my_check.checks.k8s import _load_client
from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
)

log = logging.getLogger(__name__)


def _has_sealed_or_external_secrets(api_client: client.ApiClient) -> bool:
    """Return *True* if SealedSecret or ExternalSecret CRDs are installed."""
    ext = client.ApiextensionsV1Api(api_client)
    try:
        crds = ext.list_custom_resource_definition().items
    except Exception:
        return False

    known_crds = {"sealedsecrets.bitnami.com", "externalsecrets.external-secrets.io"}
    for crd in crds:
        if crd.spec.group in known_crds:
            return True
    return False


@dataclass(slots=True)
class SecretsCheck:
    id: str = "k8s-secrets"
    name: str = "Secrets Management"
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
            ns = pod.metadata.namespace
            pod_name = pod.metadata.name
            containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])

            for container in containers:
                if not container.env:
                    continue
                for env_var in container.env:
                    # Flag env vars that embed secret values directly (value set,
                    # no valueFrom, but name looks secret-ish)
                    if env_var.value and not env_var.value_from:
                        name_lower = env_var.name.lower()
                        if any(
                            kw in name_lower
                            for kw in ("secret", "password", "token", "api_key", "apikey")
                        ):
                            issues.append(
                                {
                                    "type": "plain_env_secret",
                                    "namespace": ns,
                                    "pod": pod_name,
                                    "container": container.name,
                                    "env_var": env_var.name,
                                }
                            )

        has_external = _has_sealed_or_external_secrets(api_client)

        score = 100
        score = max(0, score - len(issues) * 5)
        if has_external:
            score = min(100, score + 10)  # bonus for using external secret management

        details: dict[str, object] = {"issues": issues, "external_secret_crds": has_external}

        if not issues:
            msg = "No secrets management issues found."
            if has_external:
                msg += " SealedSecret/ExternalSecret CRDs detected — good practice."
            return CheckResult(status=CheckStatus.PASS, score=min(100, score), message=msg)

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=f"Found {len(issues)} secrets management issue(s).",
            details=details,
            remediation=(
                "Avoid injecting secrets as plain environment variables. "
                "Use volume-mounted secrets or an external secrets operator "
                "(e.g. SealedSecrets, External Secrets Operator) instead."
            ),
        )
