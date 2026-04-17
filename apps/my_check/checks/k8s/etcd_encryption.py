"""ETCD encryption at rest check.

Verifies that the Kubernetes API server is configured with encryption
at rest for secrets. This check inspects:
- The kube-apiserver pod for --encryption-provider-config flag
- Secrets in the kube-system namespace for expected encryption providers
- EncryptionConfiguration resources if accessible
"""

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

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EtcdEncryptionCheck:
    id: str = "k8s-etcd-encryption"
    name: str = "ETCD Encryption at Rest"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")
        api_client = _load_client(target)
        core = client.CoreV1Api(api_client)

        findings: list[dict[str, str]] = []
        encryption_configured = False

        # Strategy 1: Check kube-apiserver pod for --encryption-provider-config
        try:
            api_server_pods = core.list_namespaced_pod(
                "kube-system",
                label_selector="component=kube-apiserver",
            ).items
            if not api_server_pods:
                # Try alternative label used by some distributions
                api_server_pods = core.list_namespaced_pod(
                    "kube-system",
                    label_selector="k8s-app=kube-apiserver",
                ).items

            for pod in api_server_pods:
                for container in pod.spec.containers or []:
                    args = container.command or []
                    args.extend(container.args or [])
                    for arg in args:
                        if "--encryption-provider-config" in arg:
                            encryption_configured = True
                            findings.append(
                                {
                                    "type": "encryption_flag_found",
                                    "pod": pod.metadata.name,
                                    "detail": "kube-apiserver has --encryption-provider-config set.",
                                }
                            )
                            break
        except client.ApiException as e:
            if e.status == 403:
                findings.append(
                    {
                        "type": "access_denied",
                        "detail": "Cannot read kube-system pods — insufficient permissions.",
                    }
                )
            else:
                logger.warning("Failed to list kube-apiserver pods: %s", e)
        except Exception:
            logger.warning("Unexpected error checking kube-apiserver pods", exc_info=True)

        # Strategy 2: Detect k3s/k3s-like distributions where apiserver runs as
        # a host process (not a pod).  k3s enables secrets encryption via
        # --secrets-encryption flag or /var/lib/rancher/k3s/server/cred/encryption-config.json.
        if not encryption_configured:
            is_k3s = False
            try:
                nodes = core.list_node().items
                for node in nodes:
                    version_info = node.status.node_info if node.status else None
                    if version_info and "k3s" in (version_info.kubelet_version or "").lower():
                        is_k3s = True
                        break
            except Exception:
                pass

            if is_k3s:
                findings.append(
                    {
                        "type": "k3s_detected",
                        "detail": (
                            "k3s detected — apiserver runs as a host process. "
                            "Cannot inspect flags remotely. Verify secrets encryption with: "
                            "k3s secrets-encrypt status"
                        ),
                    }
                )
                # k3s doesn't expose apiserver pods, so we can't confirm or deny.
                return CheckResult(
                    status=CheckStatus.INFO,
                    score=0,
                    message=(
                        "k3s detected — cannot verify encryption remotely. "
                        "Run 'k3s secrets-encrypt status' on the server node."
                    ),
                    details=findings,
                    remediation=(
                        "On the k3s server node, run: k3s secrets-encrypt status\n"
                        "To enable: k3s server --secrets-encryption\n"
                        "See: https://docs.k3s.io/security/secrets-encryption"
                    ),
                )

        # Strategy 3: Try to read the encryption config secret if it exists
        if not encryption_configured:
            try:
                secrets = core.list_namespaced_secret("kube-system").items
                for secret in secrets:
                    name = secret.metadata.name or ""
                    if "encryption" in name.lower() and "config" in name.lower():
                        encryption_configured = True
                        findings.append(
                            {
                                "type": "encryption_secret_found",
                                "secret": name,
                                "detail": f"Found encryption config secret '{name}' in kube-system.",
                            }
                        )
                        break
            except client.ApiException as e:
                if e.status == 403:
                    findings.append(
                        {
                            "type": "access_denied",
                            "detail": "Cannot list kube-system secrets — insufficient permissions.",
                        }
                    )
                else:
                    logger.warning("Failed to list kube-system secrets: %s", e)
            except Exception:
                logger.warning("Unexpected error checking kube-system secrets", exc_info=True)

        # If we couldn't determine either way due to access issues
        access_issues = [f for f in findings if f["type"] == "access_denied"]
        if access_issues and not encryption_configured:
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message=(
                    "Cannot determine ETCD encryption status — "
                    "insufficient permissions to inspect kube-system resources."
                ),
                details=findings,
                remediation=(
                    "Grant the scanning ServiceAccount read access to kube-system "
                    "pods and secrets, or verify encryption at rest manually with: "
                    "kubectl get pods -n kube-system kube-apiserver-* -o yaml | "
                    "grep encryption-provider-config"
                ),
            )

        if encryption_configured:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="ETCD encryption at rest is configured.",
                details=findings,
            )

        return CheckResult(
            status=CheckStatus.WARN,
            score=30,
            message="ETCD encryption at rest not detected.",
            details=findings
            or [
                {
                    "type": "not_found",
                    "detail": "No encryption configuration found on kube-apiserver.",
                }
            ],
            remediation=(
                "Enable encryption at rest for Kubernetes secrets by creating an "
                "EncryptionConfiguration and passing --encryption-provider-config "
                "to the kube-apiserver. See: "
                "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"
            ),
        )
