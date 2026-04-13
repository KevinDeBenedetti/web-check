"""Image Security check."""

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


@dataclass(slots=True)
class ImagesCheck:
    id: str = "k8s-images"
    name: str = "Image Security"
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
        total_images = 0

        for pod in pods:
            containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
            for container in containers:
                image = container.image or ""
                total_images += 1

                # Check for :latest tag
                if image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
                    issues.append(
                        {
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": image,
                            "reason": "uses :latest or untagged image",
                        }
                    )
                # Check for missing SHA digest pin
                elif "@sha256:" not in image:
                    issues.append(
                        {
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": image,
                            "reason": "not pinned by SHA digest (@sha256:...)",
                        }
                    )

        if total_images == 0:
            return CheckResult(
                status=CheckStatus.INFO,
                score=100,
                message="No container images found to evaluate.",
            )

        pinned = total_images - len(issues)
        score = max(0, int((pinned / total_images) * 100))

        if not issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message=f"All {total_images} container image(s) are pinned by digest.",
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=(
                f"{pinned}/{total_images} image(s) properly pinned. "
                f"{len(issues)} image(s) need attention."
            ),
            details=issues,
            remediation=(
                "Pin all container images to a specific SHA digest "
                "(e.g. image@sha256:abc123...) instead of mutable tags. "
                "Never use :latest in production."
            ),
        )
