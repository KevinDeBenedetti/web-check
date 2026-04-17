"""Image Security check."""

from __future__ import annotations

import re
from dataclasses import dataclass

from kubernetes import client
from my_check.checks.k8s import _load_client
from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
)

# Pattern matching a semver-ish tag like v1.2.3, 2.0.0-rc1, etc.
_VERSIONED_TAG_RE = re.compile(r"^v?\d+\.\d+")


def _classify_image(image: str) -> str:
    """Classify an image string into a risk category.

    Returns one of: "pinned", "versioned", "latest_or_untagged".
    """
    if "@sha256:" in image:
        return "pinned"
    # Extract the tag portion after the last colon (ignoring registry port numbers)
    name_part = image.rsplit("/", 1)[-1]
    if ":" not in name_part:
        return "latest_or_untagged"
    tag = name_part.split(":", 1)[1]
    if tag == "latest":
        return "latest_or_untagged"
    if _VERSIONED_TAG_RE.match(tag):
        return "versioned"
    return "latest_or_untagged"


@dataclass(slots=True)
class ImagesCheck:
    id: str = "k8s-images"
    name: str = "Image Security"
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

        critical_issues: list[dict[str, str]] = []
        warning_issues: list[dict[str, str]] = []
        total_images = 0
        pinned = 0
        versioned = 0

        for pod in pods:
            containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
            for container in containers:
                image = container.image or ""
                total_images += 1
                category = _classify_image(image)

                if category == "pinned":
                    pinned += 1
                elif category == "versioned":
                    versioned += 1
                    warning_issues.append(
                        {
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": image,
                            "severity": "low",
                            "reason": "uses versioned tag — consider pinning by SHA digest",
                        }
                    )
                else:
                    critical_issues.append(
                        {
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "image": image,
                            "severity": "high",
                            "reason": "uses :latest or untagged image",
                        }
                    )

        if total_images == 0:
            return CheckResult(
                status=CheckStatus.INFO,
                score=100,
                message="No container images found to evaluate.",
            )

        # Scoring: pinned=full credit, versioned tag=80% credit, latest/untagged=0
        weighted = pinned * 1.0 + versioned * 0.8
        score = max(0, min(100, int((weighted / total_images) * 100)))

        all_issues = critical_issues + warning_issues
        if not all_issues:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message=f"All {total_images} container image(s) are pinned by digest.",
            )

        parts: list[str] = []
        parts.append(f"{pinned}/{total_images} pinned by digest.")
        if versioned:
            parts.append(f"{versioned} use versioned tags.")
        if critical_issues:
            parts.append(f"{len(critical_issues)} use :latest or are untagged.")

        status = CheckStatus.FAIL if critical_issues else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=" ".join(parts),
            details=all_issues,
            remediation=(
                "Pin container images to a SHA digest (image@sha256:...) for "
                "maximum reproducibility. At minimum, use versioned tags "
                "(e.g. :v1.2.3) — never use :latest or untagged images."
            ),
        )
