"""Best Practices check via Polaris."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
    run_subprocess,
)


def polaris_command(ctx: K8sContext) -> list[str]:
    """`polaris audit`: without a selection, kubectl's current context, every namespace."""
    cmd = ["polaris", "audit", "--format", "json"]
    if ctx.context_name:
        cmd += ["--context", ctx.context_name]
    if ctx.namespace:
        cmd += ["--namespace", ctx.namespace]
    return cmd


def _checks(data: Any) -> Iterator[dict[str, Any]]:
    """Every check result of a polaris audit, at controller, pod and container level.

    Follows polaris's AuditData types: Results[] → Result{Results, PodResult},
    PodResult{Results, ContainerResults[]} (a list; PodResult is null for
    resources without pods), ContainerResult{Results}. Each Results is a map of
    check id to {Success, Severity, ...}.
    """
    if not isinstance(data, dict):
        return
    result_sets: list[Any] = []
    for resource in data.get("Results") or []:
        if not isinstance(resource, dict):
            continue
        result_sets.append(resource.get("Results"))
        pod = resource.get("PodResult")
        if isinstance(pod, dict):
            result_sets.append(pod.get("Results"))
            result_sets += [
                container.get("Results")
                for container in pod.get("ContainerResults") or []
                if isinstance(container, dict)
            ]
    for result_set in result_sets:
        if isinstance(result_set, dict):
            yield from (check for check in result_set.values() if isinstance(check, dict))


@dataclass(slots=True)
class PolarisCheck:
    id: str = "k8s-polaris"
    name: str = "Best Practices (Polaris)"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")

        try:
            # polaris has no --kubeconfig flag: it reads KUBECONFIG like kubectl.
            result = await run_subprocess(
                polaris_command(target), timeout=120.0, env=target.kubeconfig_env()
            )
        except FileNotFoundError:
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message="polaris not found — install it for best-practice auditing.",
            )

        if result.returncode == -1 and "not found" in result.stderr.lower():
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message="polaris not found — install it for best-practice auditing.",
            )

        if result.returncode != 0:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"polaris exited with code {result.returncode}.",
                details={"stderr": result.stderr[:500]},
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message="Failed to parse Polaris JSON output.",
                details={"raw_stdout": result.stdout[:1000]},
            )

        passing = warning = danger = 0
        for check in _checks(data):
            severity = str(check.get("Severity", "")).lower()
            if check.get("Success"):
                passing += 1
            elif severity == "danger":
                danger += 1
            elif severity == "warning":
                warning += 1
            # "ignore" (or unknown) severities are neither passing nor failing.

        total = passing + warning + danger
        score = int((passing / total) * 100) if total else 100

        summary = {
            "passing": passing,
            "warning": warning,
            "danger": danger,
            "total": total,
        }

        if danger == 0 and warning == 0:
            return CheckResult(
                status=CheckStatus.PASS,
                score=score,
                message=f"All {passing} Polaris check(s) passed.",
                details=summary,
            )

        status = CheckStatus.FAIL if score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=(
                f"Polaris: {passing}/{total} check(s) passing, {danger} danger, {warning} warning."
            ),
            details=summary,
            remediation=(
                "Review Polaris audit results and address danger-level findings first. "
                "Run `polaris audit` locally for detailed per-resource recommendations."
            ),
        )
