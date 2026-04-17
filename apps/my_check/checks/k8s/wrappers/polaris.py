"""Best Practices check via Polaris."""

from __future__ import annotations

import json
from dataclasses import dataclass

from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
    run_subprocess,
)


@dataclass(slots=True)
class PolarisCheck:
    id: str = "k8s-polaris"
    name: str = "Best Practices (Polaris)"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")

        try:
            result = await run_subprocess(
                ["polaris", "audit", "--format", "json"],
                timeout=120.0,
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

        # Polaris audit JSON has a top-level "Results" array
        passing = 0
        warning = 0
        danger = 0

        audit_results = data.get("Results", data.get("results", []))
        for resource in audit_results:
            pod_result = resource.get("PodResult", resource.get("podResult", {}))
            container_results = {
                **pod_result.get("ContainerResults", pod_result.get("containerResults", {})),
            }
            # Also check initContainerResults
            container_results.update(
                pod_result.get(
                    "InitContainerResults",
                    pod_result.get("initContainerResults", {}),
                )
            )
            for _cname, checks in container_results.items():
                if not isinstance(checks, dict):
                    continue
                results_map = checks.get("Results", checks.get("results", {}))
                if not isinstance(results_map, dict):
                    continue
                for _check_id, check_detail in results_map.items():
                    if not isinstance(check_detail, dict):
                        continue
                    severity = check_detail.get(
                        "Severity", check_detail.get("severity", "")
                    ).lower()
                    success = check_detail.get("Success", check_detail.get("success"))
                    if success:
                        passing += 1
                    elif severity == "danger":
                        danger += 1
                    else:
                        warning += 1

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
