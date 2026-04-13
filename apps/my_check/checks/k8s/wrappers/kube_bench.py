"""CIS Benchmarks check via kube-bench."""

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
class KubeBenchCheck:
    id: str = "k8s-kube-bench"
    name: str = "CIS Benchmarks (kube-bench)"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, K8sContext)

        try:
            result = await run_subprocess(["kube-bench", "run", "--json"], timeout=120.0)
        except FileNotFoundError:
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message="kube-bench not found — install it for CIS benchmarking.",
            )

        if result.returncode == -1 and "not found" in result.stderr.lower():
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message="kube-bench not found — install it for CIS benchmarking.",
            )

        if result.returncode != 0:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"kube-bench exited with code {result.returncode}.",
                details={"stderr": result.stderr[:500]},
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message="Failed to parse kube-bench JSON output.",
                details={"raw_stdout": result.stdout[:1000]},
            )

        total_pass = 0
        total_fail = 0
        total_warn = 0

        controls = data if isinstance(data, list) else data.get("Controls", [])
        for control in controls:
            tests = control.get("tests", [])
            for test in tests:
                for r in test.get("results", []):
                    status_str = r.get("status", "").upper()
                    if status_str == "PASS":
                        total_pass += 1
                    elif status_str == "FAIL":
                        total_fail += 1
                    elif status_str == "WARN":
                        total_warn += 1

        total = total_pass + total_fail + total_warn
        score = int((total_pass / total) * 100) if total else 0

        summary = {"pass": total_pass, "fail": total_fail, "warn": total_warn, "total": total}

        if total_fail == 0:
            status = CheckStatus.PASS
            message = f"All {total_pass} CIS checks passed."
        elif score >= 70:
            status = CheckStatus.WARN
            message = f"{total_fail} CIS check(s) failed out of {total}."
        else:
            status = CheckStatus.FAIL
            message = f"{total_fail} CIS check(s) failed out of {total}."

        return CheckResult(
            status=status,
            score=score,
            message=message,
            details=summary,
            remediation="Review failed CIS checks and apply recommended remediations.",
        )
