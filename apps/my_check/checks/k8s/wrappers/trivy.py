"""Vulnerability Scan check via Trivy."""

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
class TrivyCheck:
    id: str = "k8s-trivy"
    name: str = "Vulnerability Scan (Trivy)"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        assert isinstance(target, K8sContext)

        try:
            result = await run_subprocess(
                ["trivy", "k8s", "--format", "json", "--report", "summary"],
                timeout=120.0,
            )
        except FileNotFoundError:
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message="trivy not found — install it for vulnerability scanning.",
            )

        if result.returncode == -1 and "not found" in result.stderr.lower():
            return CheckResult(
                status=CheckStatus.INFO,
                score=0,
                message="trivy not found — install it for vulnerability scanning.",
            )

        if result.returncode != 0:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"trivy exited with code {result.returncode}.",
                details={"stderr": result.stderr[:500]},
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message="Failed to parse Trivy JSON output.",
                details={"raw_stdout": result.stdout[:1000]},
            )

        severity_counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        # Trivy k8s JSON may have a ClusterComplianceReport or Results array
        results = data.get("Results", data.get("results", []))
        if isinstance(results, list):
            for entry in results:
                vulns = entry.get("Vulnerabilities", entry.get("vulnerabilities", []))
                if isinstance(vulns, list):
                    for vuln in vulns:
                        sev = vuln.get("Severity", vuln.get("severity", "UNKNOWN")).upper()
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        critical = severity_counts["CRITICAL"]
        high = severity_counts["HIGH"]

        # Score: start at 100, deduct 20 per critical, 10 per high, 2 per medium
        score = 100
        score -= critical * 20
        score -= high * 10
        score -= severity_counts["MEDIUM"] * 2
        score = max(0, min(100, score))

        total_vulns = sum(severity_counts.values())

        if total_vulns == 0:
            return CheckResult(
                status=CheckStatus.PASS,
                score=100,
                message="No vulnerabilities detected by Trivy.",
                details=severity_counts,
            )

        status = CheckStatus.FAIL if critical > 0 or score < 50 else CheckStatus.WARN
        return CheckResult(
            status=status,
            score=score,
            message=(
                f"Trivy found {total_vulns} vulnerability(ies): {critical} critical, {high} high."
            ),
            details=severity_counts,
            remediation=(
                "Update affected container images to patched versions. "
                "Prioritize critical and high severity CVEs."
            ),
        )
