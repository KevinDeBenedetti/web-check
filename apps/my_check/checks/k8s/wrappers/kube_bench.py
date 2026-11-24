"""CIS Benchmarks check via kube-bench.

By default kube-bench runs on this machine and audits its own node. With
``K8sContext.kube_bench_job`` it runs as a Job in the selected cluster, from
upstream's job.yaml: the Job is created, waited for, its JSON log read, then
deleted. It audits the one node the Job is scheduled on.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from my_check.types import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    K8sContext,
    SubprocessResult,
    run_subprocess,
)

# Pinned by digest; Renovate moves tag and digest together (customManagers in renovate.json).
KUBE_BENCH_IMAGE = (
    "docker.io/aquasec/kube-bench:v0.16.0"
    "@sha256:75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679"
)

# Host paths of upstream's job.yaml (volume name, host path, mount path), all read-only.
_HOST_PATHS: tuple[tuple[str, str, str], ...] = (
    ("var-lib-cni", "/var/lib/cni", "/var/lib/cni"),
    ("var-lib-etcd", "/var/lib/etcd", "/var/lib/etcd"),
    ("var-lib-kubelet", "/var/lib/kubelet", "/var/lib/kubelet"),
    ("var-lib-kube-scheduler", "/var/lib/kube-scheduler", "/var/lib/kube-scheduler"),
    (
        "var-lib-kube-controller-manager",
        "/var/lib/kube-controller-manager",
        "/var/lib/kube-controller-manager",
    ),
    ("etc-systemd", "/etc/systemd", "/etc/systemd"),
    ("lib-systemd", "/lib/systemd", "/lib/systemd/"),
    ("srv-kubernetes", "/srv/kubernetes", "/srv/kubernetes/"),
    ("etc-kubernetes", "/etc/kubernetes", "/etc/kubernetes"),
    ("usr-bin", "/usr/bin", "/usr/local/mount-from-host/bin"),
    ("etc-cni-netd", "/etc/cni/net.d/", "/etc/cni/net.d/"),
    ("opt-cni-bin", "/opt/cni/bin/", "/opt/cni/bin/"),
)

# Seconds: how long to wait for the Job, how often to poll its status, the most
# it may run, and when Kubernetes deletes it if my-check could not (interrupted run).
_JOB_WAIT = 300
_JOB_POLL = 5
_JOB_DEADLINE = 600
_JOB_TTL = 600
# What the whole check needs in Job mode (wait, plus create, logs and delete):
# the scheduler's per-check timeout is raised to it (my_check.cli).
JOB_CHECK_TIMEOUT = float(_JOB_WAIT + 90)


def kube_bench_job_manifest(name: str) -> dict[str, Any]:
    """The kube-bench Job of upstream's job.yaml, pinned, run once, with JSON output."""
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "labels": {"app": "kube-bench", "app.kubernetes.io/managed-by": "my-check"},
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": _JOB_DEADLINE,
            "ttlSecondsAfterFinished": _JOB_TTL,
            "template": {
                "metadata": {
                    "labels": {"app": "kube-bench", "app.kubernetes.io/managed-by": "my-check"}
                },
                "spec": {
                    "hostPID": True,
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "kube-bench",
                            "image": KUBE_BENCH_IMAGE,
                            "command": ["kube-bench", "run", "--json"],
                            "volumeMounts": [
                                {"name": volume, "mountPath": mount, "readOnly": True}
                                for volume, _, mount in _HOST_PATHS
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": volume, "hostPath": {"path": path}}
                        for volume, path, _ in _HOST_PATHS
                    ],
                },
            },
        },
    }


def kubectl_command(ctx: K8sContext, *args: str) -> list[str]:
    """kubectl against the selected kubeconfig, context and namespace (default: `default`)."""
    cmd = ["kubectl"]
    if ctx.kubeconfig_path:
        cmd += ["--kubeconfig", ctx.kubeconfig_path]
    if ctx.context_name:
        cmd += ["--context", ctx.context_name]
    cmd += ["--namespace", ctx.namespace or "default"]
    return cmd + list(args)


def _not_found(tool: str) -> CheckResult:
    return CheckResult(
        status=CheckStatus.INFO,
        score=0,
        message=f"{tool} not found — install it for CIS benchmarking.",
    )


def _tool_missing(result: SubprocessResult) -> bool:
    return result.returncode == -1 and "not found" in result.stderr.lower()


def _failure(message: str, result: SubprocessResult) -> CheckResult:
    return CheckResult(
        status=CheckStatus.FAIL,
        score=0,
        message=message,
        details={"stderr": result.stderr[:500]},
    )


async def _wait_for_job(target: K8sContext, name: str) -> str | None:
    """None once the Job succeeded; why it did not otherwise (failed, timed out)."""
    deadline = time.monotonic() + _JOB_WAIT
    while True:
        status = await run_subprocess(
            kubectl_command(
                target, "get", f"job/{name}", "-o", "jsonpath={.status.succeeded}/{.status.failed}"
            ),
            timeout=30.0,
        )
        if status.returncode != 0:
            return f"its status could not be read ({status.stderr.strip()[:200]})"
        succeeded, _, failed = status.stdout.strip().partition("/")
        if succeeded not in ("", "0"):
            return None
        if failed not in ("", "0"):
            return "it failed (kubectl describe job shows why)"
        if time.monotonic() >= deadline:
            return f"it was still running after {_JOB_WAIT}s"
        await asyncio.sleep(_JOB_POLL)


@dataclass(slots=True)
class KubeBenchCheck:
    id: str = "k8s-kube-bench"
    name: str = "CIS Benchmarks (kube-bench)"
    category: CheckCategory = CheckCategory.K8S

    async def run(self, target: str | K8sContext) -> CheckResult:
        if not isinstance(target, K8sContext):
            raise TypeError(f"Expected K8sContext, got {type(target).__name__}")
        if target.kube_bench_job:
            return await self._run_job(target)
        return await self._run_local(target)

    async def _run_local(self, target: K8sContext) -> CheckResult:
        try:
            # kube-bench audits the node it runs on (files, processes) and has no
            # cluster selection; KUBECONFIG only helps its version detection.
            result = await run_subprocess(
                ["kube-bench", "run", "--json"], timeout=120.0, env=target.kubeconfig_env()
            )
        except FileNotFoundError:
            return _not_found("kube-bench")

        if _tool_missing(result):
            return _not_found("kube-bench")

        if result.returncode != 0:
            return _failure(f"kube-bench exited with code {result.returncode}.", result)

        note = ""
        if target.context_name or target.kubeconfig_path:
            selected = target.context_name or target.kubeconfig_path
            note = (
                f" (kube-bench audits the node it runs on, not the cluster '{selected}';"
                " --kube-bench-job runs it in the cluster)"
            )
        return _summarise(result.stdout, scope="local node", note=note)

    async def _run_job(self, target: K8sContext) -> CheckResult:
        name = f"my-check-kube-bench-{secrets.token_hex(3)}"
        manifest = json.dumps(kube_bench_job_manifest(name))
        try:
            created = await run_subprocess(
                kubectl_command(target, "create", "-f", "-"), timeout=60.0, stdin=manifest
            )
        except FileNotFoundError:
            return _not_found("kubectl")
        if _tool_missing(created):
            return _not_found("kubectl")
        if created.returncode != 0:
            return _failure("Could not create the kube-bench Job in the cluster.", created)

        try:
            if why := await _wait_for_job(target, name):
                return CheckResult(
                    status=CheckStatus.FAIL,
                    score=0,
                    message=f"The kube-bench Job {name} did not complete: {why}.",
                )
            logs = await run_subprocess(
                kubectl_command(target, "logs", f"job/{name}"), timeout=60.0
            )
            if logs.returncode != 0:
                return _failure(f"Could not read the log of the kube-bench Job {name}.", logs)
        finally:
            await run_subprocess(
                kubectl_command(
                    target,
                    "delete",
                    "job",
                    name,
                    "--ignore-not-found",
                    "--cascade=background",
                    "--wait=false",
                ),
                timeout=30.0,
            )

        selected = target.context_name or target.kubeconfig_path or "current context"
        return _summarise(
            logs.stdout,
            scope="cluster (Job on one node)",
            note=f" (kube-bench Job on one node of '{selected}')",
            in_pod=True,
        )


# The sections (Controls[].node_type) of a complete benchmark of a server node.
_SECTIONS = ("master", "controlplane", "node", "policies")


def _summarise(stdout: str, *, scope: str, note: str, in_pod: bool = False) -> CheckResult:
    """Turn kube-bench's JSON report into a check result.

    A benchmark that lacks sections, or whose journal-based audits ran in a pod
    (*in_pod*), where the host's journal is out of reach, is reported as partial:
    those audits are left out of the counts instead of being scored as failures.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return CheckResult(
            status=CheckStatus.FAIL,
            score=0,
            message="Failed to parse kube-bench JSON output.",
            details={"raw_stdout": stdout[:1000]},
        )

    counts = {"PASS": 0, "FAIL": 0, "WARN": 0}
    unverifiable = 0
    sections: list[str] = []

    controls = data if isinstance(data, list) else data.get("Controls", [])
    for control in controls:
        section = control.get("node_type", "")
        if section and section not in sections:
            sections.append(section)
        for test in control.get("tests", []):
            for r in test.get("results", []):
                if in_pod and "journalctl" in r.get("audit", ""):
                    unverifiable += 1
                    continue
                status_str = r.get("status", "").upper()
                if status_str in counts:
                    counts[status_str] += 1

    total_pass, total_fail, total_warn = counts["PASS"], counts["FAIL"], counts["WARN"]
    total = total_pass + total_fail + total_warn
    score = int((total_pass / total) * 100) if total else 0
    missing = [section for section in _SECTIONS if section not in sections]

    summary: dict[str, int | str] = {
        "pass": total_pass,
        "fail": total_fail,
        "warn": total_warn,
        "total": total,
        "scope": scope,
        "sections": ", ".join(sections),
    }
    if in_pod:
        summary["unverifiable"] = unverifiable
    if missing:
        summary["missing_sections"] = ", ".join(missing)

    if total_fail == 0:
        status = CheckStatus.PASS
        message = f"All {total_pass} CIS checks passed."
    elif score >= 70:
        status = CheckStatus.WARN
        message = f"{total_fail} CIS check(s) failed out of {total}."
    else:
        status = CheckStatus.FAIL
        message = f"{total_fail} CIS check(s) failed out of {total}."

    gaps = []
    if missing:
        gaps.append(f"no {', '.join(missing)} section")
    if unverifiable:
        gaps.append(f"{unverifiable} journal-based check(s) not verifiable from a pod")
    if gaps:
        # An incomplete benchmark never reads as a clean pass.
        if status == CheckStatus.PASS:
            status = CheckStatus.WARN
        message = f"Partial CIS benchmark ({'; '.join(gaps)}): {message}"

    return CheckResult(
        status=status,
        score=score,
        message=message + note,
        details=summary,
        remediation="Review failed CIS checks and apply recommended remediations."
        + (
            " On k3s, run kube-bench on each node (--benchmark k3s-cis-*) for the full benchmark."
            if gaps
            else ""
        ),
    )
