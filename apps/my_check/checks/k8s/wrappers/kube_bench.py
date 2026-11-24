"""CIS Benchmarks check via kube-bench.

By default kube-bench runs on this machine and audits its own node. With
``K8sContext.kube_bench_job`` it runs as Jobs in the selected cluster, from
upstream's job.yaml: one Job pinned to each Ready Linux node (``kubectl get
nodes``), a few at a time, so the control-plane and worker sections are both
covered. The Jobs are created, waited for, their JSON logs read and summed, then
deleted. When the nodes cannot be listed (RBAC), a single Job audits the node
the scheduler picks.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
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

# Seconds: how often to poll a Job's status, the least a Job may run (raised to
# the wait, K8sContext.kube_bench_wait), and when Kubernetes deletes it if
# my-check could not (interrupted run). The wait for the Jobs (one window for all
# of them, from the first one) and the most Jobs running at the same time come
# from K8sContext (k8s.kube_bench_wait and k8s.kube_bench_parallel).
_JOB_POLL = 5
_JOB_DEADLINE = 600
_JOB_TTL = 600


def job_check_timeout(wait: int) -> float:
    """What the whole check needs in Job mode, with *wait* seconds for the Jobs.

    Each step at its own timeout: list the nodes (30), create (60), wait plus its
    last poll (*wait* + 30), logs (60) and delete (30). The nodes' Jobs share the
    one wait window, whatever their number. The scheduler's per-check timeout is
    raised to it (my_check.cli), so the deletes are never cut short.
    """
    return float(wait + 30 + 60 + 30 + 60 + 30)


def kube_bench_job_manifest(
    name: str,
    node: str | None = None,
    benchmark: str | None = None,
    targets: str | None = None,
    wait: int = _JOB_DEADLINE,
) -> dict[str, Any]:
    """The kube-bench Job of upstream's job.yaml, pinned, run once, with JSON output.

    With *node*, its pod runs on that node (``nodeName``) and tolerates its taints,
    so control-plane nodes are audited too. With *benchmark*, kube-bench runs that
    benchmark instead of the one it detects; with *targets*, only those sections.
    The Job may run for *wait* seconds (my-check's wait for it), at least 600.
    """
    pod_placement: dict[str, Any] = (
        {"nodeName": node, "tolerations": [{"operator": "Exists"}]} if node else {}
    )
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "labels": {"app": "kube-bench", "app.kubernetes.io/managed-by": "my-check"},
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": max(_JOB_DEADLINE, wait),
            "ttlSecondsAfterFinished": _JOB_TTL,
            "template": {
                "metadata": {
                    "labels": {"app": "kube-bench", "app.kubernetes.io/managed-by": "my-check"}
                },
                "spec": {
                    **pod_placement,
                    "hostPID": True,
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "kube-bench",
                            "image": KUBE_BENCH_IMAGE,
                            "command": ["kube-bench", "run", "--json"]
                            + (["--benchmark", benchmark] if benchmark else [])
                            + (["--targets", targets] if targets else []),
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


def k3s_benchmark(kubelet_version: str) -> str | None:
    """The k3s CIS benchmark kube-bench picks for a k3s kubelet version; None off k3s.

    In a pod, kube-bench often cannot reach the API server to detect the version
    and falls back to the generic cis-1.6, whose control-plane paths k3s does not
    use. This mirrors kube-bench v0.16's own k3sBenchmark (cmd/util.go).
    """
    if "+k3s" not in kubelet_version:
        return None
    major_minor = ".".join(kubelet_version.lstrip("v").split("+")[0].split(".")[:2])
    return {
        "1.22": "k3s-cis-1.23",
        "1.23": "k3s-cis-1.23",
        "1.24": "k3s-cis-1.24",
        "1.25": "k3s-cis-1.7",
        "1.26": "k3s-cis-1.8",
    }.get(major_minor, "k3s-cis-1.9")


# One line per node, tab-separated: name, kubelet version, the values of its
# control-plane and master role labels (both empty on a worker), its
# kubernetes.io/os label, the status of its Ready condition, its `type` label and
# its taint keys (space-separated).
_NODES_JSONPATH = (
    'jsonpath={range .items[*]}{.metadata.name}{"\\t"}{.status.nodeInfo.kubeletVersion}'
    '{"\\t"}{.metadata.labels.node-role\\.kubernetes\\.io/control-plane}'
    "{.metadata.labels.node-role\\.kubernetes\\.io/master}"
    '{"\\t"}{.metadata.labels.kubernetes\\.io/os}'
    '{"\\t"}{.status.conditions[?(@.type=="Ready")].status}'
    '{"\\t"}{.metadata.labels.type}{"\\t"}{.spec.taints[*].key}{"\\n"}{end}'
)

# How a virtual-kubelet node (a serverless or burst node pool) declares itself.
_VIRTUAL_KUBELET_TYPE = "virtual-kubelet"
_VIRTUAL_KUBELET_TAINT = "virtual-kubelet.io/provider"


@dataclass(frozen=True, slots=True)
class _Node:
    kubelet_version: str
    control_plane: bool
    os: str
    ready: bool
    virtual: bool = False

    def skip_reason(self) -> str | None:
        """Why kube-bench cannot run on this node; None when it can."""
        if self.virtual:
            return "a virtual-kubelet node, no host to audit"
        if self.os != "linux":
            return f"not a Linux node ({self.os or 'no kubernetes.io/os label'})"
        if not self.ready:
            return "not Ready"
        return None


def _parse_nodes(listing: str) -> dict[str, _Node]:
    """Nodes by name, from a `_NODES_JSONPATH` listing."""
    nodes: dict[str, _Node] = {}
    for line in listing.splitlines():
        name, version, roles, os_label, ready, type_label, taints = (
            part.strip() for part in [*line.split("\t"), *[""] * 7][:7]
        )
        if name:
            virtual = (
                type_label == _VIRTUAL_KUBELET_TYPE or _VIRTUAL_KUBELET_TAINT in taints.split()
            )
            nodes[name] = _Node(version, bool(roles), os_label, ready == "True", virtual)
    return nodes


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


async def _wait_for_job(target: K8sContext, name: str, deadline: float) -> str | None:
    """None once the Job succeeded; why it did not otherwise (failed, timed out).

    *deadline* is the `time.monotonic()` value at which the wait gives up.
    """
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
            return (
                f"it was still running when the {target.kube_bench_wait}s wait for the Jobs ended"
            )
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
        try:
            listed = await run_subprocess(
                kubectl_command(
                    target,
                    "get",
                    "nodes",
                    "-o",
                    _NODES_JSONPATH,
                ),
                timeout=30.0,
            )
        except FileNotFoundError:
            return _not_found("kubectl")
        if _tool_missing(listed):
            return _not_found("kubectl")
        nodes = _parse_nodes(listed.stdout) if listed.returncode == 0 else {}

        selected = target.context_name or target.kubeconfig_path or "current context"
        deadline = time.monotonic() + target.kube_bench_wait
        if not nodes:
            # The nodes could not be listed (that needs a ClusterRole) or none was:
            # run one Job wherever it is scheduled.
            try:
                stdout = await _job_report(target, None, deadline)
            except _JobFailed as failed:
                return failed.result
            why = (
                f"nodes could not be listed: {listed.stderr.strip()[:200]}"
                if listed.returncode != 0
                else "no node listed"
            )
            return _summarise(
                stdout,
                scope="cluster (Job on one node)",
                note=f" (kube-bench Job on one node of '{selected}'; {why})",
                in_pod=True,
            )

        # kube-bench runs on Ready Linux nodes only: on another node the Job could
        # only end without a result, after the whole wait.
        skipped = {
            node: {"skipped": reason}
            for node, info in nodes.items()
            if (reason := info.skip_reason())
        }
        eligible = {node: info for node, info in nodes.items() if node not in skipped}
        if not eligible:
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"No Ready Linux node to run kube-bench on in '{selected}'"
                f" ({len(skipped)} node(s) skipped).",
                details={"nodes": skipped},
            )

        slots = asyncio.Semaphore(target.kube_bench_parallel)

        async def in_a_slot(node: str, info: _Node) -> str:
            async with slots:
                return await _job_report(
                    target,
                    node,
                    deadline,
                    k3s_benchmark(info.kubelet_version),
                    None if info.control_plane else "node",
                )

        outcomes = await asyncio.gather(
            *(in_a_slot(node, info) for node, info in eligible.items()),
            return_exceptions=True,
        )
        total = _Tally()
        per_node: dict[str, dict[str, Any]] = {}
        failures: list[CheckResult] = []
        for node, outcome in zip(eligible, outcomes, strict=True):
            if isinstance(outcome, _JobFailed):
                failures.append(outcome.result)
                stderr = (outcome.result.details or {}).get("stderr", "").strip()
                per_node[node] = {"error": f"{outcome.result.message} {stderr}".strip()[:500]}
                continue
            if isinstance(outcome, BaseException):
                raise outcome
            tally = _tally(outcome, in_pod=True)
            if tally is None:
                per_node[node] = {"error": "Its log is not kube-bench JSON.", "log": outcome[:500]}
                continue
            total.add(tally)
            per_node[node] = tally.node_summary()

        unaudited = sum(1 for summary in per_node.values() if "error" in summary)
        if unaudited == len(eligible):
            if len(eligible) == 1 and failures and not skipped:
                return failures[0]
            return CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"No kube-bench Job completed on the {len(eligible)} node(s).",
                details={"nodes": per_node | skipped},
            )

        skip_note = f"; {len(skipped)} skipped, see details.nodes" if skipped else ""
        result = _verdict(
            total,
            scope=f"cluster (Jobs on {len(eligible)} node{'s' if len(eligible) > 1 else ''})",
            note=f" (kube-bench Jobs on the {len(eligible)} node(s) of '{selected}'{skip_note})",
            in_pod=True,
            unaudited_nodes=unaudited,
        )
        result.details["nodes"] = per_node | skipped
        return result


class _JobFailed(Exception):
    """A kube-bench Job that gave no report; *result* says why."""

    def __init__(self, result: CheckResult) -> None:
        super().__init__(result.message)
        self.result = result


async def _job_report(
    target: K8sContext,
    node: str | None,
    deadline: float,
    benchmark: str | None = None,
    targets: str | None = None,
) -> str:
    """Run one kube-bench Job (on *node*, when given) and return its log.

    A worker gets *targets* ``node``: kube-bench otherwise runs every section of
    the benchmark, control plane included, on every node. *deadline* is the
    `time.monotonic()` value at which the wait for the Jobs ends: past it, no
    Job is created.
    """
    if time.monotonic() >= deadline:
        raise _JobFailed(
            CheckResult(
                status=CheckStatus.FAIL,
                score=0,
                message=f"The kube-bench Job was not started: the {target.kube_bench_wait}s wait"
                " for the Jobs ended before its turn.",
            )
        )
    name = f"my-check-kube-bench-{secrets.token_hex(3)}"
    manifest = json.dumps(
        kube_bench_job_manifest(name, node, benchmark, targets, target.kube_bench_wait)
    )
    created = await run_subprocess(
        kubectl_command(target, "create", "-f", "-"), timeout=60.0, stdin=manifest
    )
    if created.returncode != 0:
        raise _JobFailed(_failure("Could not create the kube-bench Job in the cluster.", created))

    try:
        if why := await _wait_for_job(target, name, deadline):
            raise _JobFailed(
                CheckResult(
                    status=CheckStatus.FAIL,
                    score=0,
                    message=f"The kube-bench Job {name} did not complete: {why}.",
                )
            )
        logs = await run_subprocess(kubectl_command(target, "logs", f"job/{name}"), timeout=60.0)
        if logs.returncode != 0:
            raise _JobFailed(
                _failure(f"Could not read the log of the kube-bench Job {name}.", logs)
            )
        return logs.stdout
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


# The sections (Controls[].node_type) of a complete benchmark of a server node.
_SECTIONS = ("master", "controlplane", "node", "policies")


@dataclass(slots=True)
class _Tally:
    """Counts of one kube-bench report, or of several summed."""

    counts: dict[str, int] = field(default_factory=lambda: {"PASS": 0, "FAIL": 0, "WARN": 0})
    unverifiable: int = 0
    sections: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def add(self, other: _Tally) -> None:
        for status, count in other.counts.items():
            self.counts[status] += count
        self.unverifiable += other.unverifiable
        self.sections += [s for s in other.sections if s not in self.sections]

    def node_summary(self) -> dict[str, Any]:
        return {
            "pass": self.counts["PASS"],
            "fail": self.counts["FAIL"],
            "warn": self.counts["WARN"],
            "total": self.total,
            "sections": ", ".join(self.sections),
        }


def _report_json(log: str) -> Any:
    """kube-bench's JSON report from its output; None when there is none.

    A pod log mixes stderr into stdout, so warning lines may surround the JSON:
    the report is the first line that starts a JSON document and decodes.
    """
    try:
        return json.loads(log)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    offset = 0
    for line in log.splitlines(keepends=True):
        if line.lstrip().startswith(("{", "[")):
            try:
                return decoder.raw_decode(log, offset + len(line) - len(line.lstrip()))[0]
            except json.JSONDecodeError:
                pass
        offset += len(line)
    return None


def _tally(stdout: str, *, in_pod: bool) -> _Tally | None:
    """Count the results of kube-bench's JSON report; None when it is not JSON.

    Journal-based audits run in a pod (*in_pod*), where the host's journal is out
    of reach, are counted apart as unverifiable instead of being scored.
    """
    data = _report_json(stdout)
    if data is None:
        return None

    tally = _Tally()
    controls = data if isinstance(data, list) else data.get("Controls", [])
    for control in controls:
        section = control.get("node_type", "")
        if section and section not in tally.sections:
            tally.sections.append(section)
        for test in control.get("tests", []):
            for r in test.get("results", []):
                if in_pod and "journalctl" in r.get("audit", ""):
                    tally.unverifiable += 1
                    continue
                status_str = r.get("status", "").upper()
                if status_str in tally.counts:
                    tally.counts[status_str] += 1
    return tally


def _summarise(stdout: str, *, scope: str, note: str, in_pod: bool = False) -> CheckResult:
    """Turn kube-bench's JSON report into a check result."""
    tally = _tally(stdout, in_pod=in_pod)
    if tally is None:
        return CheckResult(
            status=CheckStatus.FAIL,
            score=0,
            message="Failed to parse kube-bench JSON output.",
            details={"raw_stdout": stdout[:1000]},
        )
    return _verdict(tally, scope=scope, note=note, in_pod=in_pod)


def _verdict(
    tally: _Tally, *, scope: str, note: str, in_pod: bool, unaudited_nodes: int = 0
) -> CheckResult:
    """The check result of a tally.

    A benchmark that lacks sections, has unverifiable audits, or misses nodes
    (*unaudited_nodes*) is reported as partial and never reads as a clean pass.
    """
    total_pass, total_fail, total_warn = (
        tally.counts["PASS"],
        tally.counts["FAIL"],
        tally.counts["WARN"],
    )
    total = tally.total
    score = int((total_pass / total) * 100) if total else 0
    missing = [section for section in _SECTIONS if section not in tally.sections]

    summary: dict[str, Any] = {
        "pass": total_pass,
        "fail": total_fail,
        "warn": total_warn,
        "total": total,
        "scope": scope,
        "sections": ", ".join(tally.sections),
    }
    if in_pod:
        summary["unverifiable"] = tally.unverifiable
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
    if tally.unverifiable:
        gaps.append(f"{tally.unverifiable} journal-based check(s) not verifiable from a pod")
    if unaudited_nodes:
        gaps.append(f"{unaudited_nodes} node(s) without a result")
    if gaps:
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
            " On k3s, run the kube-bench binary on each node (--benchmark k3s-cis-*)"
            " for the full benchmark."
            if gaps
            else ""
        ),
    )
