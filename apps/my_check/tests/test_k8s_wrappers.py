"""The trivy, polaris and kube-bench wrappers target the cluster the user selected.

Output samples follow each tool's own JSON structures: trivy's Kubernetes report
(top-level Vulnerabilities per resource) and polaris's AuditData / Result /
PodResult / ContainerResult types (pkg/validator/output.go).
"""

import json
from typing import Any

import pytest
from my_check.checks.k8s.wrappers import kube_bench, polaris, trivy
from my_check.types import CheckStatus, K8sContext, SubprocessResult

CTX = K8sContext(context_name="prod", kubeconfig_path="/home/me/.kube/prod", namespace="app")


class FakeTool:
    """Stands in for run_subprocess: records the command and environment."""

    def __init__(self, output: Any, returncode: int = 0) -> None:
        self.output = output
        self.returncode = returncode
        self.cmd: list[str] = []
        self.env: dict[str, str] | None = None

    async def __call__(
        self, cmd: list[str], *, timeout: float = 120.0, env: dict[str, str] | None = None
    ) -> SubprocessResult:
        self.cmd, self.env = cmd, env
        return SubprocessResult(self.returncode, json.dumps(self.output), "")


TRIVY_REPORT = {
    "ClusterName": "prod",
    "Vulnerabilities": [
        {
            "Namespace": "app",
            "Kind": "Deployment",
            "Name": "web",
            "Results": [
                {
                    "Target": "nginx:1.25",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL"},
                        {"VulnerabilityID": "CVE-2", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-3", "Severity": "LOW"},
                    ],
                }
            ],
        }
    ],
    "Misconfigurations": [],
}


async def test_trivy_scans_the_selected_cluster(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTool(TRIVY_REPORT)
    monkeypatch.setattr(trivy, "run_subprocess", fake)

    result = await trivy.TrivyCheck().run(CTX)

    assert fake.cmd[:2] == ["trivy", "k8s"]
    assert fake.cmd[fake.cmd.index("--kubeconfig") + 1] == "/home/me/.kube/prod"
    assert fake.cmd[fake.cmd.index("--include-namespaces") + 1] == "app"
    assert fake.cmd[-1] == "prod"  # the context is trivy's positional target
    assert result.status == CheckStatus.FAIL
    assert result.details["CRITICAL"] == 1 and result.details["HIGH"] == 1


async def test_trivy_without_a_selection_uses_kubectls_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeTool({"ClusterName": "kind", "Vulnerabilities": [], "Misconfigurations": []})
    monkeypatch.setattr(trivy, "run_subprocess", fake)

    result = await trivy.TrivyCheck().run(K8sContext())

    assert fake.cmd == ["trivy", "k8s", "--format", "json", "--report", "summary"]
    assert result.status == CheckStatus.PASS


def _check(id_: str, success: bool, severity: str = "warning") -> dict[str, Any]:
    return {id_: {"ID": id_, "Message": "m", "Success": success, "Severity": severity}}


POLARIS_REPORT = {
    "PolarisOutputVersion": "1.0",
    "Results": [
        {
            "Name": "web",
            "Namespace": "app",
            "Kind": "Deployment",
            "Results": _check("hostIPCSet", True, "danger"),
            "PodResult": {
                "Name": "web",
                "Results": _check("hostNetworkSet", False, "danger"),
                "ContainerResults": [
                    {
                        "Name": "nginx",
                        "Results": {
                            **_check("cpuLimitsMissing", False),
                            **_check("ignored", False, "ignore"),
                        },
                    },
                ],
            },
        },
        {
            "Name": "app",
            "Namespace": "",
            "Kind": "Namespace",
            "Results": _check("x", True),
            "PodResult": None,
        },
    ],
}


async def test_polaris_audits_the_selected_cluster(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTool(POLARIS_REPORT)
    monkeypatch.setattr(polaris, "run_subprocess", fake)

    result = await polaris.PolarisCheck().run(CTX)

    assert fake.cmd[fake.cmd.index("--context") + 1] == "prod"
    assert fake.cmd[fake.cmd.index("--namespace") + 1] == "app"
    assert fake.env == {"KUBECONFIG": "/home/me/.kube/prod"}
    # Controller, pod and container levels all count; "ignore" findings do not.
    assert result.details == {"passing": 2, "warning": 1, "danger": 1, "total": 4}
    assert result.status == CheckStatus.WARN


async def test_kube_bench_says_it_audited_the_local_node(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTool({"Controls": [{"tests": [{"results": [{"status": "PASS"}]}]}]})
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(CTX)

    assert fake.env == {"KUBECONFIG": "/home/me/.kube/prod"}
    assert "node" in result.message and "prod" in result.message
    assert result.details["scope"] == "local node"


class FakeKubectl:
    """Stands in for run_subprocess in kube-bench Job mode: answers each kubectl verb."""

    def __init__(
        self,
        logs: Any,
        job_status: str = "1/",
        nodes: list[str] | None = None,
        nodes_returncode: int = 0,
        kubelet_version: str = "v1.30.2",
        control_planes: tuple[str, ...] = ("node-1", "cp-1"),
    ) -> None:
        self.logs = logs  # one report for every node, or {node name: report}
        self.job_status = job_status  # {.status.succeeded}/{.status.failed}
        self.nodes = ["node-1"] if nodes is None else nodes
        self.nodes_returncode = nodes_returncode
        self.kubelet_version = kubelet_version
        self.control_planes = control_planes  # nodes labelled node-role.kubernetes.io/control-plane
        self.calls: list[tuple[list[str], str | None]] = []
        self.job_nodes: dict[str, str] = {}  # Job name -> nodeName of its pod

    async def __call__(
        self,
        cmd: list[str],
        *,
        timeout: float = 120.0,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
    ) -> SubprocessResult:
        self.calls.append((cmd, stdin))
        if "nodes" in cmd:
            if self.nodes_returncode:
                return SubprocessResult(self.nodes_returncode, "", "nodes is forbidden")
            # name, kubelet version, then the control-plane and master role labels' values
            listing = "".join(
                f"{node}\t{self.kubelet_version}\t{'true' if node in self.control_planes else ''}\n"
                for node in self.nodes
            )
            return SubprocessResult(0, listing, "")
        if "create" in cmd:
            manifest = json.loads(stdin or "")
            node = manifest["spec"]["template"]["spec"].get("nodeName", "")
            self.job_nodes[manifest["metadata"]["name"]] = node
        if "get" in cmd:
            return SubprocessResult(0, self.job_status, "")
        if "logs" in cmd:
            job = cmd[-1].removeprefix("job/")
            node = self.job_nodes.get(job, "")
            report = self.logs[node] if node in self.logs else self.logs
            log = report if isinstance(report, str) else json.dumps(report)
            return SubprocessResult(0, log, "")
        return SubprocessResult(0, "", "")

    def verbs(self) -> list[str]:
        return [
            "nodes"
            if "nodes" in cmd
            else next(v for v in ("create", "get", "logs", "delete") if v in cmd)
            for cmd, _ in self.calls
        ]


JOB_CTX = K8sContext(
    context_name="prod", kubeconfig_path="/home/me/.kube/prod", namespace="app", kube_bench_job=True
)


async def test_kube_bench_job_runs_in_the_selected_cluster(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKubectl(
        {"Controls": [{"tests": [{"results": [{"status": "PASS"}, {"status": "FAIL"}]}]}]}
    )
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert fake.verbs() == ["nodes", "create", "get", "logs", "delete"]
    for cmd, _ in fake.calls:
        assert cmd[0] == "kubectl"
        assert cmd[cmd.index("--context") + 1] == "prod"
        assert cmd[cmd.index("--kubeconfig") + 1] == "/home/me/.kube/prod"
        assert cmd[cmd.index("--namespace") + 1] == "app"
    manifest = json.loads(fake.calls[1][1] or "")
    job_name = manifest["metadata"]["name"]
    assert all(job_name in " ".join(cmd) for cmd, _ in fake.calls[2:])
    assert manifest["spec"]["template"]["spec"]["nodeName"] == "node-1"
    assert result.details["scope"] == "cluster (Jobs on 1 node)"
    assert result.details["fail"] == 1
    assert "prod" in result.message


async def test_a_failed_kube_bench_job_is_reported_at_once_and_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKubectl({}, job_status="/1")
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert fake.verbs() == ["nodes", "create", "get", "delete"]
    assert result.status == CheckStatus.FAIL
    assert "did not complete: it failed" in result.message


async def test_a_running_kube_bench_job_is_polled_until_it_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKubectl({"Controls": []}, job_status="/")
    sleeps: list[float] = []

    async def no_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        fake.job_status = "1/"

    monkeypatch.setattr(kube_bench, "run_subprocess", fake)
    monkeypatch.setattr(kube_bench.asyncio, "sleep", no_sleep)

    await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert fake.verbs() == ["nodes", "create", "get", "get", "logs", "delete"]
    assert len(sleeps) == 1


def test_kube_bench_job_manifest_is_pinned_and_read_only() -> None:
    manifest = kube_bench.kube_bench_job_manifest("my-check-kube-bench-abc123")
    pod = manifest["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert "@sha256:" in container["image"]
    assert container["command"] == ["kube-bench", "run", "--json"]
    assert pod["hostPID"] is True and pod["restartPolicy"] == "Never"
    assert all(mount["readOnly"] for mount in container["volumeMounts"])
    assert {m["name"] for m in container["volumeMounts"]} == {v["name"] for v in pod["volumes"]}
    assert manifest["spec"]["backoffLimit"] == 0
    assert manifest["spec"]["ttlSecondsAfterFinished"] > 0
    # The other checks skip pods with this label: my-check must not audit its own pod.
    pod_labels = manifest["spec"]["template"]["metadata"]["labels"]
    assert pod_labels["app.kubernetes.io/managed-by"] == "my-check"


async def test_kube_bench_runs_a_job_on_every_node_and_sums_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_plane = {
        "Controls": [
            {"node_type": "master", "tests": [{"results": [_result("PASS"), _result("FAIL")]}]},
            {"node_type": "controlplane", "tests": [{"results": [_result("PASS")]}]},
        ]
    }
    worker = {
        "Controls": [
            {"node_type": "node", "tests": [{"results": [_result("PASS"), _result("WARN")]}]},
            {"node_type": "policies", "tests": [{"results": [_result("PASS")]}]},
        ]
    }
    fake = FakeKubectl({"cp-1": control_plane, "worker-1": worker}, nodes=["cp-1", "worker-1"])
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert sorted(fake.job_nodes.values()) == ["cp-1", "worker-1"]
    assert fake.verbs().count("delete") == 2
    assert result.details["pass"] == 4
    assert result.details["fail"] == 1
    assert result.details["warn"] == 1
    assert result.details["scope"] == "cluster (Jobs on 2 nodes)"
    assert "missing_sections" not in result.details, "the nodes together cover every section"
    assert result.details["nodes"]["cp-1"] == {
        "pass": 2,
        "fail": 1,
        "warn": 0,
        "total": 3,
        "sections": "master, controlplane",
    }
    assert result.details["nodes"]["worker-1"]["sections"] == "node, policies"
    assert not result.message.startswith("Partial")


def test_a_node_job_tolerates_the_nodes_taints() -> None:
    pod = kube_bench.kube_bench_job_manifest("my-check-kube-bench-abc123", node="cp-1")["spec"][
        "template"
    ]["spec"]

    assert pod["nodeName"] == "cp-1"
    assert {"operator": "Exists"} in pod["tolerations"]


async def test_a_node_whose_job_fails_makes_the_benchmark_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = {"Controls": [{"node_type": "node", "tests": [{"results": [_result("PASS")]}]}]}
    fake = FakeKubectl(report, nodes=["cp-1", "worker-1"])

    real_call = fake.__call__

    async def failing_on_cp(cmd: list[str], **kwargs: Any) -> SubprocessResult:
        if "create" in cmd and '"nodeName": "cp-1"' in (kwargs.get("stdin") or ""):
            fake.calls.append((cmd, kwargs.get("stdin")))
            return SubprocessResult(1, "", "admission webhook denied the request")
        return await real_call(cmd, **kwargs)

    monkeypatch.setattr(kube_bench, "run_subprocess", failing_on_cp)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert result.details["pass"] == 1
    assert "admission webhook" in result.details["nodes"]["cp-1"]["error"]
    assert result.status == CheckStatus.WARN
    assert result.message.startswith("Partial CIS benchmark")
    assert "1 node(s) without a result" in result.message


async def test_unlistable_nodes_fall_back_to_a_single_job(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKubectl({"Controls": []}, nodes_returncode=1)
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert fake.verbs() == ["nodes", "create", "get", "logs", "delete"]
    assert "nodeName" not in json.loads(fake.calls[1][1] or "")["spec"]["template"]["spec"]
    assert result.details["scope"] == "cluster (Job on one node)"
    assert "nodes could not be listed" in result.message


# What kube-bench prints in a pod that cannot reach the API server (seen on k3s).
_VERSION_WARNING = (
    "Warning: Kubernetes version was not auto-detected because kubectl could not connect"
    " to the Kubernetes server. Assuming default version 1.18\n"
)


async def test_a_job_log_with_warnings_before_the_json_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = {"Controls": [{"node_type": "node", "tests": [{"results": [_result("PASS")]}]}]}
    log = _VERSION_WARNING * 2 + json.dumps(report) + "\n"
    monkeypatch.setattr(kube_bench, "run_subprocess", FakeKubectl(log))

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert result.details["pass"] == 1
    assert "error" not in result.details["nodes"]["node-1"]


async def test_a_job_log_without_json_keeps_an_excerpt(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKubectl(
        {"cp-1": "level=fatal msg=unable to load config", "worker-1": {}},
        nodes=["cp-1", "worker-1"],
    )
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert "unable to load config" in result.details["nodes"]["cp-1"]["log"]


def _job_commands(fake: FakeKubectl) -> list[list[str]]:
    return [
        json.loads(stdin or "")["spec"]["template"]["spec"]["containers"][0]["command"]
        for cmd, stdin in fake.calls
        if "create" in cmd
    ]


@pytest.mark.parametrize(
    ("kubelet_version", "benchmark"),
    [
        ("v1.36.3+k3s1", "k3s-cis-1.9"),
        ("v1.27.4+k3s1", "k3s-cis-1.9"),
        ("v1.26.9+k3s1", "k3s-cis-1.8"),
        ("v1.25.2+k3s1", "k3s-cis-1.7"),
        ("v1.24.17+k3s1", "k3s-cis-1.24"),
        ("v1.23.6+k3s1", "k3s-cis-1.23"),
    ],
)
async def test_a_k3s_node_gets_the_k3s_benchmark(
    monkeypatch: pytest.MonkeyPatch, kubelet_version: str, benchmark: str
) -> None:
    fake = FakeKubectl({"Controls": []}, kubelet_version=kubelet_version)
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert _job_commands(fake) == [["kube-bench", "run", "--json", "--benchmark", benchmark]]


async def test_other_nodes_leave_the_benchmark_to_kube_bench(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKubectl({"Controls": []}, kubelet_version="v1.30.2")
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert _job_commands(fake) == [["kube-bench", "run", "--json"]]


async def test_a_worker_node_runs_only_the_node_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKubectl(
        {"Controls": []},
        nodes=["cp-1", "worker-1"],
        kubelet_version="v1.36.3+k3s1",
        control_planes=("cp-1",),
    )
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    await kube_bench.KubeBenchCheck().run(JOB_CTX)

    commands = {
        json.loads(stdin or "")["spec"]["template"]["spec"]["nodeName"]: json.loads(stdin or "")[
            "spec"
        ]["template"]["spec"]["containers"][0]["command"]
        for cmd, stdin in fake.calls
        if "create" in cmd
    }
    assert commands["cp-1"] == ["kube-bench", "run", "--json", "--benchmark", "k3s-cis-1.9"]
    assert commands["worker-1"] == [
        "kube-bench",
        "run",
        "--json",
        "--benchmark",
        "k3s-cis-1.9",
        "--targets",
        "node",
    ]


def test_kube_bench_job_is_opt_in() -> None:
    assert K8sContext().kube_bench_job is False


def _result(status: str, audit: str = "stat -c %a /var/lib/kubelet/config.yaml") -> dict:
    return {"test_number": "x", "status": status, "audit": audit}


# kube-bench's JSON (check/controls.go): Controls[].node_type, tests[].results[].audit.
# From inside a pod on k3s, journal-based audits cannot see the host's journal and
# the control-plane section may not run at all.
K3S_IN_POD_REPORT = {
    "Controls": [
        {
            "node_type": "master",
            "tests": [
                {
                    "results": [
                        _result("FAIL", "journalctl -m -u k3s | grep 'Running kube-apiserver'"),
                        _result("FAIL", "journalctl -m -u k3s | grep 'Running kube-apiserver'"),
                        _result("PASS"),
                    ]
                }
            ],
        },
        {"node_type": "node", "tests": [{"results": [_result("PASS"), _result("FAIL")]}]},
        {"node_type": "policies", "tests": [{"results": [_result("WARN")]}]},
    ]
}


async def test_kube_bench_job_reports_a_partial_benchmark(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKubectl(K3S_IN_POD_REPORT)
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    # Journal-based audits are left out of the counts, not scored as failures.
    assert result.details["pass"] == 2
    assert result.details["fail"] == 1
    assert result.details["warn"] == 1
    assert result.details["unverifiable"] == 2
    assert result.details["sections"] == "master, node, policies"
    assert result.details["missing_sections"] == "controlplane"
    assert result.message.startswith("Partial CIS benchmark")
    assert "controlplane" in result.message and "2 journal-based" in result.message


async def test_a_complete_passing_benchmark_is_not_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    report = {
        "Controls": [
            {"node_type": section, "tests": [{"results": [_result("PASS")]}]}
            for section in ("master", "controlplane", "node", "policies")
        ]
    }
    monkeypatch.setattr(kube_bench, "run_subprocess", FakeKubectl(report))

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert result.status == CheckStatus.PASS
    assert "missing_sections" not in result.details
    assert not result.message.startswith("Partial")


async def test_a_partial_benchmark_without_failures_is_a_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = {"Controls": [{"node_type": "node", "tests": [{"results": [_result("PASS")]}]}]}
    monkeypatch.setattr(kube_bench, "run_subprocess", FakeKubectl(report))

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert result.status == CheckStatus.WARN
