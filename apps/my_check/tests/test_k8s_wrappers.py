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

    def __init__(self, logs: Any, job_status: str = "1/") -> None:
        self.logs = logs
        self.job_status = job_status  # {.status.succeeded}/{.status.failed}
        self.calls: list[tuple[list[str], str | None]] = []

    async def __call__(
        self,
        cmd: list[str],
        *,
        timeout: float = 120.0,
        env: dict[str, str] | None = None,
        stdin: str | None = None,
    ) -> SubprocessResult:
        self.calls.append((cmd, stdin))
        if "get" in cmd:
            return SubprocessResult(0, self.job_status, "")
        if "logs" in cmd:
            return SubprocessResult(0, json.dumps(self.logs), "")
        return SubprocessResult(0, "", "")

    def verbs(self) -> list[str]:
        return [
            next(v for v in ("create", "get", "logs", "delete") if v in cmd)
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

    assert fake.verbs() == ["create", "get", "logs", "delete"]
    for cmd, _ in fake.calls:
        assert cmd[0] == "kubectl"
        assert cmd[cmd.index("--context") + 1] == "prod"
        assert cmd[cmd.index("--kubeconfig") + 1] == "/home/me/.kube/prod"
        assert cmd[cmd.index("--namespace") + 1] == "app"
    manifest = json.loads(fake.calls[0][1] or "")
    job_name = manifest["metadata"]["name"]
    assert all(job_name in " ".join(cmd) for cmd, _ in fake.calls[1:])
    assert result.details["scope"] == "cluster (Job on one node)"
    assert result.details["fail"] == 1
    assert "prod" in result.message


async def test_a_failed_kube_bench_job_is_reported_at_once_and_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKubectl({}, job_status="/1")
    monkeypatch.setattr(kube_bench, "run_subprocess", fake)

    result = await kube_bench.KubeBenchCheck().run(JOB_CTX)

    assert fake.verbs() == ["create", "get", "delete"]
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

    assert fake.verbs() == ["create", "get", "get", "logs", "delete"]
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
