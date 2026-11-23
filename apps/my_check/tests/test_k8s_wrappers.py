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
