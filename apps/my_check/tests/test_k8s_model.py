"""Checks survive Kubernetes objects without metadata, spec or status."""

from types import SimpleNamespace

import pytest
from kubernetes import client
from my_check.checks.k8s import _load_client, images, pss_compliance, secrets, workloads
from my_check.checks.k8s._model import containers_of, labels_of, name_of, namespace_of
from my_check.checks.k8s.pss_compliance import _check_pss_pod
from my_check.types import K8sContext


def test_missing_metadata_reads_as_empty() -> None:
    bare = SimpleNamespace(metadata=None, spec=None)
    assert (name_of(bare), namespace_of(bare), labels_of(bare)) == ("", "", {})
    assert containers_of(bare) == []


def test_containers_of_includes_init_and_optionally_ephemeral() -> None:
    spec = client.V1PodSpec(
        containers=[client.V1Container(name="app")],
        init_containers=[client.V1Container(name="init")],
        ephemeral_containers=[client.V1EphemeralContainer(name="debug")],
    )
    pod = client.V1Pod(metadata=client.V1ObjectMeta(name="p", namespace="ns"), spec=spec)

    assert [c.name for c in containers_of(pod)] == ["app", "init"]
    assert [c.name for c in containers_of(pod, init=False)] == ["app"]
    assert [c.name for c in containers_of(pod, ephemeral=True)] == ["app", "init", "debug"]
    assert (name_of(pod), namespace_of(pod)) == ("p", "ns")


def test_pss_check_skips_a_pod_without_spec() -> None:
    assert _check_pss_pod(client.V1Pod(metadata=None, spec=None)) == []


def _pod(
    name: str, labels: dict[str, str] | None = None, *, host_pid: bool = False
) -> client.V1Pod:
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name=name, namespace="default", labels=labels),
        spec=client.V1PodSpec(
            host_pid=host_pid,
            containers=[client.V1Container(name="c", image="example/app:1.0")],
        ),
    )


# The kube-bench pod my-check itself runs (--kube-bench-job), next to a pod of the cluster.
MY_CHECK_POD = _pod(
    "my-check-kube-bench-abc123-x1",
    {"app": "kube-bench", "app.kubernetes.io/managed-by": "my-check"},
    host_pid=True,
)
CLUSTER_POD = _pod("web-1", {"app": "web"})


class FakeCore:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def list_pod_for_all_namespaces(self, **kwargs):
        return SimpleNamespace(items=[MY_CHECK_POD, CLUSTER_POD])

    def list_namespaced_pod(self, namespace: str, **kwargs):
        return self.list_pod_for_all_namespaces()


@pytest.mark.parametrize(
    "module",
    [workloads, pss_compliance, images, secrets],
    ids=["workloads", "pss", "images", "secrets"],
)
async def test_pod_checks_skip_the_pods_my_check_runs(
    module, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "_load_client", lambda ctx: None)
    monkeypatch.setattr(module.client, "CoreV1Api", FakeCore)
    # The secrets check also lists CRDs (sealed / external secrets): none here.
    monkeypatch.setattr(
        module.client,
        "ApiextensionsV1Api",
        lambda *a: SimpleNamespace(
            list_custom_resource_definition=lambda: SimpleNamespace(items=[])
        ),
    )
    check = next(
        obj()
        for name, obj in vars(module).items()
        if name.endswith("Check") and isinstance(obj, type)
    )

    result = await check.run(K8sContext())

    assert "my-check-kube-bench" not in repr(result.details)
    assert "my-check-kube-bench" not in result.message


def test_a_kubeconfig_load_failure_logs_its_reason(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    # A kubeconfig whose only context is "default", asked for another one (as when
    # MY_CHECK_K8S_CONTEXT names a context of another kubeconfig).
    kubeconfig = tmp_path / "kubeconfig.yaml"
    kubeconfig.write_text(
        """
apiVersion: v1
kind: Config
current-context: default
clusters: [{name: c, cluster: {server: "https://127.0.0.1:6443"}}]
users: [{name: u, user: {token: t}}]
contexts: [{name: default, context: {cluster: c, user: u}}]
"""
    )

    # No in-cluster config on a test machine either: the error names both causes.
    with pytest.raises(RuntimeError, match="kubeconfig: .*k3s-infra.*; in-cluster config: "):
        _load_client(K8sContext(context_name="k3s-infra", kubeconfig_path=str(kubeconfig)))

    assert "k3s-infra" in caplog.text
