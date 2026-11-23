"""Checks survive Kubernetes objects without metadata, spec or status."""

from types import SimpleNamespace

from kubernetes import client
from my_check.checks.k8s._model import containers_of, labels_of, name_of, namespace_of
from my_check.checks.k8s.pss_compliance import _check_pss_pod


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
