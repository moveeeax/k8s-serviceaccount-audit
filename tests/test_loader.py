from __future__ import annotations

import json

import pytest

from conftest import pod, sa
from k8s_serviceaccount_audit.loader import InputError, load
from k8s_serviceaccount_audit.model import Ref


def write(tmp_path, name: str, payload) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_list_wrapper(tmp_path):
    path = write(tmp_path, "c.json", {"kind": "List", "items": [sa("api"), pod("api-1", "api")]})
    cluster = load([path])
    assert Ref("app", "api") in cluster.accounts
    assert [p.ref.name for p in cluster.pods] == ["api-1"]


def test_bare_object(tmp_path):
    cluster = load([write(tmp_path, "sa.json", sa("api"))])
    assert list(cluster.accounts) == [Ref("app", "api")]


def test_top_level_array(tmp_path):
    cluster = load([write(tmp_path, "a.json", [sa("api"), sa("worker")])])
    assert len(cluster.accounts) == 2


def test_concatenated_stream(tmp_path):
    path = tmp_path / "stream.json"
    path.write_text(json.dumps(sa("api")) + "\n" + json.dumps(pod("api-1", "api")), encoding="utf-8")
    cluster = load([str(path)])
    assert cluster.accounts and cluster.pods


def test_directory_of_files(tmp_path):
    directory = tmp_path / "dump"
    directory.mkdir()
    (directory / "sa.json").write_text(json.dumps({"kind": "List", "items": [sa("api")]}), encoding="utf-8")
    (directory / "pods.json").write_text(json.dumps({"kind": "PodList", "items": [pod("api-1", "api")]}), encoding="utf-8")
    cluster = load([str(directory)])
    assert len(cluster.accounts) == 1
    assert len(cluster.pods) == 1


def test_several_inputs(tmp_path):
    first = write(tmp_path, "one.json", sa("api"))
    second = write(tmp_path, "two.json", pod("api-1", "api"))
    cluster = load([first, second])
    assert cluster.accounts and cluster.pods


def test_automount_and_owner_are_parsed(tmp_path):
    payload = {
        "kind": "List",
        "items": [
            sa("api", automountServiceAccountToken=False),
            pod("api-1", "api", metadata={"ownerReferences": [{"kind": "DaemonSet", "name": "api"}]}),
        ],
    }
    cluster = load([write(tmp_path, "c.json", payload)])
    assert cluster.accounts[Ref("app", "api")].automount is False
    assert cluster.pods[0].owner_kind == "DaemonSet"


def test_only_token_type_secrets_are_kept(tmp_path):
    payload = {
        "kind": "List",
        "items": [
            sa("api"),
            {"kind": "Secret", "metadata": {"name": "db", "namespace": "app"}, "type": "Opaque"},
            {
                "kind": "Secret",
                "metadata": {
                    "name": "api-token",
                    "namespace": "app",
                    "annotations": {"kubernetes.io/service-account.name": "api"},
                },
                "type": "kubernetes.io/service-account-token",
            },
        ],
    }
    cluster = load([write(tmp_path, "c.json", payload)])
    assert [s.ref.name for s in cluster.token_secrets] == ["api-token"]


def test_rolebinding_subject_namespace_defaults_to_binding(tmp_path):
    payload = {
        "kind": "List",
        "items": [
            sa("api"),
            {
                "kind": "RoleBinding",
                "metadata": {"name": "rb", "namespace": "app"},
                "roleRef": {"kind": "Role", "name": "r"},
                "subjects": [{"kind": "ServiceAccount", "name": "api"}],
            },
        ],
    }
    cluster = load([write(tmp_path, "c.json", payload)])
    assert cluster.bindings[0].subjects[0].namespace == "app"


def test_wildcard_clusterrole_is_detected(tmp_path):
    payload = {
        "kind": "List",
        "items": [
            sa("api"),
            {
                "kind": "ClusterRole",
                "metadata": {"name": "everything"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            },
            {
                "kind": "ClusterRole",
                "metadata": {"name": "viewer"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
            },
        ],
    }
    cluster = load([write(tmp_path, "c.json", payload)])
    assert cluster.roles[Ref("", "everything")].wildcard is True
    assert cluster.roles[Ref("", "viewer")].wildcard is False


def test_item_without_metadata_becomes_a_problem(tmp_path):
    payload = {"kind": "List", "items": [sa("api"), {"kind": "Pod", "spec": {}}]}
    cluster = load([write(tmp_path, "c.json", payload)])
    assert len(cluster.problems) == 1
    assert "metadata.name" in cluster.problems[0].reason
    assert cluster.accounts, "the readable resources are still loaded"


def test_unreadable_json_raises_input_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="not valid JSON"):
        load([str(path)])


def test_missing_file_raises_input_error(tmp_path):
    with pytest.raises(InputError):
        load([str(tmp_path / "absent.json")])


def test_non_kubernetes_json_raises_input_error(tmp_path):
    with pytest.raises(InputError, match="none of ServiceAccount"):
        load([write(tmp_path, "x.json", {"kind": "Deployment", "metadata": {"name": "d"}})])


def test_empty_directory_raises_input_error(tmp_path):
    directory = tmp_path / "empty"
    directory.mkdir()
    with pytest.raises(InputError, match="no .json files"):
        load([str(directory)])
