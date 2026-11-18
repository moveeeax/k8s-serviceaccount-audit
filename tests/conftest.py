from __future__ import annotations

from pathlib import Path

import pytest

from k8s_serviceaccount_audit import checks
from k8s_serviceaccount_audit.loader import build_cluster
from k8s_serviceaccount_audit.model import Cluster

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def cluster_from(*items: dict) -> Cluster:
    """Build a cluster model straight from resource dicts, no files involved."""
    return build_cluster([("<test>", item) for item in items])


def findings_from(*items: dict) -> list:
    return checks.run(cluster_from(*items))


def ids(findings) -> list[str]:
    return [f.check for f in findings]


def sa(name: str, namespace: str = "app", **spec) -> dict:
    return {"kind": "ServiceAccount", "metadata": {"name": name, "namespace": namespace}, **spec}


def pod(name: str, account: str = "default", namespace: str = "app", projected: bool = False, **extra) -> dict:
    spec: dict = {"serviceAccountName": account}
    if projected:
        spec["volumes"] = [{"name": "kube-api-access", "projected": {"sources": [{"serviceAccountToken": {}}]}}]
    spec.update(extra.pop("spec", {}))
    metadata = {"name": name, "namespace": namespace}
    metadata.update(extra.pop("metadata", {}))
    return {"kind": "Pod", "metadata": metadata, "spec": spec}


def rolebinding(
    name: str,
    account: str,
    namespace: str = "app",
    subject_namespace: str | None = None,
    role: str = "config-reader",
    role_kind: str = "Role",
) -> dict:
    return {
        "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": namespace},
        "roleRef": {"kind": role_kind, "name": role},
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": account,
                "namespace": subject_namespace if subject_namespace is not None else namespace,
            }
        ],
    }


def clusterrolebinding(name: str, account: str, namespace: str = "app", role: str = "cluster-admin") -> dict:
    return {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "roleRef": {"kind": "ClusterRole", "name": role},
        "subjects": [{"kind": "ServiceAccount", "name": account, "namespace": namespace}],
    }


def token_secret(name: str, account: str, namespace: str = "app") -> dict:
    return {
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {"kubernetes.io/service-account.name": account},
        },
        "type": "kubernetes.io/service-account-token",
        "data": {"token": "dG9rZW4="},
    }


@pytest.fixture
def dirty_cluster() -> Path:
    return EXAMPLES / "dirty-cluster.json"


@pytest.fixture
def clean_cluster() -> Path:
    return EXAMPLES / "clean-cluster.json"
