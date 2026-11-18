from __future__ import annotations

import json

import pytest

from conftest import (
    clusterrolebinding,
    findings_from,
    ids,
    pod,
    rolebinding,
    sa,
    token_secret,
)
from k8s_serviceaccount_audit import checks
from k8s_serviceaccount_audit.loader import build_cluster, load
from k8s_serviceaccount_audit.model import Pod, Ref, ServiceAccount


# --- SA_UNUSED ---------------------------------------------------------------


def test_unused_account_is_reported_once():
    findings = [f for f in findings_from(sa("legacy-worker")) if f.check == "SA_UNUSED"]
    assert len(findings) == 1
    assert findings[0].namespace == "app"
    assert findings[0].resource == "ServiceAccount/app/legacy-worker"
    assert findings[0].severity == "low"


def test_account_with_a_pod_is_not_unused():
    assert "SA_UNUSED" not in ids(findings_from(sa("api"), pod("api-1", "api")))


def test_account_with_only_a_binding_is_not_unused():
    assert "SA_UNUSED" not in ids(findings_from(sa("api"), rolebinding("rb", "api")))


def test_default_account_is_never_unused():
    assert "SA_UNUSED" not in ids(findings_from(sa("default")))


# --- DEFAULT_SA_IN_USE / DEFAULT_SA_BOUND ------------------------------------


def test_pod_on_default_account():
    findings = [f for f in findings_from(sa("default"), pod("web-1", "default")) if f.check == "DEFAULT_SA_IN_USE"]
    assert len(findings) == 1
    assert "Pod/app/web-1" == findings[0].resource


def test_pod_with_no_service_account_field_counts_as_default():
    item = {"kind": "Pod", "metadata": {"name": "web-1", "namespace": "app"}, "spec": {}}
    assert "DEFAULT_SA_IN_USE" in ids(findings_from(sa("default"), item))


def test_mirror_pod_on_default_is_ignored():
    item = pod("kube-apiserver-node1", "default", metadata={"annotations": {"kubernetes.io/config.mirror": "abc"}})
    assert "DEFAULT_SA_IN_USE" not in ids(findings_from(sa("default"), item))


def test_binding_to_default_account_is_high():
    findings = [f for f in findings_from(sa("default"), rolebinding("rb", "default")) if f.check == "DEFAULT_SA_BOUND"]
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "default ServiceAccount of app" in findings[0].message


# --- SA_CLUSTER_ADMIN --------------------------------------------------------


def test_cluster_admin_binding_names_account_and_role():
    findings = [
        f
        for f in findings_from(sa("deployer"), pod("deployer-1", "deployer"), clusterrolebinding("crb", "deployer"))
        if f.check == "SA_CLUSTER_ADMIN"
    ]
    assert len(findings) == 1
    assert findings[0].resource == "ServiceAccount/app/deployer"
    assert "cluster-admin" in findings[0].message
    assert findings[0].severity == "high"


def test_wildcard_clusterrole_counts_as_admin():
    wildcard = {
        "kind": "ClusterRole",
        "metadata": {"name": "everything"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    }
    findings = findings_from(
        sa("op"), pod("op-1", "op"), clusterrolebinding("crb", "op", role="everything"), wildcard
    )
    assert "SA_CLUSTER_ADMIN" in ids(findings)


def test_narrow_clusterrole_is_not_admin():
    viewer = {
        "kind": "ClusterRole",
        "metadata": {"name": "viewer"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
    }
    findings = findings_from(sa("op"), pod("op-1", "op"), clusterrolebinding("crb", "op", role="viewer"), viewer)
    assert "SA_CLUSTER_ADMIN" not in ids(findings)


# --- POD_UNNEEDED_TOKEN ------------------------------------------------------


def test_pod_without_any_binding_mounts_a_useless_token():
    findings = [f for f in findings_from(sa("api"), pod("api-1", "api")) if f.check == "POD_UNNEEDED_TOKEN"]
    assert len(findings) == 1
    assert "automountServiceAccountToken: false" in findings[0].message


def test_bound_account_keeps_its_token():
    findings = findings_from(sa("api"), pod("api-1", "api"), rolebinding("rb", "api"))
    assert "POD_UNNEEDED_TOKEN" not in ids(findings)


def test_automount_false_on_account_silences_the_check():
    findings = findings_from(sa("api", automountServiceAccountToken=False), pod("api-1", "api"))
    assert "POD_UNNEEDED_TOKEN" not in ids(findings)


def test_pod_spec_beats_account_spec():
    findings = findings_from(
        sa("api", automountServiceAccountToken=True),
        pod("api-1", "api", spec={"automountServiceAccountToken": False}),
    )
    assert "POD_UNNEEDED_TOKEN" not in ids(findings)


@pytest.mark.parametrize(
    ("pod_value", "account_value", "expected"),
    [
        (None, None, True),
        (None, True, True),
        (None, False, False),
        (True, False, True),
        (False, True, False),
    ],
)
def test_effective_automount_precedence(pod_value, account_value, expected):
    account = ServiceAccount(ref=Ref("app", "api"), automount=account_value)
    subject = Pod(ref=Ref("app", "api-1"), service_account="api", automount=pod_value)
    assert checks.effective_automount(subject, account) is expected


def test_effective_automount_without_account_defaults_true():
    subject = Pod(ref=Ref("app", "api-1"), service_account="api")
    assert checks.effective_automount(subject, None) is True


# --- LEGACY_TOKEN_SECRET -----------------------------------------------------


def test_token_secret_in_a_projected_cluster_is_a_leftover():
    findings = [
        f
        for f in findings_from(
            sa("api"), pod("api-1", "api", projected=True), rolebinding("rb", "api"), token_secret("api-token", "api")
        )
        if f.check == "LEGACY_TOKEN_SECRET"
    ]
    assert len(findings) == 1
    assert "projected volumes" in findings[0].message


def test_token_secret_for_a_missing_account_is_reported_even_without_projection():
    findings = [
        f for f in findings_from(sa("api"), token_secret("ghost-token", "ghost")) if f.check == "LEGACY_TOKEN_SECRET"
    ]
    assert len(findings) == 1
    assert "does not exist" in findings[0].message


def test_token_secret_in_a_pre_124_cluster_with_a_live_owner_is_left_alone():
    findings = findings_from(sa("api"), pod("api-1", "api"), token_secret("api-token", "api"))
    assert "LEGACY_TOKEN_SECRET" not in ids(findings)


# --- SA_CROSS_NAMESPACE_BINDING ---------------------------------------------


def test_cross_namespace_subject_is_reported():
    findings = [
        f
        for f in findings_from(
            sa("api", namespace="payments"),
            pod("api-1", "api", namespace="payments"),
            rolebinding("rb", "api", namespace="ops", subject_namespace="payments"),
        )
        if f.check == "SA_CROSS_NAMESPACE_BINDING"
    ]
    assert len(findings) == 1
    assert findings[0].namespace == "ops"
    assert "payments/api" in findings[0].message


def test_same_namespace_subject_is_fine():
    findings = findings_from(sa("api"), pod("api-1", "api"), rolebinding("rb", "api"))
    assert "SA_CROSS_NAMESPACE_BINDING" not in ids(findings)


def test_clusterrolebinding_is_not_a_cross_namespace_finding():
    findings = findings_from(sa("api"), pod("api-1", "api"), clusterrolebinding("crb", "api", role="view"))
    assert "SA_CROSS_NAMESPACE_BINDING" not in ids(findings)


# --- POD_MISSING_SA / ORPHANED_BINDING --------------------------------------


def test_pod_naming_an_absent_account_is_reported_not_dropped():
    findings = [f for f in findings_from(sa("api"), pod("job-1", "importer")) if f.check == "POD_MISSING_SA"]
    assert len(findings) == 1
    assert "ServiceAccount/importer" in findings[0].message


def test_pod_missing_sa_is_silent_when_no_accounts_were_supplied():
    assert "POD_MISSING_SA" not in ids(findings_from(pod("job-1", "importer")))


def test_binding_to_an_absent_account_is_orphaned():
    findings = [f for f in findings_from(sa("api"), rolebinding("rb", "gone")) if f.check == "ORPHANED_BINDING"]
    assert len(findings) == 1
    assert findings[0].severity == "low"


# --- AUTOMOUNT_EXPLICIT_TRUE -------------------------------------------------


def test_account_explicitly_enabling_automount():
    findings = [
        f
        for f in findings_from(sa("api", automountServiceAccountToken=True), pod("api-1", "api"), rolebinding("rb", "api"))
        if f.check == "AUTOMOUNT_EXPLICIT_TRUE"
    ]
    assert len(findings) == 1
    assert findings[0].resource == "ServiceAccount/app/api"


def test_pod_overriding_a_hardened_account():
    findings = [
        f
        for f in findings_from(
            sa("api", automountServiceAccountToken=False),
            pod("api-1", "api", spec={"automountServiceAccountToken": True}),
            rolebinding("rb", "api"),
        )
        if f.check == "AUTOMOUNT_EXPLICIT_TRUE"
    ]
    assert len(findings) == 1
    assert findings[0].resource == "Pod/app/api-1"


# --- MALFORMED_RESOURCE ------------------------------------------------------


def test_malformed_item_is_a_finding_and_the_rest_is_still_audited():
    cluster = build_cluster([("dump.json", {"kind": "ServiceAccount"}), ("dump.json", sa("legacy"))])
    findings = checks.run(cluster)
    assert ids(findings).count("MALFORMED_RESOURCE") == 1
    assert "SA_UNUSED" in ids(findings)


# --- whole-cluster fixtures --------------------------------------------------


def test_clean_cluster_has_no_findings(clean_cluster):
    assert checks.run(load([str(clean_cluster)])) == []


def test_dirty_cluster_covers_every_check(dirty_cluster):
    found = set(ids(checks.run(load([str(dirty_cluster)]))))
    assert found == set(checks.SEVERITY_BY_CHECK)


def test_every_check_has_a_severity_and_a_description():
    assert set(checks.SEVERITY_BY_CHECK) == set(checks.DESCRIPTIONS)
    assert all(v in ("high", "medium", "low") for v in checks.SEVERITY_BY_CHECK.values())


def test_dirty_cluster_fixture_is_valid_json(dirty_cluster):
    assert json.loads(dirty_cluster.read_text(encoding="utf-8"))["kind"] == "List"
