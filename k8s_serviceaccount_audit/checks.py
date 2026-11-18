"""Every check is a pure function from :class:`Cluster` to a list of findings.

Adding a check means writing one function and appending it to :data:`CHECKS`.
Nothing here reads files, prints, or exits.
"""

from __future__ import annotations

from collections.abc import Callable

from .model import (
    Binding,
    Cluster,
    DEFAULT_SA_NAME,
    Finding,
    Pod,
    Ref,
    ServiceAccount,
)

#: Check id -> severity. Also the canonical list of check ids for --only/--skip.
SEVERITY_BY_CHECK = {
    "SA_CLUSTER_ADMIN": "high",
    "DEFAULT_SA_BOUND": "high",
    "POD_UNNEEDED_TOKEN": "medium",
    "DEFAULT_SA_IN_USE": "medium",
    "LEGACY_TOKEN_SECRET": "medium",
    "SA_CROSS_NAMESPACE_BINDING": "medium",
    "POD_MISSING_SA": "medium",
    "MALFORMED_RESOURCE": "medium",
    "SA_UNUSED": "low",
    "ORPHANED_BINDING": "low",
    "AUTOMOUNT_EXPLICIT_TRUE": "low",
}

DESCRIPTIONS = {
    "SA_CLUSTER_ADMIN": "ServiceAccount bound to cluster-admin or a wildcard ClusterRole",
    "DEFAULT_SA_BOUND": "a binding grants permissions to a namespace's default ServiceAccount",
    "POD_UNNEEDED_TOKEN": "pod mounts an API token while its ServiceAccount has no permissions",
    "DEFAULT_SA_IN_USE": "workload pod runs as the namespace default ServiceAccount",
    "LEGACY_TOKEN_SECRET": "long-lived service-account-token Secret left behind",
    "SA_CROSS_NAMESPACE_BINDING": "binding grants a ServiceAccount from another namespace",
    "POD_MISSING_SA": "pod names a ServiceAccount that is not in the input",
    "MALFORMED_RESOURCE": "resource item could not be read",
    "SA_UNUSED": "ServiceAccount referenced by no pod and no binding",
    "ORPHANED_BINDING": "binding subject ServiceAccount does not exist",
    "AUTOMOUNT_EXPLICIT_TRUE": "automountServiceAccountToken explicitly re-enabled",
}

#: ClusterRoles that are full admin even when their rules are not in the input.
ADMIN_ROLE_NAMES = frozenset({"cluster-admin"})


def effective_automount(pod: Pod, account: ServiceAccount | None) -> bool:
    """Pod spec beats ServiceAccount spec beats the Kubernetes default of true."""
    if pod.automount is not None:
        return pod.automount
    if account is not None and account.automount is not None:
        return account.automount
    return True


def _is_admin_role(cluster: Cluster, binding: Binding) -> bool:
    if binding.role_kind == "ClusterRole" and binding.role_name in ADMIN_ROLE_NAMES:
        return True
    role = cluster.roles.get(binding.role_ref)
    return bool(role and role.wildcard)


def _finding(check: str, namespace: str, resource: str, message: str) -> Finding:
    return Finding(
        check=check,
        severity=SEVERITY_BY_CHECK[check],
        namespace=namespace,
        resource=resource,
        message=message,
    )


def check_malformed(cluster: Cluster) -> list[Finding]:
    return [
        _finding("MALFORMED_RESOURCE", problem.namespace, problem.source, problem.reason)
        for problem in cluster.problems
    ]


def check_sa_cluster_admin(cluster: Cluster) -> list[Finding]:
    findings = []
    for binding in cluster.bindings:
        if not _is_admin_role(cluster, binding):
            continue
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount":
                continue
            findings.append(
                _finding(
                    "SA_CLUSTER_ADMIN",
                    subject.namespace,
                    f"ServiceAccount/{subject.ref}",
                    f"bound to {binding.role_kind}/{binding.role_name} by "
                    f"{binding.kind}/{binding.ref}; a token for this account is cluster takeover",
                )
            )
    return findings


def check_default_sa_bound(cluster: Cluster) -> list[Finding]:
    findings = []
    for binding in cluster.bindings:
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount" or subject.name != DEFAULT_SA_NAME:
                continue
            findings.append(
                _finding(
                    "DEFAULT_SA_BOUND",
                    subject.namespace,
                    f"{binding.kind}/{binding.ref}",
                    f"grants {binding.role_kind}/{binding.role_name} to the default ServiceAccount of "
                    f"{subject.namespace or '<unset>'}, so every pod there that names no account gets it",
                )
            )
    return findings


def check_pod_unneeded_token(cluster: Cluster) -> list[Finding]:
    bound = cluster.subject_bindings()
    findings = []
    for pod in cluster.pods:
        if pod.mirror:
            continue
        account = cluster.accounts.get(pod.sa_ref)
        if account is None:
            continue  # reported by POD_MISSING_SA
        if not effective_automount(pod, account):
            continue
        if bound.get(pod.sa_ref):
            continue
        findings.append(
            _finding(
                "POD_UNNEEDED_TOKEN",
                pod.ref.namespace,
                f"Pod/{pod.ref}",
                f"mounts a token for ServiceAccount/{pod.service_account}, which has no Role or "
                "ClusterRole binding; set automountServiceAccountToken: false",
            )
        )
    return findings


def check_default_sa_in_use(cluster: Cluster) -> list[Finding]:
    findings = []
    seen: set[Ref] = set()
    for pod in cluster.pods:
        if pod.mirror or pod.service_account != DEFAULT_SA_NAME:
            continue
        if pod.ref in seen:
            continue
        seen.add(pod.ref)
        owner = f" (owned by {pod.owner_kind})" if pod.owner_kind else ""
        findings.append(
            _finding(
                "DEFAULT_SA_IN_USE",
                pod.ref.namespace,
                f"Pod/{pod.ref}",
                f"runs as the namespace default ServiceAccount{owner}; give it a dedicated identity "
                "so permissions are not shared with every unnamed pod",
            )
        )
    return findings


def check_legacy_token_secret(cluster: Cluster) -> list[Finding]:
    projected = cluster.uses_projected_tokens
    findings = []
    for secret in cluster.token_secrets:
        owner = Ref(secret.ref.namespace, secret.service_account) if secret.service_account else None
        owner_missing = owner is None or owner not in cluster.accounts
        if owner_missing:
            named = f"ServiceAccount/{secret.service_account}" if secret.service_account else "no ServiceAccount"
            reason = f"{named} does not exist, so this token grants an identity nothing owns"
        elif projected:
            reason = (
                "this cluster mounts tokens through projected volumes, so a stored token Secret is a "
                "non-expiring credential nothing needs"
            )
        else:
            continue
        findings.append(
            _finding("LEGACY_TOKEN_SECRET", secret.ref.namespace, f"Secret/{secret.ref}", reason)
        )
    return findings


def check_cross_namespace_binding(cluster: Cluster) -> list[Finding]:
    findings = []
    for binding in cluster.bindings:
        if binding.cluster_scoped:
            continue
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount":
                continue
            if subject.namespace and subject.namespace != binding.ref.namespace:
                findings.append(
                    _finding(
                        "SA_CROSS_NAMESPACE_BINDING",
                        binding.ref.namespace,
                        f"RoleBinding/{binding.ref}",
                        f"grants {binding.role_kind}/{binding.role_name} in {binding.ref.namespace} to "
                        f"ServiceAccount/{subject.ref} from another namespace",
                    )
                )
    return findings


def check_pod_missing_sa(cluster: Cluster) -> list[Finding]:
    if not cluster.accounts:
        return []  # no ServiceAccount input at all; every pod would false-positive
    findings = []
    for pod in cluster.pods:
        if pod.sa_ref in cluster.accounts:
            continue
        findings.append(
            _finding(
                "POD_MISSING_SA",
                pod.ref.namespace,
                f"Pod/{pod.ref}",
                f"names ServiceAccount/{pod.service_account}, which is absent from the input; "
                "the pod cannot start until it exists",
            )
        )
    return findings


def check_sa_unused(cluster: Cluster) -> list[Finding]:
    bound = cluster.subject_bindings()
    used = cluster.pods_by_account()
    findings = []
    for ref, account in sorted(cluster.accounts.items(), key=lambda kv: (kv[0].namespace, kv[0].name)):
        if account.is_default:
            continue  # the default account always exists; DEFAULT_SA_* cover its misuse
        if used.get(ref) or bound.get(ref):
            continue
        findings.append(
            _finding(
                "SA_UNUSED",
                ref.namespace,
                f"ServiceAccount/{ref}",
                "no pod mounts it and no binding grants it anything; delete it",
            )
        )
    return findings


def check_orphaned_binding(cluster: Cluster) -> list[Finding]:
    if not cluster.accounts:
        return []
    findings = []
    for binding in cluster.bindings:
        for subject in binding.subjects:
            if subject.kind != "ServiceAccount" or not subject.namespace:
                continue
            if subject.ref in cluster.accounts:
                continue
            findings.append(
                _finding(
                    "ORPHANED_BINDING",
                    binding.ref.namespace or subject.namespace,
                    f"{binding.kind}/{binding.ref}",
                    f"subject ServiceAccount/{subject.ref} does not exist; the grant will activate the "
                    "moment someone recreates that name",
                )
            )
    return findings


def check_automount_explicit_true(cluster: Cluster) -> list[Finding]:
    findings = []
    for account in sorted(cluster.accounts.values(), key=lambda a: (a.ref.namespace, a.ref.name)):
        if account.automount is True:
            findings.append(
                _finding(
                    "AUTOMOUNT_EXPLICIT_TRUE",
                    account.ref.namespace,
                    f"ServiceAccount/{account.ref}",
                    "sets automountServiceAccountToken: true explicitly; drop the field unless a pod "
                    "really needs the API server",
                )
            )
    for pod in cluster.pods:
        account = cluster.accounts.get(pod.sa_ref)
        if pod.automount is True and account is not None and account.automount is False:
            findings.append(
                _finding(
                    "AUTOMOUNT_EXPLICIT_TRUE",
                    pod.ref.namespace,
                    f"Pod/{pod.ref}",
                    f"re-enables token automounting that ServiceAccount/{pod.service_account} "
                    "deliberately disabled",
                )
            )
    return findings


CHECKS: tuple[Callable[[Cluster], list[Finding]], ...] = (
    check_malformed,
    check_sa_cluster_admin,
    check_default_sa_bound,
    check_pod_unneeded_token,
    check_default_sa_in_use,
    check_legacy_token_secret,
    check_cross_namespace_binding,
    check_pod_missing_sa,
    check_sa_unused,
    check_orphaned_binding,
    check_automount_explicit_true,
)


def run(cluster: Cluster) -> list[Finding]:
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(cluster))
    return findings
