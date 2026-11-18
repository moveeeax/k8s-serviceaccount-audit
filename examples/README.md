# Examples

Both files are real `kubectl get serviceaccounts,pods,secrets,rolebindings,clusterrolebindings,clusterroles -A -o json`
shapes, trimmed to the fields the audit reads. The test suite asserts against them, so they
cannot drift from the checks.

## clean-cluster.json

A namespace that passes: one dedicated ServiceAccount with one RoleBinding, pods that name it,
a worker with `automountServiceAccountToken: false` and no binding, no token Secrets.

```bash
k8s-serviceaccount-audit --input examples/clean-cluster.json
# No ServiceAccount findings.   (exit 0)
```

## dirty-cluster.json

Triggers all eleven checks at once:

- `payments/legacy-worker` — an account nothing mounts and nothing binds (`SA_UNUSED`), with its
  pre-1.24 token Secret still around (`LEGACY_TOKEN_SECRET`).
- `payments/web-*` — a ReplicaSet pod on the namespace `default` account
  (`DEFAULT_SA_IN_USE`), and a RoleBinding that grants that account a Role
  (`DEFAULT_SA_BOUND`).
- `ops/deployer` — bound to `cluster-admin`, and `ops/tenant-operator` bound to a home-grown
  wildcard ClusterRole; both are `SA_CLUSTER_ADMIN`, the second only because `clusterroles`
  are in the dump.
- `ops/metrics` — `automountServiceAccountToken: true` with no binding anywhere
  (`AUTOMOUNT_EXPLICIT_TRUE` + `POD_UNNEEDED_TOKEN`).
- `ops/ops-grants-payments` — a RoleBinding reaching into another namespace
  (`SA_CROSS_NAMESPACE_BINDING`).
- `ops/import-job-*` — a pod naming an account that is not in the dump (`POD_MISSING_SA`), and
  `retired-bot-reader`, a ClusterRoleBinding whose subject is gone (`ORPHANED_BINDING`).
- One item that lost its `metadata` on the way out of a backup tool (`MALFORMED_RESOURCE`) —
  reported, while everything else is still audited.

```bash
k8s-serviceaccount-audit --input examples/dirty-cluster.json            # exit 1
k8s-serviceaccount-audit --input examples/dirty-cluster.json --severity high
k8s-serviceaccount-audit --input examples/dirty-cluster.json --format json --fail-on high
```
