# k8s-serviceaccount-audit

[![ci](https://github.com/moveeeax/k8s-serviceaccount-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-serviceaccount-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit Kubernetes ServiceAccounts from static `kubectl` JSON. Finds accounts nothing mounts,
pods carrying an API token they have no permissions to use, workloads riding the namespace
`default` account, long-lived token Secrets left behind by a pre-1.24 cluster, and
ServiceAccounts quietly bound to `cluster-admin`.

No API server, no kubeconfig, no cluster credentials at audit time. Dump once, audit anywhere,
including in CI on a pull request that touches manifests.

## Why

`kubectl get sa` prints a name and a secret count. It does not tell you who mounts an account,
so one left over from a deleted Deployment looks exactly like the one your controller
authenticates with. Meanwhile every pod defaults to `automountServiceAccountToken: true`, which
puts a signed JWT at `/var/run/secrets/kubernetes.io/serviceaccount/token` inside containers that
never speak to the API server — the most useful thing an attacker finds after a container escape.
A single `RoleBinding` to the `default` account grants that permission to every unnamed pod in
the namespace. All of it is derivable from JSON.

## Install

```bash
pip install git+https://github.com/moveeeax/k8s-serviceaccount-audit
```

Python 3.11+, standard library only.

## Usage

```bash
kubectl get serviceaccounts,pods,secrets,rolebindings,clusterrolebindings -A -o json > cluster.json
k8s-serviceaccount-audit --input cluster.json
```

```
SEVERITY  CHECK                       NAMESPACE  RESOURCE                                    MESSAGE
--------  --------------------------  ---------  ------------------------------------------  -------
high      DEFAULT_SA_BOUND            payments   RoleBinding/payments/default-config-reader  grants Role/config-reader to the default ServiceAccount of payments, so every pod there that names no account gets it
high      SA_CLUSTER_ADMIN            ops        ServiceAccount/ops/deployer                 bound to ClusterRole/cluster-admin by ClusterRoleBinding/deployer-admin; a token for this account is cluster takeover
medium    POD_UNNEEDED_TOKEN          ops        Pod/ops/metrics-0                           mounts a token for ServiceAccount/metrics, which has no Role or ClusterRole binding; set automountServiceAccountToken: false
medium    SA_CROSS_NAMESPACE_BINDING  ops        RoleBinding/ops/ops-grants-payments         grants Role/deploy-trigger in ops to ServiceAccount/payments/payments-api from another namespace
low       SA_UNUSED                   payments   ServiceAccount/payments/legacy-worker       no pod mounts it and no binding grants it anything; delete it

13 finding(s): 3 high, 7 medium, 3 low
```

Pipe it straight from `kubectl`, point it at a directory of dumps, or combine several files:

```bash
kubectl get sa,pods,secrets,rolebindings,clusterrolebindings -A -o json | k8s-serviceaccount-audit
k8s-serviceaccount-audit --input dump/ --format json --fail-on high
k8s-serviceaccount-audit --input cluster.json --only SA_UNUSED,DEFAULT_SA_IN_USE --ignore-namespace kube-system
```

Optionally include `roles,clusterroles` in the dump. When the rules are present,
`SA_CLUSTER_ADMIN` also catches home-grown wildcard roles, not just `cluster-admin` by name.

## Checks

| Check | Severity | What it means |
| --- | --- | --- |
| `SA_CLUSTER_ADMIN` | high | ServiceAccount bound to `cluster-admin` or a wildcard ClusterRole |
| `DEFAULT_SA_BOUND` | high | a binding grants permissions to a namespace's `default` account |
| `POD_UNNEEDED_TOKEN` | medium | pod mounts an API token while its account has no binding at all |
| `DEFAULT_SA_IN_USE` | medium | workload pod runs as the namespace `default` account |
| `LEGACY_TOKEN_SECRET` | medium | `kubernetes.io/service-account-token` Secret nothing needs, or whose owner is gone |
| `SA_CROSS_NAMESPACE_BINDING` | medium | RoleBinding grants an account from another namespace |
| `POD_MISSING_SA` | medium | pod names a ServiceAccount absent from the input |
| `MALFORMED_RESOURCE` | medium | a resource item could not be read |
| `SA_UNUSED` | low | ServiceAccount referenced by no pod and no binding |
| `ORPHANED_BINDING` | low | binding subject ServiceAccount does not exist |
| `AUTOMOUNT_EXPLICIT_TRUE` | low | `automountServiceAccountToken: true` set explicitly |

`k8s-serviceaccount-audit --list-checks` prints the same table from the installed version.

## How it works

Three stages, no shared state.

1. **Load.** `loader.py` reads files, directories or stdin and flattens whatever came back —
   a `List` wrapper, a bare object, a JSON array, or several documents concatenated in one
   stream — into a single cluster model. Pods resolve their effective automount decision
   (pod spec beats ServiceAccount spec beats the Kubernetes default of `true`), token Secrets
   join to accounts by the `kubernetes.io/service-account.name` annotation, and bindings are
   indexed by subject. A resource that lost its `metadata` becomes a finding, not a crash.
2. **Check.** Every check in `checks.py` is a pure function from the model to a list of
   findings. Nothing reads files or prints.
3. **Render and exit.** `--format table|json|csv`, `--severity` as a floor, `--only`/`--skip`
   by check id, `--namespace`/`--ignore-namespace`, and `--fail-on high|medium|low|none` for
   the exit code.

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` unreadable or
non-Kubernetes input.

## In CI

```yaml
- name: Audit ServiceAccounts
  run: |
    kubectl get serviceaccounts,pods,secrets,rolebindings,clusterrolebindings -A -o json > cluster.json
    k8s-serviceaccount-audit --input cluster.json --fail-on high --ignore-namespace kube-system
```

## Examples

`examples/clean-cluster.json` is a namespace that passes: one dedicated account with one
RoleBinding, a worker with automounting switched off, no leftover token Secrets.
`examples/dirty-cluster.json` triggers all eleven checks. Both are the test suite's fixtures,
so they stay honest.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## License

MIT
