"""Cluster model: the normalised shape every check reads.

The loader flattens mixed-kind ``kubectl get -o json`` output into these
dataclasses so that checks never touch raw dicts and never care whether the
input arrived as a List wrapper, a directory of files or a concatenated stream.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_SA_NAME = "default"
TOKEN_SECRET_TYPE = "kubernetes.io/service-account-token"  # noqa: S105 - a type string
SA_NAME_ANNOTATION = "kubernetes.io/service-account.name"
MIRROR_POD_ANNOTATION = "kubernetes.io/config.mirror"

SEVERITIES = ("high", "medium", "low")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Ref:
    """A namespace/name pair. ``namespace`` is empty for cluster-scoped objects."""

    namespace: str
    name: str

    def __str__(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name


@dataclass
class ServiceAccount:
    ref: Ref
    automount: bool | None = None
    secrets: list[str] = field(default_factory=list)

    @property
    def is_default(self) -> bool:
        return self.ref.name == DEFAULT_SA_NAME


@dataclass
class Pod:
    ref: Ref
    service_account: str = DEFAULT_SA_NAME
    automount: bool | None = None
    owner_kind: str = ""
    mirror: bool = False
    projected_token: bool = False
    mounted_token_secrets: list[str] = field(default_factory=list)

    @property
    def sa_ref(self) -> Ref:
        return Ref(self.ref.namespace, self.service_account)


@dataclass
class TokenSecret:
    ref: Ref
    service_account: str = ""
    has_token_data: bool = False


@dataclass(frozen=True)
class Subject:
    kind: str
    name: str
    namespace: str

    @property
    def ref(self) -> Ref:
        return Ref(self.namespace, self.name)


@dataclass
class Binding:
    ref: Ref
    kind: str = "RoleBinding"
    role_kind: str = "Role"
    role_name: str = ""
    subjects: list[Subject] = field(default_factory=list)

    @property
    def cluster_scoped(self) -> bool:
        return self.kind == "ClusterRoleBinding"

    @property
    def role_ref(self) -> Ref:
        # A RoleBinding may reference a ClusterRole, which is cluster-scoped.
        namespace = "" if self.role_kind == "ClusterRole" else self.ref.namespace
        return Ref(namespace, self.role_name)


@dataclass
class RoleDef:
    ref: Ref
    kind: str = "Role"
    wildcard: bool = False


@dataclass
class LoadProblem:
    """A resource item we could not read. Reported as a finding, never fatal."""

    source: str
    reason: str
    namespace: str = ""


@dataclass
class Cluster:
    accounts: dict[Ref, ServiceAccount] = field(default_factory=dict)
    pods: list[Pod] = field(default_factory=list)
    token_secrets: list[TokenSecret] = field(default_factory=list)
    bindings: list[Binding] = field(default_factory=list)
    roles: dict[Ref, RoleDef] = field(default_factory=dict)
    problems: list[LoadProblem] = field(default_factory=list)
    kinds_seen: set[str] = field(default_factory=set)

    @property
    def uses_projected_tokens(self) -> bool:
        """True when at least one pod gets its token through a projected volume.

        A 1.24+ cluster mounts every token this way, so the presence of one
        projected token means the long-lived token Secrets are leftovers.
        """
        return any(pod.projected_token for pod in self.pods)

    def subject_bindings(self) -> dict[Ref, list[Binding]]:
        """ServiceAccount -> every binding that names it as a subject."""
        index: dict[Ref, list[Binding]] = {}
        for binding in self.bindings:
            for subject in binding.subjects:
                if subject.kind != "ServiceAccount":
                    continue
                index.setdefault(subject.ref, []).append(binding)
        return index

    def pods_by_account(self) -> dict[Ref, list[Pod]]:
        index: dict[Ref, list[Pod]] = {}
        for pod in self.pods:
            index.setdefault(pod.sa_ref, []).append(pod)
        return index


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    namespace: str
    resource: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "check": self.check,
            "severity": self.severity,
            "namespace": self.namespace,
            "resource": self.resource,
            "message": self.message,
        }
