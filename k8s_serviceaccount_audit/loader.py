"""Turn whatever ``kubectl get -o json`` produced into a :class:`Cluster`.

Accepted shapes, in any mix:

* a ``{"kind": "List", "items": [...]}`` wrapper (what ``kubectl get a,b,c`` emits)
* a single resource object
* a top-level JSON array of objects
* several objects concatenated in one stream (``kubectl get a -o json; kubectl get b -o json``)
* a file, several files, a directory of ``*.json``, or ``-`` for stdin
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from .model import (
    MIRROR_POD_ANNOTATION,
    SA_NAME_ANNOTATION,
    TOKEN_SECRET_TYPE,
    Binding,
    Cluster,
    DEFAULT_SA_NAME,
    LoadProblem,
    Pod,
    Ref,
    RoleDef,
    ServiceAccount,
    Subject,
    TokenSecret,
)

KNOWN_KINDS = frozenset(
    {
        "ServiceAccount",
        "Pod",
        "Secret",
        "RoleBinding",
        "ClusterRoleBinding",
        "Role",
        "ClusterRole",
    }
)

WRAPPER_KINDS = ("List",)


class InputError(Exception):
    """Input could not be read or is not Kubernetes JSON. Maps to exit code 2."""


def _decode_stream(text: str, source: str) -> list[object]:
    """Decode one or more concatenated JSON documents from ``text``."""
    decoder = json.JSONDecoder()
    documents: list[object] = []
    index = 0
    length = len(text)
    while index < length:
        while index < length and text[index] in " \t\r\n":
            index += 1
        if index >= length:
            break
        try:
            document, index = decoder.raw_decode(text, index)
        except ValueError as exc:
            raise InputError(f"{source}: not valid JSON ({exc.args[0]})") from exc
        documents.append(document)
    if not documents:
        raise InputError(f"{source}: empty input")
    return documents


def _read_sources(paths: Iterable[str]) -> Iterator[tuple[str, str]]:
    seen_any = False
    for raw in paths:
        if raw == "-":
            seen_any = True
            yield "<stdin>", sys.stdin.read()
            continue
        path = Path(raw)
        if path.is_dir():
            files = sorted(p for p in path.rglob("*.json") if p.is_file())
            if not files:
                raise InputError(f"{raw}: directory contains no .json files")
            for file in files:
                seen_any = True
                yield str(file), file.read_text(encoding="utf-8")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"{raw}: {exc.strerror or exc}") from exc
        seen_any = True
        yield str(path), text
    if not seen_any:
        raise InputError("no input given")


def _flatten(document: object, source: str, out: list[tuple[str, dict]]) -> None:
    if isinstance(document, list):
        for item in document:
            _flatten(item, source, out)
        return
    if not isinstance(document, dict):
        raise InputError(f"{source}: expected a JSON object, got {type(document).__name__}")
    kind = document.get("kind")
    if isinstance(kind, str) and (kind in WRAPPER_KINDS or kind.endswith("List")):
        items = document.get("items")
        if items is None:
            return
        if not isinstance(items, list):
            raise InputError(f"{source}: .items is not a list")
        for item in items:
            _flatten(item, source, out)
        return
    out.append((source, document))


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _str(value: object, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _subjects(raw: object, binding_namespace: str) -> list[Subject]:
    subjects: list[Subject] = []
    if not isinstance(raw, list):
        return subjects
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = _str(item.get("kind"))
        name = _str(item.get("name"))
        if not kind or not name:
            continue
        namespace = _str(item.get("namespace"))
        if kind == "ServiceAccount" and not namespace:
            # A RoleBinding may omit it; it then means the binding's namespace.
            namespace = binding_namespace
        subjects.append(Subject(kind=kind, name=name, namespace=namespace))
    return subjects


def _has_wildcard(rules: object) -> bool:
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = rule.get("verbs") or []
        resources = rule.get("resources") or []
        groups = rule.get("apiGroups") or []
        urls = rule.get("nonResourceURLs") or []
        if "*" in verbs and ("*" in resources or "*" in urls):
            return True
        if "*" in verbs and "*" in groups and resources:
            return True
    return False


def _pod_token_usage(spec: dict) -> tuple[bool, list[str]]:
    """Return (uses a projected token, names of mounted legacy token Secrets)."""
    projected = False
    secrets: list[str] = []
    volumes = spec.get("volumes")
    if not isinstance(volumes, list):
        return projected, secrets
    for volume in volumes:
        if not isinstance(volume, dict):
            continue
        secret = volume.get("secret")
        if isinstance(secret, dict):
            name = _str(secret.get("secretName"))
            if name:
                secrets.append(name)
        sources = (volume.get("projected") or {}).get("sources") if isinstance(volume.get("projected"), dict) else None
        if isinstance(sources, list):
            for source in sources:
                if isinstance(source, dict) and isinstance(source.get("serviceAccountToken"), dict):
                    projected = True
                secret_source = source.get("secret") if isinstance(source, dict) else None
                if isinstance(secret_source, dict):
                    name = _str(secret_source.get("name"))
                    if name:
                        secrets.append(name)
    return projected, secrets


def build_cluster(items: list[tuple[str, dict]]) -> Cluster:
    cluster = Cluster()
    for source, item in items:
        kind = _str(item.get("kind"))
        if kind:
            cluster.kinds_seen.add(kind)
        if kind not in KNOWN_KINDS:
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict) or not _str(metadata.get("name")):
            cluster.problems.append(
                LoadProblem(source=source, reason=f"{kind or 'resource'} without usable metadata.name")
            )
            continue
        name = _str(metadata.get("name"))
        namespace = _str(metadata.get("namespace"))
        annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
        ref = Ref(namespace, name)

        if kind == "ServiceAccount":
            raw_secrets = item.get("secrets")
            secrets = [
                _str(entry.get("name"))
                for entry in raw_secrets
                if isinstance(entry, dict) and _str(entry.get("name"))
            ] if isinstance(raw_secrets, list) else []
            cluster.accounts[ref] = ServiceAccount(
                ref=ref,
                automount=_bool_or_none(item.get("automountServiceAccountToken")),
                secrets=secrets,
            )
        elif kind == "Pod":
            spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
            account = _str(spec.get("serviceAccountName")) or _str(spec.get("serviceAccount")) or DEFAULT_SA_NAME
            owners = metadata.get("ownerReferences")
            owner_kind = ""
            if isinstance(owners, list) and owners and isinstance(owners[0], dict):
                owner_kind = _str(owners[0].get("kind"))
            projected, mounted = _pod_token_usage(spec)
            cluster.pods.append(
                Pod(
                    ref=ref,
                    service_account=account,
                    automount=_bool_or_none(spec.get("automountServiceAccountToken")),
                    owner_kind=owner_kind,
                    mirror=MIRROR_POD_ANNOTATION in annotations,
                    projected_token=projected,
                    mounted_token_secrets=mounted,
                )
            )
        elif kind == "Secret":
            if _str(item.get("type")) != TOKEN_SECRET_TYPE:
                continue
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            cluster.token_secrets.append(
                TokenSecret(
                    ref=ref,
                    service_account=_str(annotations.get(SA_NAME_ANNOTATION)),
                    has_token_data=bool(data.get("token")),
                )
            )
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = item.get("roleRef") if isinstance(item.get("roleRef"), dict) else {}
            cluster.bindings.append(
                Binding(
                    ref=ref,
                    kind=kind,
                    role_kind=_str(role_ref.get("kind"), "Role"),
                    role_name=_str(role_ref.get("name")),
                    subjects=_subjects(item.get("subjects"), namespace),
                )
            )
        elif kind in ("Role", "ClusterRole"):
            cluster.roles[ref] = RoleDef(ref=ref, kind=kind, wildcard=_has_wildcard(item.get("rules")))
    return cluster


def load(paths: Iterable[str]) -> Cluster:
    """Load every path into one cluster model, or raise :class:`InputError`."""
    items: list[tuple[str, dict]] = []
    for source, text in _read_sources(paths):
        for document in _decode_stream(text, source):
            _flatten(document, source, items)
    if not items:
        raise InputError("input contained no resources")
    cluster = build_cluster(items)
    if not cluster.kinds_seen & KNOWN_KINDS:
        seen = ", ".join(sorted(cluster.kinds_seen)) or "none"
        raise InputError(
            "input has none of ServiceAccount, Pod, Secret, RoleBinding, ClusterRoleBinding "
            f"(kinds seen: {seen})"
        )
    return cluster


def default_input() -> list[str]:
    """``-`` when stdin is a pipe, so the tool composes with kubectl directly."""
    if not sys.stdin.isatty() and not os.environ.get("K8S_SA_AUDIT_NO_STDIN"):
        return ["-"]
    return []
