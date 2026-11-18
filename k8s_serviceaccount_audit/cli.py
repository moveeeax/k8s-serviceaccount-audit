"""Command line entrypoint: load, check, filter, render, exit."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import checks, loader, render
from .model import Finding, SEVERITIES, SEVERITY_ORDER

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2

PROG = "k8s-serviceaccount-audit"


def _split(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or ():
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Audit Kubernetes ServiceAccounts offline from kubectl JSON. Reads files, "
            "directories or stdin and never contacts an API server."
        ),
        epilog="checks: " + ", ".join(sorted(checks.SEVERITY_BY_CHECK)),
    )
    parser.add_argument(
        "--input",
        "-i",
        action="append",
        metavar="PATH",
        help="JSON file, directory of .json files, or - for stdin (repeatable)",
    )
    parser.add_argument(
        "--format", "-f", choices=sorted(render.RENDERERS), default="table", help="output format"
    )
    parser.add_argument(
        "--severity",
        choices=SEVERITIES,
        default="low",
        help="report findings at this severity or higher (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "none"),
        default="low",
        help="exit 1 when a finding at this severity or higher survives filtering (default: low)",
    )
    parser.add_argument("--only", action="append", metavar="IDS", help="report only these check ids")
    parser.add_argument("--skip", action="append", metavar="IDS", help="never report these check ids")
    parser.add_argument(
        "--namespace", "-n", action="append", metavar="NS", help="restrict to these namespaces"
    )
    parser.add_argument(
        "--ignore-namespace", action="append", metavar="NS", help="drop findings in these namespaces"
    )
    parser.add_argument("--list-checks", action="store_true", help="print every check id and exit")
    parser.add_argument("--version", action="version", version=f"{PROG} 0.1.0")
    return parser


def _validate_ids(ids: list[str], flag: str) -> None:
    unknown = [i for i in ids if i not in checks.SEVERITY_BY_CHECK]
    if unknown:
        raise SystemExit(f"{PROG}: {flag}: unknown check id(s): {', '.join(unknown)}")


def select(findings: list[Finding], args: argparse.Namespace) -> list[Finding]:
    only = set(_split(args.only))
    skip = set(_split(args.skip))
    namespaces = set(_split(args.namespace))
    ignored = set(_split(args.ignore_namespace))
    floor = SEVERITY_ORDER[args.severity]

    kept = []
    for finding in findings:
        if only and finding.check not in only:
            continue
        if finding.check in skip:
            continue
        if SEVERITY_ORDER.get(finding.severity, 99) > floor:
            continue
        if namespaces and finding.namespace not in namespaces:
            continue
        if finding.namespace and finding.namespace in ignored:
            continue
        kept.append(finding)
    return kept


def exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_CLEAN
    threshold = SEVERITY_ORDER[fail_on]
    triggered = any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in findings)
    return EXIT_FINDINGS if triggered else EXIT_CLEAN


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        for check in sorted(checks.SEVERITY_BY_CHECK, key=lambda c: (SEVERITY_ORDER[checks.SEVERITY_BY_CHECK[c]], c)):
            print(f"{check:<28} {checks.SEVERITY_BY_CHECK[check]:<7} {checks.DESCRIPTIONS[check]}")
        return EXIT_CLEAN

    _validate_ids(_split(args.only), "--only")
    _validate_ids(_split(args.skip), "--skip")

    paths = _split(args.input) or loader.default_input()
    if not paths:
        parser.error("no --input given and stdin is a terminal")

    try:
        cluster = loader.load(paths)
    except loader.InputError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_INPUT

    findings = select(checks.run(cluster), args)
    print(render.render(findings, args.format))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
