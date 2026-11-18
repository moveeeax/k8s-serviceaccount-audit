"""Finding renderers: table for humans, json for pipelines, csv for spreadsheets."""

from __future__ import annotations

import csv
import io
import json

from .model import Finding, SEVERITY_ORDER

COLUMNS = ("SEVERITY", "CHECK", "NAMESPACE", "RESOURCE", "MESSAGE")


def sort_key(finding: Finding) -> tuple:
    return (
        SEVERITY_ORDER.get(finding.severity, 99),
        finding.check,
        finding.namespace,
        finding.resource,
    )


def render_table(findings: list[Finding]) -> str:
    if not findings:
        return "No ServiceAccount findings."
    rows = [
        (f.severity, f.check, f.namespace or "-", f.resource, f.message)
        for f in findings
    ]
    widths = [len(c) for c in COLUMNS]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    # The message column is last, so it is never padded.
    widths[-1] = len(COLUMNS[-1])

    def line(cells: tuple[str, ...]) -> str:
        parts = [cell.ljust(widths[i]) for i, cell in enumerate(cells[:-1])]
        parts.append(cells[-1])
        return "  ".join(parts).rstrip()

    out = [line(COLUMNS), line(tuple("-" * w for w in widths))]
    out.extend(line(row) for row in rows)
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(
        f"{counts[sev]} {sev}" for sev in ("high", "medium", "low") if sev in counts
    )
    out.append("")
    out.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(out)


def render_json(findings: list[Finding]) -> str:
    payload = {
        "findings": [f.as_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_csv(findings: list[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([c.lower() for c in COLUMNS])
    for finding in findings:
        writer.writerow(
            [finding.severity, finding.check, finding.namespace, finding.resource, finding.message]
        )
    return buffer.getvalue().rstrip("\n")


RENDERERS = {"table": render_table, "json": render_json, "csv": render_csv}


def render(findings: list[Finding], fmt: str) -> str:
    return RENDERERS[fmt](sorted(findings, key=sort_key))
