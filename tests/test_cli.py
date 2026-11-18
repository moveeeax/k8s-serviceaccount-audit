from __future__ import annotations

import csv
import io
import json

import pytest

from k8s_serviceaccount_audit.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_dirty_cluster_exits_1_and_prints_a_table(capsys, dirty_cluster):
    code, out, _ = run(capsys, "--input", str(dirty_cluster))
    assert code == 1
    assert "SEVERITY" in out and "SA_CLUSTER_ADMIN" in out
    assert "finding(s):" in out


def test_clean_cluster_exits_0(capsys, clean_cluster):
    code, out, _ = run(capsys, "--input", str(clean_cluster))
    assert code == 0
    assert out.strip() == "No ServiceAccount findings."


def test_json_output_is_parsable(capsys, dirty_cluster):
    code, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json")
    assert code == 1
    payload = json.loads(out)
    assert payload["summary"]["total"] == len(payload["findings"])
    assert payload["summary"]["high"] > 0
    assert {"check", "severity", "namespace", "resource", "message"} == set(payload["findings"][0])


def test_csv_output_has_a_header_and_rows(capsys, dirty_cluster):
    code, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "csv")
    assert code == 1
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == ["severity", "check", "namespace", "resource", "message"]
    assert len(rows) > 5


def test_findings_are_sorted_high_first(capsys, dirty_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json")
    severities = [f["severity"] for f in json.loads(out)["findings"]]
    order = {"high": 0, "medium": 1, "low": 2}
    assert severities == sorted(severities, key=lambda s: order[s])


def test_severity_floor_drops_lower_findings(capsys, dirty_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json", "--severity", "high")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"high"}


def test_only_restricts_to_one_check(capsys, dirty_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json", "--only", "SA_UNUSED")
    assert {f["check"] for f in json.loads(out)["findings"]} == {"SA_UNUSED"}


def test_skip_removes_a_check(capsys, dirty_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json", "--skip", "SA_UNUSED")
    assert "SA_UNUSED" not in {f["check"] for f in json.loads(out)["findings"]}


def test_only_and_skip_compose_with_severity(capsys, dirty_cluster):
    _, out, _ = run(
        capsys,
        "--input",
        str(dirty_cluster),
        "--format",
        "json",
        "--only",
        "SA_UNUSED,SA_CLUSTER_ADMIN",
        "--skip",
        "SA_CLUSTER_ADMIN",
        "--severity",
        "low",
    )
    assert {f["check"] for f in json.loads(out)["findings"]} == {"SA_UNUSED"}


def test_only_with_a_severity_floor_above_the_check_yields_nothing(capsys, dirty_cluster):
    code, out, _ = run(
        capsys, "--input", str(dirty_cluster), "--only", "SA_UNUSED", "--severity", "high", "--format", "json"
    )
    assert code == 0
    assert json.loads(out)["findings"] == []


def test_namespace_scopes_the_report(capsys, dirty_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json", "--namespace", "payments")
    assert {f["namespace"] for f in json.loads(out)["findings"]} == {"payments"}


def test_ignore_namespace_drops_it(capsys, dirty_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--format", "json", "--ignore-namespace", "ops")
    assert "ops" not in {f["namespace"] for f in json.loads(out)["findings"]}


def test_fail_on_none_always_exits_0(capsys, dirty_cluster):
    code, _, _ = run(capsys, "--input", str(dirty_cluster), "--fail-on", "none")
    assert code == 0


def test_fail_on_high_ignores_low_findings(capsys, tmp_path):
    payload = {"kind": "List", "items": [{"kind": "ServiceAccount", "metadata": {"name": "idle", "namespace": "app"}}]}
    path = tmp_path / "c.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert run(capsys, "--input", str(path), "--fail-on", "high")[0] == 0
    assert run(capsys, "--input", str(path), "--fail-on", "low")[0] == 1


def test_unreadable_input_exits_2_with_one_line(capsys, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{oh no", encoding="utf-8")
    code, out, err = run(capsys, "--input", str(path))
    assert code == 2
    assert out == ""
    assert len(err.strip().splitlines()) == 1
    assert err.startswith("k8s-serviceaccount-audit:")


def test_missing_file_exits_2(capsys, tmp_path):
    assert run(capsys, "--input", str(tmp_path / "nope.json"))[0] == 2


def test_non_kubernetes_input_exits_2(capsys, tmp_path):
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"kind": "Deployment", "metadata": {"name": "d"}}), encoding="utf-8")
    assert run(capsys, "--input", str(path))[0] == 2


def test_unknown_check_id_is_rejected(capsys, dirty_cluster):
    with pytest.raises(SystemExit) as excinfo:
        main(["--input", str(dirty_cluster), "--only", "NOPE"])
    assert "unknown check id" in str(excinfo.value)


def test_several_inputs_merge(capsys, dirty_cluster, clean_cluster):
    _, out, _ = run(capsys, "--input", str(dirty_cluster), "--input", str(clean_cluster), "--format", "json")
    namespaces = {f["namespace"] for f in json.loads(out)["findings"]}
    assert "payments" in namespaces and "shop" not in namespaces


def test_stdin_is_read_for_dash(capsys, monkeypatch, dirty_cluster):
    monkeypatch.setattr("sys.stdin", io.StringIO(dirty_cluster.read_text(encoding="utf-8")))
    code, out, _ = run(capsys, "--input", "-", "--format", "json")
    assert code == 1
    assert json.loads(out)["summary"]["total"] > 0


def test_list_checks_prints_every_id(capsys):
    code, out, _ = run(capsys, "--list-checks")
    assert code == 0
    assert out.count("\n") == 11
    assert "SA_CLUSTER_ADMIN" in out and "high" in out


def test_no_input_and_a_tty_is_a_usage_error(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", Tty(""))
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2  # argparse usage error


def test_stdin_is_ignored_when_the_escape_hatch_is_set(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setenv("K8S_SA_AUDIT_NO_STDIN", "1")
    with pytest.raises(SystemExit):
        main([])
