"""Offline checks of the G7 label-review tool in scripts/chimera/bench."""

import csv
import importlib.util
import json
import pathlib

BENCH = pathlib.Path(__file__).resolve().parents[2] / "scripts/chimera/bench"
spec = importlib.util.spec_from_file_location("label_review", BENCH / "label_review.py")
lr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lr)


def analysis(root, uid, stderr="", early=False):
    d = root / uid
    d.mkdir(parents=True)
    (d / "metadata.json").write_text(json.dumps({"timeout": 180, "telemetry": {"drakvuf_exited_early": early}}))
    (d / "drakvuf_stderr.log").write_text(stderr)
    (d / "report.json").write_text(json.dumps({
        "startup": {"status": "Success", "process_name": "C:\\Users\\Public\\setup.exe", "pid": 7, "process": 10},
        "processes": [
            {"seqid": 1, "parent_seqid": None, "pid": 4, "name": "System", "args": [], "started_at": 0.0},
            {"seqid": 10, "parent_seqid": 1, "pid": 7, "name": "setup.exe", "args": ["/S"], "started_at": 100.0},
            {"seqid": 11, "parent_seqid": 10, "pid": 8, "name": "cmd.exe", "args": [], "started_at": 101.5},
        ],
        "modified_files": [{"filename": "C:\\Users\\Public\\x.dll", "process_seqids": [11]}],
        "dns_queries": [{"domain": "example.test", "process_seqids": [10]}],
        "connections": [], "http_requests": [{"verb": "GET", "path": "/a", "process_seqid": 11}],
    }))
    (d / "regmon.log").write_text(
        json.dumps({"TimeStamp": "99.0", "PID": 4, "Method": "NtSetValueKey", "Key": "\\BEFORE"}) + "\n"
        + json.dumps({"TimeStamp": "102.0", "PID": 8, "ProcessName": "cmd.exe", "Method": "NtSetValueKey",
                      "Key": "\\REGISTRY\\RUN", "ValueName": "x", "Value": "C:\\x.exe"}) + "\n"
        + json.dumps({"TimeStamp": "103.0", "PID": 8, "Method": "NtQueryValueKey", "Key": "\\READ"}) + "\n"
    )
    return d


def test_strict_complete_needs_complete_telemetry_no_early_exit_and_no_error_line(tmp_path):
    assert lr.is_strict(analysis(tmp_path, "a", "DRAKVUF v1.1\n"), {"telemetry_complete": True})
    assert not lr.is_strict(analysis(tmp_path, "b", "VMI_ERROR: xen_request_page_fault error -1\n"),
                            {"telemetry_complete": True})
    assert not lr.is_strict(analysis(tmp_path, "c", early=True), {"telemetry_complete": True})
    assert not lr.is_strict(analysis(tmp_path, "d"), {"telemetry_complete": False})


def test_draw_is_seeded_and_stratified():
    runs = [{"role": role, "strict": strict, "task_uid": f"{role}{strict}{i}"}
            for role in ("malware", "benign") for strict in (True, False) for i in range(15)]
    chosen = lr.draw(runs, 10, seed=5)
    assert chosen == lr.draw(runs, 10, seed=5) and len(chosen) == 40
    assert all(sum((r["role"], r["strict"]) == cell for r in chosen) == 10
               for cell in {(r["role"], r["strict"]) for r in runs})
    # Shuffled together, not presented cell by cell
    assert [r["role"] for r in chosen] != sorted(r["role"] for r in chosen)


def test_sheet_hides_labels_and_keeps_the_key_apart(tmp_path):
    analyses = tmp_path / "analyses"
    results = tmp_path / "results.jsonl"
    rows = []
    for i in range(3):
        analysis(analyses, f"uid{i}")
        rows.append({"task_uid": f"uid{i}", "telemetry_complete": True, "executed": True, "children": 1,
                     "persistence": True, "file_drops": 1, "network_intent": True, "family": "Secret"})
    results.write_text("".join(json.dumps(r) + "\n" for r in rows))
    out, key = tmp_path / "review", tmp_path / "private/key.csv"
    lr.main(["sheet", "--results", f"malware={results}", "--per-cell", "2", "--seed", "1", "--out", str(out),
             "--key", str(key), "--analyses", str(analyses)])
    assert sorted(p.name for p in out.iterdir()) == ["R01", "R02", "README.md", "review-form.csv"]
    shown = "".join(p.read_text() for p in out.rglob("*") if p.is_file())
    assert "Secret" not in shown and "malware" not in shown and "uid" not in shown
    registry = list(csv.DictReader((out / "R01/registry_writes.csv").open()))
    assert [(r["key"], r["time_s"]) for r in registry] == [("\\REGISTRY\\RUN", "2.0")]  # value writes since start
    processes = list(csv.DictReader((out / "R01/processes.csv").open()))
    assert processes[2]["started_s"] == "1.5" and processes[2]["parent_seqid"] == "10"
    assert "11 cmd.exe" in (out / "R01/network.csv").read_text()
    keyed = list(csv.DictReader(key.open()))
    assert [k["run"] for k in keyed] == ["R01", "R02"] and keyed[0]["network_intent"] == "True"


def test_agreement_and_kappa():
    assert lr.cohen_kappa([(True, True), (False, False)]) == (1.0, 2, 2)
    kappa, agree, n = lr.cohen_kappa([(True, True), (True, False), (False, False), (False, True)])
    assert (round(kappa, 6), agree, n) == (0.0, 2, 4)
    assert lr.cohen_kappa([(True, True)] * 3)[0] is None  # no variation: undefined
    key = [{"run": "R01", "role": "benign", **{lab: "True" for lab in lr.LABELS}},
           {"run": "R02", "role": "benign", **{lab: "False" for lab in lr.LABELS}}]
    a = [{"run": "R01", **{lab: "yes" for lab in lr.LABELS}}, {"run": "R02", **{lab: "no" for lab in lr.LABELS}}]
    b = [{"run": "R01", **{lab: "no" for lab in lr.LABELS}}, {"run": "R02", **{lab: "" for lab in lr.LABELS}}]
    b[0]["executed"] = "yes"
    table, consensus = lr.agreement(key, {"A": a, "B": b})
    rows = {(r["label"], r["pair"]): r for r in table}
    assert rows[("network_intent", "automatic vs A")]["agree"] == 2
    assert rows[("network_intent", "automatic vs B")]["n"] == 1  # an empty cell is left out
    net = next(c for c in consensus if c["label"] == "network_intent")
    assert net["reviewers_disagree"] == 2
    executed = next(c for c in consensus if c["label"] == "executed")
    assert executed["auto_yes_reviewers_yes"] == 1 and executed["reviewers_disagree"] == 1
