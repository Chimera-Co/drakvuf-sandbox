import json
from pathlib import Path

from chimera_clf.cape_adapter import adapt_report, load_hooks

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "bginfo-96f7ee81-features.json"


def call(api, ts="2024-01-01 10:00:00,000", repeated=0, category="misc", status=True, **args):
    return {"api": api, "timestamp": ts, "repeated": repeated, "category": category, "status": status,
            "thread_id": "1", "arguments": [{"name": k, "value": v} for k, v in args.items()]}


def report(processes):
    return {"target": {"file": {"name": "sample.exe", "sha256": "AB" * 32, "type": "PE32", "size": 10}},
            "behavior": {"processes": processes, "processtree": []}, "signatures": [], "detections": []}


def proc(pid, ppid, name, calls, first_seen="2024-01-01 10:00:00,000"):
    return {"process_id": pid, "parent_id": ppid, "process_name": name, "module_path": "C:\\x\\" + name,
            "first_seen": first_seen, "calls": calls}


def test_schema_matches_chimera_fixture():
    def shape(d):
        return {k: (shape(v) if isinstance(v, dict) and k not in ("api_calls",) else type(v).__name__)
                for k, v in d.items()}
    chimera = json.loads(FIXTURE.read_text())
    ours = adapt_report(report([proc(1, 0, "sample.exe", [call("LdrLoadDll")])]))["features"]
    assert shape(ours) == shape(chimera)


def test_scope_window_repeats_implied_and_hooks():
    calls = [
        call("LoadLibraryExW"),                                  # implies LdrLoadDll
        call("CreateProcessW", ts="2024-01-01 10:00:01,000"),    # implies CreateProcessInternalW
        call("RegOpenKeyExW", repeated=2, ts="2024-01-01 10:00:02,000"),
        call("NtClose"),                                         # not hooked by CHIMERA
        call("LdrGetProcedureAddressForCaller"),                 # deliberately not aliased
        call("RegSetValueExA", ts="2024-01-01 10:00:59,000", category="registry",
             FullName="HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"),
        call("WriteProcessMemory", ts="2024-01-01 10:05:00,000"),  # outside a 60 s window
    ]
    child = proc(2, 1, "child.exe", [call("NtSetValueKey", category="registry", FullName="HKEY_X\\k"),
                                     call("NtCreateFile", category="filesystem", FileName="C:\\a.exe",
                                          ExistedBefore="no", CreateDisposition="2")])
    other = proc(3, 99, "svchost.exe", [call("CreateRemoteThread")])  # not a descendant
    rec = adapt_report(report([proc(1, 0, "sample.exe", calls), child, other]), window_s=60)
    f = rec["features"]
    assert f["processes"]["count"] == 2 and f["processes"]["max_depth"] == 1
    assert f["api_calls"]["LdrLoadDll"] == 1
    assert f["api_calls"]["CreateProcessInternalW"] == 1
    assert f["api_calls"]["RegOpenKeyExW"] == 3
    assert "CreateProcessW" not in f["api_calls"]          # not in hooks.txt
    assert "NtClose" not in f["api_calls"]
    assert "LdrGetProcedureAddress" not in f["api_calls"]
    assert "WriteProcessMemory" not in f["api_calls"]       # outside window
    assert "CreateRemoteThread" not in f["api_calls"]       # outside scope
    assert set(f["api_calls"]) <= load_hooks()
    assert f["registry"]["set_value"] == 2                   # RegSetValueExA + NtSetValueKey
    assert f["registry"]["autorun_touched"] is True
    assert f["files"]["created"] == 1
    assert f["api_sequence"][:2] == ["LdrLoadDll", "CreateProcessInternalW"]
    assert rec["aux"]["root_method"] == "name"
