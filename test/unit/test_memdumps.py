import json
import zipfile

from drakrun.analyzer.static import memdumps, sandbox
from drakrun.lib.config import StaticConfigSection

AID = "8f14e45f-ceea-467a-9575-1c4b5d6e7f80"


def make_analysis(tmp_path, dumps):
    adir = tmp_path / "analyses" / AID
    adir.mkdir(parents=True)
    with zipfile.ZipFile(adir / "dumps.zip", "w") as z:
        for name, data in dumps.items():
            z.writestr(f"dumps/{name}", data)
    log = [
        {"DumpFilename": "a_sample_mz", "DumpPID": 100, "ProcessName": "evil.exe",
         "DumpReason": "NtFreeVirtualMemory heuristic", "DumpAddr": "0x400000"},
        {"DumpFilename": "b_other_mz", "DumpPID": 4, "ProcessName": "System", "DumpReason": "CreateRemoteThread"},
        {"DumpFilename": "c_other_data", "DumpPID": 4, "ProcessName": "System", "DumpReason": "free"},
        {"DumpFilename": "d_sample_copy", "DumpPID": 101, "ProcessName": "child.exe", "DumpReason": "write"},
    ]
    (adir / "memdump.log").write_text("\n".join(json.dumps(r) for r in log) + "\nnot json\n")
    tree = [{"seqid": 1, "pid": 4, "children": [{"seqid": 7, "pid": 100, "children": [
        {"seqid": 8, "pid": 101, "children": []}]}]}]
    (adir / "process_tree.json").write_text(json.dumps(tree))
    (adir / "report.json").write_text(json.dumps({"startup": {"process": 7}}))
    return adir


def test_selection_prefers_sample_tree_then_mz(tmp_path):
    adir = make_analysis(tmp_path, {"a_sample_mz": b"MZ" + b"a" * 10, "b_other_mz": b"MZ" + b"b" * 50,
                                    "c_other_data": b"x" * 500, "d_sample_copy": b"MZ" + b"a" * 10,
                                    "e_huge": b"MZ" + b"z" * 5000})
    picked, total = memdumps.select_dumps(adir, 16, 4096)
    assert total == 5
    # sample tree first; within it an injection-type reason ("write") before others; then MZ; huge one dropped
    assert [c["name"] for c in picked] == ["d_sample_copy", "a_sample_mz", "b_other_mz", "c_other_data"]
    assert picked[1]["sample_tree"] and picked[1]["process"] == "evil.exe"


def test_scan_dedupes_and_summarises(tmp_path, monkeypatch):
    adir = make_analysis(tmp_path, {"a_sample_mz": b"MZ" + b"a" * 10, "d_sample_copy": b"MZ" + b"a" * 10,
                                    "b_other_mz": b"MZ" + b"b" * 50})
    seen = []

    def fake_run(settings, dump_id, work, name, deep=False):
        seen.append((name, (work / "in" / "sample").read_bytes()[:2]))
        return {"type": {"format": "pe", "pe_kind": "exe"}, "level": "high", "score": 70,
                "universal": {"yara": [{"rule": "Unpacked_Loader"}], "embedded": [{"type": "pe"}],
                              "iocs": {"urls": ["http://c2.example/x"]}},
                "findings": [{"id": "x", "title": "low one", "severity": "low"},
                             {"id": "y", "title": "high one", "severity": "high", "attack": ["T1055"]}],
                "container": {"backend": "vm"}}

    monkeypatch.setattr(sandbox, "run_in_container", fake_run)
    settings = StaticConfigSection(memdump_scan_max=8)
    doc = memdumps.scan(AID, analyses_dir=tmp_path / "analyses", static_dir=tmp_path / "static",
                        settings=settings)
    assert doc["schema"] == "chimera-memdumps/1" and doc["dumps_total"] == 3
    assert len(doc["scanned"]) == 2 and doc["duplicates"] == 1  # identical contents scanned once
    first = doc["scanned"][0]
    assert first["yara"] == ["Unpacked_Loader"] and first["findings"][0]["severity"] == "high"
    assert first["embedded_executables"] == 1 and first["iocs"]["urls"] == ["http://c2.example/x"]
    assert all(magic == b"MZ" for _, magic in seen)
    assert not (tmp_path / "static" / AID / "memdumps").exists()  # work files removed


def test_scan_reports_unreadable_archive(tmp_path):
    adir = tmp_path / "analyses" / AID
    adir.mkdir(parents=True)
    (adir / "dumps.zip").write_bytes(b"not a zip")
    doc = memdumps.scan(AID, analyses_dir=tmp_path / "analyses", static_dir=tmp_path / "static",
                        settings=StaticConfigSection())
    assert "cannot read dumps.zip" in doc["error"] and doc["scanned"] == []
