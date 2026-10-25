"""Combined report (chimera-report/1): scoping, evidence links and a page that cannot run anything."""

import hashlib
import json
import re

from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
    build_chimera_report,
    build_report,
    render_html,
)

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'&"


def write_analysis(directory, static=None, verdict=None, startup="Success"):
    directory.mkdir(exist_ok=True)
    meta = {
        "id": directory.name,
        "status": "finished",
        "vm_id": 1,
        "options": {
            "guest_os": "windows",
            "timeout": 180,
            "sample_filename": "sample.exe",
            "start_command": HOSTILE,
        },
        "telemetry": {
            "complete": True,
            "plugins": {"procmon": {"status": "produced"}},
        },
    }
    report = {
        "info": {
            "file": {
                "name": HOSTILE + ".exe",
                "sha256": "a" * 64,
                "size_bytes": 10,
                "type": "PE32+",
            }
        },
        "startup": {"status": startup, "process": 10},
        "processes": [
            {"seqid": 1, "parent_seqid": None, "name": "C:\\Windows\\explorer.exe"},
            {"seqid": 10, "parent_seqid": 1, "name": "C:\\Users\\u\\sample.exe"},
            {"seqid": 11, "parent_seqid": 10, "name": "C:\\Windows\\cmd.exe"},
            {"seqid": 20, "parent_seqid": 1, "name": "C:\\Windows\\svchost.exe"},
        ],
        "modified_files": [
            {"filename": "C:\\dropped.dll", "process_seqids": [11]},
            {"filename": "C:\\os-noise.log", "process_seqids": [20]},
        ],
        "dns_queries": [
            {"domain": "evil.example", "process_seqid": 10},
            {"domain": "windowsupdate.example", "process_seqid": 20},
        ],
        "ttps": [
            {"name": "Run key", "att&ck": ["T1547.001"], "process_seqids": [11]},
            {"name": "OS noise", "att&ck": ["T1082"], "process_seqids": [20]},
        ],
    }
    features = {"sample": {"sha256": "a" * 64}}
    if static is not None:
        features["static"] = static
    (directory / "metadata.json").write_text(json.dumps(meta))
    (directory / "report.json").write_text(json.dumps(report))
    (directory / "features.json").write_text(json.dumps(features))
    if verdict is not None:
        (directory / "classification.json").write_text(json.dumps(verdict))
    return directory


STATIC = {
    "analyzer_version": "0.1.0",
    "type": {"format": "pe"},
    "coverage": {"complete": True, "type_plugin": "pe", "failed_stages": []},
    "file": {"sha256": "a" * 64, "ssdeep": "3:x:y"},
    "findings": [
        {
            "title": "Packed section",
            "severity": "high",
            "source": "pe",
            "attack": ["T1027"],
        },
        {"title": "Imports GetTickCount", "severity": "low", "source": "pe"},
    ],
}
VERDICT = {
    "schema": "chimera-verdict/1",
    "label": "malicious",
    "score": 0.81,
    "model": "chimera-fusion",
    "model_version": "0.1",
    "explanation": [HOSTILE],
    "components": {
        "dynamic": {"label": "malicious", "score": 0.9, "explanation": [HOSTILE]}
    },
}


def test_scoped_to_the_sample_tree(tmp_path):
    r = build_report(write_analysis(tmp_path / "a1", STATIC, VERDICT))
    assert r["schema"] == "chimera-report/1"
    assert r["status"] == "complete" and r["mode"] == "combined"
    text = json.dumps(r["claims"])
    assert "dropped.dll" in text and "os-noise.log" not in text
    assert [i["value"] for i in r["iocs"] if i["type"] == "domain"] == ["evil.example"]
    assert {a["technique"] for a in r["attack"]} == {"T1547.001", "T1027"}
    assert r["stages"]["dynamic"]["payload"]["processes_in_tree"] == 2
    assert any("2 other guest process" in x for x in r["limitations"])
    # low-severity static findings stay in static.json, not in the report's claims
    assert "GetTickCount" not in text


def test_every_reference_resolves_to_hashed_evidence(tmp_path):
    directory = write_analysis(tmp_path / "a2", STATIC, VERDICT)
    r = build_report(directory)
    ids = [e["id"] for e in r["evidence"]]
    assert len(ids) == len(set(ids))
    assert len({(e["artifact"], e["selector"]) for e in r["evidence"]}) == len(ids)
    groups = (r["claims"], r["attack"], r["iocs"], r["stages"].values())
    refs = [
        i
        for group in groups + ([r["assessment"]],)
        for item in group
        for i in item.get("evidence_ids") or []
    ]
    assert refs and set(refs) <= set(ids)
    report_sha = hashlib.sha256((directory / "report.json").read_bytes()).hexdigest()
    shas = {e["sha256"] for e in r["evidence"] if e["artifact"] == "report.json"}
    assert shas == {report_sha}


def test_missing_parts_are_reported_not_invented(tmp_path):
    r = build_report(write_analysis(tmp_path / "a3", startup="Failed"))
    assert r["status"] == "partial" and r["mode"] == "dynamic-only"
    assert r["stages"]["static"]["status"] == "unavailable"
    assert r["stages"]["classifier"]["status"] == "unavailable"
    assert r["assessment"]["confidence"] == "unknown"
    assert r["assessment"]["text"].startswith("No verdict")
    assert r["claims"][0]["id"] == "start"

    partial = dict(
        STATIC, coverage={"complete": False, "type_plugin": None, "failed_stages": []}
    )
    r = build_report(write_analysis(tmp_path / "a4", partial, VERDICT))
    assert r["stages"]["static"]["status"] == "partial"
    assert r["stages"]["static"]["reason"] == "no parser for pe files"
    assert r["status"] == "partial"


def test_page_escapes_guest_strings_and_loads_nothing(tmp_path):
    page = render_html(build_report(write_analysis(tmp_path / "a5", STATIC, VERDICT)))
    assert "<script" not in page.lower() and "<img" not in page.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "default-src 'none'" in page
    assert not re.search(r"(src|href)\s*=\s*['\"]?(https?:)?//", page, re.I)
    assert not re.search(r"href=['\"](?!#)", page)
    assert "0.81" in page and "not a probability" in page
    for n in range(1, 9):
        assert f"<h2>{n}. " in page


def test_plugin_writes_both_files_and_flags_metadata(tmp_path):
    directory = write_analysis(tmp_path / "a6", STATIC, VERDICT)

    class Context:
        analysis_dir = directory

        def __init__(self):
            self.flags = {}

        def update_metadata(self, metadata):
            self.flags.update(metadata)

    context = Context()
    build_chimera_report(context)
    report = json.loads((directory / "chimera-report.json").read_text())
    assert report["analysis_id"] == "a6"
    page = (directory / "chimera-report.html").read_text()
    assert page.startswith("<!doctype html>")
    assert context.flags == {"chimera_report": True}
