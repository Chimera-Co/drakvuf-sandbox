"""Check one Linux analysis of probe.c for the behaviour the probe is known to perform.

    python3 check_probe.py ANALYSIS_DIR   -> one JSON line {"id", "ok", "checks": {name: bool}}
"""
import json
import pathlib
import sys


def walk(nodes):
    for node in nodes:
        yield node
        yield from walk(node.get("children", []))


def main(path):
    d = pathlib.Path(path)
    meta = json.loads((d / "metadata.json").read_text())
    report = json.loads((d / "report.json").read_text()) if (d / "report.json").exists() else {}
    tree = json.loads((d / "process_tree.json").read_text()) if (d / "process_tree.json").exists() else []
    procs = list(walk(tree))
    sample = next((p for p in procs if p["procname"].endswith("/probe-dyn") or p["procname"].endswith("/probe-static")), None)
    sub = list(walk([sample])) if sample else []
    sub_ids = {p["seqid"] for p in sub}
    names = [p["procname"] for p in sub]

    def attributed(entries, pred):
        return any(pred(e) and sub_ids & set(e.get("process_seqids", [])) for e in entries)

    telemetry = meta.get("telemetry") or {}
    checks = {
        "no_error": meta.get("error") is None,
        "telemetry_complete": telemetry.get("complete") is True,
        "monitor_ready": (meta.get("linux") or {}).get("monitor_ready") is True,
        "upload_hash_ok": bool((meta.get("linux") or {}).get("upload", {}).get("sha256")),
        "sample_in_tree": sample is not None,
        "sample_exit_0": sample is not None and sample.get("exit_code") == 0,
        "exec_sh_id_uname": all(any(n.endswith(x) for n in names) for x in ("/dash", "/id", "/uname")),
        "fork_child_exit_3": any(p.get("exit_code") == 3 for p in sub),
        "file_written": attributed(report.get("modified_files", []), lambda e: e["filename"] == "/tmp/chimera-probe.txt"),
        "file_renamed": attributed(report.get("modified_files", []), lambda e: e["filename"] == "/tmp/chimera-probe.moved"),
        "file_deleted": attributed(report.get("deleted_files", []), lambda e: e["filename"] == "/tmp/chimera-probe.moved"),
        "symlink": any(l["link"] == "/tmp/chimera-probe.link" and l["process_seqid"] in sub_ids
                       for l in report.get("linux", {}).get("links", [])),
        "chmod": any(p["filename"] == "/tmp/chimera-probe.moved" and p["process_seqid"] in sub_ids
                     for p in report.get("linux", {}).get("permission_changes", [])),
        "tcp_connect_attributed": attributed(report.get("connections", []),
                                             lambda e: e["remote_ip"] == "203.0.113.10" and e["remote_port"] == 80
                                             and e["protocol"] == "tcp"),
        "dns_attributed": attributed(report.get("dns_queries", []), lambda e: e["domain"] == "probe.chimera.test"),
        "postprocess_ok": not [k for k, v in (meta.get("postprocess") or {}).items() if str(v).startswith("failed")],
    }
    print(json.dumps({"id": d.name, "ok": all(checks.values()), "elapsed_s": meta.get("elapsed_s"),
                      "failed": [k for k, v in checks.items() if not v], "checks": checks}))


if __name__ == "__main__":
    main(sys.argv[1])
