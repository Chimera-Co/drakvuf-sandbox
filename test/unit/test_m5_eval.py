"""Offline checks of the M5 evaluation tooling in scripts/chimera/bench."""

import csv
import importlib.util
import json
import pathlib

import pytest

BENCH = pathlib.Path(__file__).resolve().parents[2] / "scripts/chimera/bench"


def load(name):
    spec = importlib.util.spec_from_file_location(name, BENCH / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m5 = load("m5_eval")
samples = load("m5_samples")
SHA = ["%064x" % i for i in range(1, 5)]


def write_analysis(tmp_path, processes, report=None, regmon=(), status="finished", rc=0):
    d = tmp_path / "analysis"
    d.mkdir()
    (d / "metadata.json").write_text(
        json.dumps(
            {
                "status": status,
                "time_execution_started": "2026-10-20T07:30:53+00:00",
                "telemetry": {"drakvuf_returncode": rc, "drakvuf_hard_timeout": False},
            }
        )
    )
    body = {"startup": {"status": "Success", "process": 10}, "processes": processes}
    body.update(report or {})
    (d / "report.json").write_text(json.dumps(body))
    (d / "regmon.log").write_text("".join(json.dumps(e) + "\n" for e in regmon))
    return d


def proc(seqid, parent, pid, started=1792481454.0, exited=None):
    return {"seqid": seqid, "parent_seqid": parent, "pid": pid, "name": f"p{seqid}", "started_at": started, "exited_at": exited}


def test_labels_count_only_the_sample_process_tree(tmp_path):
    d = write_analysis(
        tmp_path,
        [proc(1, None, 4), proc(10, 1, 2044), proc(11, 10, 3000), proc(12, 1, 900)],
        {
            "dns_queries": [{"domain": "c2.example", "process_seqids": [11]}, {"domain": "msft.example", "process_seqids": [12]}],
            "connections": [
                {"remote_ip": "127.0.0.1", "process_seqids": [10]},
                {"remote_ip": "10.13.0.1", "process_seqids": [12]},
            ],
            "http_requests": [],
            "modified_files": [
                {"filename": "C:\\Users\\u\\AppData\\Roaming\\x.exe", "process_seqids": [11]},
                {"filename": "C:\\Users\\u\\notes.txt", "process_seqids": [10]},
                {"filename": "C:\\Windows\\Temp\\other.dll", "process_seqids": [12]},
            ],
        },
        regmon=[
            {"PID": 3000, "Method": "NtSetValueKey", "Key": "\\REGISTRY\\USER\\S-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {"PID": 900, "Method": "NtSetValueKey", "Key": "\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SCHEDULE\\TASKCACHE\\TASKS\\{X}"},
        ],
    )
    labels = m5.label_analysis(d)
    assert labels["telemetry_complete"] and labels["executed"]
    assert labels["children"] == 1
    assert labels["dns_queries"] == 1 and labels["connections"] == 0
    assert labels["file_drops"] == 1
    assert labels["persistence"] and len(labels["persistence_evidence"]) == 1
    assert labels["payload_behaviour"] and not labels["early_exit"]


def test_quick_silent_exit_is_early_exit_without_payload(tmp_path):
    d = write_analysis(tmp_path, [proc(1, None, 4), proc(10, 1, 2044, exited=1792481457.0)])
    labels = m5.label_analysis(d)
    assert labels["early_exit"] and labels["sample_lifetime_s"] == 3.0
    assert not labels["payload_behaviour"]


def test_failed_drakvuf_run_is_not_complete(tmp_path):
    d = write_analysis(tmp_path, [proc(1, None, 4), proc(10, 1, 2044)], rc=1)
    assert not m5.label_analysis(d)["telemetry_complete"]


def test_schedule_is_complete_seeded_and_mixes_arm_order():
    register = [{"sha256": s, "role": "test"} for s in SHA]
    schedule = m5.make_schedule(register, ["A0", "H3"], 2, seed=7)
    assert schedule == m5.make_schedule(register, ["A0", "H3"], 2, seed=7)
    assert sorted(i["key"] for i in schedule) == sorted(f"{s}/{a}/{r}" for s in SHA for a in ("A0", "H3") for r in (1, 2))
    # Each sample's four runs are consecutive, and not every sample starts on the same arm
    assert all(len({schedule[i + j]["sha256"] for j in range(4)}) == 1 for i in range(0, len(schedule), 4))
    assert {schedule[i]["arm"] for i in range(0, len(schedule), 4)} == {"A0", "H3"}


def test_mcnemar_exact_values():
    assert m5.mcnemar_exact(0, 0) == 1.0
    assert m5.mcnemar_exact(0, 6) == pytest.approx(0.03125)
    assert m5.mcnemar_exact(2, 8) == pytest.approx(0.109375)


def test_summary_pairs_tests_and_excludes_incomplete_samples():
    register = [
        {"sha256": SHA[0], "role": "test"},
        {"sha256": SHA[1], "role": "test"},
        {"sha256": SHA[2], "role": "test"},
        {"sha256": SHA[3], "role": "control"},
    ]

    def run(sha, arm, observed, complete=True):
        return {"sha256": sha, "arm": arm, "payload_behaviour": observed, "telemetry_complete": complete}

    results = [
        run(SHA[0], "A0", False), run(SHA[0], "H3", True), run(SHA[0], "H3", False),  # tie -> observed
        run(SHA[1], "A0", True), run(SHA[1], "H3", True),
        run(SHA[2], "A0", True, complete=False), run(SHA[2], "H3", True),
        run(SHA[3], "A0", False), run(SHA[3], "H3", True),
    ]
    summary = m5.summarise(results, register, "A0", "H3")
    assert summary["excluded"] == [SHA[2]]
    assert summary["paired"] == 2  # the control is reported but not paired
    assert (summary["only_H3"], summary["only_A0"], summary["both"]) == (1, 0, 1)


def test_register_rejects_bad_rows(tmp_path):
    path = tmp_path / "register.csv"
    path.write_text("sha256,path,role\nnot-a-hash,x.zip,test\n")
    with pytest.raises(ValueError):
        m5.read_register(path)
    path.write_text(f"sha256,path,role\n{SHA[0]},x.zip,test\n{SHA[0]},y.zip,test\n")
    with pytest.raises(ValueError):
        m5.read_register(path)


def entry(sha, family, tags, first_seen="2026-10-01 10:00:00", file_type="exe"):
    return {"sha256_hash": sha, "signature": family, "tags": tags, "first_seen": first_seen, "file_type": file_type, "file_name": "a.exe"}


def test_shortlist_one_per_family_drops_worms_and_old_or_non_exe():
    by_tag = {
        "anti-vm": [
            entry(SHA[0], "Lumma", ["anti-vm"], "2026-09-01 00:00:00"),
            entry(SHA[1], "Lumma", ["anti-vm", "evasive"], "2026-10-01 00:00:00"),
            entry("a" * 64, "WannaCry", ["anti-vm"]),
            entry("b" * 64, "Agent", ["anti-vm", "worm"]),
            entry("c" * 64, "OldFam", ["anti-vm"], "2025-01-01 00:00:00"),
            entry("d" * 64, "DllFam", ["anti-vm"], file_type="dll"),
        ],
    }
    by_family = {
        "AsyncRAT": [entry(SHA[2], "AsyncRAT", ["rat"]), entry("e" * 64, "AsyncRAT", ["rat", "anti-vm"], "2026-10-10 00:00:00")],
    }
    rows = samples.shortlist(lambda t: by_tag.get(t, []), lambda f: by_family.get(f, []), 10, 5, "2026-04-01")
    assert [(r["sha256"], r["role"]) for r in rows] == [(SHA[1], "test"), (SHA[2], "control")]
    assert rows[0]["source_url"].endswith(f"/{SHA[1]}/")


def test_download_refuses_without_signoff(tmp_path):
    with pytest.raises(SystemExit, match="signoff"):
        samples.main(["download", "--out", str(tmp_path)])


def test_downloaded_register_is_readable_by_the_runner(tmp_path):
    path = tmp_path / "register.csv"
    fields = ["sha256", "path", "role", "family", "tags", "archive_password", "entry", "source_url", "retrieved"]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerow(dict(zip(fields, [SHA[0].upper(), "z.zip", "control", "AsyncRAT", "rat", "infected", "", "u", "2026-10-20T00:00:00+00:00"])))
    assert m5.read_register(path)[0]["sha256"] == SHA[0]
