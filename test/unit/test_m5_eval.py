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
            {"PID": 3000, "Method": "NtSetValueKey", "Key": "\\REGISTRY\\USER\\S-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "ValueName": "x"},
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


@pytest.mark.parametrize(
    "method,key,value,expected",
    [
        ("NtSetValueKey", "\\REGISTRY\\USER\\S-1\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", "Updater", True),
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\evilsvc", "ImagePath", True),
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\evilsvc\\Parameters", "ServiceDll", True),
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit", True),
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SCHEDULE\\TASKCACHE\\TREE\\Upd", "Id", True),
        # Windows' own writes seen in a real run of the probe
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\BAM\\STATE\\USERSETTINGS\\S-1-5-21-1", "x", False),
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Hostname", False),
        ("NtSetValueKey", "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "LastUsedUsername", False),
        ("NtCreateKey", "\\REGISTRY\\USER\\S-1\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", None, False),
    ],
)
def test_persistence_rules(method, key, value, expected):
    assert m5.is_persistence_write({"Method": method, "Key": key, "ValueName": value}) is expected


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
    by_family = {
        "GuLoader": [
            entry(SHA[0], "GuLoader", ["exe"], "2026-10-05 00:00:00"),
            entry(SHA[1], "GuLoader", ["anti-vm", "evasive"], "2026-10-01 00:00:00"),
            entry("a" * 64, "WannaCry", ["anti-vm"]),
            entry("b" * 64, "Agent", ["anti-vm", "worm"]),
            entry("c" * 64, "OldFam", ["anti-vm"], "2025-01-01 00:00:00"),
            entry("d" * 64, "DllFam", ["anti-vm"], file_type="dll"),
            entry("f" * 64, "guloader", ["exe"], "2026-10-09 00:00:00"),  # same family, other spelling
        ],
        "AsyncRAT": [entry(SHA[2], "AsyncRAT", ["rat"]), entry("e" * 64, "AsyncRAT", ["rat", "anti-vm"], "2026-10-10 00:00:00")],
    }
    rows = samples.shortlist(lambda f: by_family.get(f, []), 10, 5, "2026-04-01")
    assert [(r["sha256"], r["role"]) for r in rows] == [(SHA[1], "test"), (SHA[2], "control")]
    assert rows[0]["source_url"].endswith(f"/{SHA[1]}/")


def test_add_takes_the_next_best_sample_not_on_the_list():
    rows = [{"sha256": SHA[1], "role": "test", "family": "GuLoader"}]
    fetched = [
        entry(SHA[1], "GuLoader", ["anti-vm"]),
        entry(SHA[0], "GuLoader", ["exe"], "2026-10-02 00:00:00"),
        entry(SHA[2], "GuLoader", ["exe"], "2026-10-09 00:00:00"),
        entry(SHA[3], "Formbook", ["anti-vm"]),  # another family in the same response is ignored
    ]
    added = samples.add_samples(rows, lambda f: fetched, ["GuLoader", "Nothing"], "2026-04-01")
    assert [(r["sha256"], r["role"]) for r in added] == [(SHA[2], "test")]


def test_metadata_is_queried_once_per_family(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(samples, "query", lambda session, key, **data: calls.append(data) or [{"signature": "X"}])
    fetch = samples.cached_fetch(None, "k", tmp_path / "metadata")
    assert fetch("GuLoader") == fetch("guloader") == [{"signature": "X"}]
    assert len(calls) == 1


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


@pytest.mark.skipif(not __import__("shutil").which("7z"), reason="needs host 7-Zip")
def test_read_sample_decrypts_aes_zip_in_memory(tmp_path):
    import hashlib
    import subprocess

    payload = tmp_path / "Columnised.exe"
    payload.write_bytes(b"MZ not really a program")
    archive = tmp_path / "s.zip"
    subprocess.run(["7z", "a", "-tzip", "-mem=AES256", "-pinfected", str(archive), str(payload)], check=True, capture_output=True)
    payload.unlink()
    sha = hashlib.sha256(b"MZ not really a program").hexdigest()
    name, data = m5.read_sample({"sha256": sha, "path": str(archive), "archive_password": "infected"})
    assert (name, hashlib.sha256(data).hexdigest()) == ("Columnised.exe", sha)


def test_hash_named_samples_get_a_neutral_guest_name():
    assert m5.sample_name("%064x.exe" % 5) == "setup.exe"
    assert m5.sample_name("Invoice_0921.exe") == "Invoice_0921.exe"
    assert m5.sample_name("dir/report") == "report.exe"


def test_tools_the_batch_calls_are_executable():
    # m5_eval runs chimera-arm directly; a 644 copy in a fresh deploy checkout fails at the first arm switch
    import os

    scripts = pathlib.Path(m5.__file__).resolve().parents[1]
    for tool in (scripts / "arms/chimera-arm", scripts / "containment/chimera-net-check"):
        assert os.access(tool, os.X_OK), tool


def test_register_takes_guest_os_and_benign_role(tmp_path):
    path = tmp_path / "register.csv"
    path.write_text(
        f"sha256,path,role,guest_os\n{SHA[0]},a.zip,benign,Linux\n{SHA[1]},b.zip,test,\n{SHA[2]},c.zip,calibration,\n"
    )
    rows = m5.read_register(path)
    assert [(r["role"], r["guest_os"]) for r in rows] == [
        ("benign", "linux"), ("test", "windows"), ("calibration", "windows")  # calibration: m5_samples.py cohort
    ]
    path.write_text(f"sha256,path,role,guest_os\n{SHA[0]},a.zip,test,macos\n")
    with pytest.raises(ValueError):
        m5.read_register(path)


def test_linux_samples_are_scheduled_on_the_linux_arms_only():
    register = [{"sha256": SHA[0], "guest_os": "windows"}, {"sha256": SHA[1], "guest_os": "linux"}]
    schedule = m5.make_schedule(register, ["A0", "H3"], 2, seed=3, linux_arms=["L"])
    assert sorted((i["os"], i["arm"]) for i in schedule if i["sha256"] == SHA[1]) == [("linux", "L")] * 2
    assert {i["arm"] for i in schedule if i["sha256"] == SHA[0]} == {"A0", "H3"}


def test_linux_labels_use_linux_paths(tmp_path):
    d = write_analysis(
        tmp_path,
        [proc(1, None, 1), proc(10, 1, 786), proc(11, 10, 790)],
        {
            "modified_files": [
                {"filename": "/null", "process_seqids": [10]},
                {"filename": "/proc/786/status", "process_seqids": [10]},
                {"filename": "/tmp/.x/kworker", "process_seqids": [11]},
                {"filename": "/etc/cron.d/update", "process_seqids": [11]},
                {"filename": "/home/u/.config/autostart/x.desktop", "process_seqids": [11]},
            ],
            "connections": [{"remote_ip": "10.99.0.2", "process_seqids": [11]}],
        },
        regmon=(),
    )
    labels = m5.label_analysis(d, "linux")
    assert labels["persistence_evidence"] == ["/etc/cron.d/update", "/home/u/.config/autostart/x.desktop"]
    assert labels["file_drops"] == 3 and "/null" not in labels["file_drop_evidence"]
    assert labels["connections"] == 1 and labels["payload_behaviour"]


def test_linux_guest_names_keep_no_extension():
    assert m5.sample_name("%064x.elf" % 5, "linux") == "update"
    assert m5.sample_name("dir/xmrig", "linux") == "xmrig"


def test_benign_plain_file_is_read_without_7zip(tmp_path):
    program = tmp_path / "Bginfo64.exe"
    program.write_bytes(b"MZ benign")
    name, data = m5.read_sample({"sha256": "x", "path": str(program), "archive_password": ""})
    assert (name, data) == ("Bginfo64.exe", b"MZ benign")


def test_run_is_saved_to_the_dataset_folder_and_indexed(tmp_path):
    import threading

    analysis = tmp_path / "analysis"
    analysis.mkdir()
    (analysis / "features.json").write_text('{"schema": "chimera-features/1"}')
    (analysis / "classification.json").write_text('{"label": "benign", "score": 0.1, "model": "chimera-stub"}')
    (analysis / "sample.exe").write_bytes(b"MZ")  # never copied
    dataset = tmp_path / "dataset"
    sample = {"sha256": SHA[0], "role": "benign", "family": "Sysinternals"}
    record = {"key": f"{SHA[0]}/H3/1", "sha256": SHA[0], "arm": "H3", "run": 1, "os": "windows", "payload_behaviour": False}
    lock = threading.Lock()
    m5.save_to_dataset(dataset, sample, record, analysis, lock)
    m5.save_to_dataset(dataset, sample, {**record, "run": 2}, analysis, lock)
    run_dir = dataset / "windows/benign" / SHA[0] / "H3-1"
    assert sorted(p.name for p in run_dir.iterdir()) == ["classification.json", "features.json", "labels.json"]
    rows = list(csv.DictReader((dataset / "index.csv").open()))
    assert [(r["run"], r["verdict"], r["path"]) for r in rows] == [
        ("1", "benign", f"windows/benign/{SHA[0]}/H3-1"),
        ("2", "benign", f"windows/benign/{SHA[0]}/H3-2"),
    ]
    out = tmp_path / "export.tar.gz"
    m5.main(["export", "--dataset", str(dataset), "--output", str(out)])
    import tarfile

    names = tarfile.open(out).getnames()
    assert "chimera-dataset/index.csv" in names and not any(n.endswith(".exe") for n in names)


@pytest.mark.parametrize(
    "domains,drakvuf,busy",
    [
        ("vm-2 7", "12 drakvuf -o json -d vm-2 -t 60", False),  # a Linux analysis
        ("vm-1 5", "", True),
        ("", "12 drakvuf -o json -d vm-1", True),
        ("", "12 drakvuf --no-domain", True),
    ],
)
def test_arm_switch_waits_only_for_windows_slots(monkeypatch, domains, drakvuf, busy):
    def fake_sh(*argv, check=True):
        if argv[0] == "xl":
            return "Name ID\nDomain-0 0\n" + (domains + "\n" if domains else "")
        return drakvuf

    monkeypatch.setattr(m5, "sh", fake_sh)
    assert m5.windows_slots_busy() is busy


def test_an_egress_drop_in_one_lane_stops_both(tmp_path, monkeypatch):
    import threading

    drops = iter([0, 1] + [1] * 20)  # the first run sees one new drop
    monkeypatch.setattr(m5, "egress_drops", lambda: next(drops))
    monkeypatch.setattr(m5, "switch_arm", lambda arm: None)
    monkeypatch.setattr(m5, "submit", lambda *a: ("uid", "finished"))
    monkeypatch.setattr(m5, "label_analysis", lambda d, os_: {"payload_behaviour": False})
    monkeypatch.setattr(m5, "save_to_dataset", lambda *a: None)
    monkeypatch.setattr(m5, "ANALYSES_DIR", tmp_path)
    ctx = {
        "register": {SHA[0]: {"sha256": SHA[0]}, SHA[1]: {"sha256": SHA[1]}}, "api": "", "timeout": 1, "poll": 0,
        "results": tmp_path / "results.jsonl", "dataset": tmp_path, "lock": threading.Lock(), "stop": threading.Event(),
    }
    windows = m5.Lane("windows", [{"key": f"{SHA[0]}/H3/{i}", "sha256": SHA[0], "arm": "H3", "run": i, "os": "windows"} for i in (1, 2)], ctx)
    windows.run()
    linux = m5.Lane("linux", [{"key": f"{SHA[1]}/L/1", "sha256": SHA[1], "arm": "L", "run": 1, "os": "linux"}], ctx)
    linux.run()
    assert "EGRESS-DROP" in str(windows.error) and ctx["stop"].is_set()
    assert len((tmp_path / "results.jsonl").read_text().splitlines()) == 1  # nothing ran after the drop


def test_report_compares_arms_on_windows_malware_only(tmp_path):
    register = tmp_path / "register.csv"
    register.write_text(
        "sha256,path,role,family,guest_os\n"
        f"{SHA[0]},a,test,GuLoader,windows\n{SHA[1]},b,test,XorDDoS,linux\n{SHA[2]},c,benign,Bginfo,windows\n"
    )
    (tmp_path / "schedule.json").write_text(json.dumps({"register": str(register), "arms": ["A0", "H3"], "schedule": [1] * 6}))

    def run(sha, arm, os_, observed):
        return {"sha256": sha, "arm": arm, "os": os_, "payload_behaviour": observed, "telemetry_complete": True, "verdict": "benign"}

    results = [run(SHA[0], "A0", "windows", False), run(SHA[0], "H3", "windows", True),
               run(SHA[1], "L", "linux", True), run(SHA[2], "A0", "windows", False), run(SHA[2], "H3", "windows", False)]
    (tmp_path / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in results))
    m5.main(["report", "--out", str(tmp_path)])
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["paired"] == 1 and summary["only_H3"] == 1
    report = (tmp_path / "report.md").read_text()
    assert "## Linux samples" in report and "XorDDoS" in report
    assert "## Benign samples (false-positive check)" in report and "Bginfo" in report


def test_linux_shortlist_takes_recent_elf_and_skips_spreading_bots():
    by_family = {
        "BPFDoor": [
            entry(SHA[0], "BPFDoor", ["elf"], file_type="elf"),
            entry(SHA[1], "BPFDoor", ["elf", "mirai"], file_type="elf"),
            entry(SHA[2], "BPFDoor", ["exe"]),
        ],
        "CoinMiner": [entry(SHA[3], "CoinMiner", ["elf", "xmrig"], file_type="elf")],
    }
    rows = samples.linux_shortlist(lambda f: by_family.get(f, []), "2026-04-01")
    assert [(r["sha256"], r["role"], r["guest_os"]) for r in rows] == [(SHA[0], "test", "linux"), (SHA[3], "control", "linux")]
    assert samples.LINUX_PER_FAMILY == 2


def test_only_x86_64_elf_runs_in_the_linux_guest():
    head = bytearray(64)
    head[:4], head[4], head[5] = b"\x7fELF", 2, 1
    head[18:20] = (0x3E).to_bytes(2, "little")
    assert samples.elf_machine(bytes(head)) == "x86-64"
    head[18:20] = (0x28).to_bytes(2, "little")  # ARM
    assert samples.elf_machine(bytes(head)) == "ELF machine 0x28"
    head[4] = 1
    assert samples.elf_machine(bytes(head)) == "32-bit ELF"
    assert samples.elf_machine(b"MZ") == "not an ELF file"


def test_sample_name_keeps_windows_installer_and_script_extensions():
    assert m5.sample_name("tightvnc-setup-64bit.msi") == "tightvnc-setup-64bit.msi"
    assert m5.sample_name("it-inventory.ps1") == "it-inventory.ps1"
    assert m5.sample_name("logon-setup.bat") == "logon-setup.bat"
    assert m5.sample_name("notes.txt") == "notes.txt.exe"


def test_register_start_command_reaches_upload_fields(tmp_path):
    reg = tmp_path / "register.csv"
    reg.write_text(
        "sha256,role,guest_os,start_command\n"
        + "a" * 64 + ',benign,windows," msiexec /i ""{sample}"" /qn "\n'
        + "b" * 64 + ",benign,linux,\n"
    )
    rows = m5.read_register(reg)
    assert rows[0]["start_command"] == 'msiexec /i "{sample}" /qn'
    fields = m5.upload_fields(rows[0], "vnc.msi", 120)
    assert fields == {"timeout": "120", "file_name": "vnc.msi", "guest_os": "windows",
                      "start_command": 'msiexec /i "{sample}" /qn'}
    assert "start_command" not in m5.upload_fields(rows[1], "rclone", 120)


def test_classifier_is_frozen_and_verdicts_tabulated(tmp_path):
    clf = tmp_path / "clf"
    clf.mkdir()
    (clf / "MANIFEST.json").write_text(json.dumps({"model": "m", "model_version": "0.1"}))
    (clf / "model.py").write_text("x = 1\n")
    frozen = m5.classifier_fingerprint(clf)
    assert frozen["model_version"] == "0.1" and set(frozen["files"]) == {"MANIFEST.json", "model.py"}
    assert m5.classifier_fingerprint(tmp_path / "absent") is None
    (clf / "model.py").write_text("x = 2\n")
    assert m5.classifier_fingerprint(clf)["digest"] != frozen["digest"]

    analysis = tmp_path / "a"
    analysis.mkdir()
    (analysis / "classification.json").write_text(json.dumps(
        {"label": "suspicious", "score": 0.3, "model_version": "0.1+fusion0.1", "components": {"static": {"label": "unknown"}}}))
    fields = m5.verdict_fields(analysis)
    assert fields["verdict_class"] == "I" and fields["verdict_static"] == "unknown"
    assert m5.verdict_fields(tmp_path / "none") == {"verdict": None, "verdict_class": None}

    register = [{"sha256": SHA[0], "role": "test"}, {"sha256": SHA[1], "role": "control"}, {"sha256": SHA[2], "role": "benign"}]
    results = [{"sha256": SHA[0], "os": "windows", "arm": "H3", "verdict_class": "M", "verdict_model_version": "0.1"},
               {"sha256": SHA[1], "os": "windows", "arm": "H3", "verdict_class": None},
               {"sha256": SHA[2], "os": "windows", "arm": "H3", "verdict_class": "B"},
               {"sha256": SHA[2], "os": "windows", "arm": "H3", "verdict_class": "I"}]
    text = "\n".join(m5.verdict_tables(results, register, frozen))
    assert "| malware | 1 | 0 | 0 | 1 | 1/2 |" in text  # the failed run stays in the denominator
    assert "| benign | 0 | 1 | 1 | 0 | 0/2 |" in text
    assert frozen["digest"][:16] in text


def test_run_refuses_a_changed_classifier(tmp_path):
    clf = tmp_path / "clf"
    clf.mkdir()
    (clf / "model.py").write_text("x = 1\n")
    (tmp_path / "schedule.json").write_text(json.dumps(
        {"register": str(tmp_path / "r.csv"), "arms": ["A0", "H3"], "schedule": [],
         "classifier": m5.classifier_fingerprint(clf)}))
    (clf / "model.py").write_text("x = 2\n")
    with pytest.raises(SystemExit, match="classifier changed"):
        m5.main(["run", "--out", str(tmp_path), "--classifier-dir", str(clf)])
