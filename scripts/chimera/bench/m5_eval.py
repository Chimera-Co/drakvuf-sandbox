#!/usr/bin/env python3
"""
CHIMERA real-malware evaluation (M5) batch runner and report.

Follows docs/chimera/malware-evaluation-protocol.md. The operator supplies the
samples; this tool never downloads anything. The sample register is private
and must stay outside the repository.

  plan    register CSV -> schedule.json (every sample x arm x run, in rounds: every
          sample once on each arm, then the repeat round; order randomised per round)
  run     submit the schedule: a Windows lane (one analysis at a time, switching arms
          with chimera-arm) and a Linux lane run side by side on their own workers;
          resumable: runs already in results.jsonl are skipped. Stop rules: any
          CHIMERA-EGRESS-DROP stops both lanes, destroys every analysis domain and
          takes the guest bridges down at once; a hot CPU pauses the batch between
          runs; every run records the SHA-256 of the image it restored
          (stops.jsonl, images.json)
  label   print the outcome labels of one analysis directory
  report  results.jsonl -> per-run CSV, per-sample tables and McNemar test (report.md)
  export  the classifier dataset folder -> one .tar.gz (features and labels, no samples)

Register columns (CSV, header required):
  sha256, path (password-protected ZIP, or a plain file for benign samples),
  role (test|control|benign), family, tags, archive_password,
  entry (path inside the archive, optional), file_name (optional),
  guest_os (windows|linux, default windows)

Each sample is decrypted in memory with the host's 7-Zip, its SHA-256 checked
against the register, and submitted as a plain file, so A0 (no 7-Zip in the
guest) and H3 get identical input. Windows samples run on every --arms arm;
Linux samples on --linux-arms, which are labels only (the Linux image has no
arms to switch).

After every run its features.json, classification.json and labels are copied to
the dataset folder (--dataset), one directory per run:
  <dataset>/<guest_os>/<role>/<sha256>/<arm>-<run>/  + index.csv

Run as root with the deployment venv, for example:
  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_eval.py plan \
      --register /var/lib/chimera-samples/register.csv --out /var/lib/chimera-evidence/m5
  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_eval.py run --out /var/lib/chimera-evidence/m5
  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_eval.py report --out /var/lib/chimera-evidence/m5
"""

import argparse
import csv
import datetime
import hashlib
import json
import math
import pathlib
import random
import re
import subprocess
import sys
import time

ANALYSES_DIR = pathlib.Path("/var/lib/drakrun/analyses")
ARMS_DIR = pathlib.Path("/var/lib/chimera-arms")
CHIMERA_ARM = pathlib.Path(__file__).resolve().parents[1] / "arms/chimera-arm"
ANALYSIS_WORKER = "drakrun-worker@1"  # the Windows worker; arm switches restart only it
# Windows files the guest starts by extension (startup_command.py); anything else gets ".exe"
WINDOWS_RUN_EXTENSIONS = (".exe", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js")
DATASET_DIR = pathlib.Path("/var/lib/chimera-dataset")
CLASSIFIER_DIR = pathlib.Path("/etc/drakrun/classifier")
# Scoring map for verdicts: suspicious and "no verdict" are indeterminate, never counted as either class
VERDICT_CLASS = {"malicious": "M", "benign": "B", "suspicious": "I", "unknown": "I"}
ROLES = ("test", "control", "benign", "calibration")  # calibration: the cohort from m5_samples.py cohort
GUEST_OSES = ("windows", "linux")
# The VM slots restored from the Windows arms (vm-0 = the golden image). chimera-arm
# only waits for these, so a Linux analysis on vm-2 does not block an arm switch.
WINDOWS_SLOTS = ("vm-0", "vm-1")
# Evasion scans restore the same snapshots; one starting mid-batch would run on
# whichever arm is current and block arm switches, so they pause for the batch.
EVASION_WORKERS = ["drakrun-evasion-worker@1", "drakrun-evasion-worker@2"]
TERMINAL = {"finished", "failed"}
EARLY_EXIT_S = 10
# What a restored analysis reads. chimera-arm points the Windows paths at the current arm; the Linux image is one
# golden set. A directory counts as the files in it.
WINDOWS_IMAGE_PATHS = (
    "/var/lib/drakrun/volumes/vm-0.img", "/var/lib/drakrun/volumes/snapshot.sav", "/etc/drakrun/install.json",
    "/etc/drakrun/cfg.template", "/var/lib/drakrun/profiles",
)
LINUX_IMAGE_PATHS = (
    "/var/lib/drakrun/linux/golden/vm-0.img", "/var/lib/drakrun/linux/golden/snapshot.sav",
    "/var/lib/drakrun/linux/golden/install.json", "/var/lib/drakrun/linux/golden/kernel.json",
    "/etc/drakrun/cfg-linux.template", "/var/lib/drakrun/linux/profile",
)
ANALYSIS_DOMAIN = re.compile(r"^vm-\d+$")
EGRESS_POLL_S = 2
STOP_GRACE_S = 120  # after a stop, how long a run in flight may take to reach a terminal status
# CPU temperature sensors, hottest wins: coretemp's package sensor where the kernel has one (a Xen dom0 has not),
# the DPTF CPU zone and the embedded controller's CPU sensor, as the thermal panel reads them
CPU_THERMAL_ZONES = ("x86_pkg_temp", "TCPU")
CPU_HWMON_LABELS = ("Package id 0", "CPU (EC)")
PAUSE_TEMP_C = 92
RESUME_TEMP_C = 80
THERMAL_POLL_S = 30
DROP_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "bat", "cmd", "hta", "jar", "lnk", "msi",
}
# Persistence = a value written under an autostart location. Only NtSetValueKey counts:
# NtCreateKey is also how Windows opens existing keys. Under Services and Winlogon
# only the values that make something start count; Windows itself writes other
# values there (e.g. Services\bam\State, Services\Tcpip\Parameters).
PERSISTENCE_ANY_VALUE = re.compile(
    r"\\CURRENTVERSION\\(RUN|RUNONCE|RUNSERVICES|RUNSERVICESONCE|POLICIES\\EXPLORER\\RUN)$"
    r"|\\SCHEDULE\\TASKCACHE\\(TASKS|TREE)\\",
    re.IGNORECASE,
)
PERSISTENCE_VALUES = [
    (re.compile(r"\\(CURRENTCONTROLSET|CONTROLSET\d+)\\SERVICES\\[^\\]+$", re.IGNORECASE), {"imagepath"}),
    (re.compile(r"\\(CURRENTCONTROLSET|CONTROLSET\d+)\\SERVICES\\[^\\]+\\PARAMETERS$", re.IGNORECASE), {"servicedll"}),
    (re.compile(r"\\CURRENTVERSION\\WINLOGON$", re.IGNORECASE), {"shell", "userinit", "notify"}),
]
PERSISTENCE_PATHS = re.compile(
    r"\\WINDOWS\\SYSTEM32\\TASKS\\|\\START MENU\\PROGRAMS\\STARTUP\\", re.IGNORECASE
)


def is_persistence_write(event):
    if event.get("Method") != "NtSetValueKey":
        return False
    key = (event.get("Key") or "").rstrip("\\")
    if PERSISTENCE_ANY_VALUE.search(key):
        return True
    value = (event.get("ValueName") or "").lower()
    return any(pattern.search(key) and value in names for pattern, names in PERSISTENCE_VALUES)

# Linux persistence: files written where something starts automatically
LINUX_PERSISTENCE_PATHS = re.compile(
    r"^/etc/(cron|crontab|anacrontab|rc\.local|init\.d/|rc\d\.d/|systemd/system/|profile\.d/|ld\.so\.preload|xdg/autostart/)"
    r"|^/var/spool/cron/|^/(usr/)?lib/systemd/system/"
    r"|/\.config/(autostart|systemd/user)/|/\.(bashrc|bash_profile|profile)$|/\.ssh/authorized_keys$"
)
# Linux file writes that are not drops: pseudo filesystems, logs. filetracer also
# reports some paths relative to their mount (e.g. /dev/null as "/null"), so a
# single path component is not counted either.
LINUX_NOT_DROP = re.compile(r"^/(proc|sys|dev|run|var/log)/|^/[^/]*$")

LOOPBACK = ("127.", "0.0.0.0", "::1", "::")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# --- schedule -----------------------------------------------------------------


def read_register(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    seen = set()
    for row in rows:
        sha = row.get("sha256", "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError(f"register row has no valid sha256: {row}")
        if sha in seen:
            raise ValueError(f"duplicate sample {sha}")
        seen.add(sha)
        role = (row.get("role") or "test").strip()
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}: {sha}")
        guest_os = (row.get("guest_os") or "windows").strip().lower()
        if guest_os not in GUEST_OSES:
            raise ValueError(f"guest_os must be windows or linux: {sha}")
        row.update(sha256=sha, role=role, guest_os=guest_os, start_command=(row.get("start_command") or "").strip())
    return rows


def make_schedule(register, arms, runs, seed, linux_arms=("L",)):
    """Every sample x arm x run, in rounds: round i runs every sample once on each of its arms, so a batch that
    stops early has whole rounds, not some samples with all their runs and others with none. Samples in a new
    random order each round; each sample's arms back to back in their own random order, so no arm always runs
    first (C2 time checks). Windows samples run on `arms`, Linux samples on `linux_arms`."""
    rng = random.Random(seed)
    schedule = []
    for i in range(1, runs + 1):
        samples = list(register)
        rng.shuffle(samples)
        for sample in samples:
            guest_os = sample.get("guest_os", "windows")
            sample_arms = list(linux_arms if guest_os == "linux" else arms)
            rng.shuffle(sample_arms)
            for arm in sample_arms:
                schedule.append(
                    {"key": f"{sample['sha256']}/{arm}/{i}", "sha256": sample["sha256"], "arm": arm, "run": i,
                     "os": guest_os}
                )
    return schedule


# --- labels ---------------------------------------------------------------------


def _subtree(processes, root):
    children = {}
    for proc in processes:
        children.setdefault(proc.get("parent_seqid"), []).append(proc["seqid"])
    found, stack = [], [root]
    while stack:
        seqid = stack.pop()
        if seqid in found:
            continue
        found.append(seqid)
        stack.extend(children.get(seqid, []))
    return found


def _ts(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value) or None
    return datetime.datetime.fromisoformat(value).timestamp()


def _ext(name):
    base = re.split(r"[\\/]", name)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def label_analysis(analysis_dir, guest_os="windows"):
    """Outcome labels of protocol section 4, from one analysis's telemetry."""
    analysis_dir = pathlib.Path(analysis_dir)
    metadata = json.loads((analysis_dir / "metadata.json").read_text())
    telemetry = metadata.get("telemetry") or {}
    labels = {
        "status": metadata.get("status"),
        "telemetry_complete": metadata.get("status") == "finished"
        and telemetry.get("drakvuf_returncode") == 0
        and not telemetry.get("drakvuf_hard_timeout"),
    }
    report_path = analysis_dir / "report.json"
    if not report_path.exists():
        labels.update(executed=False, telemetry_complete=False)
        return labels
    report = json.loads(report_path.read_text())
    startup = report.get("startup") or {}
    processes = report.get("processes", [])
    root = startup.get("process")
    executed = startup.get("status") == "Success" and any(p["seqid"] == root for p in processes)
    tree = set(_subtree(processes, root)) if executed else set()
    pids = {p["pid"] for p in processes if p["seqid"] in tree}

    def by_tree(entry):
        seqids = entry.get("process_seqids")
        if seqids is None:
            seqids = [entry.get("process_seqid")]
        return any(s in tree for s in seqids)

    dns = sorted({d["domain"] for d in report.get("dns_queries", []) if by_tree(d)})
    connections = [
        c for c in report.get("connections", [])
        if by_tree(c) and not str(c.get("remote_ip", "")).startswith(LOOPBACK)
    ]
    http = [h for h in report.get("http_requests", []) if by_tree(h)]
    written = [f["filename"] for f in report.get("modified_files", []) if by_tree(f)]
    if guest_os == "linux":
        # No file types on Linux: any write outside pseudo filesystems and logs
        drops = sorted({f for f in written if not LINUX_NOT_DROP.search(f)})
        persistence = sorted({f for f in written if LINUX_PERSISTENCE_PATHS.search(f)})
    else:
        drops = sorted({f for f in written if _ext(f) in DROP_EXTENSIONS})
        persistence = sorted({f for f in written if PERSISTENCE_PATHS.search(f)})
    regmon = analysis_dir / "regmon.log"
    if pids and regmon.exists():
        with regmon.open(errors="replace") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("PID") in pids and is_persistence_write(event):
                    persistence.append(f"{event['Key']}\\{event.get('ValueName') or ''}")
    persistence = sorted(set(persistence))

    sample = next((p for p in processes if p["seqid"] == root), {}) if executed else {}
    started = _ts(sample.get("started_at")) or _ts(metadata.get("time_execution_started"))
    exited = _ts(sample.get("exited_at"))
    lifetime = round(exited - started, 2) if started and exited else None
    network = bool(dns or connections or http)
    labels.update(
        executed=executed,
        children=max(len(tree) - 1, 0),
        persistence=bool(persistence),
        persistence_evidence=persistence[:20],
        file_drops=len(drops),
        file_drop_evidence=drops[:20],
        dns_queries=len(dns),
        connections=len(connections),
        http_requests=len(http),
        network_intent=network,
        sample_lifetime_s=lifetime,
        early_exit=executed
        and lifetime is not None
        and lifetime <= EARLY_EXIT_S
        and len(tree) == 1
        and not network,
    )
    labels["payload_behaviour"] = bool(persistence or drops or network)
    return labels


# --- statistics -----------------------------------------------------------------


def mcnemar_exact(only_a, only_b):
    """Two-sided exact McNemar p-value (binomial test on the discordant pairs)."""
    n = only_a + only_b
    if n == 0:
        return 1.0
    k = min(only_a, only_b)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, 2 * tail)


# Protocol Amendment 1 (section 8): network intent is the primary outcome of the paired test. The secondary
# outcomes are exploratory, each with its own discordant counts; "behaviours" is the 0-3 count of distinct
# behaviours (persistence, file drop, network intent), paired as higher on one arm vs the other (sign test).
PRIMARY_OUTCOME = "network_intent"
SECONDARY_OUTCOMES = ("persistence", "payload_behaviour", "file_drops", "children", "behaviours")
OUTCOME_NAMES = {
    "network_intent": "network intent",
    "persistence": "persistence",
    "payload_behaviour": "payload behaviour (persistence, file drop or network intent; as registered)",
    "file_drops": "file drops",
    "children": "child processes",
    "behaviours": "distinct behaviours (0-3)",
}


def run_value(run, outcome):
    """One run's value of an outcome: observed or not, or 0-3 for the distinct-behaviour count."""
    if outcome == "behaviours":
        return sum(bool(run.get(k)) for k in ("persistence", "file_drops", "network_intent"))
    return bool(run.get(outcome))


def sample_outcome(runs, outcome=PRIMARY_OUTCOME):
    """Majority over complete runs; a tie counts as observed (the upper median, which is also how the 0-3
    count is aggregated). None if no complete run."""
    values = sorted(run_value(r, outcome) for r in runs if r.get("telemetry_complete"))
    if not values:
        return None
    return values[len(values) // 2]


def paired_counts(paired, arm_a, arm_b, outcome):
    """Concordant and discordant samples for one outcome; for the 0-3 count, discordant = higher on one arm."""
    values = [(r[f"{arm_a}_outcomes"][outcome], r[f"{arm_b}_outcomes"][outcome]) for r in paired]
    only_a = sum(1 for a, b in values if a > b)
    only_b = sum(1 for a, b in values if b > a)
    both = sum(1 for a, b in values if a == b and a)
    return {
        "outcome": outcome,
        "both": both,
        "neither": len(values) - only_a - only_b - both,
        f"only_{arm_a}": only_a,
        f"only_{arm_b}": only_b,
        "mcnemar_p": mcnemar_exact(only_a, only_b),
    }


def summarise(results, register, arm_a, arm_b):
    roles = {s["sha256"]: s for s in register}
    per_sample, excluded = [], []
    for sha, sample in roles.items():
        row = {"sha256": sha, "role": sample["role"], "family": sample.get("family", "")}
        for arm in (arm_a, arm_b):
            runs = [r for r in results if r["sha256"] == sha and r["arm"] == arm]
            row[f"{arm}_runs"] = len(runs)
            row[f"{arm}_complete"] = sum(1 for r in runs if r.get("telemetry_complete"))
            row[f"{arm}_outcomes"] = {o: sample_outcome(runs, o) for o in (PRIMARY_OUTCOME, *SECONDARY_OUTCOMES)}
            row[f"{arm}_observed"] = row[f"{arm}_outcomes"][PRIMARY_OUTCOME]
            complete = [r for r in runs if r.get("telemetry_complete")] or [{}]
            row[f"{arm}_children"] = max(r.get("children", 0) for r in complete)
            row[f"{arm}_network"] = any(r.get("network_intent") for r in complete)
        if row[f"{arm_a}_observed"] is None or row[f"{arm_b}_observed"] is None:
            excluded.append(sha)
        per_sample.append(row)
    paired = [r for r in per_sample if r["role"] == "test" and r["sha256"] not in excluded]
    return {
        "per_sample": per_sample,
        "excluded": excluded,
        "paired": len(paired),
        **paired_counts(paired, arm_a, arm_b, PRIMARY_OUTCOME),
        "secondary": {o: paired_counts(paired, arm_a, arm_b, o) for o in SECONDARY_OUTCOMES},
    }


# --- running --------------------------------------------------------------------


def sh(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check).stdout


def current_arm():
    return (ARMS_DIR / "CURRENT").read_text().strip()


def egress_drop_lines():
    return [line for line in sh("dmesg").splitlines() if "CHIMERA-EGRESS-DROP" in line]


def egress_drops():
    return len(egress_drop_lines())


def log_stop(ctx, event):
    with ctx["lock"]:
        with (ctx["out"] / "stops.jsonl").open("a") as f:
            f.write(json.dumps({"time": now(), **event}) + "\n")
    print(json.dumps(event), flush=True)


def destroy_analysis_domains():
    names = [line.split()[0] for line in sh("xl", "list").splitlines()[1:] if line.split()]
    names = [n for n in names if ANALYSIS_DOMAIN.match(n)]
    for name in names:
        sh("xl", "destroy", name, check=False)
    return names


def guest_bridges_down():
    """Every drakrun guest bridge (drak<N>) down; the next analysis's network setup deletes and recreates it."""
    bridges = [line.split(": ")[1].split("@")[0] for line in sh("ip", "-o", "link", "show", "type", "bridge").splitlines()
               if ": " in line]
    bridges = [b for b in bridges if re.fullmatch(r"drak\d+", b)]
    for bridge in bridges:
        sh("ip", "link", "set", "dev", bridge, "down", check=False)
    return bridges


def egress_watchdog(ctx, baseline, finished, poll=EGRESS_POLL_S):
    """Protocol stop rule: on any new CHIMERA-EGRESS-DROP, at once (not when the run ends) stop both lanes,
    destroy every analysis domain and take the guest bridges down."""
    while not finished.wait(poll):
        drops = egress_drops()
        if drops > baseline:
            ctx["stop"].set()
            domains = destroy_analysis_domains()
            bridges = guest_bridges_down()
            log_stop(ctx, {"event": "egress_drop", "new_drops": drops - baseline, "destroyed": domains,
                           "bridges_down": bridges, "log": egress_drop_lines()[-5:]})
            return


def cpu_temperature(sysfs="/sys"):
    """Hottest CPU sensor in degrees C, or None if the machine exposes none of them."""
    readings = []
    for zone in pathlib.Path(sysfs, "class/thermal").glob("thermal_zone*"):
        try:
            if (zone / "type").read_text().strip() in CPU_THERMAL_ZONES:
                readings.append(int((zone / "temp").read_text()))
        except (OSError, ValueError):
            continue
    for label in pathlib.Path(sysfs, "class/hwmon").glob("hwmon*/temp*_label"):
        try:
            if label.read_text().strip() in CPU_HWMON_LABELS:
                readings.append(int(label.with_name(label.name.replace("_label", "_input")).read_text()))
        except (OSError, ValueError):
            continue
    return max(readings) / 1000 if readings else None


def wait_until_cool(ctx):
    """Protocol stop rule: before the next run, pause while the CPU is at or above pause_temp, until it is at or
    below resume_temp (or the batch stops)."""
    temp = cpu_temperature()
    if temp is None or temp < ctx["pause_temp"]:
        return
    log_stop(ctx, {"event": "thermal_pause", "temp_c": temp})
    while not ctx["stop"].is_set():
        time.sleep(ctx["thermal_poll"])
        temp = cpu_temperature()
        if temp is None or temp <= ctx["resume_temp"]:
            break
    log_stop(ctx, {"event": "thermal_resume", "temp_c": temp})


def image_files(paths):
    """{path as drakrun opens it: the real file behind it}; a directory counts as its files."""
    files = {}
    for path in map(pathlib.Path, paths):
        if path.is_dir():
            files.update((str(p), p.resolve()) for p in sorted(path.iterdir()) if p.is_file())
        elif path.exists():
            files[str(path)] = path.resolve()
    return files


def file_sha256(path, cache):
    """SHA-256 of a file, cached by real path, size and mtime: a 27 GB disk image is hashed once, not per run."""
    st = path.stat()
    hit = cache.get(str(path))
    if hit and hit["size"] == st.st_size and hit["mtime_ns"] == st.st_mtime_ns:
        return hit["sha256"]
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            digest.update(block)
    cache[str(path)] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "sha256": digest.hexdigest()}
    return digest.hexdigest()


def image_identity(paths, cache):
    """(digest, files): the image a run restores, as one digest over its files' SHA-256 by the path drakrun opens."""
    files = {name: {"file": str(real), "sha256": file_sha256(real, cache)} for name, real in image_files(paths).items()}
    digest = hashlib.sha256(json.dumps({n: f["sha256"] for n, f in files.items()}, sort_keys=True).encode()).hexdigest()
    return digest, files


def run_image(guest_os, arm, ctx):
    """The digest of the image this run restores; hashes are cached in image-cache.json, each image's files
    are listed once in images.json."""
    paths = LINUX_IMAGE_PATHS if guest_os == "linux" else WINDOWS_IMAGE_PATHS
    with ctx["image_lock"]:
        cache_path, images_path = ctx["out"] / "image-cache.json", ctx["out"] / "images.json"
        cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
        digest, files = image_identity(paths, cache)
        cache_path.write_text(json.dumps(cache, indent=1))
        images = json.loads(images_path.read_text()) if images_path.exists() else {}
        if digest not in images:
            images[digest] = {"guest_os": guest_os, "arm": arm, "first_seen": now(), "files": files}
            images_path.write_text(json.dumps(images, indent=1))
    return digest


def windows_slots_busy():
    """True while a Windows-slot domain exists or a drakvuf runs on one (or on an
    unknown domain); a Linux analysis on vm-2 does not count."""
    domains = {line.split()[0] for line in sh("xl", "list").splitlines()[1:] if line.split()}
    if domains & set(WINDOWS_SLOTS):
        return True
    for line in sh("pgrep", "-a", "-x", "drakvuf", check=False).splitlines():
        argv = line.split()
        target = argv[argv.index("-d") + 1] if "-d" in argv[:-1] else None
        if target is None or target in WINDOWS_SLOTS:
            return True
    return False


def switch_arm(arm):
    if current_arm() == arm:
        return
    # chimera-arm refuses while a Windows slot or its drakvuf is running; the
    # previous analysis has ended, so wait for its domain to go away.
    for _ in range(60):
        if not windows_slots_busy():
            break
        time.sleep(2)
    sh(str(CHIMERA_ARM), "use", arm)
    # The worker reads install.json and profiles on start, so restart it on the new arm
    sh("systemctl", "restart", ANALYSIS_WORKER)
    time.sleep(10)


def read_sample(sample):
    """The executable from the sample's password-protected ZIP, decrypted in
    memory with the host's 7-Zip (MalwareBazaar ZIPs use AES, which neither
    the stdlib nor PowerShell's Expand-Archive in the A0 guest can open)."""
    if not sample.get("archive_password") and not sample["path"].lower().endswith(".zip"):
        # A benign program kept as a plain file
        data = pathlib.Path(sample["path"]).read_bytes()
        return sample_name(sample.get("file_name") or sample["path"], sample.get("guest_os", "windows")), data
    password = ["-p" + sample["archive_password"]] if sample.get("archive_password") else ["-p"]
    listing = sh("7z", "l", "-slt", *password, sample["path"])
    entries = [
        line.split(" = ", 1)[1]
        for line in listing.splitlines()
        if line.startswith("Path = ") and line.split(" = ", 1)[1] != sample["path"]
    ]
    entry = sample.get("entry") or (entries[0] if len(entries) == 1 else None)
    if not entry:
        raise RuntimeError(f"{sample['sha256']}: archive has {len(entries)} entries; set entry in the register")
    data = subprocess.run(["7z", "x", "-so", *password, sample["path"], entry], capture_output=True, check=True).stdout
    return sample_name(sample.get("file_name") or entry, sample.get("guest_os", "windows")), data


def sample_name(name, guest_os="windows"):
    """Guest file name: the submitted name, unless it is just a hash (itself a sandbox tell)."""
    base = re.split(r"[\\/]", name)[-1]
    stem = base.rsplit(".", 1)[0]
    if guest_os == "linux":
        # Linux runs the file by its mode, not its extension
        return "update" if re.fullmatch(r"[0-9a-fA-F]{32,64}", stem) else base
    if re.fullmatch(r"[0-9a-fA-F]{32,64}", stem):
        return "setup.exe"
    return base if base.lower().endswith(WINDOWS_RUN_EXTENSIONS) else base + ".exe"


def upload_fields(sample, name, timeout):
    fields = {"timeout": str(timeout), "file_name": name, "guest_os": sample.get("guest_os", "windows")}
    if sample.get("start_command"):
        # e.g. an installer's silent switch: '"{sample}" /S'; the analyzer fills in the guest path
        fields["start_command"] = sample["start_command"]
    return fields


def submit(api, sample, timeout, poll, stop=None):
    import requests

    name, data = read_sample(sample)
    digest = hashlib.sha256(data).hexdigest()
    if digest != sample["sha256"]:
        raise RuntimeError(f"archive content {digest} does not match register {sample['sha256']}")
    resp = requests.post(
        f"{api}/upload",
        files={"file": (name, data)},
        data=upload_fields(sample, name, timeout),
        timeout=60,
    )
    resp.raise_for_status()
    task_uid = resp.json()["task_uid"]
    deadline = time.monotonic() + timeout + 1800
    status = None
    while time.monotonic() < deadline:
        status = requests.get(f"{api}/status/{task_uid}", timeout=30).json().get("status")
        if status in TERMINAL:
            break
        if stop is not None and stop.is_set():
            # The batch stopped (its domain may already be destroyed): wait only briefly for the worker to finish
            deadline = min(deadline, time.monotonic() + STOP_GRACE_S)
        time.sleep(poll)
    return task_uid, status


def classifier_fingerprint(directory=CLASSIFIER_DIR):
    """SHA-256 of every deployed classifier file: the batch records it at plan time and refuses to run on
    anything else, so every verdict in one evaluation comes from the same frozen model and policy."""
    directory = pathlib.Path(directory)
    if not directory.is_dir():
        return None
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir()) if p.is_file()}
    manifest = json.loads((directory / "MANIFEST.json").read_text()) if "MANIFEST.json" in files else {}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"model": manifest.get("model"), "model_version": manifest.get("model_version"), "digest": digest,
            "files": files}


def verdict_fields(analysis_dir):
    try:
        verdict = json.loads((pathlib.Path(analysis_dir) / "classification.json").read_text())
    except (OSError, ValueError):
        return {"verdict": None, "verdict_class": None}
    components = verdict.get("components") if isinstance(verdict.get("components"), dict) else {}
    return {
        "verdict": verdict.get("label"),
        "verdict_class": VERDICT_CLASS.get(verdict.get("label")),
        "verdict_score": verdict.get("score"),
        "verdict_model_version": verdict.get("model_version"),
        **{f"verdict_{name}": c.get("label") for name, c in components.items() if isinstance(c, dict)},
    }


def cmd_plan(args):
    register = read_register(args.register)
    for sample in register:
        if not pathlib.Path(sample["path"]).is_file():
            raise SystemExit(f"missing sample file: {sample['path']}")
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**32)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)
    plan = {
        "created": now(),
        "register": str(pathlib.Path(args.register).resolve()),
        "arms": args.arms,
        "linux_arms": args.linux_arms,
        "runs": args.runs,
        "timeout": args.timeout,
        "seed": seed,
        "order": "rounds",
        "classifier": classifier_fingerprint(args.classifier_dir),
        "schedule": make_schedule(register, args.arms, args.runs, seed, args.linux_arms),
    }
    (out / "schedule.json").write_text(json.dumps(plan, indent=1))
    lanes = {os_: [i for i in plan["schedule"] if i["os"] == os_] for os_ in GUEST_OSES}
    # The two lanes run side by side, so the batch takes as long as the longer one
    hours = max(len(items) for items in lanes.values()) * (args.timeout + 60) / 3600
    print(
        f"{len(register)} samples, {len(plan['schedule'])} runs"
        f" ({len(lanes['windows'])} Windows, {len(lanes['linux'])} Linux), ~{hours:.1f} h; seed {seed}"
    )


INDEX_FIELDS = [
    "guest_os", "role", "family", "sha256", "arm", "run", "task_uid", "status", "telemetry_complete",
    "payload_behaviour", "verdict", "verdict_score", "verdict_model", "path",
]


def save_to_dataset(dataset, sample, record, analysis_dir, lock):
    """Copy one run's classifier input and verdict, plus its labels, into the
    dataset folder and index it. Never copies the sample itself."""
    run_dir = dataset / record["os"] / sample["role"] / record["sha256"] / f"{record['arm']}-{record['run']}"
    run_dir.mkdir(parents=True, exist_ok=True)
    for name in ("features.json", "classification.json"):
        source = analysis_dir / name
        if source.exists():
            (run_dir / name).write_bytes(source.read_bytes())
    labels = {**record, "family": sample.get("family", ""), "role": sample["role"]}
    (run_dir / "labels.json").write_text(json.dumps(labels, indent=1))
    verdict = {}
    if (run_dir / "classification.json").exists():
        verdict = json.loads((run_dir / "classification.json").read_text())
    row = {
        **labels,
        "guest_os": record["os"],
        "verdict": verdict.get("label", ""),
        "verdict_score": verdict.get("score", ""),
        "verdict_model": verdict.get("model", ""),
        "path": str(run_dir.relative_to(dataset)),
    }
    index = dataset / "index.csv"
    with lock:
        new = not index.exists()
        with index.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=INDEX_FIELDS, extrasaction="ignore")
            if new:
                writer.writeheader()
            writer.writerow(row)


class Lane:
    """One guest OS's runs, one at a time on that OS's worker. Lanes share a
    stop flag: an egress drop in either stops both (protocol section 6)."""

    def __init__(self, guest_os, items, ctx):
        self.guest_os, self.items, self.ctx = guest_os, items, ctx
        self.error = None

    def run(self):
        ctx = self.ctx
        try:
            for item in self.items:
                if ctx["stop"].is_set():
                    return
                wait_until_cool(ctx)
                if ctx["stop"].is_set():
                    return
                if self.guest_os == "windows":
                    switch_arm(item["arm"])
                image = run_image(self.guest_os, item["arm"], ctx)
                drops_before = egress_drops()
                started = now()
                sample = ctx["register"][item["sha256"]]
                task_uid, status = submit(ctx["api"], sample, ctx["timeout"], ctx["poll"], ctx["stop"])
                record = {**item, "task_uid": task_uid, "submitted": started, "completed": now(), "image": image}
                record.update(label_analysis(ANALYSES_DIR / task_uid, self.guest_os))
                record.update(verdict_fields(ANALYSES_DIR / task_uid))
                record["status"] = status
                features = ANALYSES_DIR / task_uid / "features.json"
                if features.exists():
                    executed_sha = json.loads(features.read_text()).get("sample", {}).get("sha256")
                    record["sha256_matches"] = executed_sha == item["sha256"]
                # dmesg is host-wide: with two lanes a drop cannot be told apart, so both stop
                record["egress_drops"] = egress_drops() - drops_before
                with ctx["lock"]:
                    with ctx["results"].open("a") as f:
                        f.write(json.dumps(record) + "\n")
                save_to_dataset(ctx["dataset"], sample, record, ANALYSES_DIR / task_uid, ctx["lock"])
                print(json.dumps({k: record.get(k) for k in ("key", "os", "task_uid", "status", "network_intent", "payload_behaviour")}), flush=True)
                if record["egress_drops"] > 0:
                    ctx["stop"].set()
                    raise RuntimeError(f"CHIMERA-EGRESS-DROP during {task_uid}; batch stopped")
        except BaseException as exc:  # noqa: BLE001 - reported by cmd_run after both lanes end
            self.error = exc
            ctx["stop"].set()


def cmd_run(args):
    import threading

    out = pathlib.Path(args.out)
    plan = json.loads((out / "schedule.json").read_text())
    frozen = plan.get("classifier")
    if frozen:
        current = classifier_fingerprint(args.classifier_dir) or {"files": {}}
        changed = sorted(n for n in set(frozen["files"]) | set(current["files"])
                         if frozen["files"].get(n) != current["files"].get(n))
        if changed and not args.allow_classifier_change:
            raise SystemExit(f"classifier changed since the plan was made ({', '.join(changed)}); the evaluation"
                             " needs one frozen model. Redeploy the planned one, or re-plan.")
    register = {s["sha256"]: s for s in read_register(plan["register"])}
    oses = GUEST_OSES if args.os == "both" else (args.os,)
    for item in plan["schedule"]:
        item.setdefault("os", register[item["sha256"]]["guest_os"])
    windows_arms = {i["arm"] for i in plan["schedule"] if i["os"] == "windows"}
    for arm in windows_arms:
        if not (ARMS_DIR / arm).is_dir():
            raise SystemExit(f"no such arm: {arm}")
    check = ["chimera-net-check", "--require-inetsim"]
    if subprocess.run(check).returncode != 0:
        raise SystemExit("containment check failed; not starting")
    results_path = out / "results.jsonl"
    done = set()
    if results_path.exists():
        done = {json.loads(line)["key"] for line in results_path.read_text().splitlines() if line}
    dataset = pathlib.Path(args.dataset)
    dataset.mkdir(parents=True, exist_ok=True)
    dataset.chmod(0o700)
    ctx = {
        "register": register, "api": args.api, "timeout": plan["timeout"], "poll": args.poll,
        "results": results_path, "dataset": dataset, "lock": threading.Lock(), "stop": threading.Event(),
        "out": out, "image_lock": threading.Lock(), "pause_temp": args.pause_temp, "resume_temp": args.resume_temp,
        "thermal_poll": THERMAL_POLL_S,
    }
    lanes = [
        Lane(os_, [i for i in plan["schedule"] if i["os"] == os_ and i["key"] not in done], ctx)
        for os_ in oses
    ]
    lanes = [lane for lane in lanes if lane.items]
    windows = any(lane.guest_os == "windows" for lane in lanes)
    original_arm = current_arm() if windows else None
    evasion_active = [w for w in EVASION_WORKERS if sh("systemctl", "is-active", w, check=False).strip() == "active"]
    for worker in evasion_active:
        sh("systemctl", "stop", worker)
    finished = threading.Event()
    watchdog = threading.Thread(target=egress_watchdog, args=(ctx, egress_drops(), finished), name="egress")
    watchdog.start()
    try:
        threads = [threading.Thread(target=lane.run, name=lane.guest_os) for lane in lanes]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        finished.set()
        watchdog.join()
        if windows:
            switch_arm(original_arm)
        for worker in evasion_active:
            sh("systemctl", "start", worker)
    errors = [f"{lane.guest_os}: {lane.error}" for lane in lanes if lane.error]
    if errors:
        raise SystemExit("; ".join(errors))


def cmd_export(args):
    """The dataset folder as one archive for the classifier team: features,
    verdicts and labels only. The samples themselves are never in it."""
    import tarfile

    dataset = pathlib.Path(args.dataset)
    with tarfile.open(args.output, "w:gz") as tar:
        for path in sorted(dataset.rglob("*")):
            if path.is_file() and (path.name in ("features.json", "classification.json", "labels.json", "index.csv")):
                tar.add(path, arcname=str(pathlib.Path("chimera-dataset") / path.relative_to(dataset)))
    print(f"wrote {args.output}")


def cmd_label(args):
    print(json.dumps(label_analysis(args.analysis_dir, args.guest_os), indent=1))


def _fmt(value):
    return "–" if value is None else ("yes" if value is True else "no" if value is False else str(value))


def _verdicts(runs):
    return " ".join(sorted({r.get("verdict") or "–" for r in runs}))


def verdict_tables(results, register, frozen=None):
    """Truth (register role) x classifier verdict, per lane and arm, over every attempted run. M/B/I as in
    VERDICT_CLASS; "none" = no classification.json (failed run or classifier error) stays in the denominator."""
    truth = {s["sha256"]: ("benign" if s["role"] == "benign" else "malware") for s in register}
    lines = ["", "## Classifier verdicts (truth by verdict, every attempted run)", ""]
    if frozen:
        lines.append(f"Frozen classifier: {frozen.get('model')} {frozen.get('model_version')},"
                     f" files digest `{frozen['digest'][:16]}` ({len(frozen['files'])} files hashed in schedule.json).")
        seen = sorted({str(r.get("verdict_model_version")) for r in results if r.get("verdict_model_version")})
        lines += [f"Model versions in the verdicts: {', '.join(seen) or 'none'}.", ""]
    for os_, arm in sorted({(r["os"], r.get("arm")) for r in results}):
        runs = [r for r in results if r["os"] == os_ and r.get("arm") == arm and r["sha256"] in truth]
        lines += [f"**{os_} / {arm}** ({len(runs)} runs)", "",
                  "| Truth | Malicious (M) | Benign (B) | Indeterminate (I) | No verdict file | M rate |",
                  "|---|---|---|---|---|---|"]
        for t in ("malware", "benign"):
            rows = [r for r in runs if truth[r["sha256"]] == t]
            n = {k: sum(1 for r in rows if r.get("verdict_class") == k) for k in ("M", "B", "I")}
            none = len(rows) - sum(n.values())
            rate = f"{n['M']}/{len(rows)}" if rows else "–"
            lines.append(f"| {t} | {n['M']} | {n['B']} | {n['I']} | {none} | {rate} |")
        lines.append("")
    lines.append("M rate is end-to-end: malicious verdicts over all attempted runs of that truth class"
                 " (detection rate for malware, false-alarm rate for benign).")
    return lines


def other_tables(results, register):
    """Linux malware runs (descriptive, no second arm to compare) and benign runs
    (a false-positive check: payload behaviour should be rare, verdicts benign)."""
    lines = []
    linux = [s for s in register if s["guest_os"] == "linux" and s["role"] != "benign"]
    if linux:
        lines += [
            "", "## Linux samples", "",
            "| SHA-256 | Role | Family | Runs | Complete | Payload observed | Children | Network |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for sample in sorted(linux, key=lambda s: (s["role"], s.get("family", ""), s["sha256"])):
            runs = [r for r in results if r["sha256"] == sample["sha256"]]
            complete = [r for r in runs if r.get("telemetry_complete")] or [{}]
            lines.append(
                f"| `{sample['sha256'][:12]}` | {sample['role']} | {sample.get('family', '')} | {len(runs)}"
                f" | {sum(1 for r in runs if r.get('telemetry_complete'))} | {_fmt(sample_outcome(runs, 'payload_behaviour'))}"
                f" | {max(r.get('children', 0) for r in complete)} | {_fmt(any(r.get('network_intent') for r in complete))} |"
            )
    benign = [s for s in register if s["role"] == "benign"]
    if benign:
        lines += [
            "", "## Benign samples (false-positive check)", "",
            "| OS | Name | SHA-256 | Runs | Complete | Payload observed | Persistence | Drops | Network | Verdicts |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for sample in sorted(benign, key=lambda s: (s["guest_os"], s.get("family", ""), s["sha256"])):
            runs = [r for r in results if r["sha256"] == sample["sha256"]]
            complete = [r for r in runs if r.get("telemetry_complete")]
            lines.append(
                f"| {sample['guest_os']} | {sample.get('family') or sample.get('file_name', '')} | `{sample['sha256'][:12]}`"
                f" | {len(runs)} | {len(complete)} | {_fmt(sample_outcome(runs, 'payload_behaviour'))}"
                f" | {sum(1 for r in complete if r.get('persistence'))} | {sum(1 for r in complete if r.get('file_drops'))}"
                f" | {sum(1 for r in complete if r.get('network_intent'))} | {_verdicts(runs)} |"
            )
    return lines


def cmd_report(args):
    out = pathlib.Path(args.out)
    plan = json.loads((out / "schedule.json").read_text())
    register = read_register(plan["register"])
    results = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines() if line]
    for result in results:
        result.setdefault("os", "windows")
    arm_a, arm_b = args.arms or plan["arms"][:2]
    # The arm comparison is Windows only: Linux has one image, benign samples are a check
    windows_malware = [s for s in register if s["guest_os"] == "windows" and s["role"] != "benign"]
    summary = summarise([r for r in results if r["os"] == "windows"], windows_malware, arm_a, arm_b)

    fields = [
        "key", "os", "sha256", "arm", "run", "task_uid", "status", "telemetry_complete", "executed",
        "children", "persistence", "file_drops", "dns_queries", "connections", "http_requests",
        "network_intent", "early_exit", "payload_behaviour", "sample_lifetime_s", "sha256_matches", "egress_drops",
    ]
    with (out / "runs.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    incomplete = [r for r in results if not r.get("telemetry_complete")]
    mismatched = [r for r in results if r.get("sha256_matches") is False]
    lines = [
        f"# M5 results: Windows {arm_a} vs {arm_b}, Linux, benign",
        "",
        f"Runs: {len(results)} of {len(plan['schedule'])} scheduled; incomplete telemetry (excluded): {len(incomplete)};"
        f" executed hash differs from register: {len(mismatched)};"
        f" egress drops: {sum(r.get('egress_drops', 0) for r in results)}.",
        "",
        f"## Primary outcome: {OUTCOME_NAMES[PRIMARY_OUTCOME]} (test samples, protocol Amendment 1)",
        "",
        f"| | {arm_b} observed | {arm_b} not observed |",
        "|---|---|---|",
        f"| **{arm_a} observed** | {summary['both']} | {summary[f'only_{arm_a}']} |",
        f"| **{arm_a} not observed** | {summary[f'only_{arm_b}']} | {summary['neither']} |",
        "",
        f"Paired samples: {summary['paired']}; excluded (no complete run in an arm): {len(summary['excluded'])}.",
        f"Exact McNemar test on the discordant pairs ({summary[f'only_{arm_a}']} {arm_a}-only vs"
        f" {summary[f'only_{arm_b}']} {arm_b}-only): p = {summary['mcnemar_p']:.3f}."
        " Exploratory: the sample is small.",
        "",
        "## Secondary outcomes (exploratory)",
        "",
        "Same paired samples. For the 0-3 count, discordant means a higher count on one arm (sign test).",
        "",
        f"| Outcome | Both | Neither | {arm_a} only | {arm_b} only | Exact p |",
        "|---|---|---|---|---|---|",
        *(
            f"| {OUTCOME_NAMES[o]} | {c['both']} | {c['neither']} | {c[f'only_{arm_a}']} | {c[f'only_{arm_b}']}"
            f" | {c['mcnemar_p']:.3f} |"
            for o, c in summary["secondary"].items()
        ),
        "",
        "## Per sample",
        "",
        f"| SHA-256 | Role | Family | {arm_a} network intent | {arm_b} network intent | {arm_a} children | {arm_b} children"
        f" | {arm_a} network (any run) | {arm_b} network (any run) | Complete runs ({arm_a}/{arm_b}) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(summary["per_sample"], key=lambda r: (r["role"], r["family"], r["sha256"])):
        lines.append(
            f"| `{row['sha256'][:12]}` | {row['role']} | {row['family']} | {_fmt(row[f'{arm_a}_observed'])}"
            f" | {_fmt(row[f'{arm_b}_observed'])} | {row[f'{arm_a}_children']} | {row[f'{arm_b}_children']}"
            f" | {_fmt(row[f'{arm_a}_network'])} | {_fmt(row[f'{arm_b}_network'])}"
            f" | {row[f'{arm_a}_complete']}/{row[f'{arm_b}_complete']} |"
        )
    lines += verdict_tables(results, register, plan.get("classifier"))
    lines += other_tables(results, register)
    (out / "report.md").write_text("\n".join(lines) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print("\n".join(lines[:16]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--register", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--arms", nargs="+", default=["A0", "H3"])
    p.add_argument("--runs", type=int, default=2)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--linux-arms", nargs="+", default=["L"], help="labels for the Linux runs (one image, no switching)")
    p.add_argument("--seed", type=int)
    p.add_argument("--classifier-dir", default=str(CLASSIFIER_DIR))
    p.set_defaults(func=cmd_plan)
    p = sub.add_parser("run")
    p.add_argument("--out", required=True)
    p.add_argument("--api", default="http://127.0.0.1:5000/api")
    p.add_argument("--poll", type=float, default=5.0)
    p.add_argument("--os", choices=["both", *GUEST_OSES], default="both", help="run only one lane")
    p.add_argument("--dataset", default=str(DATASET_DIR))
    p.add_argument("--classifier-dir", default=str(CLASSIFIER_DIR))
    p.add_argument("--allow-classifier-change", action="store_true",
                   help="run although the deployed classifier differs from the one frozen in the plan")
    p.add_argument("--pause-temp", type=float, default=PAUSE_TEMP_C, help="pause before a run at this CPU temperature")
    p.add_argument("--resume-temp", type=float, default=RESUME_TEMP_C, help="resume once the CPU is this cool")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("label")
    p.add_argument("analysis_dir")
    p.add_argument("--guest-os", choices=GUEST_OSES, default="windows")
    p.set_defaults(func=cmd_label)
    p = sub.add_parser("export")
    p.add_argument("--dataset", default=str(DATASET_DIR))
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_export)
    p = sub.add_parser("report")
    p.add_argument("--out", required=True)
    p.add_argument("--arms", nargs=2)
    p.set_defaults(func=cmd_report)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
