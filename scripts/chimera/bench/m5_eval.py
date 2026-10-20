#!/usr/bin/env python3
"""
CHIMERA real-malware evaluation (M5) batch runner and report.

Follows docs/chimera/malware-evaluation-protocol.md. The operator supplies the
samples; this tool never downloads anything. The sample register is private
and must stay outside the repository.

  plan    register CSV -> schedule.json (every sample x arm x run, order randomised per sample)
  run     submit the schedule one analysis at a time, switching arms with chimera-arm;
          resumable: runs already in results.jsonl are skipped
  label   print the outcome labels of one analysis directory
  report  results.jsonl -> per-run CSV, per-sample table and McNemar test (report.md)

Register columns (CSV, header required):
  sha256, path (password-protected ZIP), role (test|control), family, tags,
  archive_password, entry (path inside the archive, optional), file_name (optional)

Each sample is decrypted in memory with the host's 7-Zip, its SHA-256 checked
against the register, and submitted as a plain file, so A0 (no 7-Zip in the
guest) and H3 get identical input.

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
ANALYSIS_WORKER = "drakrun-worker@1"
# Evasion scans restore the same Windows snapshot; one starting mid-batch would
# run on whichever arm is current and block arm switches, so it pauses for the batch.
EVASION_WORKER = "drakrun-evasion-worker@1"
TERMINAL = {"finished", "failed"}
EARLY_EXIT_S = 10
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
        if row.get("role", "test").strip() not in ("test", "control"):
            raise ValueError(f"role must be test or control: {sha}")
        row["sha256"] = sha
        row["role"] = row.get("role", "test").strip()
    return rows


def make_schedule(register, arms, runs, seed):
    """Every sample x arm x run. Samples in random order; each sample's runs in
    its own random arm order, so no arm always runs first (C2 time checks)."""
    rng = random.Random(seed)
    samples = list(register)
    rng.shuffle(samples)
    schedule = []
    for sample in samples:
        slots = [(arm, i) for arm in arms for i in range(1, runs + 1)]
        rng.shuffle(slots)
        for arm, i in slots:
            schedule.append({"key": f"{sample['sha256']}/{arm}/{i}", "sha256": sample["sha256"], "arm": arm, "run": i})
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


def label_analysis(analysis_dir):
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


def sample_outcome(runs):
    """Majority over complete runs; a tie counts as observed. None if no complete run."""
    complete = [r for r in runs if r.get("telemetry_complete")]
    if not complete:
        return None
    return 2 * sum(1 for r in complete if r.get("payload_behaviour")) >= len(complete)


def summarise(results, register, arm_a, arm_b):
    roles = {s["sha256"]: s for s in register}
    per_sample, excluded = [], []
    for sha, sample in roles.items():
        row = {"sha256": sha, "role": sample["role"], "family": sample.get("family", "")}
        for arm in (arm_a, arm_b):
            runs = [r for r in results if r["sha256"] == sha and r["arm"] == arm]
            row[f"{arm}_runs"] = len(runs)
            row[f"{arm}_complete"] = sum(1 for r in runs if r.get("telemetry_complete"))
            row[f"{arm}_observed"] = sample_outcome(runs)
            complete = [r for r in runs if r.get("telemetry_complete")] or [{}]
            row[f"{arm}_children"] = max(r.get("children", 0) for r in complete)
            row[f"{arm}_network"] = any(r.get("network_intent") for r in complete)
        if row[f"{arm_a}_observed"] is None or row[f"{arm_b}_observed"] is None:
            excluded.append(sha)
        per_sample.append(row)
    paired = [r for r in per_sample if r["role"] == "test" and r["sha256"] not in excluded]
    only_a = sum(1 for r in paired if r[f"{arm_a}_observed"] and not r[f"{arm_b}_observed"])
    only_b = sum(1 for r in paired if r[f"{arm_b}_observed"] and not r[f"{arm_a}_observed"])
    both = sum(1 for r in paired if r[f"{arm_a}_observed"] and r[f"{arm_b}_observed"])
    neither = len(paired) - only_a - only_b - both
    return {
        "per_sample": per_sample,
        "excluded": excluded,
        "paired": len(paired),
        "both": both,
        "neither": neither,
        f"only_{arm_a}": only_a,
        f"only_{arm_b}": only_b,
        "mcnemar_p": mcnemar_exact(only_a, only_b),
    }


# --- running --------------------------------------------------------------------


def sh(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check).stdout


def current_arm():
    return (ARMS_DIR / "CURRENT").read_text().strip()


def egress_drops():
    return sh("dmesg").count("CHIMERA-EGRESS-DROP")


def switch_arm(arm):
    if current_arm() == arm:
        return
    # chimera-arm refuses while a vm-* domain or drakvuf is running; the
    # previous analysis has ended, so wait for its domain to go away.
    for _ in range(60):
        if not re.search(r"^vm-", sh("xl", "list"), re.MULTILINE) and not sh("pgrep", "-x", "drakvuf", check=False):
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
    return sample_name(sample.get("file_name") or entry), data


def sample_name(name):
    """Guest file name: the submitted name, unless it is just a hash (itself a sandbox tell)."""
    base = re.split(r"[\\/]", name)[-1]
    stem = base.rsplit(".", 1)[0]
    if re.fullmatch(r"[0-9a-fA-F]{32,64}", stem):
        return "setup.exe"
    return base if base.lower().endswith(".exe") else base + ".exe"


def submit(api, sample, timeout, poll):
    import requests

    name, data = read_sample(sample)
    digest = hashlib.sha256(data).hexdigest()
    if digest != sample["sha256"]:
        raise RuntimeError(f"archive content {digest} does not match register {sample['sha256']}")
    resp = requests.post(
        f"{api}/upload",
        files={"file": (name, data)},
        data={"timeout": str(timeout), "file_name": name},
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
        time.sleep(poll)
    return task_uid, status


def cmd_plan(args):
    register = read_register(args.register)
    for sample in register:
        if not pathlib.Path(sample["path"]).is_file():
            raise SystemExit(f"missing sample archive: {sample['path']}")
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2**32)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)
    plan = {
        "created": now(),
        "register": str(pathlib.Path(args.register).resolve()),
        "arms": args.arms,
        "runs": args.runs,
        "timeout": args.timeout,
        "seed": seed,
        "schedule": make_schedule(register, args.arms, args.runs, seed),
    }
    (out / "schedule.json").write_text(json.dumps(plan, indent=1))
    hours = len(plan["schedule"]) * (args.timeout + 60) / 3600
    print(f"{len(register)} samples, {len(plan['schedule'])} runs, ~{hours:.1f} h; seed {seed}")


def cmd_run(args):
    out = pathlib.Path(args.out)
    plan = json.loads((out / "schedule.json").read_text())
    register = {s["sha256"]: s for s in read_register(plan["register"])}
    for arm in plan["arms"]:
        if not (ARMS_DIR / arm).is_dir():
            raise SystemExit(f"no such arm: {arm}")
    check = ["chimera-net-check", "--require-inetsim"]
    if subprocess.run(check).returncode != 0:
        raise SystemExit("containment check failed; not starting")
    results_path = out / "results.jsonl"
    done = set()
    if results_path.exists():
        done = {json.loads(line)["key"] for line in results_path.read_text().splitlines() if line}
    original_arm = current_arm()
    evasion_was_active = sh("systemctl", "is-active", EVASION_WORKER, check=False).strip() == "active"
    if evasion_was_active:
        sh("systemctl", "stop", EVASION_WORKER)
    try:
        for item in plan["schedule"]:
            if item["key"] in done:
                continue
            switch_arm(item["arm"])
            drops_before = egress_drops()
            started = now()
            task_uid, status = submit(args.api, register[item["sha256"]], plan["timeout"], args.poll)
            record = {**item, "task_uid": task_uid, "submitted": started, "completed": now()}
            record.update(label_analysis(ANALYSES_DIR / task_uid))
            record["status"] = status
            features = ANALYSES_DIR / task_uid / "features.json"
            if features.exists():
                executed_sha = json.loads(features.read_text()).get("sample", {}).get("sha256")
                record["sha256_matches"] = executed_sha == item["sha256"]
            record["egress_drops"] = egress_drops() - drops_before
            with results_path.open("a") as f:
                f.write(json.dumps(record) + "\n")
            print(json.dumps({k: record.get(k) for k in ("key", "task_uid", "status", "payload_behaviour")}), flush=True)
            if record["egress_drops"] > 0:
                # Protocol section 6: investigate before the batch continues
                raise SystemExit(f"CHIMERA-EGRESS-DROP during {task_uid}; batch stopped")
    finally:
        switch_arm(original_arm)
        if evasion_was_active:
            sh("systemctl", "start", EVASION_WORKER)


def cmd_label(args):
    print(json.dumps(label_analysis(args.analysis_dir), indent=1))


def _fmt(value):
    return "–" if value is None else ("yes" if value is True else "no" if value is False else str(value))


def cmd_report(args):
    out = pathlib.Path(args.out)
    plan = json.loads((out / "schedule.json").read_text())
    register = read_register(plan["register"])
    results = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines() if line]
    arm_a, arm_b = args.arms or plan["arms"][:2]
    summary = summarise(results, register, arm_a, arm_b)

    fields = [
        "key", "sha256", "arm", "run", "task_uid", "status", "telemetry_complete", "executed",
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
        f"# M5 results: {arm_a} vs {arm_b}",
        "",
        f"Runs: {len(results)} of {len(plan['schedule'])} scheduled; incomplete telemetry (excluded): {len(incomplete)};"
        f" executed hash differs from register: {len(mismatched)};"
        f" egress drops: {sum(r.get('egress_drops', 0) for r in results)}.",
        "",
        "## Paired outcome (test samples, payload behaviour observed)",
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
        "## Per sample",
        "",
        f"| SHA-256 | Role | Family | {arm_a} observed | {arm_b} observed | {arm_a} children | {arm_b} children"
        f" | {arm_a} network | {arm_b} network | Complete runs ({arm_a}/{arm_b}) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(summary["per_sample"], key=lambda r: (r["role"], r["family"], r["sha256"])):
        lines.append(
            f"| `{row['sha256'][:12]}` | {row['role']} | {row['family']} | {_fmt(row[f'{arm_a}_observed'])}"
            f" | {_fmt(row[f'{arm_b}_observed'])} | {row[f'{arm_a}_children']} | {row[f'{arm_b}_children']}"
            f" | {_fmt(row[f'{arm_a}_network'])} | {_fmt(row[f'{arm_b}_network'])}"
            f" | {row[f'{arm_a}_complete']}/{row[f'{arm_b}_complete']} |"
        )
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
    p.add_argument("--seed", type=int)
    p.set_defaults(func=cmd_plan)
    p = sub.add_parser("run")
    p.add_argument("--out", required=True)
    p.add_argument("--api", default="http://127.0.0.1:5000/api")
    p.add_argument("--poll", type=float, default=5.0)
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("label")
    p.add_argument("analysis_dir")
    p.set_defaults(func=cmd_label)
    p = sub.add_parser("report")
    p.add_argument("--out", required=True)
    p.add_argument("--arms", nargs=2)
    p.set_defaults(func=cmd_report)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
