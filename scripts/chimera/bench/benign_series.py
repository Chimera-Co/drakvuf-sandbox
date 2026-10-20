#!/usr/bin/env python3
"""
CHIMERA benign reliability/timing series.

Submits the same benign sample N times through the real web API -> RQ ->
worker path, one at a time, and records per run: final status, per-substatus
stage timestamps, the telemetry completeness summary, analysis storage size,
and whether a stale Xen domain / qemu device model survived the run.

Run as root (analysis directories are root-only), with the deployment venv:
  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/benign_series.py \
      --sample /var/lib/chimera-fixtures/Bginfo64.exe --runs 10 --timeout 120 \
      --out /var/lib/chimera-evidence/benign-series-<date>
"""

import argparse
import csv
import datetime
import json
import pathlib
import subprocess
import sys
import time

import requests

ANALYSES_DIR = pathlib.Path("/var/lib/drakrun/analyses")
TERMINAL = {"finished", "failed"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def dir_size(path: pathlib.Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def lifecycle_leftovers():
    """Dying/stale domains and qemu device models other than dom0's backend."""
    xl = subprocess.run(["xl", "list"], capture_output=True, text=True).stdout.splitlines()[1:]
    domains = [line.split()[0] + ":" + line.split()[4] for line in xl if line.split()[1] != "0"]
    ps = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True).stdout
    qemus = [
        line.split()[0]
        for line in ps.splitlines()
        if "qemu-system" in line and "-xen-domid" in line and "-xen-domid 0 " not in line
    ]
    return {"domains": domains, "device_models": qemus}


def run_one(api, sample, timeout, poll):
    with open(sample, "rb") as f:
        resp = requests.post(
            f"{api}/upload",
            files={"file": (pathlib.Path(sample).name, f)},
            data={"timeout": str(timeout)},
            timeout=60,
        )
    resp.raise_for_status()
    task_uid = resp.json()["task_uid"]
    record = {"task_uid": task_uid, "submitted": now(), "transitions": []}
    last = None
    deadline = time.monotonic() + timeout + 1800
    while time.monotonic() < deadline:
        status = requests.get(f"{api}/status/{task_uid}", timeout=30).json()
        state = (status.get("status"), status.get("substatus"))
        if state != last:
            record["transitions"].append({"t": now(), "status": state[0], "substatus": state[1]})
            last = state
        if state[0] in TERMINAL:
            break
        time.sleep(poll)
    record["completed"] = now()
    record["status"] = last[0] if last else None

    metadata_path = ANALYSES_DIR / task_uid / "metadata.json"
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        for key in ("time_started", "time_execution_started", "time_finished", "telemetry", "postprocess", "error"):
            record[key] = metadata.get(key)
        record["storage_bytes"] = dir_size(ANALYSES_DIR / task_uid)
    return record


def seconds(a, b):
    if not a or not b:
        return None
    fa, fb = datetime.datetime.fromisoformat(a), datetime.datetime.fromisoformat(b)
    return round((fb - fa).total_seconds(), 2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:5000/api")
    parser.add_argument("--sample", required=True)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--poll", type=float, default=2.0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for i in range(1, args.runs + 1):
        record = run_one(args.api, args.sample, args.timeout, args.poll)
        time.sleep(3)
        record["leftovers_after"] = lifecycle_leftovers()
        record["run"] = i
        (out / f"run-{i:02d}.json").write_text(json.dumps(record, indent=1))
        tel = record.get("telemetry") or {}
        stage = {t["substatus"]: t["t"] for t in record["transitions"]}
        row = {
            "run": i,
            "task_uid": record["task_uid"],
            "status": record["status"],
            "submit_to_done_s": seconds(record["submitted"], record["completed"]),
            "queue_wait_s": seconds(record["submitted"], record.get("time_started")),
            "vm_start_to_exec_s": seconds(record.get("time_started"), record.get("time_execution_started")),
            "exec_to_finished_s": seconds(record.get("time_execution_started"), record.get("time_finished")),
            "postprocess_s": seconds(stage.get("postprocessing"), stage.get("done") or record.get("time_finished")),
            "drakvuf_rc": tel.get("drakvuf_returncode"),
            "hard_timeout": tel.get("drakvuf_hard_timeout"),
            "missing_plugins": " ".join(tel.get("missing_plugins", [])),
            "storage_mb": round(record.get("storage_bytes", 0) / 1e6, 1),
            "leftover_domains": " ".join(record["leftovers_after"]["domains"]),
            "leftover_qemu": " ".join(record["leftovers_after"]["device_models"]),
        }
        rows.append(row)
        print(json.dumps(row), flush=True)

    with (out / "summary.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    ok = sum(1 for r in rows if r["status"] == "finished")
    print(f"finished {ok}/{len(rows)}", flush=True)
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
