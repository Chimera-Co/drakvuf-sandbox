#!/usr/bin/env python3
"""
CHIMERA benign batch: run the benign candidate list (benign-v4-candidates.csv) through the web API.

The list names each program and its vendor page; the installers are downloaded by hand from those pages
into one directory. Each file is matched to its row by name (the file name starts with the row's name,
ignoring case, spaces, dashes and dots) and submitted with the row's start command, at most --parallel at a
time (one per analysis worker). Without --submit it only prints the matches and what is missing.

  python3 scripts/chimera/bench/benign_batch.py --dir /var/lib/chimera-benign
  python3 scripts/chimera/bench/benign_batch.py --dir /var/lib/chimera-benign --submit \
      --out /var/lib/chimera-evidence/benign-v4-<date>.csv
"""

import argparse
import csv
import datetime
import pathlib
import re
import sys
import time

import requests

TERMINAL = {"finished", "failed"}
HERE = pathlib.Path(__file__).resolve().parent


def key(text):
    return re.sub(r"[^a-z0-9]", "", text.lower())


def match(rows, directory):
    files = sorted(p for p in directory.iterdir() if p.is_file())
    pairs, missing = [], []
    # Longest names first, so "7zip" does not take the file meant for "7zip-zstd".
    for row in sorted(rows, key=lambda r: -len(key(r["name"]))):
        found = next((p for p in files if key(p.name).startswith(key(row["name"]))), None)
        if found is None:
            missing.append(row["name"])
            continue
        files.remove(found)
        pairs.append((row, found))
    return pairs, missing, files


def submit(api, row, path, timeout):
    data = {"timeout": str(timeout), "mode": "combined"}
    if row.get("start_command"):
        data["start_command"] = row["start_command"]
    with path.open("rb") as fh:
        resp = requests.post(f"{api}/upload", files={"file": (path.name, fh)}, data=data, timeout=120)
    resp.raise_for_status()
    return resp.json()["task_uid"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", required=True, type=pathlib.Path)
    ap.add_argument("--csv", type=pathlib.Path, default=HERE / "benign-v4-candidates.csv")
    ap.add_argument("--api", default="http://127.0.0.1:5000/api")
    ap.add_argument("--timeout", type=int, default=300, help="seconds of guest run per sample")
    ap.add_argument("--parallel", type=int, default=2)
    ap.add_argument("--submit", action="store_true", help="actually submit (default: list matches only)")
    ap.add_argument("--out", type=pathlib.Path, help="CSV of name, file, task id, final status")
    args = ap.parse_args()

    rows = list(csv.DictReader(args.csv.open()))
    pairs, missing, extra = match(rows, args.dir)
    print(f"{len(pairs)} of {len(rows)} programs have a file in {args.dir}")
    for name in missing:
        print(f"  missing: {name}")
    for path in extra:
        print(f"  not in the list: {path.name}")
    if not args.submit:
        return 0
    if not args.out:
        sys.exit("--out is required with --submit")

    queue, running, done = list(pairs), {}, []
    while queue or running:
        while queue and len(running) < args.parallel:
            row, path = queue.pop(0)
            uid = submit(args.api, row, path, args.timeout)
            running[uid] = (row, path)
            print(f"{datetime.datetime.now():%H:%M:%S} submitted {row['name']} -> {uid}", flush=True)
        time.sleep(15)
        for uid in list(running):
            status = requests.get(f"{args.api}/status/{uid}", timeout=30).json().get("status")
            if status in TERMINAL:
                row, path = running.pop(uid)
                done.append({"name": row["name"], "category": row["category"], "file": path.name,
                             "task_uid": uid, "status": status})
                print(f"{datetime.datetime.now():%H:%M:%S} {status}: {row['name']}", flush=True)
    with args.out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["name", "category", "file", "task_uid", "status"])
        writer.writeheader()
        writer.writerows(done)
    print(f"{sum(d['status'] == 'finished' for d in done)} finished, "
          f"{sum(d['status'] == 'failed' for d in done)} failed -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
