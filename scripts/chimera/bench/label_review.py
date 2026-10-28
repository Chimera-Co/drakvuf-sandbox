#!/usr/bin/env python3
"""
Blind review of the automatic behaviour labels (goal G7) from recorded runs; nothing is detonated.

  sheet      draw a stratified random set of recorded runs (role x strict-complete), seed recorded, and write
             per-run evidence for two reviewers with every automatic label, role and family hidden; the key
             (run id -> analysis, role, automatic labels) goes to a separate private file
  agreement  key + two filled review forms -> agreement per label (automatic vs each reviewer, reviewer vs
             reviewer), Cohen's kappa, and the automatic labels against the reviewers' consensus by role

Strict-complete as in the report (Table 3.5): telemetry-complete, DRAKVUF did not exit early, and no error line
in DRAKVUF's log (in practice a refused page-fault injection).

Run as root with the deployment venv, for example:
  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/label_review.py sheet \
      --results malware=/var/lib/chimera-evidence/cohort-2026-10-exe/results.jsonl \
      --results benign=/var/lib/chimera-evidence/benign-v4-2026-10/results.jsonl \
      --per-cell 10 --out review/ --key /var/lib/chimera-evidence/g7/key.csv
  label_review.py agreement --key key.csv --form A=review-A.csv --form B=review-B.csv
"""

import argparse
import csv
import json
import math
import pathlib
import random
import secrets
import sys

ANALYSES_DIR = pathlib.Path("/var/lib/drakrun/analyses")
# The outcomes of protocol section 4 the reviewers judge, as yes/no
LABELS = ("executed", "children", "persistence", "file_drop", "network_intent")
FORM_FIELDS = ["run", *LABELS, "notes"]
INSTRUCTIONS = """# Behaviour label review (G7)

Each folder R01..R{last} holds the telemetry of one recorded run on the sandbox. For every run, decide from the
evidence alone and fill one row of `review-form.csv` with yes / no (leave a cell empty if you cannot decide):

- **executed**: the submitted program started as a process (see `summary.md`, startup).
- **children**: that process started at least one other process, directly or through its descendants.
- **persistence**: the program or its descendants made something start automatically: a value written under a
  Run/RunOnce key, a service ImagePath/ServiceDll, Winlogon Shell/Userinit/Notify, a scheduled task, or a file in
  a Startup folder.
- **file_drop**: the program or its descendants wrote an executable or script file (exe, dll, sys, scr, com,
  cpl, ocx, ps1, psm1, vbs, vbe, js, jse, wsf, bat, cmd, hta, jar, lnk, msi).
- **network_intent**: the program or its descendants made a DNS query, a connection to a non-loopback address, or
  an HTTP request.

Windows itself runs many processes and writes the registry constantly: count only what the submitted program and
its descendants did. Work independently; do not compare notes before both forms are complete.

Files per run: `summary.md` (startup and run facts), `processes.csv` (every process in the guest, with parent and
start/exit time relative to the program's start), `files_written.csv` and `files_deleted.csv` (with the writing
process), `registry_writes.csv` (every registry value set or deleted from the program's start on, any process),
`network.csv` (DNS, connections, HTTP, with the process).
"""


def is_strict(analysis_dir, record):
    """Telemetry-complete, no early DRAKVUF exit, no error line in DRAKVUF's log."""
    if not record.get("telemetry_complete"):
        return False
    telemetry = json.loads((analysis_dir / "metadata.json").read_text()).get("telemetry") or {}
    if telemetry.get("drakvuf_exited_early"):
        return False
    stderr = analysis_dir / "drakvuf_stderr.log"
    log = stderr.read_text(errors="replace") if stderr.exists() else ""
    return not any("error" in line.lower() for line in log.splitlines())


def automatic_labels(record):
    return {
        "executed": bool(record.get("executed")),
        "children": (record.get("children") or 0) > 0,
        "persistence": bool(record.get("persistence")),
        "file_drop": (record.get("file_drops") or 0) > 0,
        "network_intent": bool(record.get("network_intent")),
    }


def draw(runs, per_cell, seed):
    """per_cell runs from every (role, strict) cell, then shuffled together; runs are dicts with role, strict."""
    rng = random.Random(seed)
    chosen = []
    for cell in sorted({(r["role"], r["strict"]) for r in runs}):
        pool = sorted((r for r in runs if (r["role"], r["strict"]) == cell), key=lambda r: r["task_uid"])
        chosen.extend(rng.sample(pool, min(per_cell, len(pool))))
    rng.shuffle(chosen)
    return chosen


def _write_csv(path, fields, rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _rel(t, t0):
    return "" if not t or not t0 else round(float(t) - t0, 2)


def write_evidence(analysis_dir, run_dir):
    """The run's telemetry without any automatic label: processes, files, registry value writes, network."""
    report = json.loads((analysis_dir / "report.json").read_text())
    metadata = json.loads((analysis_dir / "metadata.json").read_text())
    startup = report.get("startup") or {}
    processes = report.get("processes", [])
    names = {p["seqid"]: p.get("name", "") for p in processes}
    root = next((p for p in processes if p["seqid"] == startup.get("process")), {})
    t0 = root.get("started_at") or None

    def who(entry):
        seqids = entry.get("process_seqids")
        if seqids is None:
            seqids = [entry.get("process_seqid")]
        return "; ".join(f"{s} {names.get(s, '?')}" for s in seqids)

    run_dir.mkdir(parents=True, exist_ok=True)
    telemetry = metadata.get("telemetry") or {}
    (run_dir / "summary.md").write_text(
        f"Startup status: {startup.get('status')}\n"
        f"Startup process: {startup.get('process_name')} {startup.get('arguments') or ''}\n"
        f"Startup pid / seqid: {startup.get('pid')} / {startup.get('process')}\n"
        f"Analysis window: {metadata.get('timeout')} s; DRAKVUF runtime {telemetry.get('drakvuf_runtime_s')} s\n"
        "Times in the CSV files are seconds from the startup process's start.\n"
    )
    _write_csv(run_dir / "processes.csv",
               ["seqid", "parent_seqid", "pid", "name", "args", "started_s", "exited_s", "exit_code"],
               [{**p, "args": " ".join(p.get("args") or []), "started_s": _rel(p.get("started_at"), t0),
                 "exited_s": _rel(p.get("exited_at"), t0)} for p in processes])
    for kind in ("modified", "deleted"):
        _write_csv(run_dir / f"files_{'written' if kind == 'modified' else kind}.csv", ["filename", "process"],
                   [{"filename": f["filename"], "process": who(f)} for f in report.get(f"{kind}_files", [])])
    network = (
        [{"kind": "dns", "target": d.get("domain"), "process": who(d)} for d in report.get("dns_queries", [])]
        + [{"kind": f"connection {c.get('protocol', '')}", "target": f"{c.get('remote_ip')}:{c.get('remote_port')}",
            "process": who(c)} for c in report.get("connections", [])]
        + [{"kind": f"http {h.get('verb', '')}", "target": h.get("path"), "process": who(h)}
           for h in report.get("http_requests", [])]
    )
    _write_csv(run_dir / "network.csv", ["kind", "target", "process"], network)
    writes = []
    regmon = analysis_dir / "regmon.log"
    if regmon.exists():
        with regmon.open(errors="replace") as f:
            for line in f:
                if '"NtSetValueKey"' not in line and '"NtDeleteValueKey"' not in line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if t0 and float(event.get("TimeStamp") or 0) < t0:
                    continue
                writes.append({"time_s": _rel(event.get("TimeStamp"), t0), "pid": event.get("PID"),
                               "process": event.get("ProcessName"), "method": event.get("Method"),
                               "key": event.get("Key"), "value_name": event.get("ValueName"),
                               "value": str(event.get("Value") or "")[:200]})
    _write_csv(run_dir / "registry_writes.csv", ["time_s", "pid", "process", "method", "key", "value_name", "value"],
               writes)


def cmd_sheet(args):
    runs = []
    for spec in args.results:
        role, path = spec.split("=", 1)
        for line in pathlib.Path(path).read_text().splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            analysis = args.analyses / record["task_uid"]
            runs.append({"role": role, "task_uid": record["task_uid"], "results": path,
                         "strict": is_strict(analysis, record), **automatic_labels(record)})
    seed = args.seed if args.seed is not None else secrets.randbelow(2**32)
    chosen = draw(runs, args.per_cell, seed)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    width = len(str(len(chosen)))
    key = []
    for i, run in enumerate(chosen, 1):
        run_id = f"R{i:0{max(width, 2)}d}"
        write_evidence(args.analyses / run["task_uid"], out / run_id)
        key.append({"run": run_id, **run})
    _write_csv(out / "review-form.csv", FORM_FIELDS, [{"run": k["run"]} for k in key])
    (out / "README.md").write_text(INSTRUCTIONS.replace("{last}", key[-1]["run"][1:]))
    key_path = pathlib.Path(args.key)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(key_path, ["run", "role", "strict", "task_uid", "results", *LABELS], key)
    cells = {}
    for run in chosen:
        cells[(run["role"], run["strict"])] = cells.get((run["role"], run["strict"]), 0) + 1
    print(json.dumps({"seed": seed, "runs": len(chosen), "drawn_from": len(runs),
                      "cells": {f"{r}/{'strict' if s else 'not-strict'}": n for (r, s), n in sorted(cells.items())}}))


def _yes(value):
    value = (value or "").strip().lower()
    return {"yes": True, "y": True, "true": True, "no": False, "n": False, "false": False}.get(value)


def cohen_kappa(pairs):
    """(kappa or None, agreements, n) for a list of (bool, bool)."""
    n = len(pairs)
    if not n:
        return None, 0, 0
    agree = sum(a == b for a, b in pairs)
    pa = sum(a for a, _ in pairs) / n
    pb = sum(b for _, b in pairs) / n
    expected = pa * pb + (1 - pa) * (1 - pb)
    kappa = None if math.isclose(expected, 1.0) else (agree / n - expected) / (1 - expected)
    return kappa, agree, n


def agreement(key, forms):
    """Rows of the agreement table: per label, automatic vs each reviewer and reviewer vs reviewer; then the
    automatic label against the consensus (both reviewers agree) by role."""
    sources = {"automatic": {k["run"]: {lab: _yes(k[lab]) for lab in LABELS} for k in key}}
    for name, rows in forms.items():
        sources[name] = {r["run"]: {lab: _yes(r.get(lab)) for lab in LABELS} for r in rows}
    names = list(forms)
    comparisons = [("automatic", n) for n in names] + [(a, b) for i, a in enumerate(names) for b in names[i + 1:]]
    table, consensus = [], []
    for label in LABELS:
        for a, b in comparisons:
            pairs = [(sources[a][run][label], sources[b].get(run, {}).get(label)) for run in sources[a]]
            pairs = [(x, y) for x, y in pairs if x is not None and y is not None]
            kappa, agree, n = cohen_kappa(pairs)
            table.append({"label": label, "pair": f"{a} vs {b}", "agree": agree, "n": n, "kappa": kappa})
        if len(names) >= 2:
            for role in sorted({k["role"] for k in key}):
                cells = {"auto_yes_reviewers_yes": 0, "auto_yes_reviewers_no": 0, "auto_no_reviewers_yes": 0,
                         "auto_no_reviewers_no": 0, "reviewers_disagree": 0}
                for k in key:
                    if k["role"] != role:
                        continue
                    votes = {sources[n].get(k["run"], {}).get(label) for n in names}
                    if len(votes) != 1 or None in votes:
                        cells["reviewers_disagree"] += 1
                        continue
                    auto = "yes" if _yes(k[label]) else "no"
                    cells[f"auto_{auto}_reviewers_{'yes' if votes.pop() else 'no'}"] += 1
                consensus.append({"label": label, "role": role, **cells})
    return table, consensus


def cmd_agreement(args):
    with open(args.key, newline="") as f:
        key = list(csv.DictReader(f))
    forms = {}
    for spec in args.form:
        name, path = spec.split("=", 1)
        with open(path, newline="") as f:
            forms[name] = list(csv.DictReader(f))
    table, consensus = agreement(key, forms)
    print("| Label | Pair | Agree | Cohen's kappa |\n|---|---|---|---|")
    for row in table:
        kappa = "undefined" if row["kappa"] is None else f"{row['kappa']:.2f}"
        print(f"| {row['label']} | {row['pair']} | {row['agree']}/{row['n']} | {kappa} |")
    if consensus:
        print("\n| Label | Role | auto yes, reviewers yes | auto yes, reviewers no | auto no, reviewers yes"
              " | auto no, reviewers no | reviewers disagree |\n|---|---|---|---|---|---|---|")
        for row in consensus:
            print(f"| {row['label']} | {row['role']} | {row['auto_yes_reviewers_yes']} | {row['auto_yes_reviewers_no']}"
                  f" | {row['auto_no_reviewers_yes']} | {row['auto_no_reviewers_no']} | {row['reviewers_disagree']} |")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sheet")
    p.add_argument("--results", action="append", required=True, help="ROLE=results.jsonl (repeatable)")
    p.add_argument("--per-cell", type=int, default=10, help="runs per role x strict-complete cell")
    p.add_argument("--seed", type=int)
    p.add_argument("--out", required=True)
    p.add_argument("--key", required=True, help="private file: run id -> analysis, role and automatic labels")
    p.add_argument("--analyses", type=pathlib.Path, default=ANALYSES_DIR)
    p.set_defaults(func=cmd_sheet)
    p = sub.add_parser("agreement")
    p.add_argument("--key", required=True)
    p.add_argument("--form", action="append", required=True, help="NAME=filled review-form.csv (repeatable)")
    p.set_defaults(func=cmd_agreement)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
