"""Collect CHIMERA runs (benign and test malware) into one JSONL file for training/evaluation.

Accepts any mix of:
  - the `m5_eval.py export` archive (chimera-dataset.tar.gz) or its unpacked folder:
      <os>/<role>/<sha256>/<arm>-<run>/{features.json, labels.json}
  - raw analysis folders (/var/lib/drakrun/analyses/<uuid>/ copies). If features.json is
    missing, it is computed with CHIMERA's own extractor (vendored from sprint/final);
  - folders of loose *features.json files.

Runs without labels.json get --role (default: benign). An optional --labels-csv adds or
overrides labels; columns: key (analysis id, folder name or sha256), role, family, program, category.

    .venv/bin/python scripts/02_load_chimera.py ../../chimera-benign-dataset/windows ../../chimera-benign-dataset/linux \
        --index-csv ../../chimera-benign-dataset/index.csv --out data/chimera/chimera.jsonl

role "benign" -> label 0 (training); roles "test" and "control" (the M5 malware runs) -> label 1,
kept in the same file but marked split="chimera_test" so training never sees them.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import tarfile
from collections import Counter
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from chimera_clf.vendor.chimera_features import extract_features  # noqa: E402

MALWARE_ROLES = {"test", "control"}


def _record(features: dict, labels: dict, origin: str, default_role: str, extra: dict) -> dict:
    sample = features.get("sample") or {}
    sha = (labels.get("sha256") or sample.get("sha256") or "").lower()
    role = (extra.get("role") or labels.get("role") or default_role).strip().lower()
    arm = labels.get("arm") or extra.get("arm") or ""
    run = labels.get("run") if labels.get("run") is not None else extra.get("run", "")
    program = extra.get("program") or sample.get("file_name") or sha[:12]
    malicious = 1 if role in MALWARE_ROLES else 0 if role == "benign" else None
    return {
        "id": f"chimera:{sha or origin}:{arm}-{run}" if (arm or run != "") else f"chimera:{sha or origin}:{origin}",
        "source": "chimera",
        "group": f"prog:{sha or program}",
        "split": "chimera_test" if role in MALWARE_ROLES else "train" if role == "benign" else "unlabelled",
        "label": {"malicious": malicious, "role": role, "family": extra.get("family") or labels.get("family") or None,
                  "category": extra.get("category") or None},
        "features": features,
        "aux": {"origin": origin, "arm": arm, "run": run, "program": program,
                "guest_os": (features.get("run") or {}).get("guest_os"),
                "complete": (features.get("run") or {}).get("complete"),
                "vm_stalled": (features.get("run") or {}).get("vm_stalled"),
                "task_uid": labels.get("task_uid"), "payload_behaviour": labels.get("payload_behaviour")},
    }


def _from_tar(path: Path):
    with tarfile.open(path, "r:*") as tar:
        members = {PurePosixPath(m.name): m for m in tar.getmembers() if m.isfile()}
        for name, member in members.items():
            if name.name != "features.json":
                continue
            features = json.load(tar.extractfile(member))
            lab = members.get(name.with_name("labels.json"))
            labels = json.load(tar.extractfile(lab)) if lab else {}
            yield features, labels, f"{path.name}:{name.parent}", name.parent.name


def _from_dir(path: Path):
    seen_dirs = set()
    for fpath in sorted(path.rglob("*features.json")):
        seen_dirs.add(fpath.parent)
        labels_path = fpath.with_name("labels.json")
        labels = json.loads(labels_path.read_text()) if labels_path.exists() else {}
        yield json.loads(fpath.read_text()), labels, str(fpath.parent), fpath.parent.name
    # raw analysis folders without features.json: compute them like the sandbox does
    for meta in sorted(path.rglob("metadata.json")):
        d = meta.parent
        if d in seen_dirs or not (d / "process_tree.json").exists():
            continue
        yield extract_features(d), {}, str(d), d.name


def _iter_inputs(paths):
    for p in paths:
        p = Path(p).expanduser()
        if p.is_file() and (p.suffix in (".gz", ".tgz", ".tar") or p.name.endswith(".tar.gz")):
            yield from _from_tar(p)
        elif p.is_file() and p.name.endswith(".json"):
            yield json.loads(p.read_text()), {}, str(p), p.stem
        elif p.is_dir():
            yield from _from_dir(p)
        else:
            print(f"skipping {p}: not a file or folder I understand", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "chimera" / "chimera.jsonl")
    ap.add_argument("--role", default="benign", help="role for runs without labels.json")
    ap.add_argument("--labels-csv", type=Path)
    ap.add_argument("--index-csv", type=Path,
                    help="chimera-benign-dataset index.csv: names and categories per program (sha256)")
    ap.add_argument("--append", action="store_true")
    a = ap.parse_args()

    overrides = {}
    if a.index_csv:
        with a.index_csv.open(newline="") as f:
            for row in csv.DictReader(f):
                sha = (row.get("sha256") or "").strip().lower()
                if sha:
                    overrides[sha] = {"role": "benign", "category": row.get("category") or None,
                                      "program": f"{row.get('name', '')} {row.get('version', '')}".strip() or None}
    if a.labels_csv:
        with a.labels_csv.open(newline="") as f:
            for row in csv.DictReader(f):
                overrides[(row.get("key") or "").strip().lower()] = {k: v for k, v in row.items() if v}

    a.out.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if a.append and a.out.exists():
        for line in a.out.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                existing.update((r["id"], r["aux"].get("content_sha256", "")))
    stats = Counter()
    with a.out.open("a" if a.append else "w") as out:
        for features, labels, origin, key in _iter_inputs(a.inputs):
            if features.get("schema") != "chimera-features/1":
                stats["not_chimera_features"] += 1
                continue
            sha = ((features.get("sample") or {}).get("sha256") or "").lower()
            extra = overrides.get(key.lower()) or overrides.get(sha) or {}
            rec = _record(features, labels, origin, a.role, extra)
            content = hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest()
            rec["aux"]["content_sha256"] = content
            if rec["id"] in existing or content in existing:
                stats["duplicate"] += 1
                continue
            existing.update((rec["id"], content))
            out.write(json.dumps(rec) + "\n")
            stats[f"{rec['label']['role']}/{rec['aux']['guest_os']}"] += 1
    groups = Counter()
    for line in a.out.read_text().splitlines():
        r = json.loads(line)
        if r["split"] == "train":
            groups[r["group"]] += 1
    print(json.dumps({"written": dict(stats), "benign_programs": len(groups),
                      "benign_runs": sum(groups.values()), "out": str(a.out)}, indent=1))


if __name__ == "__main__":
    main()
