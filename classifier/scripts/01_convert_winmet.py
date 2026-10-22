"""Stream WinMET 7z volumes and convert every CAPE report to chimera-features/1.

One decompression pass per volume; each report is converted as soon as py7zr finishes it,
then freed, so the ~750 GB of JSON never touches the disk.

    .venv/bin/python scripts/01_convert_winmet.py --volumes 1 2 3 4 5 --jobs 5
    .venv/bin/python scripts/01_convert_winmet.py --volumes 1 --limit 20 --out data/winmet_test

Output per volume: <out>/v<N>.jsonl.gz (one record per report), <out>/v<N>.errors.jsonl,
<out>/v<N>.done.json (summary). Re-running skips reports already in the output file
(decompression still has to pass over them, conversion does not).
"""

from __future__ import annotations

import argparse
import gzip
import io
import multiprocessing as mp
import os
import sys
import time
import traceback
from pathlib import Path

import orjson
import py7zr
from py7zr.io import Py7zIO, WriterFactory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from chimera_clf.paths import DATASETS  # noqa: E402
from chimera_clf.cape_adapter import (  # noqa: E402
    ADAPTER_VERSION, adapt_report, hooks_sha256, load_aliases, load_hooks)

PASSWORD = "infected"  # published on the WinMET Zenodo record


class _StreamingIO(Py7zIO):
    """Buffers one archive member; hands it to a callback when py7zr closes it."""

    def __init__(self, name, on_complete, skip):
        self.name, self.on_complete, self.skip = name, on_complete, skip
        self.buf = None if skip else io.BytesIO()
        self._size = 0

    def write(self, s):
        self._size += len(s)
        if self.buf is not None:
            self.buf.write(s)
        return len(s)

    def read(self, size=None):
        return b""

    def seek(self, offset, whence=0):
        return 0

    def flush(self):
        pass

    def size(self):
        return self._size

    def close(self):
        if self.buf is not None:
            data, self.buf = self.buf.getvalue(), None
            self.on_complete(self.name, data)
        else:
            self.on_complete(self.name, None)


class _Factory(WriterFactory):
    def __init__(self, on_complete, done_ids):
        self.on_complete, self.done_ids = on_complete, done_ids

    def create(self, filename):
        sha = Path(filename).stem.lower()
        return _StreamingIO(filename, self.on_complete, skip=sha in self.done_ids)


def _done_ids(path: Path) -> set[str]:
    ids = set()
    if path.exists():
        try:
            with gzip.open(path, "rb") as fh:
                for line in fh:
                    try:
                        ids.add(orjson.loads(line)["id"])
                    except Exception:
                        continue
        except (EOFError, OSError):
            pass  # truncated tail from an interrupted run; complete lines were read
    return ids


def convert_volume(volume: int, out_dir: Path, window_s: float, limit: int | None,
                   labels_path: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"v{volume}.jsonl.gz"
    err_path = out_dir / f"v{volume}.errors.jsonl"
    log_path = out_dir / f"v{volume}.log"
    labels = {k.lower(): v for k, v in orjson.loads(labels_path.read_bytes()).items() if isinstance(v, dict)}
    hooks, implied = load_hooks(), load_aliases()
    done = _done_ids(out_path)
    stats = {"volume": volume, "converted": 0, "skipped_done": 0, "errors": 0, "bytes": 0,
             "no_label": 0, "empty_scope": 0, "started": time.time(), "resumed_with": len(done)}

    out = gzip.open(out_path, "ab", compresslevel=6)
    err = open(err_path, "ab")
    log = open(log_path, "a", encoding="utf-8")

    def on_complete(name, data):
        sha = Path(name).stem.lower()
        if data is None:
            stats["skipped_done"] += 1
            return
        stats["bytes"] += len(data)
        try:
            report = orjson.loads(data)
            del data
            label = labels.get(sha)
            if label is None:
                stats["no_label"] += 1
            rec = adapt_report(report, label, window_s=window_s, hooks=hooks, implied=implied, volume=volume)
            del report
            if not rec["features"]["api_calls"]:
                stats["empty_scope"] += 1
            rec["id"] = rec["id"] or sha
            out.write(orjson.dumps(rec) + b"\n")
            stats["converted"] += 1
        except Exception as exc:  # one bad report must not stop the volume
            stats["errors"] += 1
            err.write(orjson.dumps({"id": sha, "error": f"{type(exc).__name__}: {exc}",
                                    "trace": traceback.format_exc()[-2000:]}) + b"\n")
            err.flush()
        n = stats["converted"] + stats["skipped_done"] + stats["errors"]
        if n % 100 == 0:
            el = time.time() - stats["started"]
            log.write(f"{time.strftime('%H:%M:%S')} v{volume} {n} reports, {stats['bytes'] / 1e9:.1f} GB, "
                      f"{n / el:.1f}/s, errors {stats['errors']}\n")
            log.flush()
            out.flush()

    with py7zr.SevenZipFile(DATASETS / f"WinMET_volume_{volume}.7z", "r", password=PASSWORD) as z:
        names = [n for n in z.getnames() if n.endswith(".json")]
        targets = names[:limit] if limit else None
        stats["members"] = len(targets or names)
        z.extract(targets=targets, factory=_Factory(on_complete, done))

    out.close()
    err.close()
    stats.update({"finished": time.time(), "adapter_version": ADAPTER_VERSION, "window_s": window_s,
                  "hooks_sha256": hooks_sha256(), "complete": not limit and
                  stats["converted"] + stats["skipped_done"] + stats["errors"] == stats["members"]})
    stats["elapsed_s"] = round(stats["finished"] - stats["started"], 1)
    log.write(f"done: {stats}\n")
    log.close()
    (out_dir / f"v{volume}.done.json").write_bytes(orjson.dumps(stats, option=orjson.OPT_INDENT_2))
    return stats


def _worker(args):
    try:
        return convert_volume(*args)
    except Exception as exc:
        return {"volume": args[0], "fatal": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--volumes", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "winmet")
    ap.add_argument("--window", type=float, default=180.0, help="seconds after the root process starts")
    ap.add_argument("--limit", type=int, default=None, help="only the first N reports per volume (testing)")
    ap.add_argument("--jobs", type=int, default=min(5, os.cpu_count() or 1))
    ap.add_argument("--labels", type=Path, default=DATASETS / "reports_consensus_label.json")
    a = ap.parse_args()
    jobs = [(v, a.out, a.window, a.limit, a.labels) for v in a.volumes]
    if a.jobs <= 1 or len(jobs) == 1:
        results = [_worker(j) for j in jobs]
    else:
        with mp.get_context("spawn").Pool(min(a.jobs, len(jobs))) as pool:
            results = pool.map(_worker, jobs)
    for r in results:
        print(orjson.dumps({k: v for k, v in r.items() if k != "trace"}).decode())
        if "fatal" in r:
            print(r["trace"], file=sys.stderr)
    sys.exit(1 if any("fatal" in r for r in results) else 0)


if __name__ == "__main__":
    main()
