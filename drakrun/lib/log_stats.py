"""Per-log summaries (counts, top values, time histogram) for the analysis dashboard.

One streaming pass, bounded memory: lines are capped at MAX_LINE, values at MAX_VALUE characters, and each
counter is pruned to its most frequent PRUNE_TO values once it exceeds MAX_DISTINCT (the result then says
"approximate": counts of rare values may be low; the top values are right unless the log has hundreds of
thousands of equally frequent values). Timestamps go into a float array (8 bytes per event) for the
histogram. Postprocessing writes the result to <analysis>/log_stats/<log>.json so the web never has to read
a 200 MB log during a request.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from array import array
from collections import Counter
from pathlib import Path

MAX_VALUE = 512
MAX_LINE = 1024 * 1024
MAX_DISTINCT = 200_000
PRUNE_TO = 50_000
TOP = 50
BUCKETS = 120
STATS_DIR = "log_stats"
STATS_VERSION = 3
PLAIN_LOGS = ("drakrun", "drakvuf_stderr")
REGISTRY_WRITES = {"NtSetValueKey", "NtCreateKey", "NtDeleteKey", "NtDeleteValueKey", "NtRenameKey"}
VALUE_FIELDS = {
    "files": ("FileName", "DumpFilename"),
    "keys": ("Key",),
    "remote": ("RemoteIp", "RemoteAddress", "Host", "ServerName"),
}


def lines(stream):
    """Yield each line (bytes, without the newline); None for a line longer than MAX_LINE."""
    pending = b""
    oversized = False
    while True:
        chunk = stream.read(1 << 20)
        if not chunk:
            if pending or oversized:
                yield None if oversized else pending
            return
        pieces = chunk.split(b"\n")
        for index, piece in enumerate(pieces):
            if not oversized:
                if len(pending) + len(piece) > MAX_LINE:
                    oversized, pending = True, b""
                else:
                    pending += piece
            if index < len(pieces) - 1:
                yield None if oversized else pending
                pending, oversized = b"", False


def events(stream):
    for line in lines(stream):
        if line == b"":
            continue
        try:
            value = json.loads(line) if line is not None else None
        except (ValueError, UnicodeError):
            value = None
        yield value if isinstance(value, dict) else None


def timestamp(event):
    try:
        value = float(event.get("TimeStamp", event.get("timestamp")))
    except (TypeError, ValueError, OverflowError):
        return None
    return value if math.isfinite(value) else None


class _Counter:
    def __init__(self):
        self.counts = Counter()
        self.pruned = False

    def add(self, value):
        self.counts[value] += 1
        if len(self.counts) > MAX_DISTINCT:
            self.counts = Counter(dict(self.counts.most_common(PRUNE_TO)))
            self.pruned = True

    def top(self):
        return sorted(self.counts.items(), key=lambda item: (-item[1], str(item[0])))[:TOP]


def compute_stats(stream, log_type: str) -> dict:
    total = errors = registry_writes = 0
    plain = log_type in PLAIN_LOGS
    counters = {kind: _Counter() for kind in ("methods", "processes", *VALUE_FIELDS)}
    stamps = array("d")
    for event in (lines(stream) if plain else events(stream)):
        if event is None:
            errors += 1
            continue
        total += 1
        if plain:
            continue
        ts = timestamp(event)
        if ts is not None:
            stamps.append(ts)
        method = str(event.get("Method") or event.get("Event") or "unknown")[:MAX_VALUE]
        counters["methods"].add(method)
        if log_type == "regmon" and method in REGISTRY_WRITES:
            registry_writes += 1
        pid = event.get("PID", event.get("InjectedPid"))
        name = str(event.get("ProcessName", event.get("RunningProcess", "")))[:MAX_VALUE]
        counters["processes"].add((event.get("seqid", event.get("SeqId")), pid, name))
        for kind, fields in VALUE_FIELDS.items():
            value = next((event[key] for key in fields if event.get(key) is not None), None)
            if value is not None:
                if kind == "remote" and event.get("RemotePort") is not None:
                    value = f"{value}:{event['RemotePort']}"
                counters[kind].add(str(value)[:MAX_VALUE])

    first = min(stamps) if stamps else None
    last = max(stamps) if stamps else None
    if first is not None:
        bucket = max((last - first) / (BUCKETS - 1), 0.001)
        histogram = [0] * min(BUCKETS, int((last - first) / bucket) + 1)
        for ts in stamps:
            histogram[min(len(histogram) - 1, int((ts - first) / bucket))] += 1
    else:
        bucket, histogram = 1, []
    values = {kind: [[v, n] for v, n in counters[kind].top()] for kind in VALUE_FIELDS if counters[kind].counts}
    return {
        "total": total,
        "parse_errors": errors,
        "registry_writes": registry_writes,
        "first_ts": first,
        "last_ts": last,
        "methods": [[v, n] for v, n in counters["methods"].top()],
        "processes": [[*v, n] for v, n in counters["processes"].top()],
        "histogram": {"bucket_s": bucket, "counts": histogram},
        "top_values": values,
        "approximate": any(c.pruned for c in counters.values()),
    }


def signature(path: Path) -> list:
    st = path.stat()
    return [STATS_VERSION, st.st_size, st.st_mtime_ns]


def cache_path(analysis_dir: Path, log_type: str) -> Path:
    return analysis_dir / STATS_DIR / f"{log_type}.json"


def read_cache(analysis_dir: Path, log_type: str):
    try:
        cached = json.loads(cache_path(analysis_dir, log_type).read_text())
        if cached["signature"] == signature(analysis_dir / f"{log_type}.log"):
            return cached["stats"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def write_cache(analysis_dir: Path, log_type: str, stats: dict) -> None:
    target = cache_path(analysis_dir, log_type)
    target.parent.mkdir(exist_ok=True)
    doc = {"signature": signature(analysis_dir / f"{log_type}.log"), "stats": stats}
    fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(doc, out)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def precompute(analysis_dir: Path) -> dict:
    """Compute and cache stats for every *.log in the analysis directory; returns {log: total}."""
    totals = {}
    for log in sorted(analysis_dir.glob("*.log")):
        log_type = log.name[:-4]
        stats = read_cache(analysis_dir, log_type)
        if stats is None:
            with log.open("rb") as stream:
                stats = compute_stats(stream, log_type)
            write_cache(analysis_dir, log_type, stats)
        totals[log_type] = stats["total"]
    return totals
