"""Shared bounded byte inspection, file layout and string annotations."""

import heapq
import re
from collections import Counter
from functools import lru_cache

from . import knowledge as K
from .universal import entropy

ENTROPY_BYTES = 1 << 20


def byte_entropy(data: bytes, offset=0, size=None) -> float:
    """Use at most the first MiB of a region; callers report this sampling limit."""
    size = len(data) - offset if size is None else size
    return round(entropy(memoryview(data)[max(0, offset):max(0, offset) + min(max(0, size), ENTROPY_BYTES)]), 4)


def magic(data: bytes) -> str | None:
    for prefix, name in ((b"MZ", "PE"), (b"\x7fELF", "ELF"), (b"PK\x03\x04", "ZIP"),
                         (b"MSCF", "CAB"), (b"\x89PNG\r\n\x1a\n", "PNG"),
                         (b"\x00\x00\x01\x00", "ICO"), (b"{\\rtf", "RTF"),
                         (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!", "RAR")):
        if data.startswith(prefix):
            return name
    head = data[:4096]
    if b"NullsoftInst" in head or b"\xef\xbe\xad\xdeNullsoftInst" in head:
        return "NSIS"
    if b"Inno Setup" in head:
        return "Inno"
    if b"InstallShield" in head:
        return "InstallShield"
    if b"<assembly" in head or b":assembly" in head:
        return "manifest XML"
    if head.lstrip().startswith(b"<?xml"):
        return "XML"
    return None


def layout(data: bytes, regions: list[dict]) -> list[dict]:
    """Partition bytes exactly once; first region wins when malformed ranges overlap."""
    clipped = []
    for order, region in enumerate(regions):
        start = max(0, min(len(data), region["offset"]))
        end = max(start, min(len(data), region["offset"] + region["size"]))
        if start < end:
            clipped.append((start, end, order, region))
    # Boundaries are bounded by the parser's section/segment limits.
    points = sorted({0, len(data)} | {p for a, b, _, _ in clipped for p in (a, b)})
    out = []
    for start, end in zip(points, points[1:]):
        if start == end:
            continue
        match = next((r for a, b, _, r in clipped if a <= start < b), None)
        name, kind = (match["name"], match["kind"]) if match else ("Unmapped bytes", "gap")
        if out and out[-1]["name"] == name and out[-1]["kind"] == kind:
            out[-1]["size"] += end - start
        else:
            out.append({"name": name, "kind": kind, "offset": start, "size": end - start})
    for item in out:
        item["entropy"] = byte_entropy(data, item["offset"], item["size"])
    return out


@lru_cache(maxsize=1)
def _string_matchers():
    rules = K.load("strings_rules")
    compiled = [(cat, rule, [re.compile(rx, re.I) for rx in rule["regexes"]])
                for cat, rule in rules.items()]
    # Token lookup avoids one regex search per known API for every string.
    return compiled, re.compile(r"[A-Za-z_][A-Za-z_0-9]{2,127}")


def flagged_strings(data: bytes) -> dict:
    """Independent scan preserves original string output and retains byte offsets."""
    from .universal import STRINGS_SCAN_BYTES

    window = data[:STRINGS_SCAN_BYTES]
    rules, tokens = _string_matchers()
    heap, counts, total, sequence = [], Counter(), 0, 0
    candidates, candidate_limit = 0, 100000

    @lru_cache(maxsize=4096)
    def classify(value):
        low = value.lower()
        hits = {}
        for cat, rule, regexes in rules:
            if any(k.lower() in low for k in rule["keywords"]) or any(rx.search(value) for rx in regexes):
                hits[cat] = (rule["severity"], rule["attack"])
        for token in set(tokens.findall(value)):
            rec = K.api(token)
            if rec.get("severity"):
                cat = "api_" + rec["category"]
                if rec["severity"] > hits.get(cat, (0, []))[0]:
                    hits[cat] = (rec["severity"], rec["attack"])
        return hits
    # A finite match length avoids multi-megabyte values and pathological regex work.
    for encoding, rx in (("ascii", rb"[\x20-\x7e]{4,4096}"),
                         ("utf-16-le", rb"(?:[\x20-\x7e]\x00){4,4096}")):
        for match in re.finditer(rx, window):
            value = match.group().decode(encoding)
            if candidates >= candidate_limit:
                break
            candidates += 1
            hits = classify(value)
            for cat, (severity, attack) in hits.items():
                counts[cat] += 1
                total += 1
                rec = {"value": value[:500], "category": cat, "severity": severity,
                       "offset": match.start(), "encoding": encoding, "attack": attack}
                # Keep the highest severities throughout the scan, including late hits.
                entry = (severity, -sequence, rec)
                sequence += 1
                if len(heap) < 600:
                    heapq.heappush(heap, entry)
                elif entry[:2] > heap[0][:2]:
                    heapq.heapreplace(heap, entry)
    kept = [item[2] for item in sorted(heap, key=lambda item: (-item[0], -item[1]))]
    return {"strings_flagged": kept, "strings_summary": dict(counts),
            "strings_flagged_truncated": total > 600, "strings_flagged_scanned_bytes": len(window),
            "strings_candidates_scanned": candidates, "strings_candidates_limit": candidate_limit,
            "strings_scan_truncated": candidates >= candidate_limit or len(data) > len(window)}
