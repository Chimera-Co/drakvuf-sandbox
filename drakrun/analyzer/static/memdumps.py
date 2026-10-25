"""Static analysis of the memory dumps DRAKVUF took during a run (dumps.zip).

Packed malware shows its real code only in memory: DRAKVUF's memdump plugin saves regions on heuristics
(remote thread creation, written-then-executed memory, freed images). Each selected dump goes through the same
analyzer and sandbox as the upload (static VM or dom0 container): YARA, PE/ELF parsing, embedded executables,
strings and IOCs. Results go to memdumps.json beside static.json (schema chimera-memdumps/1) and into the
report. Runs on the deep queue after the analysis, so it never delays the verdict, and its result never
feeds the classifier.

Every dump up to `memdump_scan_max_mb` is scanned, in this order: the sample's own process tree first, then
dumps that start with an MZ header, then injection-type reasons, then size. Identical contents are scanned
once. The scan stops at `memdump_scan_max` dumps or after `memdump_scan_budget_s` seconds; the document says
which, so a partial scan is never mistaken for a complete one.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
import uuid
import zipfile
from pathlib import Path
from typing import Optional

from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR

logger = logging.getLogger(__name__)

SCHEMA = "chimera-memdumps/1"
INJECTION_REASONS = ("remote", "inject", "write", "apc", "hollow")
MAX_FINDINGS = 12
MAX_IOCS = 10
MAX_INDICATORS = 8


def _memdump_records(analysis_dir: Path) -> dict:
    """DumpFilename -> memdump.log record (process, reason, address)."""
    records = {}
    try:
        with (analysis_dir / "memdump.log").open("rb") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("DumpFilename"):
                    records[str(rec["DumpFilename"])] = rec
    except OSError:
        pass
    return records


def _sample_pids(analysis_dir: Path) -> set:
    """PIDs of the started sample and its descendants (process_tree.json + report.json startup)."""
    try:
        tree = json.loads((analysis_dir / "process_tree.json").read_text())
        startup = (
            json.loads((analysis_dir / "report.json").read_text()).get("startup") or {}
        )
    except (OSError, ValueError):
        return set()
    root_seqid = startup.get("process")
    found = set()

    def walk(nodes, inside):
        for node in nodes or []:
            here = inside or node.get("seqid") == root_seqid
            if here and node.get("pid") is not None:
                found.add(node["pid"])
            walk(node.get("children"), here)

    walk(tree if isinstance(tree, list) else [tree], False)
    return found


def select_dumps(
    analysis_dir: Path, max_dumps: int, max_bytes: int
) -> tuple[list[dict], int]:
    """Choose the dumps to scan; returns (candidates, number of dumps in the archive)."""
    path = analysis_dir / "dumps.zip"
    records = _memdump_records(analysis_dir)
    sample_pids = _sample_pids(analysis_dir)
    with zipfile.ZipFile(path) as archive:
        infos = [i for i in archive.infolist() if not i.is_dir()]
        candidates = []
        for info in infos:
            name = info.filename.rsplit("/", 1)[-1]
            rec = records.get(name, {})
            pid = rec.get("DumpPID", rec.get("PID"))
            reason = str(rec.get("DumpReason") or "")
            with archive.open(info) as fh:
                head = fh.read(2)
            candidates.append(
                {
                    "member": info.filename,
                    "name": name,
                    "size": info.file_size,
                    "pid": pid,
                    "process": rec.get("ProcessName"),
                    "reason": reason or None,
                    "address": rec.get("DumpAddr"),
                    "mz": head == b"MZ",
                    "sample_tree": pid in sample_pids,
                }
            )
    total = len(candidates)
    candidates = [c for c in candidates if 0 < c["size"] <= max_bytes]
    candidates.sort(
        key=lambda c: (
            not c["sample_tree"],
            not c["mz"],
            not any(k in (c["reason"] or "").lower() for k in INJECTION_REASONS),
            -c["size"],
            c["name"],
        )
    )
    return candidates, total


def _summary(candidate: dict, digest: str, result: dict) -> dict:
    universal = result.get("universal") or {}
    iocs = universal.get("iocs") or {}
    findings = sorted(
        result.get("findings") or [],
        key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f.get("severity"), 3),
    )
    return {
        **{
            k: candidate[k]
            for k in (
                "member",
                "size",
                "pid",
                "process",
                "reason",
                "address",
                "sample_tree",
            )
        },
        "sha256": digest,
        "error": result.get("error"),
        "format": (result.get("type") or {}).get("format"),
        "pe_kind": (result.get("type") or {}).get("pe_kind"),
        "level": result.get("level"),
        "score": result.get("score"),
        "yara": [m.get("rule") for m in universal.get("yara") or []][:20],
        "findings": [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "attack": f.get("attack") or [],
            }
            for f in findings[:MAX_FINDINGS]
        ],
        # Insight indicators of severity 2+ (suspicious in context): injected code shows its imports here.
        "indicators": [
            {
                "title": i.get("title"),
                "severity": i.get("severity"),
                "category": i.get("category"),
                "attack": i.get("attack") or [],
            }
            for i in sorted(
                (
                    x
                    for x in result.get("indicators") or []
                    if (x.get("severity") or 0) >= 2
                ),
                key=lambda x: -(x.get("severity") or 0),
            )[:MAX_INDICATORS]
        ],
        "embedded_executables": sum(
            1 for e in universal.get("embedded") or [] if e.get("type") in ("pe", "elf")
        ),
        "iocs": {
            k: (iocs.get(k) or [])[:MAX_IOCS]
            for k in ("urls", "domains", "ips")
            if iocs.get(k)
        },
        "backend": (result.get("container") or {}).get("backend"),
    }


def scan(
    analysis_id: str,
    analyses_dir: Path = ANALYSES_DIR,
    static_dir: Optional[Path] = None,
    settings=None,
) -> dict:
    from .sandbox import run_in_container, stage_sample
    from .worker import job_dir

    settings = settings or load_config().static
    analysis_dir = analyses_dir / analysis_id
    started = time.time()
    doc = {
        "schema": SCHEMA,
        "analysis_id": analysis_id,
        "dumps_total": 0,
        "scanned": [],
        "skipped": 0,
        "duplicates": 0,
        "too_large_or_empty": 0,
        "stopped": None,
        "limits": {
            "max_dumps": settings.memdump_scan_max,
            "max_mb": settings.memdump_scan_max_mb,
            "budget_s": settings.memdump_scan_budget_s,
        },
    }
    try:
        candidates, doc["dumps_total"] = select_dumps(
            analysis_dir, settings.memdump_scan_max, settings.memdump_scan_max_mb << 20
        )
    except (OSError, zipfile.BadZipFile) as exc:
        doc["error"] = f"cannot read dumps.zip: {str(exc)[:200]}"
        return doc
    doc["too_large_or_empty"] = doc["dumps_total"] - len(candidates)
    base = job_dir(analysis_id, static_dir) / "memdumps"
    seen = set()
    try:
        with zipfile.ZipFile(analysis_dir / "dumps.zip") as archive:
            for candidate in candidates:
                if len(doc["scanned"]) >= settings.memdump_scan_max:
                    doc["stopped"] = "dump limit"
                    break
                if time.time() - started >= settings.memdump_scan_budget_s:
                    doc["stopped"] = "time budget"
                    break
                work = base / str(len(doc["scanned"]))
                shutil.rmtree(work, ignore_errors=True)
                work.mkdir(parents=True, mode=0o711)
                raw = work / "dump.bin"
                digest = hashlib.sha256()
                fd = os.open(
                    raw, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(fd, "wb") as out, archive.open(
                    candidate["member"]
                ) as src:
                    while chunk := src.read(1 << 20):
                        digest.update(chunk)
                        out.write(chunk)
                sha = digest.hexdigest()
                if sha in seen:
                    doc["duplicates"] += 1
                    shutil.rmtree(work, ignore_errors=True)
                    continue
                seen.add(sha)
                stage_sample(raw, work, settings)
                raw.unlink()
                dump_id = str(uuid.uuid5(uuid.UUID(analysis_id), candidate["member"]))
                result = run_in_container(
                    settings, dump_id, work, f"memdump-{candidate['name']}"
                )
                doc["scanned"].append(_summary(candidate, sha, result))
                shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    doc["skipped"] = max(
        0,
        doc["dumps_total"]
        - len(doc["scanned"])
        - doc["duplicates"]
        - doc["too_large_or_empty"],
    )
    doc["wall_s"] = round(time.time() - started, 2)
    return doc


def run_memdump_job(analysis_id: str) -> dict:
    """RQ job on the deep queue: scan, write memdumps.json beside static.json, refresh the report."""
    from .worker import _refresh_report, _write_json, job_dir

    doc = scan(analysis_id)
    directory = job_dir(analysis_id)
    directory.mkdir(
        mode=0o711, parents=True, exist_ok=True
    )  # dynamic-only runs have no static folder yet
    _write_json(directory, "memdumps.json", doc)
    _refresh_report(analysis_id)
    hits = sum(1 for d in doc["scanned"] if d["yara"])
    logger.info(
        "[static] memory dumps %s: %d scanned, %d with YARA matches",
        analysis_id,
        len(doc["scanned"]),
        hits,
    )
    return {
        "scanned": len(doc["scanned"]),
        "yara_hits": hits,
        "error": doc.get("error"),
    }


def load_memdumps(analysis_id: str, base: Optional[Path] = None) -> Optional[dict]:
    from .worker import job_dir

    try:
        doc = json.loads((job_dir(analysis_id, base) / "memdumps.json").read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == SCHEMA else None
