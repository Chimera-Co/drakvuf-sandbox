"""Analysis pipeline status and the full analyses list.

An upload goes through several independent jobs (static fast pass, the DRAKVUF run and its postprocessing,
classifier, deep pass with capa/FLOSS/Ghidra, memory-dump scan, threat intel), each on its own RQ queue and
finishing at its own time. /api/pipeline/<id> reports where each one is, from the files it writes and the state
of its RQ job, so the UI can show progress after the VM run itself has finished.

/api/analyses lists every analysis: the RQ registries only keep the newest jobs (older ones are pruned on
upload), so analyses that are only on disk are read from their metadata.json.
"""

from __future__ import annotations

import json
import logging
import pathlib
import uuid
from typing import Optional

from flask import jsonify
from flask_openapi3 import APIBlueprint
from rq.exceptions import NoSuchJobError
from rq.job import Job

from drakrun.analyzer.analysis_metadata import AnalysisMetadata
from drakrun.analyzer.worker import analysis_job_to_metadata, get_analyses_list
from drakrun.lib.paths import ANALYSES_DIR, STATIC_DIR
from drakrun.lib.s3_storage import is_s3_enabled
from drakrun.web.schema import AnalysisRequestPath, APIErrorResponse

from .api import config, redis

logger = logging.getLogger(__name__)
pipeline_api = APIBlueprint("pipeline_api", __name__, url_prefix="/api")

DISK_LIST_MAX = 5000
_disk_cache: dict = {}
DEEP_LABEL = "Deep static (capa, FLOSS, Ghidra)"


def _job(job_id: str) -> Optional[Job]:
    try:
        return Job.fetch(job_id, connection=redis)
    except NoSuchJobError:
        return None


def _job_state(job_id: str) -> Optional[str]:
    job = _job(job_id)
    if job is None:
        return None
    status = job.get_status()
    return getattr(status, "value", status)


def _read_json(path: pathlib.Path) -> Optional[dict]:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _from_job(state: Optional[str], waiting: str = "pending") -> str:
    return {
        "queued": "queued",
        "deferred": "queued",
        "scheduled": "queued",
        "started": "running",
        "failed": "failed",
        "stopped": "failed",
        "canceled": "skipped",
        "finished": "done",
    }.get(state or "", waiting)


def pipeline(analysis_id: str) -> Optional[dict]:
    analysis_dir = ANALYSES_DIR / analysis_id
    static_dir = STATIC_DIR / analysis_id
    meta = _read_json(analysis_dir / "metadata.json")
    vm_job = _job(analysis_id)
    if meta is None and vm_job is None and not static_dir.exists():
        return None
    meta = meta or {}
    if vm_job is not None and not meta:
        meta = analysis_job_to_metadata(vm_job).store_to_dict()
    options = meta.get("options") or {}
    mode = options.get("mode", "combined")
    status = meta.get("status")
    substatus = meta.get("substatus")
    if vm_job is not None:
        state = vm_job.get_status()
        state = getattr(state, "value", state)
        if state in ("queued", "started", "deferred", "scheduled"):
            status = state
            substatus = (vm_job.meta or {}).get("substatus", substatus)
    stages = []

    def add(stage_id, label, state, detail=""):
        stages.append(
            {"id": stage_id, "label": label, "state": state, "detail": detail}
        )

    add("upload", "Upload", "done", (meta.get("file") or {}).get("name") or "")

    static = _read_json(static_dir / "static.json")
    if mode == "dynamic-only":
        add("static", "Static analysis", "skipped", "dynamic-only analysis")
    elif static is not None:
        backend = (static.get("container") or {}).get("backend") or ""
        detail = static.get("error") or " · ".join(
            x for x in (static.get("level"), backend) if x
        )
        add(
            "static",
            "Static analysis",
            "failed" if static.get("error") else "done",
            detail,
        )
    else:
        job_id = analysis_id if mode == "static-only" else f"static-{analysis_id}"
        add("static", "Static analysis", _from_job(_job_state(job_id)))

    if mode == "static-only":
        add("dynamic", "Dynamic analysis (VM)", "skipped", "static-only analysis")
        add("postprocess", "Postprocessing", "skipped")
    else:
        dyn = {
            "queued": "queued",
            "deferred": "queued",
            "scheduled": "queued",
            "started": "running",
            "finished": "done",
            "failed": "failed",
        }.get(status or "", "pending")
        if dyn == "running" and substatus == "postprocessing":
            add("dynamic", "Dynamic analysis (VM)", "done")
            add("postprocess", "Postprocessing", "running")
        else:
            add(
                "dynamic",
                "Dynamic analysis (VM)",
                dyn,
                (substatus or "").replace("_", " "),
            )
            done = (analysis_dir / "report.json").exists()
            post = "done" if done else ("failed" if dyn == "failed" else "pending")
            add("postprocess", "Postprocessing", post)

    classification = _read_json(analysis_dir / "classification.json")
    if classification is not None and classification.get("not_applicable"):
        add("classifier", "Classifier", "skipped", "mobile app: see the MobSF report")
    elif classification is not None:
        add("classifier", "Classifier", "done", str(classification.get("label") or ""))
    else:
        add("classifier", "Classifier", "failed" if status == "failed" else "pending")

    fmt = ((static or {}).get("type") or {}).get("format")
    deep = _read_json(static_dir / "deep.json")
    mobsf = _read_json(static_dir / "mobsf.json")
    if fmt in ("apk", "ipa") and (
        mobsf is not None or _job_state(f"static-mobsf-{analysis_id}")
    ):
        # APKs take MobSF on the deep queue instead of capa/FLOSS/Ghidra.
        if mobsf is not None:
            score = mobsf.get("security_score")
            add(
                "deep",
                "Deep static (MobSF)",
                "failed" if mobsf.get("error") else "done",
                f"security score {score}" if score is not None else "",
            )
        else:
            add(
                "deep",
                "Deep static (MobSF)",
                _from_job(_job_state(f"static-mobsf-{analysis_id}")),
            )
    elif deep is not None:
        add("deep", DEEP_LABEL, "failed" if deep.get("error") else "done")
    elif mode == "dynamic-only" or (static is not None and fmt not in ("pe", "elf")):
        add("deep", DEEP_LABEL, "skipped", f"not used for {fmt or 'this analysis'}")
    else:
        add("deep", DEEP_LABEL, _from_job(_job_state(f"static-deep-{analysis_id}")))

    memdumps = _read_json(static_dir / "memdumps.json")
    if memdumps is not None:
        detail = f"{len(memdumps.get('scanned') or [])} of {memdumps.get('dumps_total', 0)} dumps"
        add(
            "memdumps",
            "Memory-dump scan",
            "failed" if memdumps.get("error") else "done",
            detail,
        )
    elif mode == "static-only":
        add("memdumps", "Memory-dump scan", "skipped", "no detonation")
    else:
        waiting = "skipped" if status in ("finished", "failed") else "pending"
        add(
            "memdumps",
            "Memory-dump scan",
            _from_job(_job_state(f"static-memdumps-{analysis_id}"), waiting),
        )

    report = _read_json(analysis_dir / "chimera-report.json")
    intel = ((report or {}).get("stages") or {}).get("intel") or {}
    online = _read_json(static_dir / "intel-online.json")
    online_job = _job_state(f"intel-online-{analysis_id}")
    if online is not None:
        add(
            "intel", "Threat intel", "done", f"online: {online.get('connectivity', '')}"
        )
    elif online_job:
        add("intel", "Threat intel", _from_job(online_job))
    elif intel:
        state = "done" if intel.get("status") in ("ok", "stale") else "skipped"
        add("intel", "Threat intel", state, str(intel.get("reason") or "offline only"))
    else:
        add("intel", "Threat intel", "pending")

    add("report", "Report", "done" if report is not None else "pending")
    active = any(s["state"] in ("queued", "running") for s in stages) or (
        report is None and status not in ("failed",)
    )
    return {
        "analysis_id": analysis_id,
        "mode": mode,
        "status": status,
        "stages": stages,
        "active": active,
    }


@pipeline_api.get("/pipeline/<task_uid>", responses={404: APIErrorResponse})
def pipeline_status(path: AnalysisRequestPath):
    try:
        analysis_id = str(uuid.UUID(path.task_uid))
    except ValueError:
        return jsonify({"error": "Analysis not found"}), 404
    result = pipeline(analysis_id)
    if result is None:
        return jsonify({"error": "Analysis not found"}), 404
    return jsonify(result)


def _disk_metadata(skip: set) -> list:
    """metadata.json of every analysis on disk not in `skip`, cached by file mtime."""
    out = []
    try:
        entries = sorted(
            ANALYSES_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True
        )
    except OSError:
        return out
    for entry in entries[:DISK_LIST_MAX]:
        if entry.name in skip:
            continue
        meta_path = entry / "metadata.json"
        try:
            mtime = meta_path.stat().st_mtime_ns
        except OSError:
            continue
        cached = _disk_cache.get(entry.name)
        if not cached or cached[0] != mtime:
            data = _read_json(meta_path)
            if data is None:
                continue
            data.setdefault("id", entry.name)
            try:
                data = AnalysisMetadata.load_from_dict(data).store_to_dict()
            except (
                Exception
            ):  # an old or partial metadata file is still listed as it is
                logger.debug("metadata of %s kept as stored", entry.name)
            cached = (mtime, data)
            _disk_cache[entry.name] = cached
        out.append(cached[1])
    return out


@pipeline_api.get("/analyses")
def all_analyses():
    """Live RQ jobs plus every analysis on disk, newest first."""
    live = [
        analysis_job_to_metadata(job).store_to_dict()
        for job in get_analyses_list(connection=redis)
    ]
    if not is_s3_enabled(config.s3):
        live += _disk_metadata({str(item.get("id")) for item in live})

    def when(item):
        # queued analyses have no start time yet and belong at the top
        return str(item.get("time_started") or item.get("time_finished") or "9999")

    return jsonify(sorted(live, key=when, reverse=True))
