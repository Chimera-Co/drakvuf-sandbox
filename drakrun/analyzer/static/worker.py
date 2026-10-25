"""Static-analysis queue: staged at upload, analysed in a container, read by classify_sample.

    upload (api.py) ──stage_and_enqueue()──> /var/lib/drakrun/static/<id>/in/sample (0440, never +x)
                                         └─> RQ queue "chimera-static"
    drakrun static-worker ──run_static_job()──> container ──> /var/lib/drakrun/static/<id>/static.json
    classify_sample ──wait_for_static()──> features["static"]

The worker process itself never parses the sample: it copies bytes and reads the container's JSON.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Optional

from redis import Redis
from rq import Queue, Worker

from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR, STATIC_DIR

from .sandbox import SCHEMA, ghidra_wall_s, run_ghidra, run_in_container, stage_sample

logger = logging.getLogger(__name__)
STATIC_QUEUE_NAME = "chimera-static"
STATIC_ONLY_QUEUE_NAME = "chimera-static-only"
INTEL_QUEUE_NAME = "chimera-intel"
DEEP_QUEUE_NAME = "chimera-static-deep"
DEEP_FORMATS = {"pe", "elf"}  # what capa (and FLOSS, PE only) can disassemble


class StaticAnalysisFailed(RuntimeError):
    """static.json was written but records an error; raised so RQ marks the job failed, not "Job OK"."""


def job_dir(analysis_id: str, base: Optional[Path] = None) -> Path:
    # uuid.UUID also rejects path tricks
    return Path(base or STATIC_DIR) / str(uuid.UUID(analysis_id))


def static_path(analysis_id: str, base: Optional[Path] = None) -> Path:
    return job_dir(analysis_id, base) / "static.json"


def stage_and_enqueue(
    analysis_id: str,
    sample_path: Path,
    file_name: str,
    connection,
    settings,
    base: Optional[Path] = None,
):
    """Called from the upload request, before the upload may be moved to S3 and deleted."""
    if not settings.enabled:
        return None
    stage_sample(Path(sample_path), job_dir(analysis_id, base), settings)
    queue = Queue(name=STATIC_QUEUE_NAME, connection=connection)
    return queue.enqueue(
        run_static_job,
        analysis_id,
        file_name,
        str(base or STATIC_DIR),
        job_id=f"static-{analysis_id}",
        job_timeout=int(settings.timeout_s + 120),
        result_ttl=24 * 3600,
    )


def run_static_job(
    analysis_id: str, file_name: str, base: Optional[str] = None
) -> dict:
    settings = load_config().static
    directory = job_dir(analysis_id, Path(base) if base else None)
    started = time.time()
    try:
        result = run_in_container(settings, analysis_id, directory, file_name)
    except BaseException:
        shutil.rmtree(directory / "in", ignore_errors=True)
        raise
    # the staged sample is not kept, unless the deep pass still needs it (it deletes it when done)
    if not _enqueue_deep(settings, analysis_id, file_name, base, result):
        shutil.rmtree(directory / "in", ignore_errors=True)
    result["job"] = {
        "analysis_id": analysis_id,
        "wall_s": round(time.time() - started, 2),
    }
    final = directory / "static.json"
    tmp = directory / ".static.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(result, fh, allow_nan=False)
    os.replace(tmp, final)
    shutil.rmtree(directory / "out", ignore_errors=True)
    # static.json stays for the classifier and the UI; the job itself failed
    if result.get("error"):
        logger.error(
            "[static] analysis %s failed: %s", analysis_id, str(result["error"])[:500]
        )
        raise StaticAnalysisFailed(str(result["error"])[:500])
    return {"error": None, "score": result.get("score"), "level": result.get("level")}


def _enqueue_deep(
    settings, analysis_id: str, file_name: str, base, result: dict
) -> bool:
    if result.get("error"):
        return False
    file_format = (result.get("type") or {}).get("format")
    if file_format == "apk" and settings.mobsf_enabled:
        return _enqueue_mobsf(settings, analysis_id, base)
    if not settings.deep_enabled or file_format not in DEEP_FORMATS:
        return False
    from rq import get_current_job

    job = get_current_job()
    if (
        job is None
    ):  # called outside a worker (tests, tools): no queue to hand the deep pass to
        return False
    try:
        Queue(name=DEEP_QUEUE_NAME, connection=job.connection).enqueue(
            run_deep_job,
            analysis_id,
            file_name,
            str(base or STATIC_DIR),
            job_id=f"static-deep-{analysis_id}",
            job_timeout=int(
                settings.deep_timeout_s
                + (ghidra_wall_s(settings) if settings.ghidra_enabled else 0)
                + 120
            ),
            result_ttl=24 * 3600,
        )
    except Exception:
        logger.exception("[static] deep pass could not be queued for %s", analysis_id)
        return False
    return True


def _enqueue_mobsf(settings, analysis_id: str, base) -> bool:
    """APKs go to MobSF on the deep queue (drakrun/analyzer/static/mobsf.py), which deletes the staged copy."""
    from rq import get_current_job

    from .mobsf import run_mobsf_job

    job = get_current_job()
    if job is None:
        return False
    try:
        Queue(name=DEEP_QUEUE_NAME, connection=job.connection).enqueue(
            run_mobsf_job,
            analysis_id,
            str(base or STATIC_DIR),
            job_id=f"static-mobsf-{analysis_id}",
            job_timeout=int(settings.mobsf_timeout_s + 300),
            result_ttl=24 * 3600,
        )
    except Exception:
        logger.exception("[static] MobSF scan could not be queued for %s", analysis_id)
        return False
    return True


def _write_json(directory: Path, name: str, value: dict) -> None:
    tmp = directory / f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(value, fh, allow_nan=False)
    os.replace(tmp, directory / name)


def run_deep_job(analysis_id: str, file_name: str, base: Optional[str] = None) -> dict:
    """capa + FLOSS in the same locked-down container (`--deep`); writes deep.json beside static.json and
    refreshes the analysis report if one was already written."""
    settings = load_config().static
    directory = job_dir(analysis_id, Path(base) if base else None)
    started = time.time()
    try:
        result = run_in_container(
            settings, analysis_id, directory, file_name, deep=True
        )
        if (
            settings.ghidra_enabled
            and not result.get("error")
            and result.get("format") in DEEP_FORMATS
        ):
            result["ghidra"] = _decompile(settings, analysis_id, directory, result)
    finally:
        shutil.rmtree(directory / "in", ignore_errors=True)
    result["job"] = {
        "analysis_id": analysis_id,
        "wall_s": round(time.time() - started, 2),
    }
    _write_json(directory, "deep.json", result)
    shutil.rmtree(directory / "out", ignore_errors=True)
    if base is None or Path(base) == STATIC_DIR:
        _refresh_report(analysis_id)
    if result.get("error"):
        logger.error(
            "[static] deep pass %s failed: %s", analysis_id, str(result["error"])[:500]
        )
        raise StaticAnalysisFailed(str(result["error"])[:500])
    return {"error": None, "errors": len(result.get("errors") or [])}


def _decompile(
    settings, analysis_id: str, directory: Path, result: dict
) -> Optional[dict]:
    """Ghidra on the functions capa pointed at (then entry points, exports, largest). A failure is recorded
    as a deep-pass error, never fatal."""
    targets = [
        {"addr": address, "rule": rule.get("name")}
        for rule in (result.get("capa") or {}).get("rules") or []
        for address in rule.get("addresses") or []
    ]
    started = time.time()
    doc = run_ghidra(settings, analysis_id, directory, targets)
    result.setdefault("timings_s", {})["ghidra"] = round(time.time() - started, 3)
    if doc.get("error") and "functions" not in doc:
        result.setdefault("errors", []).append(
            {"stage": "ghidra", "error": str(doc["error"])[:300]}
        )
        return None
    return doc


def _refresh_report(analysis_id: str) -> None:
    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
        render_html,
    )

    directory = ANALYSES_DIR / str(uuid.UUID(analysis_id))
    if not (directory / "chimera-report.json").is_file():
        return  # the analysis is still running; its postprocessing will read deep.json itself
    try:
        report = build_report(directory)
        (directory / "chimera-report.json").write_text(
            json.dumps(report, indent=1, allow_nan=False), encoding="utf-8"
        )
        (directory / "chimera-report.html").write_text(
            render_html(report), encoding="utf-8"
        )
    except Exception:
        logger.exception(
            "[static] report refresh after the deep pass failed for %s", analysis_id
        )


def load_deep(analysis_id: str, base: Optional[Path] = None) -> Optional[dict]:
    path = job_dir(analysis_id, base) / "deep.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return (
        data
        if isinstance(data, dict) and data.get("schema") == "chimera-deep/1"
        else None
    )


def load_static(analysis_id: str, base: Optional[Path] = None) -> Optional[dict]:
    path = static_path(analysis_id, base)
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA else None


def wait_for_static(
    analysis_id: str, wait_s: float, base: Optional[Path] = None, poll_s: float = 1.0
) -> Optional[dict]:
    deadline = time.monotonic() + wait_s
    while True:
        result = load_static(analysis_id, base)
        if result is not None or time.monotonic() >= deadline:
            return result
        time.sleep(poll_s)


def static_worker_main(burst: bool = False, deep: bool = False):
    config = load_config()
    if not config.static.enabled:
        logger.warning("[static] enabled = false in config.toml; the worker will idle")
    STATIC_DIR.mkdir(mode=0o711, parents=True, exist_ok=True)
    worker = Worker(
        # The deep pass has its own worker so a slow capa run never holds up the fast pass.
        queues=(
            [DEEP_QUEUE_NAME] if deep else [STATIC_QUEUE_NAME, STATIC_ONLY_QUEUE_NAME]
        ),
        name=f"chimera-static{'-deep' if deep else ''}@{os.uname().nodename}",
        connection=Redis(
            host=config.redis.host,
            port=config.redis.port,
            username=config.redis.username,
            password=config.redis.password,
        ),
    )
    worker.work(burst=burst)


def enqueue_static_only(
    analysis_id, sample_path, file_metadata, options, connection, config
):
    stage_sample(Path(sample_path), job_dir(analysis_id), config.static)
    return Queue(name=STATIC_ONLY_QUEUE_NAME, connection=connection).enqueue(
        run_static_only_analysis,
        analysis_id,
        file_metadata.to_dict(),
        options.to_dict(),
        job_id=analysis_id,
        meta={"file": file_metadata.to_dict(), "options": options.to_dict()},
        job_timeout=int(config.static.timeout_s + config.classifier.timeout_s + 120),
        result_ttl=config.drakrun.result_ttl,
    )


def run_static_only_analysis(analysis_id: str, file_metadata: dict, options: dict):
    from rq import get_current_job

    from drakrun.analyzer.classifier.runner import run_classifier, unknown_verdict
    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
        render_html,
    )

    config = load_config()
    directory = ANALYSES_DIR / str(uuid.UUID(analysis_id))
    directory.mkdir(parents=True, exist_ok=True)
    metadata = {
        "id": analysis_id,
        "file": file_metadata,
        "options": options,
        "status": "started",
        "time_started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    def write(name, value):
        (directory / name).write_text(
            json.dumps(value, indent=2, allow_nan=False), encoding="utf-8"
        )

    write("metadata.json", metadata)
    failed = False
    try:
        run_static_job(analysis_id, file_metadata["name"])
    except Exception:
        logger.exception("Static-only analysis failed for %s", analysis_id)
        failed = True
    static = load_static(analysis_id)
    features = {
        "schema": "chimera-features/1",
        "sample": {
            "sha256": file_metadata["sha256"],
            "file_name": file_metadata["name"],
            "size_bytes": file_metadata.get("size_bytes"),
            "file_type": file_metadata.get("type"),
        },
        "run": {"mode": "static-only", "guest_os": None},
        "static": static,
    }
    write("features.json", features)
    if config.classifier.enabled:
        try:
            verdict = run_classifier(
                features,
                directory,
                config.classifier.model_path,
                config.classifier.timeout_s,
            )
        except Exception as error:
            verdict = unknown_verdict(f"{type(error).__name__}: {error}")
        write("classification.json", verdict)
        metadata["classification"] = verdict
    metadata.update(
        status="failed" if failed else "finished",
        time_finished=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    write("metadata.json", metadata)
    report = build_report(directory)
    write("chimera-report.json", report)
    (directory / "chimera-report.html").write_text(
        render_html(report), encoding="utf-8"
    )
    metadata["chimera_report"] = True
    write("metadata.json", metadata)
    job = get_current_job()
    if job is not None:
        job.meta["extra_metadata"] = metadata
        job.save_meta()
    if job is not None and static:
        from drakrun.lib.intel.online.run import enqueue

        enqueue(analysis_id, job.connection, options)
    if failed:
        raise StaticAnalysisFailed("static-only analysis failed")
