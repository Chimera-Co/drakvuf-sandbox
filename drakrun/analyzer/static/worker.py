"""Static-analysis queue: staged at upload, analysed in a container, read by classify_sample.

    upload (api.py) ──stage_and_enqueue()──> /var/lib/drakrun/static/<id>/in/sample (0440, never +x)
                                         └─> RQ queue "chimera-static"
    drakrun static-worker ──run_static_job()──> container ──> /var/lib/drakrun/static/<id>/static.json
    classify_sample ──wait_for_static()──> features["static"]

The worker process itself never parses the sample: it copies bytes and reads the container's JSON.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Optional

from rq import Queue, Worker

from drakrun.lib.config import load_config
from drakrun.lib.paths import STATIC_DIR

from .sandbox import SCHEMA, run_in_container, stage_sample

logger = logging.getLogger(__name__)
STATIC_QUEUE_NAME = "chimera-static"


def job_dir(analysis_id: str, base: Optional[Path] = None) -> Path:
    return Path(base or STATIC_DIR) / str(uuid.UUID(analysis_id))  # also rejects path tricks


def static_path(analysis_id: str, base: Optional[Path] = None) -> Path:
    return job_dir(analysis_id, base) / "static.json"


def stage_and_enqueue(analysis_id: str, sample_path: Path, file_name: str, connection, settings,
                      base: Optional[Path] = None):
    """Called from the upload request, before the upload may be moved to S3 and deleted."""
    if not settings.enabled:
        return None
    stage_sample(Path(sample_path), job_dir(analysis_id, base), settings)
    queue = Queue(name=STATIC_QUEUE_NAME, connection=connection)
    return queue.enqueue(run_static_job, analysis_id, file_name, str(base or STATIC_DIR), job_id=f"static-{analysis_id}",
                         job_timeout=int(settings.timeout_s + 120), result_ttl=24 * 3600)


def run_static_job(analysis_id: str, file_name: str, base: Optional[str] = None) -> dict:
    settings = load_config().static
    directory = job_dir(analysis_id, Path(base) if base else None)
    started = time.time()
    try:
        result = run_in_container(settings, analysis_id, directory, file_name)
    finally:
        shutil.rmtree(directory / "in", ignore_errors=True)  # the staged sample is not kept
    result["job"] = {"analysis_id": analysis_id, "wall_s": round(time.time() - started, 2)}
    final = directory / "static.json"
    tmp = directory / ".static.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(result, fh, allow_nan=False)
    os.replace(tmp, final)
    shutil.rmtree(directory / "out", ignore_errors=True)
    return {"error": result.get("error"), "score": result.get("score"), "level": result.get("level")}


def load_static(analysis_id: str, base: Optional[Path] = None) -> Optional[dict]:
    path = static_path(analysis_id, base)
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA else None


def wait_for_static(analysis_id: str, wait_s: float, base: Optional[Path] = None, poll_s: float = 1.0) -> Optional[dict]:
    deadline = time.monotonic() + wait_s
    while True:
        result = load_static(analysis_id, base)
        if result is not None or time.monotonic() >= deadline:
            return result
        time.sleep(poll_s)


def static_worker_main(burst: bool = False):
    from drakrun.analyzer.worker import get_redis_connection

    config = load_config()
    if not config.static.enabled:
        logger.warning("[static] enabled = false in config.toml; the worker will idle")
    STATIC_DIR.mkdir(mode=0o711, parents=True, exist_ok=True)
    worker = Worker(queues=[STATIC_QUEUE_NAME], name=f"chimera-static@{os.uname().nodename}",
                    connection=get_redis_connection(config.redis))
    worker.work(burst=burst)
