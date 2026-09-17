"""Sandbox Evasion HTTP API.

Mirrors drakrun.web.api's conventions exactly: one APIBlueprint, responses
are jsonify(dict), errors are jsonify({"error": ...}), code, and file
serving/listing reuses drakrun.web.storage's traversal-guarded, S3-aware
helpers (now generalized to take a base directory - see storage.py) instead
of a parallel implementation.

Every route here is capability-driven: /sandboxes and /tools always derive
their content from get_sandbox_registry()/all_adapters()/options_schema(),
never a hardcoded platform or tool name, so a future non-Windows sandbox or
adapter changes what these endpoints return with no code change here.

Scoring semantics from Phase C are surfaced completely unmodified: whatever
EvasionScore/EvasionScanMetadata already contain (chimera_score, which is
None/omitted for an incomplete scan; per-tool tool_scores, where only the
primary tool carries weighted_score) is exactly what these endpoints return.
Nothing here computes, defaults, or coerces a score.
"""

from __future__ import annotations

import json
import logging
import uuid

from flask import jsonify, send_file
from flask_openapi3 import APIBlueprint
from rq.exceptions import NoSuchJobError
from rq.job import Job, JobStatus

from drakrun.evasion.constants import (
    METADATA_FILENAME,
    REPORT_FILENAME,
    RESULT_FILENAME,
)
from drakrun.evasion.models import EvasionScanMetadata, EvasionScanOptions
from drakrun.evasion.sandbox_registry import (
    SandboxNotFound,
    get_sandbox_registry,
    resolve_sandbox,
)
from drakrun.evasion.storage import build_artifacts_zip, get_scan_dir
from drakrun.evasion.verifiers import all_adapters, get_adapters_for_platform
from drakrun.evasion.verifiers.base import VerifierError
from drakrun.evasion.worker import (
    enqueue_verification,
    get_redis_connection,
    get_scans_list,
    scan_job_to_metadata,
)
from drakrun.lib.config import load_config
from drakrun.lib.paths import EVASION_DIR
from drakrun.web.schema import APIErrorResponse
from drakrun.web.schema_evasion import (
    CreateScanRequest,
    CreateScanResponse,
    EvasionScanFileQuery,
    EvasionScanPath,
    SandboxListResponse,
    ScanListResponse,
    ScanStatusResponse,
    ToolListResponse,
)
from drakrun.web.storage import list_entity_files, read_entity_file, send_entity_file

evasion_api = APIBlueprint("evasion", __name__, url_prefix="/api/evasion")

config = load_config()
redis = get_redis_connection(config.redis)
logger = logging.getLogger(__name__)


def _tool_info(adapter) -> dict:
    """The one true shape a tool is described in, everywhere - /tools, each
    sandbox's available_tools, and nowhere else, so the frontend never has
    to reconcile two different tool descriptions."""
    return {
        "id": adapter.id,
        "display_name": adapter.display_name,
        "supported_platforms": sorted(adapter.supported_platforms),
        "options_schema": adapter.options_schema(),
    }


def _available_tools_for_sandbox(sandbox) -> list:
    """A sandbox's own declared verifier ids, intersected with the adapters
    that actually support its platform - never the full adapter list. A
    sandbox that opts into a tool its platform can't run (or a platform no
    adapter yet supports) simply offers nothing for that gap; nothing is
    fabricated to fill it."""
    platform_adapters = {a.id: a for a in get_adapters_for_platform(sandbox.platform)}
    return [
        _tool_info(platform_adapters[tool_id])
        for tool_id in sandbox.verifiers
        if tool_id in platform_adapters
    ]


@evasion_api.get("/sandboxes", responses={200: SandboxListResponse})
def list_sandboxes():
    sandboxes = get_sandbox_registry(config)
    return jsonify(
        [
            {
                "id": sandbox.id,
                "display_name": sandbox.display_name,
                "platform": sandbox.platform,
                "os_version": sandbox.os_version,
                "firmware": sandbox.firmware,
                "hypervisor": sandbox.hypervisor,
                "lifecycle": sandbox.lifecycle,
                "available_tools": _available_tools_for_sandbox(sandbox),
            }
            for sandbox in sandboxes
        ]
    )


@evasion_api.get("/tools", responses={200: ToolListResponse})
def list_tools():
    return jsonify([_tool_info(adapter) for adapter in all_adapters()])


@evasion_api.post(
    "/scans",
    responses={200: CreateScanResponse, 400: APIErrorResponse, 404: APIErrorResponse},
)
def create_scan(body: CreateScanRequest):
    try:
        sandbox = resolve_sandbox(config, body.sandbox_id)
    except SandboxNotFound:
        return jsonify({"error": f"Sandbox '{body.sandbox_id}' not found"}), 404

    if body.profile not in ("full", "custom"):
        return jsonify({"error": "profile must be 'full' or 'custom'"}), 400

    if not body.tools:
        return jsonify({"error": "At least one tool must be selected"}), 400

    platform_adapters = {a.id: a for a in get_adapters_for_platform(sandbox.platform)}
    validated_tool_options = {}
    for tool_id in body.tools:
        if tool_id not in sandbox.verifiers or tool_id not in platform_adapters:
            return (
                jsonify(
                    {
                        "error": f"Tool '{tool_id}' is not available for sandbox "
                        f"'{sandbox.id}' (platform={sandbox.platform})"
                    }
                ),
                400,
            )
        adapter = platform_adapters[tool_id]
        raw_options = (
            body.tool_options.get(tool_id, {}) if body.profile == "custom" else {}
        )
        try:
            validated_tool_options[tool_id] = adapter.validate_options(raw_options)
        except VerifierError as exc:
            return jsonify({"error": str(exc)}), 400

    timeout = body.timeout or config.evasion.default_timeout
    options = EvasionScanOptions(
        sandbox_id=sandbox.id,
        tools=list(body.tools),
        profile=body.profile,
        tool_options=validated_tool_options,
        timeout=timeout,
    )

    scan_id = str(uuid.uuid4())
    enqueue_verification(
        job_id=scan_id,
        sandbox=sandbox,
        options=options,
        connection=redis,
        result_ttl=config.drakrun.result_ttl,
        job_timeout=timeout + config.drakrun.job_timeout_leeway,
    )
    return jsonify({"scan_id": scan_id})


def _read_scan_json(scan_id: str, filename: str) -> dict:
    """Read one JSON artifact from a scan directory. Raises FileNotFoundError
    - never a parse exception - if it is absent, unreadable, or unparseable;
    callers treat all three identically as 'not available yet', which is
    what an in-progress or not-yet-written scan actually is."""
    try:
        data = read_entity_file(scan_id, filename, config.s3, base_dir=EVASION_DIR)
    except FileNotFoundError:
        raise
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Malformed %s for scan %s: %s", filename, scan_id, exc)
        raise FileNotFoundError from exc


def _metadata_for_job(job) -> EvasionScanMetadata:
    """The full normalized record for one scan: while the job is still
    live (queued/started) this is necessarily partial (no tool_results/score
    yet - those only exist once compute_score has run). Once the job is
    terminal, evasion.json (the complete record, written by
    drakrun.evasion.report.write_evasion_json) is preferred; metadata.json
    (written at scan start, before any tool has produced results) is only a
    fallback for a scan that failed before evasion.json could be written."""
    if job.get_status() not in (JobStatus.FINISHED, JobStatus.FAILED):
        return scan_job_to_metadata(job)
    try:
        return EvasionScanMetadata.load_from_dict(
            _read_scan_json(job.id, RESULT_FILENAME)
        )
    except FileNotFoundError:
        pass
    try:
        return EvasionScanMetadata.load_from_dict(
            _read_scan_json(job.id, METADATA_FILENAME)
        )
    except FileNotFoundError:
        return scan_job_to_metadata(job)


@evasion_api.get("/scans", responses={200: ScanListResponse})
def list_scans():
    jobs = get_scans_list(connection=redis)
    entries = []
    for job in jobs:
        metadata = _metadata_for_job(job)
        entries.append(
            {
                "id": metadata.id,
                "status": metadata.status,
                "substatus": metadata.substatus,
                "sandbox": metadata.sandbox,
                "profile": metadata.options.profile,
                "tools": metadata.options.tools,
                "score": metadata.score.to_dict() if metadata.score else None,
                "time_started": metadata.time_started,
                "time_finished": metadata.time_finished,
            }
        )
    return jsonify(entries)


@evasion_api.get(
    "/scans/<scan_id>", responses={200: APIErrorResponse, 404: APIErrorResponse}
)
def get_scan(path: EvasionScanPath):
    scan_id = path.scan_id
    try:
        job = Job.fetch(scan_id, connection=redis)
    except NoSuchJobError:
        job = None

    if job is not None:
        metadata = _metadata_for_job(job)
        return jsonify(metadata.store_to_dict())

    # No live job record (expired from Redis, or the id is simply unknown) -
    # fall back to whatever is on disk, exactly like GET /api/status does
    # for analyses.
    try:
        return jsonify(_read_scan_json(scan_id, RESULT_FILENAME))
    except FileNotFoundError:
        pass
    try:
        return jsonify(_read_scan_json(scan_id, METADATA_FILENAME))
    except FileNotFoundError:
        return jsonify({"error": "Scan not found"}), 404


@evasion_api.get(
    "/scans/<scan_id>/status",
    responses={200: ScanStatusResponse, 404: APIErrorResponse},
)
def scan_status(path: EvasionScanPath):
    scan_id = path.scan_id
    try:
        job = Job.fetch(scan_id, connection=redis)
    except NoSuchJobError:
        job = None

    if job is not None and job.get_status() not in (
        JobStatus.FINISHED,
        JobStatus.FAILED,
    ):
        job_meta = job.get_meta()
        return jsonify(
            {
                "id": scan_id,
                "status": job.get_status().value,
                "substatus": job_meta.get("substatus"),
                "vm_id": job_meta.get("vm_id"),
                "time_started": (
                    job.started_at.isoformat() if job.started_at is not None else None
                ),
                "time_finished": None,
            }
        )

    try:
        metadata_dict = _read_scan_json(scan_id, METADATA_FILENAME)
        return jsonify(
            {
                "id": metadata_dict.get("id", scan_id),
                "status": metadata_dict.get("status"),
                "substatus": metadata_dict.get("substatus"),
                "vm_id": metadata_dict.get("vm_id"),
                "time_started": metadata_dict.get("time_started"),
                "time_finished": metadata_dict.get("time_finished"),
            }
        )
    except FileNotFoundError:
        if job is not None:
            return jsonify(
                {
                    "id": scan_id,
                    "status": job.get_status().value,
                    "substatus": None,
                    "vm_id": None,
                    "time_started": (
                        job.started_at.isoformat()
                        if job.started_at is not None
                        else None
                    ),
                    "time_finished": (
                        job.ended_at.isoformat() if job.ended_at is not None else None
                    ),
                }
            )
        return jsonify({"error": "Scan not found"}), 404


@evasion_api.get("/scans/<scan_id>/json")
def scan_json(path: EvasionScanPath):
    return send_entity_file(
        path.scan_id,
        RESULT_FILENAME,
        mimetype="application/json",
        s3_config=config.s3,
        base_dir=EVASION_DIR,
    )


@evasion_api.get("/scans/<scan_id>/report")
def scan_report(path: EvasionScanPath):
    return send_entity_file(
        path.scan_id,
        REPORT_FILENAME,
        mimetype="text/html",
        s3_config=config.s3,
        base_dir=EVASION_DIR,
        download_name=f"evasion-report-{path.scan_id}.html",
    )


@evasion_api.get("/scans/<scan_id>/files")
def list_scan_files_endpoint(path: EvasionScanPath):
    try:
        files = list_entity_files(
            path.scan_id, s3_config=config.s3, base_dir=EVASION_DIR
        )
    except FileNotFoundError:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(files)


@evasion_api.get("/scans/<scan_id>/files/download")
def download_scan_file(path: EvasionScanPath, query: EvasionScanFileQuery):
    try:
        return send_entity_file(
            path.scan_id,
            query.filename,
            mimetype="application/octet-stream",
            s3_config=config.s3,
            download_name=query.filename.split("/")[-1],
            base_dir=EVASION_DIR,
        )
    except ValueError:
        # check_path() raises ValueError when the requested filename would
        # escape the scan directory (e.g. "../../etc/passwd").
        return jsonify({"error": "Invalid filename"}), 400


@evasion_api.get("/scans/<scan_id>/logs")
def scan_artifacts_zip(path: EvasionScanPath):
    scan_dir = get_scan_dir(EVASION_DIR, path.scan_id)
    if not scan_dir.exists():
        return jsonify({"error": "Scan not found"}), 404
    zip_path = build_artifacts_zip(scan_dir)
    return send_file(
        zip_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{path.scan_id}_artifacts.zip",
    )


__all__ = ["evasion_api"]
