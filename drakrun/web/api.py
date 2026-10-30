import logging
import pathlib
import uuid

from flask import Response, jsonify, request
from flask_openapi3 import APIBlueprint
from rq.exceptions import NoSuchJobError
from rq.job import Job, JobStatus

from drakrun.analyzer.analysis_metadata import AnalysisMetadata, FileMetadata
from drakrun.analyzer.postprocessing.indexer import (
    get_log_index_for_process,
    get_plugin_names_for_process,
    scattered_read_file,
)
from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
    iocs_csv,
    iocs_export,
)
from drakrun.analyzer.postprocessing.process_tree import tree_from_dict
from drakrun.analyzer.static.worker import enqueue_static_only, stage_and_enqueue
from drakrun.analyzer.worker import (
    analysis_job_to_metadata,
    enqueue_analysis,
    get_analyses_list,
    get_redis_connection,
    truncate_analysis_list,
)
from drakrun.lib.analysis_time import (
    check_free_disk,
    public_settings,
    validate_time_options,
)
from drakrun.lib.config import load_config
from drakrun.lib.intel.online.options import OnlineAnalysisOptions
from drakrun.lib.paths import ANALYSES_DIR, STATIC_DIR, UPLOADS_DIR
from drakrun.lib.s3_storage import get_s3_client, is_s3_enabled, upload_sample_to_s3
from drakrun.web.schema import (
    AnalysisFileRequestQuery,
    AnalysisListResponse,
    AnalysisRequestPath,
    AnalysisResponse,
    APIErrorResponse,
    KartonResultsUploadForm,
    KartonResultsUploadPath,
    KartonResultsUploadResponse,
    LogsRequestPath,
    ProcessInfoRequestPath,
    ProcessLogsRequestPath,
    ScreenshotRequestPath,
    UploadAnalysisResponse,
    UploadFileForm,
)
from drakrun.web.storage import (
    list_analysis_files,
    list_analysis_logs,
    open_seekable_stream,
    read_analysis_json,
    send_analysis_file,
    send_entity_file,
)

ANALYSES_LIST_MAX_LENGTH = 100
api = APIBlueprint("api", __name__, url_prefix="/api")


class OnlineUploadForm(UploadFileForm):
    intel_online: bool | None = None


config = load_config()
redis = get_redis_connection(config.redis)
logger = logging.getLogger(__name__)


@api.post("/upload", responses={200: UploadAnalysisResponse})
def upload_sample(form: OnlineUploadForm):
    intel_online = (
        config.intel.online_default if form.intel_online is None else form.intel_online
    )
    if form.mode == "static-only":
        if not config.static.enabled:
            return jsonify({"error": "static analysis is disabled on this server"}), 400
        for field in (
            "extract_archive",
            "start_command",
            "file_path",
            "start_working_dir",
        ):
            if getattr(form, field):
                return (
                    jsonify(
                        {"error": f"{field} is not supported for static-only analysis"}
                    ),
                    400,
                )

    if form.guest_os in ("android", "ios") and form.mode != "static-only":
        return (
            jsonify(
                {"error": "mobile apps are analysed statically only (mode static-only)"}
            ),
            400,
        )
    request_file = form.file
    job_id = str(uuid.uuid4())

    timeout = form.timeout
    if not timeout:
        timeout = config.drakrun.default_timeout
    clock_scale = form.clock_scale or 1
    if form.mode != "static-only":
        problem = validate_time_options(timeout, clock_scale, config.analysis_time)
        if problem is None and (clock_scale > 1 or form.sleep_skip):
            if form.guest_os != "windows":
                problem = "clock speed-up and sleep shortening are Windows only"
        if problem is None:
            problem = check_free_disk(ANALYSES_DIR, timeout, config.analysis_time)
        if problem is not None:
            return jsonify({"error": problem}), 400
    sample_filename = form.file_name
    if not sample_filename:
        sample_filename = request_file.filename
    start_command = form.start_command
    start_method = form.start_method
    plugins = form.plugins
    preset = form.preset
    no_internet = form.no_internet
    no_screenshots = form.no_screenshots

    UPLOADS_DIR.mkdir(exist_ok=True)
    tmp_upload_path = UPLOADS_DIR / f"{job_id}.sample"

    try:
        request_file.save(tmp_upload_path)
        # Samples are data on the host, never programs: owner read-only, no execute bits.
        tmp_upload_path.chmod(0o400)
        file_metadata = FileMetadata.evaluate(
            file_path=tmp_upload_path, file_name=sample_filename
        )
        # Static analysis starts now, beside the detonation (stages its own copy before
        # the upload may be moved to S3 and deleted below). Never blocks the upload.
        try:
            if form.mode == "combined":
                stage_and_enqueue(
                    job_id, tmp_upload_path, sample_filename, redis, config.static
                )
        except Exception:
            logger.exception("Static analysis could not be queued for %s", job_id)

        from drakrun.analyzer.static.worker import _write_json, job_dir

        if config.intel.online_enabled:
            intel_directory = job_dir(job_id)
            intel_directory.mkdir(parents=True, exist_ok=True)
            _write_json(
                intel_directory, "online-options.json", {"intel_online": intel_online}
            )
        if form.mode == "static-only":
            analysis_options = OnlineAnalysisOptions(
                intel_online=intel_online,
                mode=form.mode,
                plugins=[],
                net_enable=False,
                sample_filename=sample_filename,
            )
            enqueue_static_only(
                job_id, tmp_upload_path, file_metadata, analysis_options, redis, config
            )
            tmp_upload_path.unlink()
            truncate_analysis_list(connection=redis, limit=ANALYSES_LIST_MAX_LENGTH)
            return jsonify({"task_uid": job_id})

        if is_s3_enabled(config.s3):
            s3_client = get_s3_client(config.s3)
            s3_bucket = config.s3.bucket
            with tmp_upload_path.open("rb") as f:
                upload_sample_to_s3(job_id, f, s3_client, s3_bucket)
            tmp_upload_path.unlink()
            sample_path = None
        else:
            sample_path = tmp_upload_path.as_posix()

        analysis_options = OnlineAnalysisOptions.with_config_defaults(
            intel_online=intel_online,
            config=config,
            guest_os=form.guest_os,
            mode=form.mode,
            preset=preset,
            host_sample_path=pathlib.Path(sample_path) if sample_path else None,
            sample_filename=sample_filename,
            start_command=start_command,
            start_method=start_method,
            plugins=plugins,
            timeout=timeout,
            # Postprocessing time grows with the log: 10 more minutes per hour of run time.
            job_timeout_leeway=config.drakrun.job_timeout_leeway + timeout // 6,
            clock_scale=clock_scale,
            sleep_skip=bool(form.sleep_skip),
        )
        if no_internet:
            analysis_options.net_enable = False
        if no_screenshots:
            analysis_options.no_screenshotter = True
        if form.guest_os == "windows" and form.file_path:
            analysis_options.guest_target_directory = pathlib.PureWindowsPath(
                form.file_path
            )
        if form.guest_os == "windows" and form.start_working_dir:
            analysis_options.guest_working_directory = pathlib.PureWindowsPath(
                form.start_working_dir
            )
        if form.extract_archive:
            logger.info(
                f"Archive upload: extract_archive=True, archive_entry_path={form.archive_entry_path}"
            )
            analysis_options.extract_archive = True
            analysis_options.archive_password = form.archive_password
            # For archives, archive_entry_path contains the entry path to execute (e.g., "dir/malware.exe")
            analysis_options.guest_archive_entry_path = form.archive_entry_path
            logger.info(
                f"Archive upload: set guest_archive_entry_path={analysis_options.guest_archive_entry_path}"
            )
        enqueue_analysis(
            job_id=job_id,
            file_metadata=file_metadata,
            options=analysis_options,
            connection=redis,
            result_ttl=config.drakrun.result_ttl,
        )
    except Exception:
        tmp_upload_path.unlink(missing_ok=True)
        raise

    truncate_analysis_list(connection=redis, limit=ANALYSES_LIST_MAX_LENGTH)
    return jsonify({"task_uid": job_id})


@api.post(
    "/analysis/<analysis_id>/karton-results",
    responses={
        200: KartonResultsUploadResponse,
        400: APIErrorResponse,
        403: APIErrorResponse,
        404: APIErrorResponse,
        500: APIErrorResponse,
    },
)
def karton_results_upload(path: KartonResultsUploadPath, form: KartonResultsUploadForm):
    """
    Upload Karton analysis results to Redis hash.
    Validates token stored when analysis was sent to Karton.
    """
    try:
        job = Job.fetch(path.analysis_id, connection=redis)
    except NoSuchJobError:
        return jsonify({"error": "Analysis not found"}), 404

    token = job.meta.get("token")
    if not token or token != form.token:
        return jsonify({"error": "Invalid token"}), 403

    target_key = form.key
    if not target_key:
        return jsonify({"error": "Key required"}), 400

    data_content = form.data.read()

    redis_key = f"karton-results:{path.analysis_id}"
    redis.hset(redis_key, target_key, data_content)
    redis.expire(redis_key, config.karton.redis_ttl)

    logger.info(
        f"Karton result uploaded to Redis: analysis={path.analysis_id}, key={target_key}"
    )
    return jsonify({"status": "success", "key": target_key})


@api.get("/list", responses={200: AnalysisListResponse})
def list_analyses():
    analysis_list = get_analyses_list(connection=redis)
    return jsonify(
        [analysis_job_to_metadata(job).store_to_dict() for job in analysis_list]
    )


@api.get("/status/<task_uid>", responses={200: AnalysisResponse, 404: APIErrorResponse})
def status(path: AnalysisRequestPath):
    task_uid = path.task_uid
    try:
        job = Job.fetch(task_uid, connection=redis)
    except NoSuchJobError:
        job = None

    if job is not None and job.get_status() not in [
        JobStatus.FINISHED,
        JobStatus.FAILED,
    ]:
        metadata = analysis_job_to_metadata(job)
    else:
        try:
            metadata_dict = read_analysis_json(task_uid, "metadata.json", config.s3)
            if "id" not in metadata_dict:
                metadata_dict = {"id": task_uid, **metadata_dict}
            metadata = AnalysisMetadata.load_from_dict(metadata_dict)
        except FileNotFoundError:
            return jsonify({"error": "Job not found"}), 404

    return jsonify(metadata.store_to_dict())


@api.get("/processed/<task_uid>/process_tree")
def process_tree(path: AnalysisRequestPath):
    task_uid = path.task_uid
    try:
        process_tree = read_analysis_json(task_uid, "process_tree.json", config.s3)
    except FileNotFoundError:
        return jsonify({"error": "Data not found"}), 404
    return jsonify(process_tree)


@api.get("/logs/<task_uid>/<log_type>")
def logs(path: LogsRequestPath):
    task_uid = path.task_uid
    log_type = path.log_type
    return send_analysis_file(
        task_uid, f"{log_type}.log", mimetype="text/plain", s3_config=config.s3
    )


@api.get("/logs/<task_uid>/<log_type>/stats")
def log_statistics(path: LogsRequestPath):
    from drakrun.web.log_stats import get_stats

    try:
        return jsonify(get_stats(path.task_uid, path.log_type, config.s3))
    except (FileNotFoundError, ValueError):
        return jsonify({"error": "Data not found"}), 404


@api.get("/logs/<task_uid>/stats")
def analysis_log_statistics(path: AnalysisRequestPath):
    from drakrun.web.log_stats import combined_stats

    try:
        return jsonify(combined_stats(path.task_uid, config.s3))
    except (FileNotFoundError, ValueError):
        return jsonify({"error": "Data not found"}), 404


@api.get("/logs/<task_uid>/stats/process/<seqid>")
def process_log_statistics(path: ProcessInfoRequestPath):
    from drakrun.web.log_stats import process_stats

    try:
        return jsonify(process_stats(path.task_uid, path.seqid, config.s3))
    except (FileNotFoundError, ValueError):
        return jsonify({"error": "Data not found"}), 404


@api.get("/process_info/<task_uid>/<seqid>")
def process_info(path: ProcessInfoRequestPath):
    task_uid = path.task_uid
    seqid = path.seqid
    try:
        process_tree_dict = read_analysis_json(task_uid, "process_tree.json", config.s3)
    except FileNotFoundError:
        return jsonify({"error": "Data not found"}), 404
    process_tree = tree_from_dict(process_tree_dict)
    process = process_tree.processes[seqid]
    try:
        with open_seekable_stream(task_uid, "log_index", config.s3) as log_index:
            plugin_names = get_plugin_names_for_process(log_index, seqid)
            logs = {}
            for plugin_name in plugin_names:
                log_index.seek(0)
                process_log_index = get_log_index_for_process(
                    log_index, seqid, plugin_name
                )
                if process_log_index:
                    logs[plugin_name] = process_log_index["values"]
            return jsonify({"process": process.as_dict(), "logs": logs})
    except FileNotFoundError:
        return jsonify({"error": "Data not found"}), 404


@api.get("/logs/<task_uid>/<log_type>/process/<seqid>")
def process_logs(path: ProcessLogsRequestPath):
    task_uid = path.task_uid
    log_type = path.log_type
    seqid = path.seqid
    try:
        with open_seekable_stream(task_uid, "log_index", config.s3) as log_index:
            index = get_log_index_for_process(log_index, seqid, log_type)
            if not index:
                return dict(error="Data not found"), 404
    except FileNotFoundError:
        return dict(error="Data not found"), 404
    blocks = index["blocks"]
    filter_values = request.args.getlist("filter[]")
    if filter_values:
        filter_indices = [
            index["values"].index(filter_value)
            for filter_value in filter_values
            if filter_value in index["values"]
        ]
        blocks = [
            block
            for (block, mapping) in zip(index["blocks"], index["mapping"])
            if mapping in filter_indices
        ]
    if request.range:
        if len(request.range.ranges) > 1:
            return dict(error="Multiple ranges unsupported"), 400
        range_start, range_stop = request.range.ranges[0]
        skip = range_start
        length = (range_stop - range_start + 1) if range_stop is not None else None
    else:
        skip, length = 0, None
    try:
        with open_seekable_stream(task_uid, f"{log_type}.log", config.s3) as log_file:
            scattered_read = scattered_read_file(
                log_file, blocks, skip=skip, length=length
            )
            return Response(b"".join(scattered_read), mimetype="text/plain")
    except FileNotFoundError:
        return dict(error="Data not found"), 404


@api.get("/pcap_file/<task_uid>")
def pcap_file(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "dump.pcap",
        mimetype="application/octet-stream",
        s3_config=config.s3,
        download_name=f"{task_uid}_dump.pcap",
    )


@api.get("/pcap_keys/<task_uid>")
def pcap_keys(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "wireshark_key_file.txt",
        mimetype="application/octet-stream",
        s3_config=config.s3,
        download_name=f"{task_uid}_wireshark_key_file.txt",
    )


@api.get("/dumps/<task_uid>")
def dumps(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "dumps.zip",
        mimetype="application/zip",
        s3_config=config.s3,
        download_name=f"{task_uid}_dumps.zip",
    )


@api.get("/report/<task_uid>")
def report(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "report.json",
        mimetype="application/json",
        s3_config=config.s3,
    )


@api.get("/classification/<task_uid>", responses={404: APIErrorResponse})
def classification(path: AnalysisRequestPath):
    return send_analysis_file(
        path.task_uid,
        "classification.json",
        mimetype="application/json",
        s3_config=config.s3,
    )


@api.get("/static/<task_uid>", responses={404: APIErrorResponse})
def static_analysis(path: AnalysisRequestPath):
    """Static analysis report (chimera-static/1); 404 until the static worker has finished."""
    return send_entity_file(
        path.task_uid,
        "static.json",
        "application/json",
        None,  # static reports always stay on the host (not in S3)
        base_dir=STATIC_DIR,
    )


@api.get("/static/<task_uid>/deep", responses={404: APIErrorResponse})
def static_deep(path: AnalysisRequestPath):
    """Deep static pass (chimera-deep/1: capa + FLOSS); 404 until it has run, or when it does not apply."""
    return send_entity_file(
        path.task_uid,
        "deep.json",
        "application/json",
        None,  # static reports always stay on the host (not in S3)
        base_dir=STATIC_DIR,
    )


@api.get("/static/<task_uid>/memdumps", responses={404: APIErrorResponse})
def static_memdumps(path: AnalysisRequestPath):
    """Memory-dump scan (chimera-memdumps/1); 404 until the deep worker has scanned the run's dumps."""
    return send_entity_file(
        path.task_uid,
        "memdumps.json",
        "application/json",
        None,  # static reports always stay on the host (not in S3)
        base_dir=STATIC_DIR,
    )


@api.get("/static/<task_uid>/mobsf", responses={404: APIErrorResponse})
def static_mobsf(path: AnalysisRequestPath):
    """MobSF APK scan (chimera-mobsf/1); 404 until it has run, or for anything but an APK."""
    return send_entity_file(
        path.task_uid,
        "mobsf.json",
        "application/json",
        None,  # static reports always stay on the host (not in S3)
        base_dir=STATIC_DIR,
    )


@api.get("/static/<task_uid>/mobsf/source", responses={404: APIErrorResponse})
def static_mobsf_source(path: AnalysisRequestPath):
    """One JADX-decompiled source file of an APK (?path=...), as plain text; only paths mobsf.json lists."""
    from drakrun.analyzer.static.mobsf import read_source

    text = read_source(path.task_uid, request.args.get("path", ""))
    if text is None:
        return jsonify({"error": "Source not found"}), 404
    response = Response(text, mimetype="text/plain")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = "inline"
    return response


@api.get("/features/<task_uid>", responses={404: APIErrorResponse})
def features(path: AnalysisRequestPath):
    return send_analysis_file(
        path.task_uid, "features.json", mimetype="application/json", s3_config=config.s3
    )


@api.get("/logs/<task_uid>")
def list_logs(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis_logs = list_analysis_logs(task_uid, s3_config=config.s3)
    return jsonify(analysis_logs)


@api.get("/files/<task_uid>")
def list_files(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis_files = list_analysis_files(task_uid, s3_config=config.s3)
    return jsonify(analysis_files)


@api.get("/files/<task_uid>/download")
def download_analysis_file(path: AnalysisRequestPath, query: AnalysisFileRequestQuery):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        query.filename,
        s3_config=config.s3,
        mimetype="application/octet-stream",
        download_name=query.filename.split("/")[-1],
    )


@api.get("/graph/<task_uid>")
def graph(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid, "graph.dot", mimetype="text/plain", s3_config=config.s3
    )


@api.get("/screenshot/<task_uid>/<which>")
def screenshot(path: ScreenshotRequestPath):
    task_uid = path.task_uid
    which = path.which
    return send_analysis_file(
        task_uid,
        f"screenshots/screenshot_{which}.png",
        mimetype="image/png",
        s3_config=config.s3,
    )


@api.get("/html/<task_uid>")
def get_html_report(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "report.html",
        mimetype="text/html",
        s3_config=config.s3,
        download_name=f"report-{task_uid}.html",
    )


@api.get("/chimera_report/<task_uid>", responses={404: APIErrorResponse})
def chimera_report(path: AnalysisRequestPath):
    """Evidence-linked report (chimera-report/1); 404 until postprocessing has written it."""
    return send_analysis_file(
        path.task_uid,
        "chimera-report.json",
        mimetype="application/json",
        s3_config=config.s3,
    )


@api.get("/chimera_report/<task_uid>/html", responses={404: APIErrorResponse})
def chimera_report_html(path: AnalysisRequestPath):
    """Printable page of the same report, shown inline. It carries guest-controlled strings, so
    the page may load nothing and run nothing, whatever its own meta tag says."""
    response = send_analysis_file(
        path.task_uid,
        "chimera-report.html",
        mimetype="text/html",
        s3_config=config.s3,
    )
    if isinstance(response, Response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _report_or_404(task_uid: str):
    try:
        return read_analysis_json(task_uid, "chimera-report.json", config.s3)
    except FileNotFoundError:
        return None


@api.get("/intel/<task_uid>", responses={404: APIErrorResponse})
def intel_report(path: AnalysisRequestPath):
    report = _report_or_404(path.task_uid)
    if report is None:
        return jsonify({"error": "Data not found"}), 404
    return jsonify(
        report.get("stages", {}).get(
            "intel",
            {
                "status": "unavailable",
                "payload": None,
                "reason": "No offline intel snapshot",
            },
        )
    )


@api.get("/chimera_report/<task_uid>/iocs.json", responses={404: APIErrorResponse})
def chimera_report_iocs_json(path: AnalysisRequestPath):
    report = _report_or_404(path.task_uid)
    if report is None:
        return jsonify({"error": "Data not found"}), 404
    response = jsonify(iocs_export(report))
    response.headers["Content-Disposition"] = (
        f"attachment; filename=iocs-{path.task_uid}.json"
    )
    return response


@api.get("/chimera_report/<task_uid>/iocs.csv", responses={404: APIErrorResponse})
def chimera_report_iocs_csv(path: AnalysisRequestPath):
    report = _report_or_404(path.task_uid)
    if report is None:
        return jsonify({"error": "Data not found"}), 404
    return Response(
        iocs_csv(report),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=iocs-{path.task_uid}.csv",
            "X-Content-Type-Options": "nosniff",
        },
    )


@api.get("/analysis-time")
def analysis_time_settings():
    return jsonify(public_settings(config.analysis_time))


@api.get("/intel/providers")
def intel_providers():
    from drakrun.lib.intel.online import inventory

    return jsonify(
        {
            "providers": inventory(config.intel),
            "online_enabled": config.intel.online_enabled,
            "online_default": config.intel.online_default,
            "hash_providers": config.intel.hash_providers,
        }
    )


@api.post("/intel/<task_uid>/recheck")
def recheck_offline_intel(path: AnalysisRequestPath):
    """Re-match the analysis against the offline feeds installed now (after a new bundle was imported)."""
    if _report_or_404(path.task_uid) is None:
        return jsonify({"error": "Data not found"}), 404
    from rq import Queue

    from drakrun.analyzer.static.worker import INTEL_QUEUE_NAME
    from drakrun.lib.intel.online.run import run_offline_recheck_job

    Queue(name=INTEL_QUEUE_NAME, connection=redis).enqueue(
        run_offline_recheck_job,
        str(path.task_uid),
        job_id=f"intel-recheck-{path.task_uid}",
        job_timeout=600,
        result_ttl=600,
    )
    return jsonify({"status": "queued"}), 202


@api.post("/intel/<task_uid>/refresh")
def refresh_intel(path: AnalysisRequestPath):
    if not config.intel.online_enabled:
        return (
            jsonify({"error": "Online intel disabled; set intel.online_enabled=true"}),
            409,
        )
    if _report_or_404(path.task_uid) is None:
        return jsonify({"error": "Data not found"}), 404
    from drakrun.lib.intel.online.run import enqueue

    enqueue(path.task_uid, redis, {"intel_online": True})
    return jsonify({"status": "queued"}), 202
