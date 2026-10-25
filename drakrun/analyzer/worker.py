import datetime
import logging
import math
import shutil
import socket
from typing import List, Optional

from redis import Redis
from rq import Queue, Worker, get_current_job
from rq.exceptions import InvalidJobOperation
from rq.job import Job, JobStatus

from drakrun.lib.config import RedisConfigSection, WorkerGuestOS, load_config
from drakrun.lib.paths import ANALYSES_DIR, UPLOADS_DIR

from ..lib.s3_storage import (
    download_sample_from_s3,
    get_s3_client,
    is_s3_enabled,
    upload_analysis,
)
from .analysis_metadata import AnalysisMetadata, FileMetadata
from .analysis_options import AnalysisOptions
from .analyzer import AnalysisSubstatus, analyze_file
from .linux_analyzer import analyze_linux_file
from .static.worker import STATIC_ONLY_QUEUE_NAME

ANALYSIS_QUEUE_NAME = "drakrun-analysis"
LINUX_ANALYSIS_QUEUE_NAME = "drakrun-analysis-linux"
ANALYSIS_QUEUE_NAMES = (ANALYSIS_QUEUE_NAME, LINUX_ANALYSIS_QUEUE_NAME)

LISTED_QUEUE_NAMES = ANALYSIS_QUEUE_NAMES + (STATIC_ONLY_QUEUE_NAME,)
_WORKER_VM_ID: Optional[int] = None
_WORKER_GUEST_OS: WorkerGuestOS = "any"

logger = logging.getLogger(__name__)


def get_redis_connection(config: RedisConfigSection):
    redis = Redis(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
    )
    return redis


def analysis_job_to_metadata(job: Job) -> AnalysisMetadata:
    job_status = job.get_status()
    job_meta = job.get_meta()
    time_finished = job.meta["time_finished"] if "time_finished" in job.meta else None
    if time_finished is None:
        time_finished = job.ended_at.isoformat() if job.ended_at is not None else None
    return AnalysisMetadata.load_from_dict(
        {
            **job_meta.get("extra_metadata", {}),
            **(
                {
                    "memory_admission_wait_seconds": job_meta[
                        "memory_admission_wait_seconds"
                    ]
                }
                if "memory_admission_wait_seconds" in job_meta
                else {}
            ),
            "id": job.id,
            "status": job_status.value if job_status is not None else "unknown",
            "substatus": job_meta.get("substatus"),
            "options": job_meta["options"],
            "file": job_meta["file"],
            "vm_id": job_meta.get("vm_id"),
            "time_started": (
                job.started_at.isoformat() if job.started_at is not None else None
            ),
            "time_execution_started": (
                job.meta["time_execution_started"]
                if "time_execution_started" in job.meta
                else None
            ),
            "time_finished": time_finished,
        }
    )


def worker_analyze(options: AnalysisOptions):
    if _WORKER_VM_ID is None:
        raise RuntimeError("Fatal error: no vm_id assigned in worker")

    config = load_config()
    # Reconstruct options object to include worker-side preset defaults
    options = AnalysisOptions.with_config_defaults(config, **dict(options))

    if _WORKER_GUEST_OS != "any" and options.guest_os != _WORKER_GUEST_OS:
        raise RuntimeError(
            f"Worker vm-{_WORKER_VM_ID} is bound to {_WORKER_GUEST_OS}; "
            f"refusing {options.guest_os} analysis"
        )

    if not options.plugins:
        raise RuntimeError("Cannot analyze sample without plugins specified")

    if is_s3_enabled(config.s3):
        s3_client = get_s3_client(config.s3)
        s3_bucket = config.s3.bucket
    else:
        s3_client = None
        s3_bucket = None

    job = get_current_job()
    job.meta["vm_id"] = _WORKER_VM_ID
    job.save_meta()

    file_metadata = FileMetadata.model_validate(job.meta["file"])

    vm_id = _WORKER_VM_ID
    output_dir = ANALYSES_DIR / job.id
    output_dir.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(output_dir / "drakrun.log")
    formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    drakrun_logger = logging.getLogger("drakrun")
    drakrun_logger.addHandler(file_handler)

    metadata = AnalysisMetadata(
        id=job.id,
        options=options,
        time_started=job.started_at.isoformat(),
        vm_id=vm_id,
        file=file_metadata,
    )
    metadata_file = output_dir / "metadata.json"
    metadata.store_to_file(metadata_file)

    def substatus_callback(substatus: AnalysisSubstatus, updated_options: bool = False):
        job.meta["substatus"] = substatus.value
        if substatus == AnalysisSubstatus.analyzing:
            metadata.time_execution_started = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            job.meta["time_execution_started"] = metadata.time_execution_started
        if updated_options:
            job.meta["options"] = options.to_dict(exclude_none=True)
        job.save_meta()

    if options.host_sample_path is None:
        if s3_client is None:
            raise RuntimeError("Got sample referenced on S3 but S3 is not enabled")
        # Sample is passed via S3
        UPLOADS_DIR.mkdir(exist_ok=True)
        upload_path = UPLOADS_DIR / f"{job.id}.sample"
        download_sample_from_s3(job.id, upload_path, s3_client, s3_bucket)
        options.host_sample_path = upload_path

    job_success = True
    try:
        analyzer = (
            analyze_linux_file if metadata.options.guest_os == "linux" else analyze_file
        )
        extra_metadata = analyzer(
            vm_id, output_dir, metadata, substatus_callback=substatus_callback
        )
        job.meta.update({"extra_metadata": extra_metadata})
        metadata.model_extra.update(extra_metadata)
        job.save_meta()
    except BaseException:
        job_success = False
        logger.exception("Failed to analyze sample")
        raise
    finally:
        drakrun_logger.removeHandler(file_handler)
        file_handler.close()

        metadata.status = "finished" if job_success else "failed"
        if "memory_admission_wait_seconds" in job.meta:
            metadata.model_extra["memory_admission_wait_seconds"] = job.meta[
                "memory_admission_wait_seconds"
            ]
        metadata.time_finished = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        job.meta["time_finished"] = metadata.time_finished
        job.save_meta()

        metadata.store_to_file(metadata_file)
        options.host_sample_path.unlink()
        if s3_client is not None:
            upload_analysis(job.id, output_dir, s3_client, s3_bucket)
            if config.s3.remove_local_after_upload:
                shutil.rmtree(output_dir)


def worker_main(vm_id: int, guest_os: Optional[WorkerGuestOS] = None):
    global _WORKER_VM_ID, _WORKER_GUEST_OS
    _WORKER_VM_ID = vm_id
    config = load_config()
    _WORKER_GUEST_OS = guest_os or config.worker.vm_guest_os.get(vm_id, "any")
    if _WORKER_GUEST_OS not in ("windows", "linux", "any"):
        raise ValueError(f"Invalid worker guest OS: {_WORKER_GUEST_OS}")
    hostname = config.drakrun.worker_hostname or socket.gethostname()

    worker = Worker(
        queues=(
            list(ANALYSIS_QUEUE_NAMES)
            if _WORKER_GUEST_OS == "any"
            else [queue_for_guest_os(_WORKER_GUEST_OS)]
        ),
        name=f"drakrun-worker@{hostname}:vm-{vm_id}",
        connection=get_redis_connection(config.redis),
    )
    worker.work()


def queue_for_guest_os(guest_os: str) -> str:
    if guest_os == "windows":
        return ANALYSIS_QUEUE_NAME
    if guest_os == "linux":
        return LINUX_ANALYSIS_QUEUE_NAME
    raise ValueError(f"Invalid analysis guest OS: {guest_os}")


def enqueue_analysis(
    job_id: str,
    file_metadata: FileMetadata,
    options: AnalysisOptions,
    connection: Redis,
    result_ttl: int,
) -> Job:
    queue = Queue(name=queue_for_guest_os(options.guest_os), connection=connection)
    if options.timeout is None:
        raise RuntimeError("Timeout is required when spawning analysis to worker")
    return queue.enqueue(
        worker_analyze,
        options,
        job_id=job_id,
        meta={
            "options": options.to_dict(exclude_none=True),
            "file": file_metadata.to_dict(),
        },
        # RQ's wall-clock budget must leave time for admission before analysis.
        job_timeout=(
            options.timeout
            + options.job_timeout_leeway
            + math.ceil(load_config().worker.memory_admission_timeout)
        ),
        result_ttl=result_ttl,
    )


def get_analyses_list(connection: Redis) -> List[Job]:
    jobs = {}
    for queue_name in LISTED_QUEUE_NAMES:
        queue = Queue(name=queue_name, connection=connection)
        for job in queue.get_jobs():
            jobs[job.id] = job
        for job_registry in [
            queue.started_job_registry,
            queue.finished_job_registry,
            queue.failed_job_registry,
            queue.deferred_job_registry,
            queue.scheduled_job_registry,
            queue.canceled_job_registry,
        ]:
            job_ids = job_registry.get_job_ids()
            for job in Job.fetch_many(job_ids, connection=connection):
                if job is not None:
                    jobs[job.id] = job
    return sorted(
        jobs.values(), key=lambda job: job.enqueued_at or job.created_at, reverse=True
    )


def truncate_analysis_list(connection: Redis, limit: int) -> None:
    jobs_to_truncate = get_analyses_list(connection=connection)[limit:]
    for job in jobs_to_truncate:
        try:
            status = job.get_status()
        except InvalidJobOperation:
            # Already deleted?
            continue
        if status in [JobStatus.FINISHED, JobStatus.FAILED]:
            job.delete()
