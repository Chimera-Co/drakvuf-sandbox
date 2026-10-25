"""Queue host lookups after analysis postprocessing."""

from drakrun.lib.intel.online.run import enqueue, read_json


def queue_online_intel(context):
    from rq import get_current_job
    from rq.job import Dependency, Job

    from drakrun.analyzer.static.worker import job_dir
    from drakrun.lib.config import load_config

    job = get_current_job()
    if job is None:
        return
    metadata = read_json(context.analysis_dir / "metadata.json")
    options = read_json(
        job_dir(context.analysis_dir.name) / "online-options.json"
    ) or metadata.get("options")
    settings = load_config().static
    dependency = None
    scan_id = f"static-memdumps-{context.analysis_dir.name}"
    # Wait for the memory-dump scan (its IOCs are looked up too) only when it was actually queued: a dependency on
    # a job id that does not exist would fail this step.
    if (
        settings.enabled
        and settings.memdump_scan_enabled
        and Job.exists(scan_id, connection=job.connection)
    ):
        dependency = Dependency(jobs=[scan_id], allow_failure=True)
    enqueue(context.analysis_dir.name, job.connection, options, depends_on=dependency)
