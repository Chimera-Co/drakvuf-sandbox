import logging

from drakrun.analyzer.static.sandbox import GRACE_S

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def queue_memdump_scan(context: PostprocessContext) -> None:
    """Hand dumps.zip to the deep static worker (drakrun/analyzer/static/memdumps.py)."""
    from rq import Queue, get_current_job

    from drakrun.analyzer.static.memdumps import run_memdump_job
    from drakrun.analyzer.static.worker import DEEP_QUEUE_NAME
    from drakrun.lib.config import load_config

    settings = load_config().static
    if not (settings.enabled and settings.memdump_scan_enabled):
        return
    job = get_current_job()
    if job is None:  # reprocessing outside a worker: nothing to queue on
        return
    analysis_id = context.analysis_dir.name
    Queue(name=DEEP_QUEUE_NAME, connection=job.connection).enqueue(
        run_memdump_job,
        analysis_id,
        job_id=f"static-memdumps-{analysis_id}",
        # The scan stops itself at the budget; the margin covers the one dump still running then.
        job_timeout=int(
            settings.memdump_scan_budget_s + settings.timeout_s + GRACE_S + 300
        ),
        result_ttl=3600,
        failure_ttl=7 * 24 * 3600,
    )
    logger.info("Queued memory dump scan for %s", analysis_id)
