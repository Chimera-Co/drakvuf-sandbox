"""RQ job plumbing for Sandbox Evasion scans.

Mirrors drakrun.analyzer.worker's analysis conventions exactly, on a
separate queue (EVASION_QUEUE_NAME) so verification scans never appear in
/api/list and are never touched by truncate_analysis_list. This module
provides both the enqueue/list/job-to-metadata helpers the API layer
(Phase D) needs and, since Phase F, worker_verify's real body: restore the
selected sandbox's disposable overlay through the exact same run_vm/
VirtualMachine lifecycle worker_analyze uses, run each requested verifier
against it via a real GuestSession, score and persist the result.

Every Xen/DRAKVUF-only import (run_vm, Injector, InstallInfo, VmiInfo, the
real GuestSession) is deliberately local to worker_verify's function body,
not at module scope: drakrun/web/evasion_api.py imports
enqueue_verification/get_scans_list/scan_job_to_metadata/get_redis_connection
from this exact module and must stay importable (and tested) on a plain
Windows checkout with no Xen installed. worker_verify itself is only ever
invoked by a real RQ worker process on the Debian/Xen box.
"""

from __future__ import annotations

from typing import List, Optional

from redis import Redis
from rq import Queue
from rq.job import Job

from drakrun.evasion.constants import (
    EVASION_QUEUE_NAME,
    LOG_FILENAME,
    METADATA_FILENAME,
    EvasionSubstatus,
    ToolStatus,
)
from drakrun.evasion.models import EvasionScanMetadata, EvasionScanOptions, ToolResult
from drakrun.evasion.sandbox_registry import SandboxDefinition, resolve_sandbox
from drakrun.lib.config import DrakrunConfig, RedisConfigSection

_WORKER_VM_ID: Optional[int] = None


def _admin_options_for_tool(tool_id: str, config: DrakrunConfig) -> dict:
    """Administrator-controlled, host-side settings each adapter's run()
    expects merged into its options dict - never something a scan request
    can set itself (the API layer's CreateScanRequest has no field for
    either of these). Named per tool id because EvasionConfigSection itself
    declares one config section per tool (AlKhaserConfigSection,
    PerdedorConfigSection), not a generic settings bag; the actual
    sandbox/tool CAPABILITY resolution in worker_verify below stays fully
    data-driven regardless of this mapping existing."""
    if tool_id == "alkhaser":
        path = config.evasion.alkhaser.host_binary_path
        return {"host_binary_path": str(path) if path else None}
    if tool_id == "perdedor":
        path = config.evasion.perdedor.repo_path
        return {"repo_path": str(path) if path else None}
    return {}


def _timeout_seconds_for_tool(tool_id: str, config: DrakrunConfig) -> float:
    if tool_id == "alkhaser":
        return float(config.evasion.alkhaser.timeout)
    if tool_id == "perdedor":
        return float(config.evasion.perdedor.timeout)
    return float(config.evasion.default_timeout)


def get_redis_connection(config: RedisConfigSection) -> Redis:
    """Identical to drakrun.analyzer.worker.get_redis_connection, duplicated
    (not imported) deliberately: analyzer.worker's module-level imports pull
    in analysis_metadata (python-magic, a libmagic binary dependency) and
    analyzer.analyzer (Xen/DRAKVUF-dependent) purely as a side effect of
    importing that module at all. The evasion API layer only ever needs this
    one connection-factory function and must stay importable/testable on a
    plain Windows checkout with none of that installed."""
    return Redis(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
    )


def worker_verify(options: EvasionScanOptions) -> None:
    """RQ task entry point for a verification scan.

    Mirrors drakrun.analyzer.worker.worker_analyze's own structure closely:
    write metadata.json at start, attach a FileHandler for the scan's own
    log, run the actual work inside a try/finally that always records a
    terminal status and re-raises on failure (so RQ marks the job FAILED,
    never FINISHED, when something genuinely broke), and never return
    before every artifact this scan promises (evasion.json, report.html,
    metadata.json) is safely written - that ordering is what keeps the
    frontend's poll loop from ever observing a "finished" job whose report
    isn't actually there yet.
    """
    import datetime
    import logging
    import time

    from rq import get_current_job

    from drakrun.analyzer.post_restore import get_post_restore_command
    from drakrun.analyzer.run_tools import run_vm
    from drakrun.evasion.guest_runner import connect_guest_session
    from drakrun.evasion.report import write_evasion_json, write_html_report
    from drakrun.evasion.scoring import compute_score
    from drakrun.evasion.storage import get_scan_dir
    from drakrun.evasion.verifiers import get_adapters_for_platform
    from drakrun.evasion.verifiers.base import VerifierError
    from drakrun.lib.config import NetworkConfigSection, load_config
    from drakrun.lib.injector import Injector
    from drakrun.lib.install_info import InstallInfo
    from drakrun.lib.libvmi import VmiInfo
    from drakrun.lib.paths import (
        EVASION_DIR,
        INSTALL_INFO_PATH,
        VMI_INFO_PATH,
        VMI_KERNEL_PROFILE_PATH,
    )

    logger = logging.getLogger(__name__)

    if _WORKER_VM_ID is None:
        raise RuntimeError("Fatal error: no vm_id assigned in worker")
    vm_id = _WORKER_VM_ID

    job = get_current_job()
    config = load_config()

    # Re-resolve the sandbox from the CURRENT registry, not the snapshot
    # captured at enqueue time - the snapshot in job.meta/metadata.json is
    # for historical display only (so past runs stay readable even if the
    # registry later changes); execution must reflect what the operator has
    # configured right now, exactly like worker_analyze reconstructs
    # AnalysisOptions from the current config rather than trusting only
    # what was true when the job was enqueued.
    sandbox = resolve_sandbox(config, options.sandbox_id)

    scan_dir = get_scan_dir(EVASION_DIR, job.id)
    scan_dir.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(scan_dir / LOG_FILENAME)
    file_handler.setFormatter(
        logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s] %(message)s")
    )
    drakrun_logger = logging.getLogger("drakrun")
    drakrun_logger.addHandler(file_handler)

    def substatus_callback(
        substatus: str, current_tool: Optional[str] = "__unset__"
    ) -> None:
        job.meta["substatus"] = substatus
        job.meta["vm_id"] = vm_id
        if current_tool != "__unset__":
            if current_tool is None:
                job.meta.pop("current_tool", None)
            else:
                job.meta["current_tool"] = current_tool
        job.save_meta()

    substatus_callback(EvasionSubstatus.preparing.value)

    metadata = EvasionScanMetadata(
        id=job.id,
        status="started",
        substatus=EvasionSubstatus.preparing.value,
        sandbox=sandbox.to_dict(),
        options=options,
        vm_id=vm_id,
        time_started=(
            job.started_at.isoformat()
            if job.started_at is not None
            else datetime.datetime.now(datetime.timezone.utc).isoformat()
        ),
    )
    metadata_file = scan_dir / METADATA_FILENAME
    metadata.store_to_file(metadata_file)

    platform_adapters = {a.id: a for a in get_adapters_for_platform(sandbox.platform)}

    # Pre-flight capability + configuration validation, before ever booting
    # a guest - "never turn infrastructure failure into a clean result"
    # applies just as much to a tool that should never have been asked to
    # run at all (platform/sandbox mismatch, or a rejected configuration)
    # as to one that fails mid-flight. Re-validating here (not just trusting
    # the API layer's own validation at submission time) is deliberate
    # defense in depth against the registry or admin config changing while
    # a scan sat queued.
    tool_results: List[ToolResult] = []
    runnable_tools = []
    for tool_id in options.tools:
        if tool_id not in sandbox.verifiers or tool_id not in platform_adapters:
            tool_results.append(
                ToolResult(
                    tool=tool_id,
                    status=ToolStatus.unsupported,
                    error=(
                        f"'{tool_id}' is not available for sandbox "
                        f"'{sandbox.id}' (platform={sandbox.platform}) at "
                        "execution time."
                    ),
                )
            )
            continue
        adapter = platform_adapters[tool_id]
        raw_user_options = (
            dict(options.tool_options.get(tool_id, {}))
            if options.profile == "custom"
            else {}
        )
        try:
            validated_user_options = adapter.validate_options(raw_user_options)
        except VerifierError as exc:
            tool_results.append(
                ToolResult(
                    tool=tool_id,
                    status=ToolStatus.error,
                    error=f"Configuration rejected at execution time: {exc}",
                )
            )
            continue
        run_options = {
            **validated_user_options,
            **_admin_options_for_tool(tool_id, config),
        }
        runnable_tools.append((tool_id, adapter, run_options))

    job_success = True
    try:
        if runnable_tools:
            install_info = InstallInfo.load(INSTALL_INFO_PATH)
            vmi_info = VmiInfo.load(VMI_INFO_PATH)
            kernel_profile_path = VMI_KERNEL_PROFILE_PATH.as_posix()
            network_conf = NetworkConfigSection(
                out_interface=config.network.out_interface,
                dns_server=config.network.dns_server,
                net_enable=config.network.net_enable,
            )

            substatus_callback(EvasionSubstatus.booting.value)
            # The exact same disposable-overlay lifecycle worker_analyze
            # uses: restore() on entry, destroy() in run_vm's own finally on
            # exit - regardless of how this "with" block is left (normal
            # completion, an adapter bug, a guest becoming unreachable, or
            # the score/report step raising below).
            with run_vm(vm_id, install_info, network_conf) as vm:
                injector = Injector(vm.vm_name, vmi_info, kernel_profile_path)
                session = connect_guest_session(vm.vm_name, injector)

                if not config.drakrun.no_post_restore:
                    post_restore_cmd = get_post_restore_command(network_conf.net_enable)
                    session.drakshell.check_call(post_restore_cmd)

                substatus_callback(EvasionSubstatus.probing.value, current_tool=None)

                for tool_id, adapter, run_options in runnable_tools:
                    substatus_callback(f"running_{tool_id}", current_tool=tool_id)
                    deadline = time.time() + _timeout_seconds_for_tool(tool_id, config)
                    try:
                        result = adapter.run(session, run_options, scan_dir, deadline)
                    except (
                        Exception
                    ) as exc:  # noqa: BLE001 - adapters are documented to never raise, but a guest-session bug must still degrade to an error result rather than abort the whole scan
                        logger.exception("Verifier '%s' raised unexpectedly", tool_id)
                        result = ToolResult(
                            tool=tool_id,
                            status=ToolStatus.error,
                            error=f"Verifier raised an unexpected error: {exc}",
                        )
                    tool_results.append(result)

                substatus_callback(EvasionSubstatus.collecting.value, current_tool=None)
                score = compute_score(
                    tool_results,
                    pass_threshold=config.evasion.score_pass_threshold,
                    warn_threshold=config.evasion.score_warn_threshold,
                )
                metadata.tool_results = tool_results
                metadata.score = score

                substatus_callback(EvasionSubstatus.reporting.value)
                write_evasion_json(scan_dir, metadata)
                write_html_report(scan_dir, metadata)

                substatus_callback(EvasionSubstatus.cleanup.value)
            # run_vm's context manager has already destroyed the VM by now.
        else:
            # Every requested tool failed capability/config validation -
            # never boot a VM for nothing, but still score (compute_score
            # correctly reports "incomplete" for an all-unsupported/error
            # result set - never a fabricated pass) and write a report.
            score = compute_score(
                tool_results,
                pass_threshold=config.evasion.score_pass_threshold,
                warn_threshold=config.evasion.score_warn_threshold,
            )
            metadata.tool_results = tool_results
            metadata.score = score
            substatus_callback(EvasionSubstatus.reporting.value)
            write_evasion_json(scan_dir, metadata)
            write_html_report(scan_dir, metadata)
    except BaseException as exc:
        job_success = False
        logger.exception("Verification scan failed")
        metadata.error = str(exc)
        raise
    finally:
        drakrun_logger.removeHandler(file_handler)
        file_handler.close()

        metadata.status = "finished" if job_success else "failed"
        metadata.substatus = (
            EvasionSubstatus.done.value if job_success else metadata.substatus
        )
        metadata.time_finished = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        job.meta["time_finished"] = metadata.time_finished
        job.meta["substatus"] = metadata.substatus
        job.save_meta()
        # The very last disk write - evasion.json (inside the try block
        # above) already reflects the full result when this scan actually
        # ran tools; metadata.json is updated here too so the API layer's
        # fallback path (evasion.json missing or unreadable) still shows an
        # accurate terminal status for a scan that failed before it could
        # write evasion.json at all.
        metadata.store_to_file(metadata_file)


def scan_job_to_metadata(job: Job) -> EvasionScanMetadata:
    """Build an EvasionScanMetadata snapshot from a live RQ job's meta -
    the evasion analogue of analyzer.worker.analysis_job_to_metadata. Used
    while a scan is still queued/running, before evasion.json/metadata.json
    exist on disk."""
    job_status = job.get_status()
    job_meta = job.get_meta()
    time_finished = job_meta.get("time_finished")
    if time_finished is None:
        time_finished = job.ended_at.isoformat() if job.ended_at is not None else None
    return EvasionScanMetadata.load_from_dict(
        {
            "id": job.id,
            "status": job_status.value if job_status is not None else "unknown",
            "substatus": job_meta.get("substatus"),
            "sandbox": job_meta["sandbox"],
            "options": job_meta["options"],
            "vm_id": job_meta.get("vm_id"),
            "time_started": (
                job.started_at.isoformat() if job.started_at is not None else None
            ),
            "time_execution_started": job_meta.get("time_execution_started"),
            "time_finished": time_finished,
        }
    )


def enqueue_verification(
    job_id: str,
    sandbox: SandboxDefinition,
    options: EvasionScanOptions,
    connection: Redis,
    result_ttl: int,
    job_timeout: int,
) -> Job:
    queue = Queue(name=EVASION_QUEUE_NAME, connection=connection)
    return queue.enqueue(
        worker_verify,
        options,
        job_id=job_id,
        meta={
            "sandbox": sandbox.to_dict(),
            "options": options.to_dict(exclude_none=True),
        },
        job_timeout=job_timeout,
        result_ttl=result_ttl,
    )


def get_scans_list(connection: Redis) -> List[Job]:
    queue = Queue(name=EVASION_QUEUE_NAME, connection=connection)
    jobs = list(queue.get_jobs())
    for job_registry in [
        queue.started_job_registry,
        queue.finished_job_registry,
        queue.failed_job_registry,
    ]:
        job_ids = job_registry.get_job_ids()
        jobs.extend(
            [
                job
                for job in Job.fetch_many(job_ids, connection=connection)
                if job is not None
            ]
        )
    return sorted(jobs, key=lambda job: job.enqueued_at, reverse=True)


__all__ = [
    "get_redis_connection",
    "worker_verify",
    "scan_job_to_metadata",
    "enqueue_verification",
    "get_scans_list",
]
