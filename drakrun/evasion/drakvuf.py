"""Optional DRAKVUF lifetime for verifier runs; Xen imports stay lazy."""

import logging
import subprocess
from contextlib import ExitStack, contextmanager

logger = logging.getLogger(__name__)


@contextmanager
def verification_drakvuf(
    scan_dir, config, vm_name, vmi_info, kernel_profile_path, metadata
):
    """Yield the process (or None on startup failure) and record attachment.

    A live process after the startup grace period is a liveness check, not
    a plugin readiness signal. An exit before teardown invalidates the
    attachment, even with return code zero. The caller must then invalidate
    tool results before scoring them.
    """
    metadata.drakvuf_attached = False
    process = None
    output_file = scan_dir / "drakvuf" / "drakmon.log"
    try:
        with ExitStack() as stack:
            # Catch startup failures only; errors in the verifier body must
            # still reach worker_verify's normal infrastructure-failure path.
            try:
                from drakrun.analyzer.analysis_options import AnalysisOptions
                from drakrun.analyzer.analyzer import prepare_drakvuf_args
                from drakrun.analyzer.run_tools import run_drakvuf
                from drakrun.lib.paths import DUMPS_DIR
                from drakrun.lib.version_detection import get_drakvuf_version

                output_dir = output_file.parent
                output_dir.mkdir(parents=True, exist_ok=True)
                # Only the fields prepare_drakvuf_args needs. No sample or
                # injection; tool deadlines and context exit own the lifetime.
                options = AnalysisOptions(
                    plugins=config.drakrun.plugins,
                    net_enable=config.network.net_enable,
                    timeout=None,
                    apimon_hooks_path=config.drakrun.apimon_hooks_path,
                    syscall_hooks_path=config.drakrun.syscall_hooks_path,
                )
                if "memdump" in options.plugins:
                    (output_dir / DUMPS_DIR).mkdir(exist_ok=True)
                process = stack.enter_context(
                    run_drakvuf(
                        vm_name=vm_name,
                        vmi_info=vmi_info,
                        kernel_profile_path=kernel_profile_path,
                        output_file=output_file,
                        output_err_file=output_dir / "drakvuf_stderr.log",
                        drakvuf_args=prepare_drakvuf_args(output_dir, options),
                        drakvuf_version_info=get_drakvuf_version(),
                        exec_parameters=None,
                        drakvuf_cwd=output_dir,
                    )
                )
                # Popen can succeed even when DRAKVUF immediately rejects its
                # arguments/profile. Give those failures time to surface.
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    metadata.drakvuf_attached = True
                else:
                    raise RuntimeError(
                        f"DRAKVUF exited during startup (return code {process.returncode})"
                    )
            except Exception as exc:
                metadata.drakvuf_error = f"DRAKVUF failed to start: {exc}"
                logger.exception("Could not attach DRAKVUF for verification")

            try:
                yield process if metadata.drakvuf_attached else None
            finally:
                # Check before run_drakvuf gracefully terminates the process,
                # so an expected termination return code isn't a false failure.
                if metadata.drakvuf_attached and process.poll() is not None:
                    metadata.drakvuf_attached = False
                    metadata.drakvuf_error = (
                        "DRAKVUF exited before verifier runs completed "
                        f"(return code {process.returncode})"
                    )
    finally:
        # ExitStack has closed run_drakvuf and waited for graceful teardown.
        if process is not None:
            metadata.drakvuf_returncode = process.returncode
        metadata.drakmon_log_nonempty = (
            output_file.is_file() and output_file.stat().st_size > 0
        )
