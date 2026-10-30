import contextlib
import fcntl
import logging
import pathlib
import subprocess
import threading
import time
from typing import Callable, List, Optional

from rq import get_current_job

from drakrun.analyzer.screenshotter import Screenshotter
from drakrun.analyzer.startup_command import ExecParameters
from drakrun.lib.config import (
    NetworkConfigSection,
    ScreenshotConfigSection,
    load_config,
)
from drakrun.lib.drakvuf_cmdline import get_base_drakvuf_cmdline
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.memory_admission import memory_admission
from drakrun.lib.network_info import NetworkInfo
from drakrun.lib.networking import start_tcpdump_collector
from drakrun.lib.paths import RUN_DIR
from drakrun.lib.version_detection import DrakvufVersionInfo
from drakrun.lib.vm import VirtualMachine
from drakrun.lib.xen import xen_unpause_vm

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def process_graceful_exit(proc: subprocess.Popen, termination_timeout: int = 5):
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(termination_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(termination_timeout)


def run_tcpdump(network_info: NetworkInfo, output_file: pathlib.Path):
    return process_graceful_exit(
        start_tcpdump_collector(network_info.bridge_name, output_file)
    )


def log_activity_watchdog(
    output_file: pathlib.Path,
    stop_event: threading.Event,
    inactivity_threshold: int = 30,
):
    last_size = 0
    last_activity_time = time.time()

    while not stop_event.wait(timeout=5):

        try:
            current_size = output_file.stat().st_size

            if current_size > last_size:
                last_activity_time = time.time()
                last_size = current_size
            else:
                inactive_duration = time.time() - last_activity_time

                if inactive_duration > inactivity_threshold:
                    logger.warning(
                        f"DRAKVUF output inactive for {inactive_duration} - possible VM crash"
                    )
                    last_activity_time = time.time()
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Watchdog error: {e}")


# A guest whose vCPUs accrue no CPU time for this long is stalled. Seen with
# apimon on this host: DRAKVUF stays alive in poll() while every vCPU waits, so
# without this the analysis runs out its timeout with a silently truncated log.
# Healthy guests (idle or under DRAKVUF) never went more than ~2 s without CPU
# progress; staying under the evasion verifier's 30 s guest-command budget means a
# freeze is flagged before a timed-out probe is mistaken for a tool verdict.
VM_STALL_THRESHOLD_S = 20
VM_STALL_INTERVAL_S = 2.0


def xl_cpu_time(vm_name: str) -> Optional[float]:
    try:
        out = subprocess.run(
            ["xl", "list", vm_name], capture_output=True, text=True, timeout=10
        ).stdout
        return float(out.splitlines()[1].split()[5])
    except (subprocess.SubprocessError, OSError, IndexError, ValueError):
        return None


class StallMonitor:
    def __init__(
        self,
        vm_name: str,
        threshold_s: float = VM_STALL_THRESHOLD_S,
        interval_s: float = VM_STALL_INTERVAL_S,
        read_cpu_time: Callable[[str], Optional[float]] = xl_cpu_time,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.vm_name = vm_name
        self.threshold_s = threshold_s
        self.interval_s = interval_s
        self._read_cpu_time = read_cpu_time
        self._clock = clock
        self._last_cpu: Optional[float] = None
        self._progress_at = 0.0
        self.max_stall_s = 0.0
        self.stalled = False
        # Set by run_drakvuf: stop DRAKVUF instead of waiting out the timeout.
        self.on_stall: Optional[Callable[[], None]] = None

    def sample(self) -> None:
        cpu = self._read_cpu_time(self.vm_name)
        now = self._clock()
        if cpu is None:
            return
        if self._last_cpu is None or cpu > self._last_cpu:
            self._last_cpu, self._progress_at = cpu, now
            return
        stall = now - self._progress_at
        self.max_stall_s = max(self.max_stall_s, stall)
        if stall >= self.threshold_s and not self.stalled:
            self.stalled = True
            logger.warning(
                f"{self.vm_name}: no guest CPU progress for {stall:.0f} s, stopping DRAKVUF"
            )
            if self.on_stall is not None:
                self.on_stall()

    def run(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(timeout=self.interval_s):
            try:
                self.sample()
            except Exception as e:
                logger.debug(f"Stall monitor error: {e}")


@contextlib.contextmanager
def run_drakvuf(
    vm_name: str,
    vmi_info: VmiInfo,
    kernel_profile_path: str,
    output_file: pathlib.Path,
    output_err_file: pathlib.Path,
    drakvuf_args: List[str],
    drakvuf_version_info: DrakvufVersionInfo,
    exec_parameters: Optional[ExecParameters] = None,
    drakvuf_cwd: Optional[pathlib.Path] = None,
    fast_singlestep: bool = True,
    stall_monitor: Optional[StallMonitor] = None,
):
    drakvuf_cmdline = get_base_drakvuf_cmdline(
        vm_name,
        kernel_profile_path,
        vmi_info=vmi_info,
        drakvuf_version_info=drakvuf_version_info,
        extra_args=drakvuf_args,
        fast_singlestep=fast_singlestep,
        **(
            dict(
                exec_cmd=exec_parameters.command,
                shellexec_args=exec_parameters.shellexec_args,
                start_method=exec_parameters.start_method,
                working_dir=exec_parameters.working_dir,
            )
            if exec_parameters
            else {}
        ),
    )

    stop_watchdog = threading.Event()
    watchdog_thread = threading.Thread(
        target=log_activity_watchdog,
        args=(output_file, stop_watchdog),
        daemon=True,
        name="drakvuf-watchdog",
    )
    watchdog_thread.start()
    stall_thread = None

    try:
        with output_file.open("wb") as output, output_err_file.open("wb") as output_err:
            drakvuf = subprocess.Popen(
                drakvuf_cmdline, stdout=output, stderr=output_err, cwd=drakvuf_cwd
            )
            if stall_monitor is not None:
                stall_monitor.on_stall = drakvuf.terminate
                stall_thread = threading.Thread(
                    target=stall_monitor.run,
                    args=(stop_watchdog,),
                    daemon=True,
                    name="drakvuf-stall-monitor",
                )
                stall_thread.start()
            with process_graceful_exit(drakvuf):
                yield drakvuf
    finally:
        stop_watchdog.set()
        watchdog_thread.join(timeout=1)
        if stall_thread is not None:
            stall_thread.join(timeout=1)


@contextlib.contextmanager
def vm_lock(vm_id: int, lock_dir: Optional[pathlib.Path] = None):
    """
    Exclusive per-VM lock shared by every worker type (analysis, evasion).
    flock() is released by the kernel when the holder dies, so a crashed
    worker can't leave the VM locked.
    """
    lock_dir = lock_dir or RUN_DIR
    lock_dir.mkdir(parents=True, exist_ok=True)
    with (lock_dir / f"vm-{vm_id}.lock").open("w") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"vm-{vm_id} is already in use by another worker")
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


@contextlib.contextmanager
def run_vm(
    vm_id: int,
    install_info: InstallInfo,
    network_conf: NetworkConfigSection,
    no_restore: bool = False,
    while_paused: Optional[Callable[[VirtualMachine], None]] = None,
):
    """
    Restores the VM and yields it running. while_paused, if given, is called with the restored
    VM before it first runs (the clock speed-up must be in place before the guest reads its TSC).
    """
    vm = VirtualMachine(vm_id, install_info, network_conf)
    with vm_lock(vm_id):
        if no_restore:
            if not vm.is_running:
                raise RuntimeError(f"Virtual machine {vm.vm_name} is not running")
            yield vm
        else:
            try:
                # Reclaim a stale domain from a previous worker before asking
                # Xen for enough memory to restore this slot again.
                if vm.is_running:
                    vm.destroy()
                # restore() is inside the try: a failed restore can leave a
                # half-created domain or the network up, and must be torn down.
                with memory_admission(
                    install_info.memory, load_config().worker, lock_dir=RUN_DIR
                ) as waited:
                    if while_paused is None:
                        vm.restore()
                    else:
                        vm.restore(pause=True)
                if while_paused is not None:
                    while_paused(vm)
                    xen_unpause_vm(vm.vm_name)
                if waited >= 1:
                    job = get_current_job()
                    if job is not None:
                        job.meta["memory_admission_wait_seconds"] = round(waited, 3)
                        job.save_meta()
                yield vm
            finally:
                vm.destroy()


@contextlib.contextmanager
def run_screenshotter(
    vm_id: int,
    install_info: InstallInfo,
    output_dir: pathlib.Path,
    enabled: bool = True,
    settings: Optional[ScreenshotConfigSection] = None,
):
    if not enabled:
        yield
        return
    settings = settings or ScreenshotConfigSection()
    screenshotter = Screenshotter(
        output_dir=output_dir,
        vnc_host="localhost",
        vnc_port=5900 + vm_id,
        vnc_password=install_info.vnc_passwd,
        loop_interval=settings.interval_s,
        max_screenshots=settings.max_screenshots,
        diff_threshold=settings.diff_threshold,
        heartbeat_interval=settings.heartbeat_s,
    )
    try:
        screenshotter.start()
        yield
    finally:
        screenshotter.stop()
