"""Hide Xen from a guest's CPUID outside DRAKVUF (scripts/chimera/linux/cpuid-hide/chimera-cpuid-hide.c).

DRAKVUF's `cpuidmon -s` hides the hypervisor while an analysis runs. The Linux guest also needs it while the
golden image boots, or its kernel sees Xen and shows it everywhere (/sys/hypervisor, the Xen clocksource, dmesg).
The helper is a separate process that holds the domain's monitor ring, so it must not run together with DRAKVUF
and must be stopped before `xl save`.

Ways to run it:
  - `cpuid_hidden(vm_name)`: for the length of a `with` block (attached to a running domain)
  - `attach(vm_name)` / `detach(process)`: around parts of a session, e.g. a Linux evasion scan that pauses
    hiding while the DRAKVUF injector uploads a file (the injector needs the monitor ring too)
  - `start_detached(vm_name)` / `stop_detached(vm_name)`: across commands, e.g. from `drakrun install` (vm-0
    is created paused, the helper attaches, then vm-0 is unpaused) until `drakrun postinstall` saves it
"""

import contextlib
import logging
import os
import pathlib
import signal
import subprocess
import time
from typing import Iterator, Optional

log = logging.getLogger(__name__)

CPUID_HIDE_BINARY = pathlib.Path("/usr/local/bin/chimera-cpuid-hide")
PID_DIR = pathlib.Path("/var/run/drakrun")


def available() -> bool:
    return CPUID_HIDE_BINARY.exists()


def _pid_file(vm_name: str) -> pathlib.Path:
    return PID_DIR / f"cpuid-hide-{vm_name}.pid"


def _start(vm_name: str, detached: bool) -> subprocess.Popen:
    process = subprocess.Popen(
        [CPUID_HIDE_BINARY.as_posix(), vm_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if detached else None,
        start_new_session=detached,
        text=True,
    )
    # The helper prints "ready" once the CPUID event is registered
    line = process.stdout.readline().strip()
    if line != "ready":
        process.kill()
        process.wait()
        raise RuntimeError(
            f"chimera-cpuid-hide did not attach to {vm_name} (exit {process.returncode})"
        )
    return process


def _alive(process_or_pid) -> bool:
    if isinstance(process_or_pid, subprocess.Popen):
        return process_or_pid.poll() is None
    try:
        os.kill(process_or_pid, 0)
    except ProcessLookupError:
        return False
    return True


def _stop(process_or_pid, timeout: float = 15) -> None:
    pid = (
        process_or_pid.pid
        if isinstance(process_or_pid, subprocess.Popen)
        else process_or_pid
    )
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout
    while _alive(process_or_pid):
        if time.monotonic() > deadline:
            raise RuntimeError(
                f"chimera-cpuid-hide (pid {pid}) did not stop within {timeout} s"
            )
        time.sleep(0.2)


def attach(vm_name: str) -> subprocess.Popen:
    return _start(vm_name, detached=False)


def detach(process: subprocess.Popen) -> None:
    _stop(process)
    process.wait()


@contextlib.contextmanager
def cpuid_hidden(
    vm_name: str, required: bool = False
) -> Iterator[Optional[subprocess.Popen]]:
    if not available():
        if required:
            raise RuntimeError(f"{CPUID_HIDE_BINARY} is missing")
        log.warning("%s is missing: %s sees Xen in CPUID", CPUID_HIDE_BINARY, vm_name)
        yield None
        return
    process = _start(vm_name, detached=False)
    try:
        yield process
    finally:
        _stop(process)


def start_detached(vm_name: str) -> int:
    if not available():
        raise RuntimeError(
            f"{CPUID_HIDE_BINARY} is missing (build scripts/chimera/linux/cpuid-hide)"
        )
    stop_detached(vm_name)
    process = _start(vm_name, detached=True)
    process.stdout.close()
    _pid_file(vm_name).write_text(str(process.pid))
    log.info("chimera-cpuid-hide attached to %s (pid %d)", vm_name, process.pid)
    return process.pid


def stop_detached(vm_name: str) -> None:
    pid_file = _pid_file(vm_name)
    if not pid_file.exists():
        return
    pid = int(pid_file.read_text())
    try:
        cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except FileNotFoundError:
        cmdline = []
    # Only stop the helper the pid file names, never a reused pid
    if cmdline[:2] == [CPUID_HIDE_BINARY.as_posix().encode(), vm_name.encode()]:
        _stop(pid)
        log.info("chimera-cpuid-hide detached from %s", vm_name)
    pid_file.unlink(missing_ok=True)
