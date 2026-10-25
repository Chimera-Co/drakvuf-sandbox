import logging
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

PROC_PATH = Path("/proc")
# Grace period for a device model to exit on its own after `xl destroy`.
DEVICE_MODEL_EXIT_GRACE = 5.0


def xen_is_vm_running(vm_name: str) -> bool:
    result = subprocess.run(["xl", "list", vm_name], capture_output=True)
    if result.returncode == 0:
        return True
    elif b"is an invalid domain identifier" in result.stderr:
        return False
    else:
        raise RuntimeError(f"Unexpected xl list output: {result.stderr}")


def xen_create_vm(
    vm_name: str,
    config_path: str,
    pause: bool = False,
    timeout: Optional[float] = None,
) -> None:
    try:
        subprocess.run(
            ["xl", "create", *(["-p"] if pause else []), config_path],
            check=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to launch VM {vm_name}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Failed to launch VM {vm_name} within {timeout} seconds")


def xen_unpause_vm(vm_name: str, timeout: Optional[float] = None) -> None:
    try:
        subprocess.run(["xl", "unpause", vm_name], check=True, timeout=timeout)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to unpause VM {vm_name}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Failed to unpause VM {vm_name} within {timeout} seconds")


def xen_restore_vm(
    vm_name: str,
    config_path: str,
    snapshot_path: str,
    pause: bool = False,
) -> None:
    try:
        subprocess.run(
            ["xl", "restore", *(["-p"] if pause else []), config_path, snapshot_path],
            check=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to restore VM {vm_name}")


def xen_save_vm(
    vm_name: str,
    snapshot_path: str,
    pause: bool = False,
) -> None:
    try:
        subprocess.run(
            ["xl", "save", *(["-p"] if pause else []), vm_name, snapshot_path],
            check=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to save VM {vm_name}")


def xen_destroy_vm(vm_name: str) -> None:
    try:
        domid: Optional[int] = xen_get_domid(vm_name)
    except (subprocess.CalledProcessError, ValueError):
        domid = None
    try:
        subprocess.run(["xl", "destroy", vm_name], check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to destroy VM {vm_name}")
    if domid is not None:
        reap_device_models(domid)


def _iter_process_cmdlines() -> Iterator[Tuple[int, List[str]]]:
    for entry in PROC_PATH.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if raw:
            yield int(entry.name), raw.rstrip(b"\0").decode(errors="replace").split(
                "\0"
            )


def find_device_models() -> Dict[int, int]:
    """Returns {pid: domid} for every running Xen qemu device model."""
    result = {}
    for pid, argv in _iter_process_cmdlines():
        if not os.path.basename(argv[0]).startswith("qemu-system"):
            continue
        try:
            idx = argv.index("-xen-domid")
            result[pid] = int(argv[idx + 1])
        except (ValueError, IndexError):
            continue
    return result


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_exit(pids: List[int], timeout: float) -> List[int]:
    deadline = time.monotonic() + timeout
    remaining = [pid for pid in pids if _pid_alive(pid)]
    while remaining and time.monotonic() < deadline:
        time.sleep(0.2)
        remaining = [pid for pid in remaining if _pid_alive(pid)]
    return remaining


def reap_device_models(domid: int, grace: float = DEVICE_MODEL_EXIT_GRACE) -> List[int]:
    """
    Make sure no qemu device model of a destroyed domain survives.

    `xl destroy` only asks the device model to quit. A qemu whose main loop is
    stuck (seen after the screenshotter's VNC connection is closed) ignores it,
    keeps the domain in the "dying" state and holds the VNC port, so the next
    restore of the same VM fails with "Address already in use".
    Returns the pids that had to be killed.
    """
    if domid == 0:
        # qemu with -xen-domid 0 is dom0's own disk backend
        return []
    pids = [pid for pid, dm_domid in find_device_models().items() if dm_domid == domid]
    stuck = _wait_for_exit(pids, grace)
    for pid in stuck:
        log.warning(
            "Device model (pid %d) of domain %d did not exit, killing it", pid, domid
        )
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    still_alive = _wait_for_exit(stuck, grace)
    if still_alive:
        raise RuntimeError(
            f"Device model(s) {still_alive} of domain {domid} survived SIGKILL"
        )
    return stuck


def xen_list_domains() -> Dict[int, Tuple[str, str]]:
    """Returns {domid: (name, state)} parsed from `xl list`."""
    output = subprocess.check_output(["xl", "list"], text=True)
    domains = {}
    for line in output.strip().splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        # name may be "(null)" for dying domains; state is the 5th-from-last column
        name, domid, state = fields[0], int(fields[1]), fields[4]
        domains[domid] = (name, state)
    return domains


def reap_orphaned_device_models() -> List[int]:
    """
    Kills device models whose domain no longer exists or is dying.
    Called before a restore so a leftover qemu can't block the VM's VNC port.
    """
    live: Set[int] = {
        domid for domid, (_, state) in xen_list_domains().items() if "d" not in state
    }
    killed = []
    for domid in sorted(set(find_device_models().values())):
        if domid != 0 and domid not in live:
            log.warning("Found orphaned device model of domain %d", domid)
            killed.extend(reap_device_models(domid, grace=0))
    return killed


def xen_get_domid(vm_name: str) -> int:
    output = subprocess.check_output(["xl", "domid", vm_name], text=True)
    return int(output.strip())


def parse_xen_commandline(xen_commandline: str) -> Dict[str, str]:
    opts = xen_commandline.split(" ")
    elements = {}
    for opt in opts:
        if not opt.strip():
            continue

        if "=" not in opt:
            elements[opt] = "1"
        else:
            k, v = opt.split("=", 1)
            elements[k] = v

    return elements


def get_xen_info() -> Dict[str, str]:
    xl_info_out = subprocess.check_output(["xl", "info"], text=True)
    xl_info_lines = xl_info_out.strip().split("\n")

    elements = {}
    for line in xl_info_lines:
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        elements[k] = v
    return elements


def xen_insert_cd(domain, drive, iso):
    subprocess.run(["xl", "cd-insert", domain, drive, iso], check=True)


def xen_eject_cd(domain, drive):
    subprocess.run(["xl", "cd-eject", domain, drive], check=True)
