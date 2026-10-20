"""Linux guest lifecycle for the drakrun install / postinstall / modify-vm0 / make-profile commands.

The Windows guest is installed from an ISO by hand and snapshotted by `drakrun postinstall`. The Linux guest
follows the same steps with the same VirtualMachine and storage code (qcow2 vm-0.img + snapshot.sav in
snapshot_dir), except that its disk is built from the official Debian 12 cloud image by a script
(data/linux/build-image.sh) and its kernel profile comes from Debian's debug package (dwarf2json):

    drakrun install --guest-os linux debian-12-nocloud-amd64.qcow2   build vm-0.img, boot vm-0
    drakrun postinstall --guest-os linux                             clean up, save snapshot.sav, test vm-1
    drakrun modify-vm0 begin|commit|rollback --guest-os linux        change the golden image
    drakrun make-profile --guest-os linux --debug-package X.deb      kernel.json for DRAKVUF
"""
import json
import logging
import pathlib
import secrets
import shutil
import string
import subprocess
import tempfile
import time
from typing import Any, Dict, Optional

from .config import NetworkConfigSection
from .install_info import InstallInfo
from .linux_agent import LinuxAgent
from .linux_profile import flatten
from .paths import PACKAGE_DATA_PATH
from .vm import VirtualMachine

log = logging.getLogger(__name__)

LINUX_DATA_PATH = PACKAGE_DATA_PATH / "linux"
LINUX_GOLDEN_DIR = pathlib.Path("/var/lib/drakrun/linux/golden")
LINUX_INSTALL_INFO_PATH = LINUX_GOLDEN_DIR / "install.json"
LINUX_CFG_TEMPLATE = pathlib.Path("/etc/drakrun/cfg-linux.template")
LINUX_KERNEL = "6.1.0-54-amd64"
# Desktop user created by data/linux/desktop.sh
DESKTOP_USER = "arjun"
DEFAULT_VCPUS = 4
DEFAULT_MEMORY = 4096
DEFAULT_DISK_SIZE = "20G"
# Profile structs whose anonymous members DRAKVUF needs by name (see linux_profile.py)
FLATTEN_STRUCTS = ["iov_iter"]


def agent_for(vm: VirtualMachine) -> LinuxAgent:
    return LinuxAgent(f"/var/run/drakrun/{vm.vm_name}.sock")


def prepare_for_snapshot(agent: LinuxAgent) -> Dict[str, Any]:
    """Leave nothing of the setup work in the image: work directory, journal, pending writes."""
    out = agent.call("sh", {"cmd": (
        "rm -rf /opt/chimera/work/* /opt/chimera/work/.chimera-*; "
        "journalctl --rotate >/dev/null 2>&1; journalctl --vacuum-time=1s >/dev/null 2>&1; "
        "systemctl --failed --no-legend --no-pager; uname -r; sync"
    ), "timeout": 60}, timeout=90)
    lines = out["stdout"].strip().splitlines()
    return {"kernel": lines[-1].strip() if lines else None, "failed_units": lines[:-1]}


def install_cfg_template() -> None:
    if not LINUX_CFG_TEMPLATE.exists():
        shutil.copy(LINUX_DATA_PATH / "cfg-linux.template", LINUX_CFG_TEMPLATE)


def install_linux(
    source_image: Optional[pathlib.Path],
    network_conf: NetworkConfigSection,
    vcpus: int = DEFAULT_VCPUS,
    memory: int = DEFAULT_MEMORY,
    disk_size: str = DEFAULT_DISK_SIZE,
    profile: str = "desktop",
    built_image: Optional[pathlib.Path] = None,
) -> InstallInfo:
    """Write install.json, build vm-0.img from the cloud image (or take an already built one), boot vm-0."""
    LINUX_GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    install_cfg_template()
    previous = InstallInfo.load(LINUX_INSTALL_INFO_PATH) if LINUX_INSTALL_INFO_PATH.exists() else None
    vnc_passwd = previous.vnc_passwd if previous else "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    install_info = InstallInfo(
        vcpus=vcpus, memory=memory, storage_backend="qcow2", disk_size=disk_size, vnc_passwd=vnc_passwd,
        xl_cfg_template=LINUX_CFG_TEMPLATE.as_posix(), snapshot_dir=LINUX_GOLDEN_DIR.as_posix(),
    )
    vm0 = VirtualMachine(0, install_info, network_conf)
    vm0.destroy()
    for name in ("vm-0.img", "snapshot.sav"):
        if (LINUX_GOLDEN_DIR / name).exists():
            (LINUX_GOLDEN_DIR / name).replace(LINUX_GOLDEN_DIR / f"{name}.prev")
    disk = LINUX_GOLDEN_DIR / "vm-0.img"
    if built_image is not None:
        subprocess.run(["cp", "--sparse=always", built_image.as_posix(), disk.as_posix()], check=True)
    else:
        subprocess.run(
            ["bash", (LINUX_DATA_PATH / "build-image.sh").as_posix(), source_image.as_posix(), disk.as_posix()],
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SIZE": disk_size, "PROFILE": profile}, check=True,
        )
    install_info.save(LINUX_INSTALL_INFO_PATH)
    LINUX_INSTALL_INFO_PATH.chmod(0o600)
    vm0.create()
    with agent_for(vm0) as agent:
        info = agent.wait_ready(300)
    log.info("vm-0 is up: %s", info)
    return install_info


def postinstall_linux(network_conf: NetworkConfigSection, settle_s: int = 120) -> Dict[str, Any]:
    """Settle, clean up and save vm-0 as the golden snapshot, then check that vm-1 restores from it."""
    install_info = InstallInfo.load(LINUX_INSTALL_INFO_PATH)
    vm0 = VirtualMachine(0, install_info, network_conf)
    if not vm0.is_running:
        raise RuntimeError("vm-0 is not running")
    with agent_for(vm0) as agent:
        agent.wait_ready(60)
        agent.call("net", {"timeout": 60}, timeout=90)
        log.info("Letting the desktop settle for %d s", settle_s)
        time.sleep(settle_s)
        state = prepare_for_snapshot(agent)
    if state["kernel"] != LINUX_KERNEL:
        raise RuntimeError(f"Guest kernel {state['kernel']} does not match the profile ({LINUX_KERNEL})")
    vm0.save()
    vm0.storage.snapshot_vm0_volume()
    check_kernel_profile()
    return {**state, "restore_check": check_restore(install_info, network_conf)}


def check_restore(install_info: InstallInfo, network_conf: NetworkConfigSection) -> Dict[str, Any]:
    vm1 = VirtualMachine(1, install_info, network_conf)
    started = time.monotonic()
    vm1.restore()
    try:
        with agent_for(vm1) as agent:
            pong = agent.wait_ready(60)
        return {"restore_s": round(time.monotonic() - started, 2), "agent": pong}
    finally:
        vm1.destroy()


def begin_modify(network_conf: NetworkConfigSection, cold_boot: bool = False) -> InstallInfo:
    install_info = InstallInfo.load(LINUX_INSTALL_INFO_PATH)
    VirtualMachine(0, install_info, network_conf).restore(cold_boot=cold_boot)
    return install_info


def commit_modify(network_conf: NetworkConfigSection) -> Dict[str, Any]:
    install_info = InstallInfo.load(LINUX_INSTALL_INFO_PATH)
    vm0 = VirtualMachine(0, install_info, network_conf)
    with agent_for(vm0) as agent:
        agent.wait_ready(60)
        state = prepare_for_snapshot(agent)
    temporary = pathlib.Path(tempfile.gettempdir()) / "linux-snapshot.sav"
    target = LINUX_GOLDEN_DIR / "snapshot.sav"
    try:
        vm0.save(temporary.as_posix())
        vm0.storage.commit_vm0_modify_storage()
        if target.exists():
            target.replace(LINUX_GOLDEN_DIR / "snapshot.sav.prev")
        shutil.move(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return {**state, "restore_check": check_restore(install_info, network_conf)}


def rollback_modify(network_conf: NetworkConfigSection) -> None:
    install_info = InstallInfo.load(LINUX_INSTALL_INFO_PATH)
    vm0 = VirtualMachine(0, install_info, network_conf)
    vm0.destroy()
    vm0.storage.delete_vm0_modify_storage()


def make_linux_profile(debug_package: pathlib.Path, dwarf2json: str = "dwarf2json") -> pathlib.Path:
    """kernel.json for DRAKVUF from Debian's linux-image-<version>-dbg package."""
    LINUX_GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["dpkg-deb", "-x", debug_package.as_posix(), tmp], check=True)
        vmlinux = next(pathlib.Path(tmp).glob("usr/lib/debug/boot/vmlinux-*"))
        original = LINUX_GOLDEN_DIR / "kernel.orig.json"
        with original.open("wb") as out:
            subprocess.run([dwarf2json, "linux", "--elf", vmlinux.as_posix()], stdout=out, check=True)
    profile = json.loads(original.read_text())
    added = flatten(profile, FLATTEN_STRUCTS)
    target = LINUX_GOLDEN_DIR / "kernel.json"
    target.write_text(json.dumps(profile))
    log.info("Linux profile %s (%d anonymous members exposed)", target, added)
    return target


def check_kernel_profile() -> None:
    profile = LINUX_GOLDEN_DIR / "kernel.json"
    if not profile.exists():
        raise RuntimeError(f"{profile} is missing: run drakrun make-profile --guest-os linux --debug-package "
                           f"linux-image-{LINUX_KERNEL}-dbg_*.deb")
