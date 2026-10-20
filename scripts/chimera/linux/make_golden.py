"""Make the Linux golden snapshot: cold-boot the image built by build-linux-image.sh, let it settle, save it.

    sudo /opt/chimera/venv/bin/python scripts/chimera/linux/make_golden.py [--image IMG] [--vm-id 2] [--settle 90]

Golden directory (InstallInfo.snapshot_dir, /var/lib/drakrun/linux/golden):
    install.json   InstallInfo for the Linux guest (template /etc/drakrun/cfg-linux.template, 2 vCPU, 2 GiB)
    vm-0.img       the disk; analyses run on qcow2 overlays of it, so it must not change after the save
    snapshot.sav   the memory snapshot, taken with the agent running
    kernel.json    DRAKVUF/LibVMI profile of the guest kernel
The previous vm-0.img/snapshot.sav are kept as *.prev.
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))

from drakrun.lib.config import load_config  # noqa: E402
from drakrun.lib.install_info import InstallInfo  # noqa: E402
from drakrun.lib.linux_agent import LinuxAgent  # noqa: E402
from drakrun.lib.vm import VirtualMachine  # noqa: E402

GOLDEN = pathlib.Path("/var/lib/drakrun/linux/golden")


class GoldenStorage:
    """Cold boot straight from the golden vm-0.img (not an overlay)."""

    def __init__(self, image: pathlib.Path):
        self.image = image

    def get_vm_disk_path(self, vm_id):
        return f"tap:qcow2:{self.image},xvda,w"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="/var/lib/drakrun/linux/img/chimera-linux-base.qcow2")
    parser.add_argument("--vm-id", type=int, default=2)
    parser.add_argument("--settle", type=int, default=90, help="seconds to wait after the agent answers")
    args = parser.parse_args()

    install_info = InstallInfo.load(GOLDEN / "install.json")
    for name in ("vm-0.img", "snapshot.sav"):
        if (GOLDEN / name).exists():
            (GOLDEN / name).replace(GOLDEN / f"{name}.prev")
    disk = GOLDEN / "vm-0.img"
    subprocess.run(["cp", "--sparse=always", args.image, disk], check=True)

    vm = VirtualMachine(args.vm_id, install_info, load_config().network)
    vm.storage = GoldenStorage(disk)
    vm.destroy()
    vm.create()
    sock = f"/var/run/drakrun/{vm.vm_name}.sock"
    with LinuxAgent(sock) as agent:
        print("agent", json.dumps(agent.wait_ready(180)))
        print("net", json.dumps(agent.call("net", {"timeout": 60}, timeout=90)))
        print(f"settling {args.settle} s")
        time.sleep(args.settle)
        out = agent.call("sh", {"cmd": (
            "rm -rf /opt/chimera/work/* /opt/chimera/work/.chimera-*; "
            "journalctl --rotate >/dev/null 2>&1; journalctl --vacuum-time=1s >/dev/null 2>&1; "
            "systemctl list-timers --no-pager; systemctl --failed --no-pager; uname -r; sync"
        )}, timeout=60)
        print(out["stdout"])
    subprocess.run(["xl", "save", vm.vm_name, str(GOLDEN / "snapshot.sav")], check=True)
    vm.destroy()
    print("saved", GOLDEN / "snapshot.sav")


if __name__ == "__main__":
    main()
