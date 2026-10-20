#!/usr/bin/env python3
"""
Restore vm-<id> from the active arm's snapshot (the same run_vm/get_drakshell
path an analysis uses), run identity.ps1 in it and print its key=value report.
Pipe into check_identity.py. The VM is destroyed afterwards.

  sudo /opt/chimera/venv/bin/python scripts/chimera/arms/validate_arm.py 1 \
      | python3 scripts/chimera/arms/check_identity.py H1/cfg.template --vcpus 4 --memory 5120
"""

import argparse
import pathlib
import sys
import time

from drakrun.analyzer.run_tools import run_vm
from drakrun.lib.config import load_config
from drakrun.lib.drakshell import get_drakshell
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_INFO_PATH, VMI_KERNEL_PROFILE_PATH

IDENTITY_SCRIPT = pathlib.Path(__file__).resolve().parent / "H1" / "identity.ps1"
GUEST_PATH = r"C:\Users\Public\chimera-identity.ps1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vm_id", type=int)
    args = parser.parse_args()

    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    started = time.monotonic()
    with run_vm(args.vm_id, install_info, config.network) as vm:
        restored = time.monotonic()
        injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH.as_posix())
        shell, _ = get_drakshell(vm, injector)
        connected = time.monotonic()
        injector.write_file(str(IDENTITY_SCRIPT), GUEST_PATH)
        exit_code = shell.run_interactive(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", GUEST_PATH],
            None,
            sys.stdout,
            sys.stderr,
        ).join()
        sys.stdout.flush()
    print(
        f"restore={restored - started:.1f}s drakshell={connected - restored:.1f}s identity_exit={exit_code}",
        file=sys.stderr,
    )
    return exit_code if isinstance(exit_code, int) else 1


if __name__ == "__main__":
    sys.exit(main())
