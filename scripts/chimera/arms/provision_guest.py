#!/usr/bin/env python3
"""
Run a provisioning PowerShell script inside vm-0 during a `drakrun modify-vm0`
session (after `begin --cold-boot`, before `commit`).

A cold-booted vm-0 has different kernel offsets and explorer PID than the
stored snapshot, so this computes fresh VMI info first (the same call
`drakrun modify-vm0 commit` makes), which also ensures drakshell is running.

  sudo /opt/chimera/venv/bin/python scripts/chimera/arms/provision_guest.py \
      scripts/chimera/arms/H1/realism.ps1

Extra files (e.g. an installer the script runs) are copied first with
--upload HOST_PATH=GUEST_PATH, which may be repeated.
"""

import argparse
import pathlib
import sys

from drakrun.lib.config import load_config
from drakrun.lib.drakshell import Drakshell
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_KERNEL_PROFILE_PATH
from drakrun.lib.vm import VirtualMachine
from drakrun.lib.vmi_profile import create_vmi_info


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("script", type=pathlib.Path)
    # The injector's writefile does not overwrite an existing guest file, so each
    # script gets its own path, and it is deleted afterwards so it isn't in the snapshot.
    parser.add_argument("--guest-path", default=None)
    parser.add_argument("--upload", action="append", default=[], metavar="HOST_PATH=GUEST_PATH")
    # Seconds per uploaded file; the injector's default of 60 is short for large installers.
    parser.add_argument("--upload-timeout", type=int, default=60)
    # Passed to the script after -File, e.g. --arg=-WhatIf (repeatable).
    parser.add_argument("--arg", action="append", default=[], dest="script_args")
    args = parser.parse_args()
    guest_path = args.guest_path or rf"C:\Users\Public\chimera-{args.script.name}"

    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm = VirtualMachine(0, install_info, config.network)
    vmi_info = create_vmi_info(vm)
    injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH.as_posix())
    for upload in args.upload:
        host_path, _, upload_guest_path = upload.partition("=")
        if not upload_guest_path:
            parser.error(f"--upload needs HOST_PATH=GUEST_PATH, got {upload!r}")
        injector.write_file(str(pathlib.Path(host_path).resolve()), upload_guest_path, timeout=args.upload_timeout)
    injector.write_file(str(args.script.resolve()), guest_path)

    shell = Drakshell(vm.vm_name)
    shell.connect(timeout=10)
    process = shell.run_interactive(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", guest_path, *args.script_args],
        None,
        sys.stdout,
        sys.stderr,
    )
    exit_code = process.join()
    shell.run_interactive(["cmd.exe", "/c", "del", "/f", "/q", guest_path], None, sys.stdout, sys.stderr).join()
    print(f"provision exit code: {exit_code}", file=sys.stderr)
    return exit_code if isinstance(exit_code, int) else 1


if __name__ == "__main__":
    sys.exit(main())
