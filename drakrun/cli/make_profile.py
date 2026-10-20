import logging

import click

from drakrun.lib.config import load_config
from drakrun.lib.drakshell import Drakshell
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_INFO_PATH
from drakrun.lib.vm import VirtualMachine
from drakrun.lib.vmi_profile import create_vmi_info, create_vmi_json_profile

from .check_root import check_root

log = logging.getLogger(__name__)


@click.command(help="Make VMI profile")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
@click.option(
    "--no-restore",
    is_flag=True,
    show_default=True,
    default=False,
    help="Don't restore VM before making profile and don't destroy after, assume it's already running",
)
@click.option(
    "--guest-os",
    "guest_os",
    type=click.Choice(["windows", "linux"]),
    default="windows",
    show_default=True,
    help="Guest operating system",
)
@click.option(
    "--debug-package",
    "debug_package",
    type=click.Path(exists=True),
    default=None,
    help="Linux only: Debian linux-image-<version>-dbg .deb of the guest kernel",
)
@check_root
def make_profile(vm_id, no_restore, guest_os, debug_package):
    if guest_os == "linux":
        import pathlib

        from drakrun.lib.linux_install import make_linux_profile

        if debug_package is None:
            raise click.UsageError("--debug-package is required for --guest-os linux")
        log.info("Profile successfully created: %s", make_linux_profile(pathlib.Path(debug_package)))
        return
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)

    vm = VirtualMachine(vm_id, install_info, config.network)
    if not no_restore:
        vm.restore()
    try:
        vmi_info = create_vmi_info(vm, with_drakshell=False)
        if vmi_info.inject_tid:
            try:
                drakshell = Drakshell(vm.vm_name)
                drakshell.connect()
                drakshell_info = drakshell.get_info()
                assert (
                    drakshell_info["pid"] == vmi_info.inject_pid
                    or drakshell_info["tid"] == vmi_info.inject_tid
                )
            except Exception as e:
                log.warning(
                    "Drakshell is not running or has incorrect state. Removing inject_tid. "
                    "Consider making a new vm0 snapshot using modify-vm0 utility.",
                    exc_info=e,
                )
                vmi_info.inject_tid = None
                VMI_INFO_PATH.write_text(vmi_info.to_json(indent=4))

        create_vmi_json_profile(vm, vmi_info)
    finally:
        if not no_restore:
            vm.destroy()
    log.info("Profile successfully created")
