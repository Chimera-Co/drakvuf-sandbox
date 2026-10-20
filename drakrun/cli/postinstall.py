import logging

import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH
from drakrun.lib.vm import VirtualMachine
from drakrun.lib.vmi_profile import create_vmi_info, create_vmi_json_profile

from .check_root import check_root

log = logging.getLogger(__name__)


@click.command(help="Finalize VM installation")
@click.option(
    "--guest-os",
    "guest_os",
    type=click.Choice(["windows", "linux"]),
    default="windows",
    show_default=True,
    help="Guest operating system",
)
@click.option(
    "--settle",
    "settle_s",
    default=120,
    type=int,
    show_default=True,
    help="Linux only: seconds to let the desktop settle before the snapshot",
)
@check_root
def postinstall(guest_os, settle_s):
    config = load_config()
    if guest_os == "linux":
        from drakrun.lib.linux_install import postinstall_linux

        log.info("Linux snapshot done: %s", postinstall_linux(config.network, settle_s))
        log.info("All right, VM setup is done.")
        return
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm0 = VirtualMachine(0, install_info, config.network)

    if vm0.is_running is False:
        log.error("vm-0 is not running")
        raise click.Abort()

    vm0.eject_cd()
    vmi_info = create_vmi_info(vm0)
    vm0.save()
    vm0.storage.snapshot_vm0_volume()

    vm1 = VirtualMachine(1, install_info, config.network)
    vm1.restore()
    try:
        create_vmi_json_profile(vm1, vmi_info)
    finally:
        vm1.destroy()
    log.info("All right, VM setup is done.")
