import logging
import os.path
import secrets
import string

import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, initialize_config_files, make_dirs
from drakrun.lib.storage import REGISTERED_BACKEND_NAMES, get_storage_backend
from drakrun.lib.vm import VirtualMachine

from .banner import banner
from .check_root import check_root
from .sanity_check import sanity_check

log = logging.getLogger(__name__)


@click.command(help="Install guest Virtual Machine", no_args_is_help=True)
@click.argument("iso_path", type=click.Path(exists=True))
@click.option(
    "--guest-os",
    "guest_os",
    type=click.Choice(["windows", "linux"]),
    default="windows",
    show_default=True,
    help="Guest operating system",
)
@click.option(
    "--vcpus",
    "vcpus",
    default=None,
    type=int,
    help="Number of vCPUs per single VM  [default: 2, Linux 4]",
)
@click.option(
    "--memory",
    "memory",
    default=None,
    type=int,
    help="Memory per single VM (in MB)  [default: 4096]",
)
@click.option(
    "--linux-profile",
    "linux_profile",
    type=click.Choice(["desktop", "server"]),
    default="desktop",
    show_default=True,
    help="Linux only: desktop PC (XFCE, autologin user) or plain server image",
)
@click.option(
    "--linux-built-image",
    "linux_built_image",
    type=click.Path(exists=True),
    default=None,
    help="Linux only: use a disk already made by data/linux/build-image.sh instead of building one",
)
@click.option(
    "--storage-backend",
    "storage_backend",
    type=click.Choice(REGISTERED_BACKEND_NAMES, case_sensitive=False),
    default="qcow2",
    show_default=True,
    help="Storage backend type",
    is_eager=True,
)
@click.option(
    "--disk-size", "disk_size", default=None, help="Disk size  [default: 100G, Linux 20G]"
)
@click.option(
    "--zfs-tank-name",
    "zfs_tank_name",
    help="Tank name (only for ZFS storage backend)",
)
@click.option(
    "--lvm-volume-group",
    "lvm_volume_group",
    help="Volume group (only for lvm storage backend)",
)
@check_root
def install(
    guest_os,
    linux_profile,
    linux_built_image,
    vcpus,
    memory,
    storage_backend,
    disk_size,
    iso_path,
    zfs_tank_name,
    lvm_volume_group,
):
    if guest_os == "linux":
        install_linux_guest(iso_path, vcpus, memory, disk_size, linux_profile, linux_built_image)
        return
    vcpus = vcpus or 2
    memory = memory or 4096
    disk_size = disk_size or "100G"
    if storage_backend == "lvm" and lvm_volume_group is None:
        logging.error("lvm storage backend requires --lvm-volume-group")
        raise click.Abort()
    if storage_backend == "zfs" and zfs_tank_name is None:
        logging.error("zfs storage backend requires --zfs-tank-name")
        raise click.Abort()

    sanity_check()
    make_dirs()
    initialize_config_files()

    config = load_config()

    log.info("Performing installation...")
    passwd_characters = string.ascii_letters + string.digits
    vnc_passwd = "".join(secrets.choice(passwd_characters) for _ in range(8))
    install_info = InstallInfo(
        vcpus=vcpus,
        memory=memory,
        storage_backend=storage_backend,
        disk_size=disk_size,
        vnc_passwd=vnc_passwd,
        zfs_tank_name=zfs_tank_name,
        lvm_volume_group=lvm_volume_group,
    )
    install_info.save(INSTALL_INFO_PATH)

    backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(
        vm_id=0, install_info=install_info, network_conf=config.network
    )
    # Ensure VM0 is destroyed
    vm0.destroy()

    backend.initialize_vm0_volume(disk_size)

    iso_path = os.path.abspath(iso_path)
    vm0.create(iso_path=iso_path)

    banner(
        f"""
        Initial VM setup is complete and the vm-0 was launched.
        Please now VNC to the port 5900 on this machine to perform Windows installation.
        After you have installed Windows and booted it to the desktop, please execute:
        # drakrun postinstall
        Your configured VNC password is:
        {vnc_passwd}
        Please note that on some machines, system installer may boot for up to 10 minutes
        and may look unresponsive during the process. Please be patient.
    """
    )


def install_linux_guest(source_image, vcpus, memory, disk_size, profile, built_image):
    """The Linux guest is built from the Debian 12 cloud image instead of installed from an ISO."""
    import pathlib

    from drakrun.lib import linux_install

    sanity_check()
    make_dirs()
    initialize_config_files()
    config = load_config()
    install_info = linux_install.install_linux(
        pathlib.Path(source_image),
        config.network,
        vcpus=vcpus or linux_install.DEFAULT_VCPUS,
        memory=memory or linux_install.DEFAULT_MEMORY,
        disk_size=disk_size or linux_install.DEFAULT_DISK_SIZE,
        profile=profile,
        built_image=pathlib.Path(built_image) if built_image else None,
    )
    banner(
        f"""
        The Linux guest image is built and vm-0 is running ({install_info.vcpus} vCPU, {install_info.memory} MB).
        VNC to port 5900 on this machine to look at the desktop or change it.
        Then execute:
        # drakrun postinstall --guest-os linux
        Your configured VNC password is:
        {install_info.vnc_passwd}
    """
    )
