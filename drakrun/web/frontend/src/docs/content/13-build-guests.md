---
title: 5. Guest images
group: Build from scratch
---
# Build step 5: guest images

Each guest type has a **golden image** `vm-0`: installed once, prepared, snapshotted. Analyses restore copies of
it as `vm-1`, `vm-2`, …

## Windows 10

### Install

Download a Windows 10 22H2 x64 ISO to dom0 and start the installation. Give the guest the size the hardening
needs (4 vCPUs, more than 4 GiB):

```bash
drakrun install --vcpus 4 --memory 5120 ./Win10_22H2.iso
```

This writes `/etc/drakrun/config.toml`, `/etc/drakrun/install.json` and the xl template, and boots `vm-0`. Connect
a VNC client to display `:0` (port 5900) through an SSH tunnel and install Windows; the VNC password is in
`install.json`. If the guest does not start, look in `/var/log/xen/` (files ending in `vm-0.log`); if dom0 is
short of memory, lower `--memory`.

### First snapshot and VMI profile

Log in to the desktop, then:

```bash
drakrun postinstall
```

It reads the kernel's VMI information, injects the drakshell helper, saves the snapshot, restores `vm-1` from it
and builds the DLL profiles.

### Prepare the guest

```bash
drakrun modify-vm0 begin       # restore vm-0 for changes; connect with VNC again
drakrun mount /path/to/software.iso   # optional: a CD with installers
```

In the session:

- turn off User Account Control and Windows Defender (Defender re-enables itself unless its policy values are
  set, so check after every reboot);
- install the Visual C++ redistributables and .NET Framework versions, run `ngen.exe executeQueuedItems` for both
  frameworks, start PowerShell once;
- make the machine look used: everyday applications, documents with old dates, browser history, a desktop that
  is not empty;
- leave Explorer running as a normal session: its parent should be `winlogon`, it must not be inside a job
  object, and its DLL directory should be empty. Applications that restart Explorer (cloud-sync clients,
  scheduled tasks) change the parent the sample inherits.

Then save it, or throw the changes away:

```bash
drakrun modify-vm0 commit      # or: drakrun modify-vm0 rollback
```

### Hardened guest template

The VM's hardware identity is set in `/etc/drakrun/cfg.template` (regenerated into each `vm-N.cfg` on restore).
The relevant keys, with neutral example values:

```text
firmware_override = "/usr/local/lib/xen/boot/hvmloader-chimera-acpi"
xen_platform_pci = 0
vif = [ 'type=ioemu,model=e1000,mac=<vendor OUI>:xx:xx:0{{ VM_ID }},bridge={{ BRIDGE_NAME }}' ]
smbios = [ "bios_vendor=…", "bios_version=…", "system_manufacturer=…", "system_product_name=…",
           "baseboard_manufacturer=…" ]
device_model_args_hvm = [ "-global", "ide-hd.model=<a real disk model>" ]
```

Delete the default `audio = 1` and `soundhw='hda'` lines. Keep `altp2m = 2` (DRAKVUF's external altp2m mode)
and `cpuid="host,htt=0"`. Use your own plausible values; never copy another machine's serial numbers.

The `firmware_override` line uses an `hvmloader` whose ACPI tables carry the host's OEM IDs instead of "Xen":

```bash
/opt/chimera/src/scripts/chimera/arms/build-hvmloader-acpi.sh /var/tmp/xen-4.19.2-hvmloader-acpi
```

ACPI tables are created at boot, so after changing the firmware, **cold-boot** `vm-0` (`modify-vm0 begin` after a
fresh install, or `xl create` of its config) and commit a new snapshot; restored snapshots keep the tables they
booted with.

### Arms

`scripts/chimera/arms/chimera-arm` keeps several complete guest states side by side in
`/var/lib/chimera-arms/<ARM>/` (golden disk, snapshot, profiles, install information, template) and points
drakrun's paths at one of them:

```bash
chimera-arm init A0          # first time: move the live files into arm A0
chimera-arm clone A0 H1      # full copy (the golden disk is large)
chimera-arm use H1
drakrun modify-vm0 begin     # harden, then commit
chimera-arm adopt            # after a commit: move the new snapshot back into the arm
chimera-arm status
```

### Runtime hardening

Add the CPUID and human-input plugins in `/etc/drakrun/config.toml`:

```toml
[drakrun]
plugins = ["apimon", "clipboardmon", "exmon", "filetracer", "memdump", "procmon", "regmon",
           "socketmon", "tlsmon", "cpuidmon", "hidsim"]
extra_drakvuf_args = { "-s" = true, "--hid-random-clicks" = true }
```

## Linux (Debian 12 desktop)

The Linux golden image is built from Debian's official cloud image by `drakrun/data/linux/build-image.sh` (an
XFCE desktop with autologin to an ordinary user, Firefox ESR, LibreOffice, a lived-in home directory; noisy
timers masked). The kernel profile must match the guest kernel exactly.

```bash
# kernel profile from the debug package of the guest kernel (once per kernel)
drakrun make-profile --guest-os linux --debug-package linux-image-<version>-amd64-dbg_<version>_amd64.deb
# build vm-0.img from the cloud image and boot vm-0 (VNC :5900 shows the desktop)
drakrun install --guest-os linux debian-12-nocloud-amd64.qcow2
# settle, clean up, save the snapshot, check that vm-1 restores from it
drakrun postinstall --guest-os linux
# later changes, like modify-vm0 on Windows
drakrun modify-vm0 begin --guest-os linux
drakrun modify-vm0 commit --guest-os linux
```

The image build refuses to continue if apt changed the kernel, and `postinstall` checks `uname -r` before saving.

| | Windows | Linux |
|---|---|---|
| Install information | `/etc/drakrun/install.json` | `/var/lib/drakrun/linux/golden/install.json` |
| Golden disk and snapshot | `/var/lib/drakrun/volumes/` | `/var/lib/drakrun/linux/golden/` |
| xl template | `/etc/drakrun/cfg.template` | `/etc/drakrun/cfg-linux.template` |
| Kernel profile | PDB symbols (`drakrun postinstall`) | dwarf2json (`drakrun make-profile --guest-os linux`) |

## Check a guest by hand

```bash
drakrun vm-start                              # restores vm-1; VNC display :1
$(drakrun drakvuf-cmdline) -a procmon         # a stream of JSON process events
drakrun vm-stop
```

Next: [workers and services](build-services.md).
