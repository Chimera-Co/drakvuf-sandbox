---
title: 1. Host and Xen
group: Build from scratch
---
# Build step 1: the host and Xen

This guide builds a CHIMERA host from a blank machine. The steps follow the order things depend on each other:

1. Host and Xen (this page)
2. [LibVMI and DRAKVUF](build-drakvuf.md)
3. [CHIMERA console](build-console.md)
4. [Network containment](build-network.md)
5. [Guest images](build-guests.md)
6. [Workers and services](build-services.md)

## Hardware and OS

| Requirement | Why |
|---|---|
| Intel CPU with VT-x and EPT | DRAKVUF needs EPT and altp2m; AMD is not supported |
| 16 GB RAM recommended | dom0, a Windows guest (5 GB), a Linux guest (4 GB) and the static VM (3.5 GB) |
| An SSD with room for golden images | A Windows golden disk is tens of GB; each arm keeps its own copy |
| Debian 12 (bookworm), GRUB | The tested host OS; Xen is installed from source |

Check the CPU flags first:

```bash
grep -m1 -o -w -E 'vmx|ept' /proc/cpuinfo | sort -u     # both must be printed
```

Enable VT-x (and VT-d if present) in the firmware setup. Install Debian 12 with a normal user and SSH, and keep
the installation minimal; the host should run nothing but CHIMERA.

## Build dependencies

```bash
apt update
apt-get install wget git bcc bin86 gawk bridge-utils iproute2 libcurl4-openssl-dev bzip2 libpci-dev \
  build-essential make gcc clang libc6-dev linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev \
  libssl-dev libsdl1.2-dev iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml libx11-dev bison flex \
  ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev \
  autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-dev \
  python3-pip golang libsystemd-dev nasm ninja-build llvm lld meson
```

## Build Xen 4.19.2 with the CHIMERA patch

CHIMERA was measured on Xen 4.19.2 with one patch that prevents guest freezes under DRAKVUF (an altp2m trap
removal must not make QEMU invalidate its map cache). Apply it before building.

```bash
cd /opt
wget https://downloads.xenproject.org/release/xen/4.19.2/xen-4.19.2.tar.gz
tar -xzf xen-4.19.2.tar.gz && cd xen-4.19.2
patch -p1 < /opt/chimera/src/scripts/chimera/patches/xen-4.19.2-altp2m-no-mapcache-invalidate.patch

./configure --enable-githttp --enable-systemd --enable-ovmf --disable-pvshim
make -j"$(nproc)" dist-xen
make -j"$(nproc)" dist-tools
make -j"$(nproc)" debball
apt install ./dist/xen-upstream-4.19.2.deb
```

> The checkout path `/opt/chimera/src` is created in [step 3](build-console.md); clone the repository there
> first (`git clone --recurse-submodules <repository URL> /opt/chimera/src`) so the patches are available.
> If `make dist-tools` asks for Git credentials, Xen's pinned OVMF revision points at a broken submodule URL:
> set `OVMF_UPSTREAM_URL` to `https://github.com/tianocore/edk2.git` and a current stable tag in `Config.mk`.

Keep the configured Xen tree: the hardened `hvmloader` in [step 5](build-guests.md) is built from it.

## Boot options

Give dom0 a fixed amount of memory and CPUs, and turn on what DRAKVUF needs (`altp2m=1`, EPT without
large pages):

```bash
echo 'GRUB_CMDLINE_XEN_DEFAULT="dom0_mem=4096M,max:4096M dom0_max_vcpus=2 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0"' >> /etc/default/grub
echo "/usr/local/lib" > /etc/ld.so.conf.d/xen.conf && ldconfig

echo "none /proc/xen xenfs defaults,nofail 0 0" >> /etc/fstab
printf 'xen-evtchn\nxen-privcmd\nxen-gntdev\n' >> /etc/modules
systemctl enable xencommons xen-qemu-dom0-disk-backend xen-init-dom0 xenconsoled
update-grub
reboot
```

Choose the "Debian GNU/Linux, with Xen hypervisor" entry in GRUB (or make it the default with
`GRUB_DEFAULT`). Size `dom0_mem` for the host: dom0 runs the workers, Redis, the static workers' podman and the
intel database, and everything else is left to the guests.

## Check

```bash
xen-detect                 # Running in PV context on Xen V4.19.
xl list                    # Domain-0 only
xl info | grep -E 'xen_version|free_memory|cc_compile_date'
```

If Xen reports "Mitigating GDS by disabling AVX", some guest software may misbehave without AVX; the mitigation
can be turned off with `spec-ctrl=gds-mit=no` on the Xen command line if that risk is acceptable on the host.

Next: [LibVMI and DRAKVUF](build-drakvuf.md).
