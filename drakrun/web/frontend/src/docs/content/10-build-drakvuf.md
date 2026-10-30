---
title: 2. LibVMI and DRAKVUF
group: Build from scratch
---
# Build step 2: LibVMI and DRAKVUF

CHIMERA needs these commands on the `PATH` of root: `drakvuf`, `injector`, `vmi-win-guid`, `vmi-win-offsets`
and `vmi-process-list`. They come from DRAKVUF and its bundled LibVMI.

## Get the sources

CHIMERA was measured with DRAKVUF `da982ab` (LibVMI `df8547f`, its bundled submodule); the CHIMERA patches in
`scripts/chimera/patches/` are named after these commits. The repository's `drakvuf/` submodule still pins an
older upstream commit, so build from a separate checkout:

```bash
cd /opt
git clone --recursive https://github.com/tklengyel/drakvuf
cd drakvuf
git checkout da982ab && git submodule update --init --recursive
```

## LibVMI

One patch makes LibVMI pick a usable kernel CR3 during initialisation when Windows uses kernel page-table
isolation, so profile creation does not fail on a vCPU that is running user code.

```bash
cd /opt/drakvuf/libvmi
patch -p1 < /opt/chimera/src/scripts/chimera/patches/libvmi-df8547f-pr1123-kernel-cr3.patch
autoreconf -vif
./configure --disable-kvm --disable-bareflank --disable-file
make -j"$(nproc)" && make install
ldconfig
vmi-win-guid               # prints its usage: LibVMI is installed
```

## DRAKVUF

Four DRAKVUF patches: two fix the use-after-free behind "re-copying remapped gfn" exits (the diagnostic one is
optional), one makes the Linux `syscalls` plugin print socket addresses correctly, and one adds optional sleep
shortening to the `delaymon` plugin (`--delaymon-skip-above` and `--delaymon-skip-to`, used by the upload
form's "Shorten long sleeps" option).

```bash
cd /opt/drakvuf
for p in drakvuf-da982ab-refresh-shadow-copy-stale-trap-list drakvuf-linuxnet-sockaddr \
         drakvuf-da982ab-delaymon-shorten-delays; do
    patch -p1 < /opt/chimera/src/scripts/chimera/patches/$p.patch
done
meson setup build --native-file llvm.ini
ninja -C build
install -m 755 build/drakvuf build/injector /usr/local/bin/
```

Check that both start:

```bash
drakvuf        # DRAKVUF v1.1-… No domain name specified (-d)!
injector       # prints the required input
```

## dwarf2json for Linux guests

Linux kernel profiles are generated with `dwarf2json` (shipped with DRAKVUF, a Go program):

```bash
cd /opt/drakvuf/dwarf2json && go build && install -m 755 dwarf2json /usr/local/bin/
```

## Other patches in the repository

| Patch | Status |
|---|---|
| `xen-4.19.2-altp2m-no-mapcache-invalidate.patch` | Required; applied in [step 1](build-host-xen.md) |
| `xen-4.19.2-libacpi-host-oem-ids.patch` | Hardening; built into a separate `hvmloader` in [step 5](build-guests.md) |
| `qemu-xen-8.0.5-invalidate-no-drain.patch` | An earlier stop-gap for the same freeze; not needed with the Xen patch |
| `drakvuf-da982ab-refresh-shadow-copy-diag.patch` | Optional diagnostics for the shadow-copy fix |

Next: [CHIMERA console](build-console.md).
