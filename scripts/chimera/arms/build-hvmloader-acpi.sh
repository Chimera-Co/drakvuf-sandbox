#!/bin/bash
# Builds hvmloader with the host laptop's ACPI OEM IDs (patches/xen-4.19.2-libacpi-host-oem-ids.patch)
# in a copy of the configured Xen 4.19.2 tree, and installs it next to the stock one as
# /usr/local/lib/xen/boot/hvmloader-chimera-acpi. Nothing uses it until an arm's cfg.template sets
#   firmware_override = "/usr/local/lib/xen/boot/hvmloader-chimera-acpi"
# and vm-0 is cold-booted (restored snapshots keep the ACPI tables they booted with).
#
#   sudo scripts/chimera/arms/build-hvmloader-acpi.sh [/var/tmp/xen-4.19.2-hvmloader-acpi]
set -euo pipefail
SRC=/opt/xen-4.19.2
WORK=${1:-/var/tmp/xen-4.19.2-hvmloader-acpi}
PATCH=$(cd "$(dirname "$0")/../patches" && pwd)/xen-4.19.2-libacpi-host-oem-ids.patch
OUT=/usr/local/lib/xen/boot/hvmloader-chimera-acpi

[[ -e $WORK ]] && { echo "$WORK exists; pass a new directory"; exit 1; }
# The OVMF checkout (3.4 GiB), stubdom and dist are not needed for hvmloader.
mkdir -p "$WORK"
tar -C "$SRC" --exclude ./tools/firmware/ovmf-dir-remote --exclude ./stubdom --exclude ./dist -cf - . | tar -C "$WORK" -xf -
patch -d "$WORK" -p1 --forward < "$PATCH"
# Force the generated ACPI tables to be rebuilt from the patched sources.
make -C "$WORK/tools/firmware/hvmloader" clean >/dev/null
make -C "$WORK/tools/firmware/hvmloader" -j"$(nproc)"

BIN=$WORK/tools/firmware/hvmloader/hvmloader
for id in ACRSYS ACRPRDCT; do
    grep -q -a "$id" "$BIN" || { echo "built hvmloader lacks $id"; exit 1; }
done
install -m 644 "$BIN" "$OUT"
sha256sum /usr/local/lib/xen/boot/hvmloader "$OUT"
