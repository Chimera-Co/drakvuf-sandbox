#!/bin/bash
# Build the CHIMERA static-analysis VM: Debian 12 root image with podman, the agent and the analyzer images.
#   sudo scripts/chimera/static-vm/build-image.sh            full build (debootstrap from deb.debian.org)
#   sudo scripts/chimera/static-vm/build-image.sh --images   reload only the analyzer images (VM stopped)
# Output in /var/lib/chimera-static-vm: root.img (read-only for the guest), scratch.img, vmlinuz, initrd.img.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=/var/lib/chimera-static-vm
ROOT=$OUT/root.img
MNT=$(mktemp -d /tmp/chimera-static-root.XXXX)
IMAGES=("localhost/chimera-static:0.1.0" "localhost/chimera-ghidra:11.1.2" "localhost/chimera-mobsf:4.5.3")
MIRROR=${MIRROR:-http://deb.debian.org/debian}
mkdir -p "$OUT"
chmod 700 "$OUT"

if xl domid chimera-static >/dev/null 2>&1; then
    echo "chimera-static is running; stop it first (systemctl stop chimera-static-vm)" >&2
    exit 1
fi

cleanup() {
    for m in dev/pts dev proc sys; do umount "$MNT/$m" 2>/dev/null || true; done
    umount "$MNT" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

if [ "${1:-}" != "--images" ]; then
    rm -f "$ROOT.new"
    truncate -s 14G "$ROOT.new"
    mkfs.ext4 -q -F -L chimera-root "$ROOT.new"
    mount -o loop "$ROOT.new" "$MNT"
    debootstrap --variant=minbase bookworm "$MNT" "$MIRROR"
    for m in proc sys dev dev/pts; do mount --bind "/$m" "$MNT/$m"; done
    # podman's dependencies do not configure inside debootstrap's base stage: install them with apt.
    printf 'deb %s bookworm main\ndeb %s bookworm-updates main\ndeb http://security.debian.org/debian-security bookworm-security main\n' \
        "$MIRROR" "$MIRROR" > "$MNT/etc/apt/sources.list"
    printf 'APT::Install-Recommends "false";\nAPT::Install-Suggests "false";\n' > "$MNT/etc/apt/apt.conf.d/90chimera"
    chroot "$MNT" /bin/sh -ec '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y -q systemd-sysv udev kmod initramfs-tools linux-image-amd64 podman crun conmon \
            fuse-overlayfs python3 xenstore-utils e2fsprogs util-linux procps
    '
    echo chimera-static > "$MNT/etc/hostname"
    printf '/dev/xvda / ext4 ro,noatime 0 1\nxenfs /proc/xen xenfs defaults 0 0\n' > "$MNT/etc/fstab"
    for d in tmp var/tmp var/log var/cache; do
        printf 'tmpfs /%s tmpfs rw,nosuid,nodev,size=128m 0 0\n' "$d" >> "$MNT/etc/fstab"
    done
    mkdir -p "$MNT/work" "$MNT/proc/xen" "$MNT/etc/containers" "$MNT/usr/lib/chimera-images"
    install -m 0644 "$HERE/guest/storage.conf" "$MNT/etc/containers/storage.conf"
    install -m 0644 "$HERE/guest/containers.conf" "$MNT/etc/containers/containers.conf"
    install -m 0755 "$HERE/guest/chimera-static-agent.py" "$MNT/usr/local/sbin/chimera-static-agent"
    install -m 0644 "$HERE/guest/chimera-scratch.service" "$HERE/guest/chimera-static-agent.service" \
        "$MNT/etc/systemd/system/"
    printf 'xen_blkfront\n' >> "$MNT/etc/initramfs-tools/modules"
    systemd-machine-id-setup --root="$MNT" >/dev/null
    chroot "$MNT" /bin/sh -ec '
        passwd -l root >/dev/null
        systemctl enable chimera-scratch.service chimera-static-agent.service >/dev/null
        systemctl mask getty@.service serial-getty@.service console-getty.service getty-static.service apt-daily.timer \
            apt-daily-upgrade.timer e2scrub_all.timer fstrim.timer >/dev/null 2>&1 || true
        update-initramfs -u -k all >/dev/null
        apt-get clean
    '
    cp -L "$MNT/vmlinuz" "$OUT/vmlinuz.new"
    cp -L "$MNT/initrd.img" "$OUT/initrd.img.new"
    for m in dev/pts dev proc sys; do umount "$MNT/$m"; done
else
    # A loop device left on root.img (a desktop automount of the image, or a crashed earlier run) makes
    # mount reuse it read-only and the reload fails half way. The VM is down (checked above): release them.
    for dev in $(losetup -j "$ROOT" | cut -d: -f1); do
        for target in $(findmnt -rn -S "$dev" -o TARGET); do umount "$target"; done
        losetup -d "$dev" 2>/dev/null || true
    done
    mount -o loop "$ROOT" "$MNT"
    if findmnt -rn -M "$MNT" -o OPTIONS | grep -qw ro; then
        echo "root.img mounted read-only; a loop device on it is still in use (losetup -j $ROOT)" >&2
        exit 1
    fi
fi

# Analyzer images into the read-only additional store (same podman version and driver as the guest).
rm -rf "$MNT/usr/lib/chimera-images"
mkdir -p "$MNT/usr/lib/chimera-images"
RUNROOT=$(mktemp -d /tmp/chimera-static-run.XXXX)
for image in "${IMAGES[@]}"; do
    tar=$(mktemp /tmp/chimera-image.XXXX.tar)
    podman save -q -o "$tar" "$image"
    podman --root "$MNT/usr/lib/chimera-images" --runroot "$RUNROOT" --storage-driver overlay load -q -i "$tar"
    rm -f "$tar"
done
podman --root "$MNT/usr/lib/chimera-images" --runroot "$RUNROOT" --storage-driver overlay images
podman --root "$MNT/usr/lib/chimera-images" --runroot "$RUNROOT" --storage-driver overlay unmount -a >/dev/null 2>&1 || true
rm -rf "$RUNROOT"
sync
umount "$MNT"

if [ "${1:-}" != "--images" ]; then
    mv "$ROOT.new" "$ROOT"
    mv "$OUT/vmlinuz.new" "$OUT/vmlinuz"
    mv "$OUT/initrd.img.new" "$OUT/initrd.img"
fi
[ -f "$OUT/scratch.img" ] || truncate -s 8G "$OUT/scratch.img"
install -D -m 0644 "$HERE/chimera-static-vm.cfg" /etc/chimera/static-vm.cfg
install -m 0644 "$HERE/chimera-static-vm.service" /etc/systemd/system/chimera-static-vm.service
# On demand: static jobs boot the VM; the idle timer stops it again (see [static] vm_idle_shutdown_s).
install -m 0644 "$HERE/chimera-static-vm-idle.service" "$HERE/chimera-static-vm-idle.timer" /etc/systemd/system/
systemctl daemon-reload
echo "built $ROOT"
