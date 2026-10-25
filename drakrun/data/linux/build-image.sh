#!/bin/bash
# Build the CHIMERA Linux golden disk from the official Debian 12 "nocloud" cloud image.
# Run by `drakrun install --guest-os linux` (drakrun/lib/linux_install.py); standalone:
#
#   sudo bash build-image.sh SRC.qcow2 OUT.qcow2
#
# SRC is debian-12-nocloud-amd64.qcow2 from https://cloud.debian.org/images/cloud/bookworm/latest/
# (check it against SHA512SUMS there). Its kernel (6.1.0-54-amd64, 6.1.190-1) matches the
# linux-image-6.1.0-54-amd64-dbg package the DRAKVUF kernel profile is built from; a newer image
# needs a new profile (see docs/chimera/linux-sandbox.md).
#
# Changes to the image:
#   - grows the disk to $SIZE (default 128G; qcow2 is sparse, so this costs only what is written)
#   - PROFILE=desktop (default): an XFCE desktop PC with an autologin user, everyday applications and a
#     lived-in home directory (desktop.sh); PROFILE=server: the plain server image
#   - installs chimera-agent (serial control channel, the Linux counterpart of drakshell) on ttyS0, as
#     console-helper so its name does not mark the guest as a sandbox;
#     the serial login and kernel console move off ttyS0 so they don't mix with the agent's lines
#   - masks timers that would start background work in the middle of an analysis
#     (apt, man-db, e2scrub, fstrim, unattended-upgrades) and NTP (the host sets the clock)
#   - removes analysis tools a desktop does not have (tcpdump)
#   - sets a hostname and creates the sample directory (the desktop user's Downloads) and the agent's
#     root-only directory /var/lib/console-helper
set -euo pipefail

SRC=$1
OUT=$2
SIZE=${SIZE:-128G}
PROFILE=${PROFILE:-desktop}
DESKTOP_USER=${DESKTOP_USER:-arjun}
DESKTOP_FULLNAME=${DESKTOP_FULLNAME:-Arjun Mehta}
if [ "$PROFILE" = desktop ]; then HOSTNAME_=${GUEST_HOSTNAME:-$DESKTOP_USER-pc}; else HOSTNAME_=${GUEST_HOSTNAME:-srv-app01}; fi
HERE=$(cd "$(dirname "$0")" && pwd)
NBD=/dev/nbd0
MNT=$(mktemp -d)

cleanup() {
    for d in dev/pts dev sys proc; do mountpoint -q "$MNT/$d" && umount "$MNT/$d"; done
    mountpoint -q "$MNT" && umount "$MNT"
    qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || true
    rmdir "$MNT"
}
trap cleanup EXIT

cp --sparse=always "$SRC" "$OUT.part"
qemu-img resize -q "$OUT.part" "$SIZE"

modprobe nbd max_part=16
qemu-nbd --connect="$NBD" "$OUT.part"
udevadm settle
# Root is partition 1, the last one on the disk: extend it to the end, then the filesystem
echo ', +' | sfdisk --quiet --no-reread -N 1 "$NBD"
udevadm settle
for i in 1 2 3 4 5 6 7 8 9 10; do blockdev --rereadpt "$NBD" 2>/dev/null && break; sleep 1; done
udevadm settle
e2fsck -fy "${NBD}p1" >/dev/null
resize2fs "${NBD}p1"
mount "${NBD}p1" "$MNT"

grep -q 'VERSION_CODENAME=bookworm' "$MNT/etc/os-release"

# Everyday server tools a real Debian host has and malware expects (ps, crontab, sshd, wget, netstat...),
# from the official Debian mirror through a chroot; services are not started (policy-rc.d)
PKGS=${PKGS:-procps cron openssh-server wget net-tools sudo less file lsof psmisc bash-completion}
if [ -n "$PKGS" ]; then
    for d in proc sys dev dev/pts; do mount --bind "/$d" "$MNT/$d"; done
    mv "$MNT/etc/resolv.conf" "$MNT/etc/resolv.conf.chimera"
    cp /etc/resolv.conf "$MNT/etc/resolv.conf"
    printf '#!/bin/sh\nexit 101\n' > "$MNT/usr/sbin/policy-rc.d"; chmod 755 "$MNT/usr/sbin/policy-rc.d"
    chroot "$MNT" apt-get -q update
    # No upgrades: the kernel must stay 6.1.0-54-amd64 to match the DRAKVUF profile
    DEBIAN_FRONTEND=noninteractive chroot "$MNT" apt-get -q -y --no-install-recommends install $PKGS
    # openssh-server made its host keys with the dom0 hostname in the comment: remake them as the guest's
    rm -f "$MNT"/etc/ssh/ssh_host_*
    for t in rsa ecdsa ed25519; do
        chroot "$MNT" ssh-keygen -q -N '' -t $t -C "root@$HOSTNAME_" -f /etc/ssh/ssh_host_${t}_key
    done
    if [ "$PROFILE" = desktop ]; then
        bash "$HERE/desktop.sh" "$MNT" "$DESKTOP_USER" "$DESKTOP_FULLNAME"
    fi
    # Analysis tools a desktop PC does not have (malware looks for them)
    DEBIAN_FRONTEND=noninteractive chroot "$MNT" apt-get -q -y purge tcpdump
    chroot "$MNT" apt-get clean
    rm -rf "$MNT/var/lib/apt/lists/"*
    rm -f "$MNT/usr/sbin/policy-rc.d"
    mv -f "$MNT/etc/resolv.conf.chimera" "$MNT/etc/resolv.conf"
    for d in dev/pts dev sys proc; do umount "$MNT/$d"; done
    test "$(ls "$MNT"/boot/vmlinuz-*)" = "$MNT/boot/vmlinuz-6.1.0-54-amd64"
fi

# Agent
install -m 0700 "$HERE/chimera-agent.py" "$MNT/usr/local/sbin/console-helper"
install -m 0644 "$HERE/chimera-agent.service" "$MNT/etc/systemd/system/console-helper.service"
ln -sf /etc/systemd/system/console-helper.service "$MNT/etc/systemd/system/multi-user.target.wants/console-helper.service"

# ttyS0 belongs to the agent: no serial getty, no kernel console there (console stays on tty0/VNC)
ln -sf /dev/null "$MNT/etc/systemd/system/serial-getty@ttyS0.service"
for f in "$MNT/boot/grub/grub.cfg" "$MNT/etc/default/grub"; do
    sed -i -E 's/ ?console=ttyS0,115200//g; s/ ?earlyprintk=ttyS0,115200//g' "$f"
done
! grep -q 'console=ttyS0' "$MNT/boot/grub/grub.cfg"

# Nothing scheduled may start during an analysis
for unit in apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer fstrim.timer \
            dpkg-db-backup.timer systemd-tmpfiles-clean.timer unattended-upgrades.service systemd-timesyncd.service; do
    ln -sf /dev/null "$MNT/etc/systemd/system/$unit"
done

echo "$HOSTNAME_" > "$MNT/etc/hostname"
sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1\t$HOSTNAME_/" "$MNT/etc/hosts"
grep -q '^127\.0\.1\.1' "$MNT/etc/hosts" || printf '127.0.1.1\t%s\n' "$HOSTNAME_" >> "$MNT/etc/hosts"
install -d -m 0700 "$MNT/var/lib/console-helper"
if [ "$PROFILE" = desktop ]; then
    chroot "$MNT" install -d -o "$DESKTOP_USER" -g "$DESKTOP_USER" -m 0755 "/home/$DESKTOP_USER/Downloads"
else
    install -d -m 0755 "$MNT/home/$DESKTOP_USER/Downloads"
fi

umount "$MNT"
qemu-nbd --disconnect "$NBD" >/dev/null
mv "$OUT.part" "$OUT"
qemu-img info "$OUT" | grep -E 'virtual size|disk size'
echo "built $OUT"
