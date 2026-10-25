#!/bin/bash
# Turn the mounted Debian 12 image into an everyday desktop PC (called by build-image.sh with the
# root filesystem mounted at $1, proc/sys/dev bound, the host's resolv.conf and a policy-rc.d in place).
#
#   desktop.sh MNT USER "FULL NAME"
#
# XFCE (Debian's own XFCE desktop) on LightDM with autologin to an ordinary user who is in the sudo
# group, as on a personal machine; Firefox ESR, LibreOffice Writer/Calc, a document viewer, an archive
# manager; India locale and time zone; a home directory with dated documents, shell history and recent
# files. No screen locker and no display blanking, so the live view and screenshots always show the
# desktop. Everything comes from the official Debian mirror; the kernel is never touched.
set -euo pipefail

MNT=$1
USER_=$2
FULLNAME=$3
HOME_=/home/$USER_

DESKTOP_PKGS="xserver-xorg lightdm lightdm-gtk-greeter xfce4 xfce4-terminal xfce4-whiskermenu-plugin
  xfce4-taskmanager xfce4-screenshooter xfce4-notifyd mousepad ristretto thunar-archive-plugin file-roller
  evince firefox-esr libreoffice-writer libreoffice-calc libreoffice-gtk3 dbus-x11 at-spi2-core gvfs
  xdg-user-dirs xdg-utils greybird-gtk-theme elementary-xfce-icon-theme desktop-base fonts-dejavu
  fonts-liberation2 locales tzdata curl git nano htop zip unzip python3 x11-xserver-utils virt-what"
DEBIAN_FRONTEND=noninteractive chroot "$MNT" apt-get -q -y --no-install-recommends install $DESKTOP_PKGS

# Locale and time zone of the owner
printf 'en_IN UTF-8\nen_US.UTF-8 UTF-8\n' > "$MNT/etc/locale.gen"
chroot "$MNT" locale-gen >/dev/null
printf 'LANG=en_IN.UTF-8\n' > "$MNT/etc/default/locale"
ln -sf /usr/share/zoneinfo/Asia/Kolkata "$MNT/etc/localtime"
echo Asia/Kolkata > "$MNT/etc/timezone"

# The user: ordinary account, sudo like on a personal machine; a random password nobody knows
# (autologin does not need it)
groups=$(for g in sudo audio video plugdev netdev cdrom users lpadmin; do
    if chroot "$MNT" getent group "$g" >/dev/null; then printf '%s,' "$g"; fi; done)
chroot "$MNT" useradd -m -s /bin/bash -c "$FULLNAME" -G "${groups%,}" "$USER_"
printf '%s:%s\n' "$USER_" "$(head -c 24 /dev/urandom | base64)" | chroot "$MNT" chpasswd
chroot "$MNT" groupadd -f autologin
chroot "$MNT" usermod -aG autologin "$USER_"

install -d "$MNT/etc/lightdm/lightdm.conf.d"
cat > "$MNT/etc/lightdm/lightdm.conf.d/50-autologin.conf" <<EOF
[Seat:*]
autologin-user=$USER_
autologin-user-timeout=0
user-session=xfce
EOF
chroot "$MNT" systemctl set-default graphical.target >/dev/null
chroot "$MNT" systemctl enable lightdm >/dev/null 2>&1 || ln -sf /lib/systemd/system/lightdm.service "$MNT/etc/systemd/system/display-manager.service"

# Display never blanks (live view, screenshots)
install -d "$MNT/etc/X11/xorg.conf.d"
cat > "$MNT/etc/X11/xorg.conf.d/10-chimera-noblank.conf" <<'EOF'
Section "ServerFlags"
    Option "BlankTime" "0"
    Option "StandbyTime" "0"
    Option "SuspendTime" "0"
    Option "OffTime" "0"
EndSection
EOF

# Home directory of someone who has used this machine for a few months
run_as() { chroot "$MNT" runuser -u "$USER_" -- "$@"; }
run_as env HOME="$HOME_" LANG=en_IN.UTF-8 xdg-user-dirs-update
cfg=$HOME_/.config/xfce4/xfconf/xfce-perchannel-xml
run_as mkdir -p "$cfg" "$HOME_/.config/autostart" "$HOME_/.config/gtk-3.0" "$HOME_/.local/share" \
    "$HOME_/Documents/College" "$HOME_/Documents/Personal" "$HOME_/Projects/expense-tracker"
# Default panel without the first-login "default or empty panel" question
cp "$MNT/etc/xdg/xfce4/panel/default.xml" "$MNT$cfg/xfce4-panel.xml"
# Laptop resolution on the first connected output. Not 1366x768: on the Cirrus adapter that becomes a
# 1360-wide VNC framebuffer whose rows are 1362 pixels apart, so every screenshot comes out sheared.
cat > "$MNT$HOME_/.config/autostart/display.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Display
Exec=sh -c 'o=$(xrandr | awk "/ connected/{print \$1; exit}"); xrandr --output "$o" --mode 1280x800 || xrandr --output "$o" --mode 1024x768 || true; xset s off -dpms'
X-GNOME-Autostart-enabled=true
EOF

w() { install -D -m 0644 /dev/stdin "$MNT$HOME_/$1"; touch -d "$2" "$MNT$HOME_/$1"; }
w Documents/College/DBMS-notes.txt "2026-08-21 22:14" <<'EOF'
Unit 3 - Normalisation
1NF: atomic values, no repeating groups
2NF: 1NF + no partial dependency on part of a composite key
3NF: 2NF + no transitive dependency
BCNF: every determinant is a candidate key
Lab: create tables for library mgmt, insert 10 rows each, submit by Friday
EOF
w Documents/College/OS-assignment-2.txt "2026-09-11 17:40" <<'EOF'
Q1. Compare FCFS, SJF and Round Robin for the given 5 processes (quantum = 4)
Q2. Explain the producer-consumer problem with semaphores
Q3. What is thrashing? How does the working set model avoid it?
EOF
w Documents/Personal/budget-oct-2026.csv "2026-10-03 21:05" <<'EOF'
date,item,category,amount
2026-10-01,Hostel mess,Food,3200
2026-10-02,Metro card recharge,Travel,500
2026-10-02,Airtel recharge,Phone,349
2026-10-05,Books - Galvin OS,College,780
2026-10-09,Movie,Fun,420
2026-10-12,Groceries,Food,610
EOF
w Documents/Personal/todo.txt "2026-10-17 23:48" <<'EOF'
- finish OS assignment 2
- pay hostel fee before 25th
- call home sunday
- fix expense tracker csv import
- internship form (TCS / Infosys) - upload resume
EOF
w Documents/College/sem5-timetable.txt "2026-07-30 09:12" <<'EOF'
MON  DBMS 9-10 | OS 10-11 | CN 11:15-12:15 | DBMS lab 2-4
TUE  OS 9-10 | TOC 10-11 | SE 11:15-12:15
WED  CN 9-10 | DBMS 10-11 | OS lab 2-4
THU  TOC 9-10 | SE 10-11 | CN lab 2-4
FRI  DBMS 9-10 | OS 10-11 | TOC 11:15-12:15 | library
EOF
w Documents/Personal/budget-sep-2026.csv "2026-09-30 22:41" <<'EOF'
date,item,category,amount
2026-09-01,Hostel mess,Food,3200
2026-09-03,Metro card recharge,Travel,500
2026-09-04,Airtel recharge,Phone,349
2026-09-14,Earphones,Shopping,899
2026-09-20,Groceries,Food,540
2026-09-27,Train ticket home,Travel,615
EOF
w Projects/expense-tracker/README.md "2026-09-28 19:22" <<'EOF'
# expense-tracker
Small Python script to read my budget CSVs and print monthly totals per category.
EOF
w Projects/expense-tracker/tracker.py "2026-09-28 19:31" <<'EOF'
import csv
import sys
from collections import defaultdict

totals = defaultdict(int)
with open(sys.argv[1]) as f:
    for row in csv.DictReader(f):
        totals[row["category"]] += int(row["amount"])
for category, amount in sorted(totals.items()):
    print(f"{category:10} {amount:6}")
EOF
w .bash_history "2026-10-18 00:12" <<'EOF'
sudo apt update
sudo apt upgrade
ls
cd Documents/
mkdir College Personal
cd
python3 --version
sudo apt install git
git config --global user.name "Arjun Mehta"
git config --global init.defaultBranch main
mkdir -p Projects/expense-tracker
cd Projects/expense-tracker/
git init
nano tracker.py
python3 tracker.py
python3 tracker.py ~/Documents/Personal/budget-oct-2026.csv
nano tracker.py
python3 tracker.py ~/Documents/Personal/budget-oct-2026.csv
cd
cd Downloads/
ls -lh
unzip OS-lab-programs.zip
cd OS-lab-programs/
gcc fcfs.c -o fcfs
./fcfs
gcc rr.c -o rr && ./rr
cd ~/Downloads
rm -rf OS-lab-programs
ls
cd
ls
cd Projects/expense-tracker/
python3 tracker.py ~/Documents/Personal/budget-oct-2026.csv
git status
git add tracker.py
git commit -m "category totals"
cd
sudo apt update
sudo apt install htop
htop
df -h
free -m
ping -c 3 google.com
firefox &
nano Documents/Personal/todo.txt
ls Downloads/
history | tail
EOF
chmod 600 "$MNT$HOME_/.bash_history"
w .config/gtk-3.0/bookmarks "2026-09-02 10:00" <<EOF
file://$HOME_/Documents/College College
file://$HOME_/Projects Projects
EOF
w .local/share/recently-used.xbel "2026-10-17 23:48" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks" xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="file://$HOME_/Documents/Personal/todo.txt" added="2026-10-17T18:18:00Z" modified="2026-10-17T18:18:00Z" visited="2026-10-17T18:18:00Z">
    <info><metadata owner="http://freedesktop.org"><mime:mime-type type="text/plain"/>
      <bookmark:applications><bookmark:application name="Mousepad" exec="&apos;mousepad %u&apos;" modified="2026-10-17T18:18:00Z" count="6"/></bookmark:applications>
    </metadata></info>
  </bookmark>
  <bookmark href="file://$HOME_/Documents/Personal/budget-oct-2026.csv" added="2026-10-03T15:35:00Z" modified="2026-10-12T16:02:00Z" visited="2026-10-12T16:02:00Z">
    <info><metadata owner="http://freedesktop.org"><mime:mime-type type="text/csv"/>
      <bookmark:applications><bookmark:application name="LibreOffice Calc" exec="&apos;localc %U&apos;" modified="2026-10-12T16:02:00Z" count="4"/></bookmark:applications>
    </metadata></info>
  </bookmark>
</xbel>
EOF
chroot "$MNT" chown -R "$USER_:$USER_" "$HOME_"
echo "desktop: $USER_ ($FULLNAME), XFCE + LightDM autologin"
