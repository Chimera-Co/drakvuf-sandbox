#!/usr/bin/env bash
# Downloads the everyday applications that H1/install-apps.ps1 installs in vm-0, from each
# vendor's own download site, into DIR (default ./apps). Upload them to the signed-in user's
# Downloads folder with provision_guest.py --upload; the guest script checks each file's
# Authenticode signature before running it.
#
#   scripts/chimera/arms/fetch-apps.sh /var/tmp/chimera-apps
set -euo pipefail
dir=${1:-apps}
mkdir -p "$dir"

# file name as a browser would save it | URL (versions as of 2026-10-20)
apps=(
  "VC_redist.x86.exe|https://aka.ms/vs/17/release/vc_redist.x86.exe"
  "googlechromestandaloneenterprise64.msi|https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
  "Firefox Setup 158.0.msi|https://download-installer.cdn.mozilla.net/pub/firefox/releases/158.0/win64/en-US/Firefox%20Setup%20158.0.msi"
  "7z2604-x64.msi|https://github.com/ip7z/7zip/releases/download/26.04/7z2604-x64.msi"
  "vlc-3.0.24-win64.exe|https://get.videolan.org/vlc/3.0.24/win64/vlc-3.0.24-win64.exe"
  "npp.8.9.8.1.Installer.x64.exe|https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x64.exe"
  "LibreOffice_26.8.1_Win_x86-64.msi|https://download.documentfoundation.org/libreoffice/stable/26.8.1/win/x86_64/LibreOffice_26.8.1_Win_x86-64.msi"
  "ZoomInstallerFull.msi|https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
  "python-3.13.16-amd64.exe|https://www.python.org/ftp/python/3.13.16/python-3.13.16-amd64.exe"
  "Git-2.56.0.2-64-bit.exe|https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.exe"
  "VSCodeSetup-x64-1.142.0.exe|https://update.code.visualstudio.com/1.142.0/win32-x64/stable"
  "audacity-win-4.0.1-x86_64.msi|https://github.com/audacity/audacity/releases/download/Audacity-4.0.1/audacity-win-4.0.1-x86_64.msi"
  "putty-64bit-0.85-installer.msi|https://the.earth.li/~sgtatham/putty/0.85/w64/putty-64bit-0.85-installer.msi"
  "OpenJDK21U-jre_x64_windows_hotspot_21.0.12.1_1.msi|https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_windows_hotspot_21.0.12.1_1.msi"
)

for entry in "${apps[@]}"; do
  name=${entry%%|*}
  url=${entry#*|}
  # Into a .part file first, so that an interrupted download is fetched again next time.
  if [ ! -s "$dir/$name" ]; then
    curl -fsSL --proto '=https' --proto-redir '=https' \
      --connect-timeout 30 --retry 3 --retry-all-errors -o "$dir/$name.part" "$url"
    mv "$dir/$name.part" "$dir/$name"
  fi
  printf '%s  %9d  %s\n' "$(sha256sum "$dir/$name" | cut -d' ' -f1)" "$(stat -c %s "$dir/$name")" "$name"
done
