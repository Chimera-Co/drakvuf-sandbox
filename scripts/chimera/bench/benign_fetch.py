#!/usr/bin/env python3
"""
CHIMERA benign corpus fetcher (benign v4): vendor installers pinned by the winget manifests.

For each row of benign-v4-candidates.csv with a winget package id (WINGET below), the newest manifest in
microsoft/winget-pkgs gives the vendor's own download URL and its SHA-256. Nothing is executed on the host.

  resolve   as a user with `gh` logged in (GitHub API): writes <lock>.json with url, sha256, version and,
            for zip/portable packages, the file to take from the archive
  download  as root: fetches every locked URL over HTTPS, checks the SHA-256 and writes the files and
            register-benign-v4.csv (the m5_eval.py register; role benign, plain files)

Rows without a winget id (the team-written admin scripts) are taken from --scripts-dir.

  python3 scripts/chimera/bench/benign_fetch.py resolve --lock /var/tmp/benign-v4-lock.json
  sudo python3 scripts/chimera/bench/benign_fetch.py download --lock /var/tmp/benign-v4-lock.json \
      --out /var/lib/chimera-samples/benign-v4 --scripts-dir scripts/chimera/bench/benign-v4-scripts
"""

import argparse
import concurrent.futures
import csv
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse
import zipfile

HERE = pathlib.Path(__file__).resolve().parent

# candidate name -> winget PackageIdentifier
WINGET = {
    "notepad++": "Notepad++.Notepad++", "gimp": "GIMP.GIMP.3", "inkscape": "Inkscape.Inkscape",
    "libreoffice": "TheDocumentFoundation.LibreOffice", "thunderbird": "Mozilla.Thunderbird",
    "vivaldi": "Vivaldi.Vivaldi", "opera": "Opera.Opera", "nodejs": "OpenJS.NodeJS.LTS", "golang": "GoLang.Go",
    "cmake": "Kitware.CMake", "temurin-jdk": "EclipseAdoptium.Temurin.21.JDK",
    "strawberry-perl": "StrawberryPerl.StrawberryPerl", "rubyinstaller": "RubyInstallerTeam.Ruby.3.4",
    "putty-msi": "PuTTY.PuTTY", "mremoteng": "mRemoteNG.mRemoteNG",
    "heidisql": "HeidiSQL.HeidiSQL", "dbeaver": "DBeaver.DBeaver.Community", "postman": "Postman.Postman",
    "signal": "OpenWhisperSystems.Signal", "element": "Element.Element",
    "obsidian": "Obsidian.Obsidian", "joplin": "Joplin.Joplin", "calibre": "calibre.calibre", "anki": "Anki.Anki",
    "krita": "KDE.Krita", "paint.net": "dotPDN.PaintDotNet", "irfanview": "IrfanSkiljan.IrfanView",
    "sharex": "ShareX.ShareX", "flameshot": "Flameshot.Flameshot", "handbrake": "HandBrake.HandBrake",
    "qbittorrent": "qBittorrent.qBittorrent", "transmission": "Transmission.Transmission",
    "mpc-hc": "clsid2.mpc-hc", "foobar2000": "PeterPawlowski.foobar2000", "sumatrapdf": "SumatraPDF.SumatraPDF",
    "openvpn": "OpenVPNTechnologies.OpenVPN", "veracrypt": "IDRIX.VeraCrypt",
    "gpg4win": "GnuPG.Gpg4win", "bitwarden": "Bitwarden.Bitwarden", "x64dbg": "x64dbg.x64dbg",
    "ilspy": "icsharpcode.ILSpy", "hxd": "MHNexus.HxD", "autohotkey": "AutoHotkey.AutoHotkey",
    "nssm": "NSSM.NSSM", "rufus": "Rufus.Rufus", "crystaldiskinfo": "CrystalDewWorld.CrystalDiskInfo",
    "crystaldiskmark": "CrystalDewWorld.CrystalDiskMark", "hwinfo": "REALiX.HWiNFO", "gpu-z": "TechPowerUp.GPU-Z",
    "windirstat": "WinDirStat.WinDirStat", "bleachbit": "BleachBit.BleachBit",
    "revo-uninstaller": "RevoUninstaller.RevoUninstaller", "treesize-free": "JAMSoftware.TreeSize.Free",
    "ventoy": "Ventoy.Ventoy", "balena-etcher": "Balena.Etcher", "aria2": "aria2.aria2",
    "wget": "JernejSimoncic.Wget", "ffmpeg": "Gyan.FFmpeg", "imagemagick": "ImageMagick.ImageMagick",
    "pandoc": "JohnMacFarlane.Pandoc", "hugo": "Hugo.Hugo", "terraform": "Hashicorp.Terraform",
    "kubectl": "Kubernetes.kubectl", "helm": "Helm.Helm", "gh": "GitHub.cli", "awscli": "Amazon.AWSCLI",
    "azure-cli": "Microsoft.AzureCLI", "jq": "jqlang.jq", "fzf": "junegunn.fzf", "nushell": "Nushell.Nushell",
    "neovim": "Neovim.Neovim", "vim": "vim.vim", "sublime-text": "SublimeHQ.SublimeText.4",
    "wezterm": "wez.wezterm", "alacritty": "Alacritty.Alacritty", "mkcert": "FiloSottile.mkcert",
    "openssl-shining-light": "ShiningLight.OpenSSL.Light", "strings": "Microsoft.Sysinternals.Strings",
    "pskill": "Microsoft.Sysinternals.PsTools", "psloggedon": "Microsoft.Sysinternals.PsTools",
    "autologon": "Microsoft.Sysinternals.Autologon",
}
# Not in winget (or only as MSIX): filezilla, slack, npcap, coreinfo, du.
# Programs already in benign v3 (same product, so not an independent program): left out of v4
IN_V3 = {"vlc", "git", "winscp", "discord", "wireshark", "system-informer", "powertoys", "starship", "tcpview"}
# The exe to take from a zip when the manifest names several (or none)
ZIP_MEMBER = {"pskill": "pskill64.exe", "psloggedon": "PsLoggedon64.exe", "strings": "strings64.exe",
              "nssm": "win64/nssm.exe", "ventoy": "/Ventoy2Disk.exe", "autologon": "Autologon64.exe",
              "x64dbg": "release/x64/x64dbg.exe", "ilspy": "ILSpy.exe", "ffmpeg": "bin/ffmpeg.exe"}
TYPE_PREFERENCE = ["msi", "wix", "nullsoft", "inno", "burn", "exe", "portable", "zip"]
# Silent switches by the installer type winget reports (the candidate list guessed some types wrong);
# portable and plain exe packages keep the list's own command line
START = {
    "msi": 'msiexec /i "{sample}" /qn', "wix": 'msiexec /i "{sample}" /qn', "nullsoft": '"{sample}" /S',
    "inno": '"{sample}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART', "burn": '"{sample}" /quiet /norestart',
}
UA = {"User-Agent": "chimera-benign-fetch/1"}


def gh_api(path):
    out = subprocess.run(["gh", "api", f"repos/microsoft/winget-pkgs/contents/{path}"],
                         capture_output=True, text=True)
    if out.returncode:
        raise LookupError(out.stderr.strip()[:200])
    return json.loads(out.stdout)


def version_key(v):
    return [int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+]", v)]


def scalar(text, key):
    m = re.search(rf"^\s*-?\s*{key}:\s*(.+?)\s*$", text, re.M)
    return m.group(1).strip("'\"") if m else None


def installers(text):
    """Installer entries of a winget installer manifest, with the top-level defaults filled in."""
    head, _, body = text.partition("\nInstallers:")
    default_type = scalar(head, "InstallerType")
    default_nested = scalar(head, "NestedInstallerType")
    default_member = scalar(head, "RelativeFilePath")
    out = []
    # One entry per top-level list item, at the indent of the first one; nested lists
    # (NestedInstallerFiles, ...) are indented further
    first = re.search(r"^( *)- ", body, re.M)
    indent = first.group(1) if first else ""
    for block in re.split(rf"\n{indent}- ", "\n" + body)[1:]:
        out.append({
            "arch": scalar(block, "Architecture"), "type": scalar(block, "InstallerType") or default_type,
            "nested": scalar(block, "NestedInstallerType") or default_nested,
            "member": scalar(block, "RelativeFilePath") or default_member,
            "scope": scalar(block, "Scope"), "url": scalar(block, "InstallerUrl"),
            "sha256": (scalar(block, "InstallerSha256") or "").lower(),
        })
    return out


def resolve(pkg):
    publisher, _, rest = pkg.partition(".")
    base = f"manifests/{publisher[0].lower()}/{publisher}/{'/'.join(rest.split('.'))}"
    versions = [e["name"] for e in gh_api(base) if e["type"] == "dir"]
    # Sub-package folders (e.g. Microsoft.Sysinternals/...) are directories too; versions start with a digit
    versions = sorted((v for v in versions if v[:1].isdigit()), key=version_key)
    if not versions:
        raise LookupError("no versions")
    version = versions[-1]
    files = gh_api(f"{base}/{version}")
    name = next(f["name"] for f in files if f["name"].endswith(".installer.yaml"))
    text = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github.raw",
                           f"repos/microsoft/winget-pkgs/contents/{base}/{version}/{name}"],
                          capture_output=True, text=True, check=True).stdout
    entries = [e for e in installers(text)
               if e["url"] and e["arch"] in ("x64", "neutral", "x86") and e["type"] in TYPE_PREFERENCE]
    entries.sort(key=lambda e: (e["arch"] != "x64", e["scope"] == "user",
                                TYPE_PREFERENCE.index(e["type"]) if e["type"] in TYPE_PREFERENCE else 99))
    if not entries:
        raise LookupError("no x64/x86 installer")
    return {"version": version, **entries[0]}


def cmd_resolve(args):
    rows = list(csv.DictReader(open(args.csv)))
    lock = json.loads(args.lock.read_text()) if args.lock.exists() else {}
    for row in rows:
        name = row["name"]
        if name in IN_V3 or name in lock or row["source"] == "team-written":
            continue
        pkg = WINGET.get(name)
        if not pkg:
            print(f"{name}: no winget id", file=sys.stderr)
            continue
        try:
            lock[name] = {"package": pkg, **resolve(pkg)}
            print(f"{name}: {lock[name]['version']} {lock[name]['type']} {lock[name]['url']}")
        except (LookupError, subprocess.CalledProcessError, StopIteration) as e:
            print(f"{name}: {pkg}: {e}", file=sys.stderr)
        args.lock.write_text(json.dumps(lock, indent=1))


def fetch(url, dest):
    """curl to a file, so a stalled mirror is abandoned (under 50 kB/s for 60 s) and retried"""
    if not url.startswith("https://"):
        raise ValueError(f"not https: {url}")
    out = subprocess.run(["curl", "-fsSL", "--proto-redir", "=https,http", "--retry", "4", "--retry-all-errors",
                          "--speed-limit", "50000", "--speed-time", "60", "-A", UA["User-Agent"], "-o", str(dest), url],
                         capture_output=True, timeout=3600)
    if out.returncode:
        raise OSError(f"curl exit {out.returncode}: {out.stderr.decode(errors='replace')[:200]}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def extract(name, entry, archive, out):
    with zipfile.ZipFile(archive) as zf:
        wanted = ZIP_MEMBER.get(name) or entry.get("member")
        members = [m for m in zf.namelist() if m.lower().endswith((".exe", ".msi"))]
        if wanted:
            wanted = wanted.replace("\\", "/").lower()
            members = [m for m in members if m.lower().endswith(wanted)]
        if len(members) != 1:
            raise ValueError(f"zip member for {name}: {members[:5]}")
        file_name = members[0].rsplit("/", 1)[-1]
        path = out / f"{name}--{file_name}"
        with zf.open(members[0]) as src, open(path, "wb") as dst:
            while block := src.read(1 << 20):
                dst.write(block)
    return file_name, path


def get_one(name, entry, row, out):
    """Download, verify and store one package; returns its register row or raises."""
    parts = entry["url"].split("?")[0].rstrip("/").split("/")
    # SourceForge links end in /download after the file name
    file_name = parts[-2] if parts[-1] == "download" else parts[-1]
    file_name = urllib.parse.unquote(file_name)
    tmp = out / f".{name}.part"
    fetch(entry["url"], tmp)
    if sha256_file(tmp) != entry["sha256"]:
        tmp.unlink()
        raise ValueError("SHA-256 differs from the winget manifest")
    installer_type = entry["type"]
    if installer_type == "zip" or file_name.lower().endswith(".zip"):
        installer_type = entry.get("nested") or "portable"
        try:
            file_name, path = extract(name, entry, tmp, out)
        finally:
            tmp.unlink()
    else:
        path = out / f"{name}--{file_name}"
        tmp.rename(path)
    if file_name.lower().endswith(".msi"):
        installer_type = "msi"
    elif installer_type in ("msi", "wix"):  # an exe wrapper around an MSI (paint.net)
        installer_type = "exe"
    return register_row(row, entry["version"], path, file_name, sha256_file(path),
                        START.get(installer_type, row["start_command"]))


def cmd_download(args):
    rows = {r["name"]: r for r in csv.DictReader(open(args.csv))}
    lock = json.loads(args.lock.read_text())
    args.out.mkdir(parents=True, exist_ok=True, mode=0o700)
    register = []
    with concurrent.futures.ThreadPoolExecutor(args.parallel) as pool:
        futures = {pool.submit(get_one, name, entry, rows[name], args.out): name for name, entry in lock.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                register.append(future.result())
                print(f"{name}: ok", flush=True)
            except Exception as e:  # noqa: BLE001 - report and continue with the rest
                print(f"{name}: failed: {e}", file=sys.stderr, flush=True)
    for script in sorted(args.scripts_dir.iterdir()) if args.scripts_dir else []:
        name = script.stem
        if name in rows:
            path = args.out / f"{name}--{script.name}"
            path.write_bytes(script.read_bytes())
            register.append(register_row(rows[name], "1.0", path, script.name, sha256_file(path)))
    register.sort(key=lambda r: r["family"].lower())
    with open(args.out.parent / "register-benign-v4.csv", "w", newline="") as f:
        w = csv.DictWriter(f, ["sha256", "path", "role", "family", "tags", "archive_password", "entry",
                               "file_name", "guest_os", "start_command"])
        w.writeheader()
        w.writerows(register)
    print(f"{len(register)} programs -> {args.out.parent / 'register-benign-v4.csv'}")


def register_row(row, version, path, file_name, digest, start_command=None):
    return {"sha256": digest, "path": str(path), "role": "benign",
            "family": f"{row['name']} {version}", "tags": row["category"], "archive_password": "", "entry": "",
            "file_name": file_name, "guest_os": "windows",
            "start_command": row["start_command"] if start_command is None else start_command}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("resolve")
    p.add_argument("--csv", type=pathlib.Path, default=HERE / "benign-v4-candidates.csv")
    p.add_argument("--lock", type=pathlib.Path, required=True)
    p = sub.add_parser("download")
    p.add_argument("--csv", type=pathlib.Path, default=HERE / "benign-v4-candidates.csv")
    p.add_argument("--lock", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--scripts-dir", type=pathlib.Path)
    p.add_argument("--parallel", type=int, default=4)
    args = ap.parse_args()
    {"resolve": cmd_resolve, "download": cmd_download}[args.cmd](args)


if __name__ == "__main__":
    main()
