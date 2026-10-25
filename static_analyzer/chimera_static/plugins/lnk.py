"""Windows shortcut (.lnk, MS-SHLLINK) parser: target, arguments, working directory, icon and the tracker
machine id. Shortcuts are a common first stage (an icon that looks like a document, a command line that runs
PowerShell or mshta), so the arguments are checked with the script rules too."""

from __future__ import annotations

import datetime
import struct

from .script import COMPILED

HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
FLAGS = {0x1: "target_idlist", 0x2: "link_info", 0x4: "name", 0x8: "relative_path", 0x10: "working_dir",
         0x20: "arguments", 0x40: "icon_location", 0x80: "unicode"}
SHOW = {1: "normal", 3: "maximized", 7: "minimized"}
LAUNCHERS = ("cmd.exe", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil",
             "bitsadmin", "msiexec", "conhost", "forfiles", "curl.exe", "explorer.exe")
DOC_ICONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", "imageres.dll", "shell32.dll")
MAX_STR = 4096


def _filetime(value: int) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cstr(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    return data[off:end if end >= 0 else len(data)][:MAX_STR].decode("latin-1")


def parse_lnk(data: bytes) -> dict:
    if data[:20] != HEADER:
        raise ValueError("not a shell link header")
    flags, attrs = struct.unpack_from("<II", data, 0x14)
    ctime, atime, wtime = struct.unpack_from("<QQQ", data, 0x1C)
    size, icon_index, show, hotkey = struct.unpack_from("<IiIH", data, 0x34)
    out = {"flags": [name for bit, name in FLAGS.items() if flags & bit], "target_size": size,
           "icon_index": icon_index, "show_command": SHOW.get(show, str(show)), "hotkey": hotkey or None,
           "times": {"created": _filetime(ctime), "accessed": _filetime(atime), "written": _filetime(wtime)},
           "target": None, "arguments": None, "working_dir": None, "icon": None, "name": None,
           "relative_path": None, "machine_id": None, "env_target": None}
    off = 0x4C
    if flags & 0x1:
        (idlist,) = struct.unpack_from("<H", data, off)
        off += 2 + idlist
    if flags & 0x2:
        info_size, header_size, info_flags, _vol, local_off = struct.unpack_from("<IIIII", data, off)
        if info_flags & 0x1 and local_off:
            out["target"] = _cstr(data, off + local_off)
        off += info_size
    unicode = bool(flags & 0x80)
    for bit, key in ((0x4, "name"), (0x8, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"),
                     (0x40, "icon")):
        if flags & bit:
            (count,) = struct.unpack_from("<H", data, off)
            off += 2
            width = 2 if unicode else 1
            raw = data[off:off + count * width]
            off += count * width
            out[key] = (raw.decode("utf-16-le", "replace") if unicode else raw.decode("latin-1"))[:MAX_STR]
    while off + 8 <= len(data):
        block_size, sig = struct.unpack_from("<II", data, off)
        if block_size < 8:
            break
        if sig == 0xA0000003 and block_size >= 0x60:
            out["machine_id"] = _cstr(data, off + 16)[:16] or None
        elif sig == 0xA0000001 and block_size >= 0x314:
            out["env_target"] = _cstr(data, off + 8)[:260] or None
        off += block_size
    if not out["target"]:
        out["target"] = out["env_target"] or out["relative_path"]
    return out


def analyze_lnk(data: bytes) -> tuple[dict, list[dict]]:
    findings: list[dict] = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence[:200],
                         "attack": list(attack), "source": "lnk"})

    info = parse_lnk(data)
    target = (info["target"] or "").lower()
    args = info["arguments"] or ""
    icon = (info["icon"] or "").lower()
    if any(name in target for name in LAUNCHERS):
        add("lnk_launches_interpreter", "Shortcut runs a command interpreter or LOLBin", "high",
            f"{info['target']} {args[:120]}", ["T1204.002", "T1218"])
    if len(args) > 256:
        add("lnk_long_arguments", "Very long shortcut arguments (often padded to hide the command)", "medium",
            f"{len(args)} characters", ["T1027"])
    if info["show_command"] == "minimized" and args:
        add("lnk_minimized", "Shortcut starts its target minimized", "low", info["show_command"], ["T1564.003"])
    if icon.endswith(DOC_ICONS) and target.endswith((".exe", ".com", ".bat", ".cmd", ".scr")):
        add("lnk_document_icon", "Executable shortcut with a document or system icon", "medium",
            f"icon {info['icon']}", ["T1036"])
    for fid, title, sev, rx, attack, _langs in COMPILED:
        m = rx.search(args)
        if m:
            add(f"lnk_{fid}", f"Shortcut arguments: {title.lower()}", sev, args[max(0, m.start() - 40):m.end() + 40],
                attack)
    return info, findings
