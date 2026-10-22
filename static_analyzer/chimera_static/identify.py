"""Layer 0: what is this file really? Magic bytes first, libmagic second, the name last."""

from __future__ import annotations

import re
import struct
import zipfile
import io

try:
    import magic  # python-magic (libmagic)
except Exception:  # pragma: no cover - optional
    magic = None

PE_MACHINES = {0x14C: ("x86", 32), 0x8664: ("x86_64", 64), 0x1C0: ("arm", 32), 0x1C4: ("arm", 32),
               0xAA64: ("arm64", 64), 0x200: ("ia64", 64), 0xEBC: ("efi_bytecode", 0)}
ELF_MACHINES = {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64", 8: "mips", 20: "ppc", 21: "ppc64",
                43: "sparcv9", 2: "sparc", 22: "s390", 243: "riscv", 50: "ia64", 42: "superh", 258: "loongarch"}
MACHO_CPUS = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 18: "ppc", 0x01000012: "ppc64"}

EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".bat", ".cmd", ".ps1",
                   ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".elf", ".so",
                   ".bin", ".apk", ".app", ".sh", ".py"}
DOCUMENT_EXTS = {".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".rtf",
                 ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar", ".7z", ".iso", ".img",
                 ".one", ".csv", ".html", ".htm", ".xml", ".odt"}
# what each format is normally called; used for extension-mismatch findings
EXPECTED_EXTS = {
    "pe": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".efi", ".drv", ".mui", ".tmp", ".bin", ".dat",
           ".sample", ""},
    "elf": {"", ".so", ".elf", ".bin", ".o", ".ko", ".out", ".sample"}, "pdf": {".pdf"},
    "ole": {".doc", ".xls", ".ppt", ".msi", ".msg", ".dot", ".xlt", ".pub", ".vsd"},
    "ooxml": {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotx", ".dotm", ".xlsb"},
    "rtf": {".rtf", ".doc"}, "zip": {".zip", ".jar"}, "apk": {".apk"}, "jar": {".jar"},
}
SCRIPT_HINTS = [
    ("powershell", re.compile(rb"(?i)(\$[a-z_]+\s*=|invoke-|new-object\s|write-host|param\s*\(|\[system\.)")),
    ("vbscript", re.compile(rb"(?i)(\bdim\s+\w|createobject\s*\(|wscript\.|\bsub\s+\w+|end\s+sub\b)")),
    ("javascript", re.compile(rb"(?i)(\bfunction\s*\w*\s*\(|\bvar\s+\w+\s*=|activexobject|\beval\s*\(|=>)")),
    ("batch", re.compile(rb"(?i)(^@echo\s+off|^\s*set\s+\w+=|%~dp0|\bgoto\s+:?\w+|^rem\s)", re.M)),
    ("hta", re.compile(rb"(?i)<hta:application")),
    ("html", re.compile(rb"(?i)<(html|script|body|iframe)\b")),
    ("python", re.compile(rb"(?m)^(import \w+|from \w+ import|def \w+\(.*\):)")),
    ("shell", re.compile(rb"(?m)^(#!\s*/bin/(ba|z|da)?sh|\s*(wget|curl|chmod)\s)")),
]
RTLO = "‮"


def _pe(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"format": "mz_dos"}
    machine, = struct.unpack_from("<H", data, e_lfanew + 4)
    characteristics, = struct.unpack_from("<H", data, e_lfanew + 22)
    opt = e_lfanew + 24
    magic_opt = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    arch, bits = PE_MACHINES.get(machine, (f"0x{machine:x}", 64 if magic_opt == 0x20B else 32))
    is_dll = bool(characteristics & 0x2000)
    subsystem = None
    sub_off = opt + 68
    if sub_off + 2 <= len(data):
        subsystem = struct.unpack_from("<H", data, sub_off)[0]
    dotnet = False
    try:  # CLR runtime header = data directory 14
        dd = opt + (96 if magic_opt == 0x10B else 112) + 14 * 8
        if dd + 8 <= len(data):
            dotnet = struct.unpack_from("<II", data, dd)[0] != 0
    except struct.error:
        pass
    kind = "driver" if subsystem == 1 else "dll" if is_dll else "exe"
    return {"format": "pe", "platform": "windows", "arch": arch, "bits": bits, "pe_kind": kind, "dotnet": dotnet}


def _elf(data: bytes):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"
    etype, machine = struct.unpack_from(endian + "HH", data, 16)
    osabi = data[7]
    platform = {0: "linux", 3: "linux", 9: "freebsd", 12: "openbsd"}.get(osabi, "unix")
    return {"format": "elf", "platform": platform, "arch": ELF_MACHINES.get(machine, f"0x{machine:x}"), "bits": bits,
            "elf_type": {1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}.get(etype, str(etype))}


def _macho(data: bytes):
    if len(data) < 8:
        return None
    head = data[:4]
    if head in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        endian = ">" if head[0] == 0xFE else "<"
        cpu, = struct.unpack_from(endian + "I", data, 4)
        return {"format": "macho", "platform": "macos", "arch": MACHO_CPUS.get(cpu, f"0x{cpu:x}"),
                "bits": 64 if head in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 32}
    if head == b"\xca\xfe\xba\xbe":  # fat Mach-O or Java class: the count of archs is small for Mach-O
        n, = struct.unpack_from(">I", data, 4)
        if 0 < n < 20:
            return {"format": "macho_fat", "platform": "macos", "arch": "multi", "bits": 0}
        return {"format": "java_class", "platform": "java", "arch": "jvm", "bits": 0}
    return None


def _zip_kind(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist()[:5000])
    except Exception:
        return "zip"
    if "AndroidManifest.xml" in names or "classes.dex" in names:
        return "apk"
    if "[Content_Types].xml" in names:
        return "ooxml"
    if "META-INF/MANIFEST.MF" in names:
        return "jar"
    return "zip"


def _script(data: bytes):
    head = data[:65536]
    if head.startswith(b"#!"):
        line = head.split(b"\n", 1)[0].lower()
        for lang in (b"python", b"perl", b"ruby", b"node", b"bash", b"sh"):
            if lang in line:
                return "shell" if lang in (b"bash", b"sh") else lang.decode()
    text = head
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = head.decode("utf-16").encode("utf-8", "ignore")
        except UnicodeDecodeError:
            pass
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in text[:4096]) / max(1, len(text[:4096]))
    if printable < 0.85:
        return None
    best, score = None, 0
    for lang, rx in SCRIPT_HINTS:
        n = len(rx.findall(text))
        if n > score:
            best, score = lang, n
    return best or "text"


def identify(data: bytes, file_name: str = "") -> dict:
    info = {"format": "unknown", "platform": "any", "arch": None, "bits": None}
    for probe in (_pe, _elf, _macho):
        found = probe(data)
        if found:
            info.update(found)
            break
    else:
        head = data[:16]
        if head.startswith(b"%PDF") or b"%PDF-" in data[:1024]:
            info.update(format="pdf", pdf_header_offset=data[:1024].find(b"%PDF-"))
        elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            info["format"] = "ole"
        elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            info["format"] = _zip_kind(data)
        elif head.startswith(b"{\\rt"):
            info["format"] = "rtf"
        elif head.startswith(b"7z\xbc\xaf\x27\x1c"):
            info["format"] = "7z"
        elif head.startswith(b"Rar!\x1a\x07"):
            info["format"] = "rar"
        elif head.startswith(b"MSCF"):
            info["format"] = "cab"
        elif head.startswith(b"\x1f\x8b"):
            info["format"] = "gzip"
        elif head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
            info.update(format="lnk", platform="windows")
        elif head.startswith(b"dex\n"):
            info.update(format="dex", platform="android")
        elif len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
            info["format"] = "iso"
        elif head.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d"):
            info["format"] = "onenote"
        else:
            lang = _script(data)
            if lang:
                info["format"] = "text" if lang == "text" else f"script:{lang}"
                if lang in ("powershell", "vbscript", "batch", "hta"):
                    info["platform"] = "windows"
                elif lang == "shell":
                    info["platform"] = "linux"
    if info["format"] == "apk":
        info["platform"] = "android"

    if magic is not None:
        try:
            info["magic"] = magic.from_buffer(data[:1 << 20])
            info["mime"] = magic.from_buffer(data[:1 << 20], mime=True)
        except Exception:
            pass

    name = file_name or ""
    lower = name.lower()
    ext = ("." + lower.rsplit(".", 1)[1]) if "." in lower.strip(".") else ""
    info["extension"] = ext
    parts = lower.split(".")
    info["double_extension"] = (len(parts) >= 3 and "." + parts[-2] in DOCUMENT_EXTS
                                and "." + parts[-1] in EXECUTABLE_EXTS)
    info["rtlo_in_name"] = RTLO in name
    expected = EXPECTED_EXTS.get(info["format"])
    info["extension_mismatch"] = bool(name and expected is not None and ext not in expected
                                      and not (info["format"] == "pe" and ext in EXECUTABLE_EXTS))
    return info
