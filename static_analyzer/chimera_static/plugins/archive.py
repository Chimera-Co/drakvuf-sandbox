"""ZIP listing from the central directory. Nothing is extracted or decompressed, so members are listed,
not analyzed: the analyzer reports such a run as partial coverage."""

from __future__ import annotations

import io
import posixpath
import zipfile

MAX_MEMBERS = 10000
MAX_LISTED = 200
EXECUTABLE = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".sys", ".elf", ".so", ".bin", ".apk", ".jar"}
SCRIPT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".bat", ".cmd", ".lnk", ".url",
          ".sh", ".py", ".chm"}
NESTED = {".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx", ".cab", ".gz", ".tar", ".xz"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".rtf"}


def _ext(name: str) -> str:
    return posixpath.splitext(name.lower())[1]


def analyze_zip(data: bytes) -> tuple[dict, list[dict]]:
    findings: list[dict] = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence,
                         "attack": list(attack), "source": "archive"})

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        comment = (z.comment or b"")[:200].decode("latin-1")
    members = [i for i in infos[:MAX_MEMBERS] if not i.is_dir()]
    listed = [{"name": i.filename[:300], "size": i.file_size, "compressed": i.compress_size,
               "encrypted": bool(i.flag_bits & 0x1)} for i in members[:MAX_LISTED]]
    total = sum(i.file_size for i in members)
    packed = sum(i.compress_size for i in members) or 1
    names = [i.filename for i in members]
    executables = [n for n in names if _ext(n) in EXECUTABLE]
    scripts = [n for n in names if _ext(n) in SCRIPT]
    nested = [n for n in names if _ext(n) in NESTED]
    encrypted = [i.filename for i in members if i.flag_bits & 0x1]
    double = [n for n in names
              if _ext(n) in EXECUTABLE | SCRIPT and _ext(posixpath.splitext(n.lower())[0]) in DOC_EXT]
    unsafe_paths = [n for n in names if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/")
                    or (len(n) > 1 and n[1] == ":")]
    info = {"members": len(members), "truncated": len(infos) > MAX_MEMBERS, "listed": listed,
            "uncompressed_bytes": total, "compression_ratio": round(total / packed, 1),
            "executables": executables[:50], "scripts": scripts[:50], "nested_archives": nested[:50],
            "encrypted": len(encrypted), "comment": comment}

    if executables:
        add("zip_executable", "Archive contains executables", "medium", ", ".join(executables[:5]), ["T1204.002"])
    if scripts:
        add("zip_script", "Archive contains scripts or shortcuts", "medium", ", ".join(scripts[:5]), ["T1204.002"])
    if double:
        add("zip_double_extension", "Archive member with a double extension", "high", ", ".join(double[:5]),
            ["T1036.007"])
    if encrypted:
        severity = "high" if executables or scripts else "medium"
        add("zip_encrypted", "Encrypted members (content hidden from scanners)", severity,
            f"{len(encrypted)} of {len(members)}", ["T1027.013"])
    if nested:
        add("zip_nested", "Archive contains further archives or disk images", "low", ", ".join(nested[:5]),
            ["T1027.009"])
    if unsafe_paths:
        add("zip_path_traversal", "Member names escape the extraction folder", "medium", ", ".join(unsafe_paths[:3]),
            [])
    if total > 1024 ** 3 or (total > 64 * 1024 ** 2 and total / packed > 100):
        add("zip_bomb", "Expands to an unusually large size (possible decompression bomb)", "medium",
            f"{total} bytes from {packed} (ratio {total / packed:.0f})", [])
    return info, findings
