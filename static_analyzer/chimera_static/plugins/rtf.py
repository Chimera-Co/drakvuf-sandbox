"""RTF embedded objects via oletools.rtfobj (parsing only). Exploit documents hide OLE objects (Equation Editor,
OLE Package with an executable) in RTF, so each object's class, size and payload type is reported."""

from __future__ import annotations

import re

from oletools import rtfobj

MAX_OBJECTS = 50
EXPLOIT_CLASSES = {"equation.3": "CVE-2017-11882 / CVE-2018-0802 (Equation Editor)",
                   "equation.dsmt4": "Equation Editor (MathType)", "word.document.8": None, "package": None,
                   "htmlfile": "CVE-2017-0199 (HTA via URL moniker)", "oleobject": None}
EXEC_EXT = (".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".ps1", ".bat", ".cmd", ".lnk")


def analyze_rtf(data: bytes) -> tuple[dict, list[dict]]:
    findings: list[dict] = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence[:200],
                         "attack": list(attack), "source": "rtf"})

    parser = rtfobj.RtfObjParser(data)
    parser.parse()
    objects = []
    for obj in parser.objects[:MAX_OBJECTS]:
        cls = (obj.class_name or b"").decode("latin-1", "replace").strip("\x00") if obj.is_ole else ""
        rec = {"start": obj.start, "size": len(obj.rawdata or b""), "ole": bool(obj.is_ole), "class": cls or None,
               "package": bool(getattr(obj, "is_package", False)),
               "filename": (getattr(obj, "filename", None) or None) and str(obj.filename)[:260],
               "embedded_pe": bool(obj.is_ole and (obj.oledata or b"")[:2] == b"MZ")
               or b"MZ\x90\x00" in (getattr(obj, "olepkgdata", None) or b"")[:4]}
        objects.append(rec)
        note = EXPLOIT_CLASSES.get(cls.lower())
        if note:
            add("rtf_exploit_class", f"RTF object of an exploited class: {cls}", "high", note, ["T1203"])
        if rec["package"] and str(rec["filename"] or "").lower().endswith(EXEC_EXT):
            add("rtf_package_executable", "RTF OLE Package carries an executable or script", "high",
                str(rec["filename"]), ["T1204.002", "T1027.009"])
        if rec["embedded_pe"]:
            add("rtf_embedded_pe", "RTF object contains a PE file", "high", cls or "OLE object", ["T1027.009"])
    if objects:
        add("rtf_objects", "RTF document embeds objects", "medium", f"{len(objects)} object(s)", ["T1204.002"])
    if re.search(rb"\\objupdate", data[:4_000_000]):
        add("rtf_objupdate", "Objects update automatically when opened (\\objupdate)", "high", "\\objupdate",
            ["T1203"])
    return {"objects": objects, "objects_total": len(parser.objects)}, findings
