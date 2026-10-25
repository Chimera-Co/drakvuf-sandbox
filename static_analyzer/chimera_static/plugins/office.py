"""Office documents (OLE and OOXML): VBA/XLM macro indicators with olevba, and external OOXML relationships.

Nothing is rendered, run or emulated. olevba only decompresses and scans the macro source; the deobfuscation
and string-decoding passes stay off so the stage stays bounded on hostile input.
"""

from __future__ import annotations

import io
import re
import zipfile

MAX_BYTES = 32 * 1024 * 1024
MAX_LIST = 25
REL_RX = re.compile(rb"<Relationship\b[^>]*>", re.I)
ATTR_RX = re.compile(rb'(\w+)\s*=\s*"([^"]{0,2000})"')
# olevba keyword groups that matter for a verdict; "IOC" values are reported, hex/base64 strings only counted
AUTOEXEC, SUSPICIOUS = "AutoExec", "Suspicious"


def _external_relationships(data: bytes) -> list[dict]:
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist()[:2000]:
            if not info.filename.endswith(".rels") or info.file_size > 1024 * 1024:
                continue
            for tag in REL_RX.findall(z.read(info)):
                attrs = {k.decode().lower(): v.decode("utf-8", "replace") for k, v in ATTR_RX.findall(tag)}
                if attrs.get("targetmode", "").lower() == "external":
                    out.append({"part": info.filename, "type": attrs.get("type", "").rsplit("/", 1)[-1],
                                "target": attrs.get("target", "")[:300]})
    return out


def analyze_office(data: bytes, fmt: str) -> tuple[dict, list[dict]]:
    from oletools.olevba import VBA_Parser

    findings: list[dict] = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence,
                         "attack": list(attack), "source": "office"})

    if len(data) > MAX_BYTES:
        raise ValueError(f"document over {MAX_BYTES} bytes; macro scan skipped")
    info: dict = {"format": fmt, "macros": False, "xlm": False, "modules": [], "autoexec": [], "suspicious": [],
                  "iocs": [], "encoded_strings": 0, "external_relationships": []}
    parser = VBA_Parser("sample", data=data)
    try:
        info["macros"] = bool(parser.detect_vba_macros())
        try:
            info["xlm"] = bool(parser.detect_xlm_macros())
        except Exception:  # XLM detection depends on the container type; absence is not an error
            info["xlm"] = False
        if info["macros"]:
            for _, stream, _, _ in parser.extract_macros():
                if stream and len(info["modules"]) < MAX_LIST:
                    info["modules"].append(str(stream)[:120])
            groups: dict[str, list[str]] = {}
            for kind, keyword, _ in parser.analyze_macros(show_decoded_strings=False, deobfuscate=False):
                groups.setdefault(kind, []).append(str(keyword)[:120])
            info["autoexec"] = sorted(set(groups.get(AUTOEXEC, [])))[:MAX_LIST]
            info["suspicious"] = sorted(set(groups.get(SUSPICIOUS, [])))[:MAX_LIST]
            info["iocs"] = sorted(set(groups.get("IOC", [])))[:MAX_LIST]
            info["encoded_strings"] = sum(len(v) for k, v in groups.items()
                                          if k in ("Hex String", "Base64 String", "Dridex string"))
    finally:
        parser.close()
    if fmt == "ooxml":
        info["external_relationships"] = _external_relationships(data)

    if info["macros"] or info["xlm"]:
        kind = "VBA" if info["macros"] else "Excel 4 (XLM)"
        add("office_macros", f"Contains {kind} macros", "medium",
            ", ".join(info["modules"][:5]) or kind, ["T1059.005"])
    if info["autoexec"]:
        add("office_autoexec", "Macro runs automatically when the document opens", "high",
            ", ".join(info["autoexec"][:5]), ["T1204.002"])
    if info["suspicious"]:
        severity = "high" if info["autoexec"] else "medium"
        add("office_suspicious_vba", "Macro uses risky calls (shell, download, file or registry access)", severity,
            ", ".join(info["suspicious"][:8]), ["T1059.005"])
    if info["encoded_strings"] >= 5:
        add("office_encoded_strings", "Macro hides strings (hex, Base64)", "medium",
            f"{info['encoded_strings']} encoded strings", ["T1027"])
    remote = [r for r in info["external_relationships"] if r["target"].lower().startswith(("http", "\\\\", "file:"))]
    templates = [r for r in remote if r["type"].lower() in ("attachedtemplate", "oleobject", "frame", "subdocument")]
    if templates:
        add("office_remote_template", "Loads a template or object from a remote location", "high",
            templates[0]["target"][:200], ["T1221"])
    elif remote:
        add("office_external_links", "Links to external resources", "low",
            f"{len(remote)} link(s), e.g. {remote[0]['target'][:150]}", [])
    return info, findings
