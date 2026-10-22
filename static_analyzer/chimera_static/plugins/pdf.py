"""PDF structure, pdfid-style: count risky keywords (including #xx-obfuscated names). No rendering."""

from __future__ import annotations

import re

KEYWORDS = ["/Page", "/Encrypt", "/ObjStm", "/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm", "/JBIG2Decode",
            "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA", "/URI", "/SubmitForm", "/GoToR", "/GoToE", "/ImportData"]
NAME_RX = re.compile(rb"/[A-Za-z0-9#]{2,40}")
URI_RX = re.compile(rb"/URI\s*\(([^)]{4,500})\)")
RISK = {
    "/JS": ("pdf_javascript", "JavaScript", "medium", ["T1059.007"]),
    "/JavaScript": ("pdf_javascript", "JavaScript", "medium", ["T1059.007"]),
    "/Launch": ("pdf_launch", "Launch action (runs a program)", "high", ["T1204.002"]),
    "/EmbeddedFile": ("pdf_embedded_file", "Embedded file", "medium", ["T1027.006"]),
    "/RichMedia": ("pdf_richmedia", "RichMedia (Flash) content", "medium", ["T1203"]),
    "/JBIG2Decode": ("pdf_jbig2", "JBIG2 stream (past exploit vector)", "low", ["T1203"]),
    "/XFA": ("pdf_xfa", "XFA form", "low", []),
    "/GoToR": ("pdf_gotor", "Remote GoTo action", "low", []),
    "/GoToE": ("pdf_gotoe", "Embedded GoTo action", "low", []),
    "/SubmitForm": ("pdf_submitform", "SubmitForm action (can send data out)", "low", ["T1041"]),
    "/ImportData": ("pdf_importdata", "ImportData action", "low", []),
}


def _normalise(name: bytes) -> tuple[str, bool]:
    if b"#" not in name:
        return name.decode("latin-1"), False
    try:
        out = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), name)
        return out.decode("latin-1"), True
    except ValueError:
        return name.decode("latin-1"), False


def analyze_pdf(data: bytes) -> tuple[dict, list[dict]]:
    findings = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence,
                         "attack": list(attack), "source": "pdf"})

    head = data[:1024]
    off = head.find(b"%PDF-")
    version = head[off + 5:off + 8].decode("latin-1", "replace") if off >= 0 else None
    counts = {k: 0 for k in KEYWORDS}
    obfuscated = 0
    for raw in NAME_RX.findall(data):
        name, was_hex = _normalise(raw)
        if was_hex:
            obfuscated += 1
        if name in counts:
            counts[name] += 1
    out = {"version": version, "header_offset": off, "objects": len(re.findall(rb"\d+\s+\d+\s+obj\b", data)),
           "endobj": data.count(b"endobj"), "streams": data.count(b"endstream"), "xref": data.count(b"xref"),
           "trailer": data.count(b"trailer"), "eof_markers": data.count(b"%%EOF"), "keywords": counts,
           "obfuscated_names": obfuscated,
           "uris": [u.decode("latin-1", "replace") for u in URI_RX.findall(data)[:100]]}
    seen = set()
    for kw, (fid, title, sev, attack) in RISK.items():
        if counts.get(kw) and fid not in seen:
            seen.add(fid)
            add(fid, title, sev, f"{kw} ×{counts[kw]}", attack)
    auto = counts["/OpenAction"] + counts["/AA"]
    if auto and (counts["/JS"] or counts["/JavaScript"]):
        add("pdf_auto_js", "JavaScript that runs when the document opens", "high",
            f"/OpenAction ×{counts['/OpenAction']}, /AA ×{counts['/AA']}", ["T1059.007", "T1204.002"])
    if counts["/Launch"] and auto:
        add("pdf_auto_launch", "Launches a program when opened", "high", "", ["T1204.002"])
    if obfuscated:
        add("pdf_obfuscated_names", "Hex-obfuscated PDF names (evasion)", "medium", f"{obfuscated} names", ["T1027"])
    if off > 0:
        add("pdf_header_offset", "PDF header not at the start of the file (polyglot?)", "low", f"offset {off}", ["T1027"])
    if counts["/Encrypt"]:
        add("pdf_encrypted", "Encrypted PDF", "info", "", [])
    if counts["/Page"] <= 1 and (counts["/JS"] or counts["/JavaScript"] or counts["/EmbeddedFile"]):
        add("pdf_single_page_active", "Single-page PDF carrying active content", "medium", "", ["T1566.001"])
    return out, findings
