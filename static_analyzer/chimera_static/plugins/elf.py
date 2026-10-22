"""ELF structure (pyelftools)."""

from __future__ import annotations

import io

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile

from ..universal import entropy

SUSPICIOUS_SYMBOLS = {
    "ptrace": ("anti_debug", "low", ["T1622"]), "prctl": ("process_hiding", "low", ["T1564"]),
    "setuid": ("privilege", "low", ["T1548.001"]), "setgid": ("privilege", "low", ["T1548.001"]),
    "execve": ("execution", "info", ["T1059.004"]), "fork": ("execution", "info", []),
    "socket": ("network", "info", []), "connect": ("network", "info", []),
    "bind": ("network", "low", ["T1571"]), "listen": ("network", "low", ["T1571"]),
    "mprotect": ("memory", "low", ["T1055"]), "memfd_create": ("fileless", "medium", ["T1620"]),
    "init_module": ("rootkit", "high", ["T1547.006"]), "finit_module": ("rootkit", "high", ["T1547.006"]),
    "dlopen": ("dynamic_load", "info", []), "unlink": ("file_delete", "info", ["T1070.004"]),
    "kill": ("process", "info", []), "inotify_add_watch": ("monitoring", "info", []),
}


def analyze_elf(data: bytes) -> tuple[dict, list[dict]]:
    findings = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence,
                         "attack": list(attack), "source": "elf"})

    elf = ELFFile(io.BytesIO(data))
    h = elf.header
    out = {"class": elf.elfclass, "endian": "little" if elf.little_endian else "big", "type": h["e_type"],
           "machine": h["e_machine"], "osabi": h["e_ident"]["EI_OSABI"], "entry": hex(h["e_entry"])}
    interp, needed, exec_stack, segs = None, [], None, []
    for seg in elf.iter_segments():
        segs.append({"type": seg["p_type"], "flags": seg["p_flags"], "filesz": seg["p_filesz"], "memsz": seg["p_memsz"]})
        if seg["p_type"] == "PT_INTERP":
            interp = seg.get_interp_name()
        if seg["p_type"] == "PT_GNU_STACK":
            exec_stack = bool(seg["p_flags"] & 1)
        if seg["p_flags"] & 1 and seg["p_flags"] & 2 and seg["p_type"] == "PT_LOAD":
            add("elf_wx_segment", "Writable and executable LOAD segment", "medium", "", ["T1027.002"])
    out["segments"] = segs[:64]
    out["interpreter"] = interp
    out["static"] = interp is None and h["e_type"] == "ET_EXEC"
    out["exec_stack"] = exec_stack
    sections, has_symtab, symbols = [], False, set()
    for sec in elf.iter_sections():
        if sec.name == ".symtab":
            has_symtab = True
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
        if sec["sh_type"] in ("SHT_DYNSYM", "SHT_SYMTAB") and len(symbols) < 20000:
            for i, sym in enumerate(sec.iter_symbols()):
                if i > 20000:
                    break
                if sym.name:
                    symbols.add(sym.name)
        body = sec.data() if sec["sh_type"] != "SHT_NOBITS" and sec["sh_size"] < 64 * 1024 * 1024 else b""
        sections.append({"name": sec.name, "type": sec["sh_type"], "size": sec["sh_size"],
                         "entropy": round(entropy(body), 3) if body else 0.0})
    out["sections"] = sections[:128]
    out["section_count"] = len(sections)
    out["stripped"] = not has_symtab
    out["needed"] = needed[:100]
    hits = {}
    for name, (cat, sev, attack) in SUSPICIOUS_SYMBOLS.items():
        if name in symbols:
            hits.setdefault(cat, []).append(name)
            if sev in ("medium", "high"):
                add(f"elf_sym_{cat}", f"Uses {cat.replace('_', ' ')} functions", sev, name, attack)
    out["symbol_categories"] = hits
    out["symbol_count"] = len(symbols)
    if b"UPX!" in data[:4096] or any(s["name"].startswith("UPX") for s in sections):
        out["packer"] = "UPX"
        add("elf_upx", "UPX-packed ELF", "medium", "", ["T1027.002"])
    if not sections:
        add("elf_no_sections", "No section headers (stripped or packed)", "medium", "", ["T1027.002"])
    if exec_stack:
        add("elf_exec_stack", "Executable stack", "low", "", [])
    if out["static"] and out["stripped"]:
        add("elf_static_stripped", "Statically linked and stripped (common for Linux malware/IoT bots)", "low", "", [])
    return out, findings
