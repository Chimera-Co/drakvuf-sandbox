"""Bounded, additive ELF analyst metadata."""

from elftools.elf.dynamic import DynamicSection, DynamicSegment

from .. import knowledge as K
from ..insight import byte_entropy, layout


def enrich(elf, data, out):
    h = elf.header
    anomalies = []

    def anomaly(key, title, evidence="", severity=1, attack=()):
        anomalies.append({"id": "elf_" + key, "category": "elf", "title": title, "detail": title,
                          "evidence": str(evidence)[:300], "severity": severity, "attack": list(attack)})

    out["header"] = {"class": elf.elfclass, "data": out["endian"], "osabi": out["osabi"],
                     "type": h["e_type"], "machine": h["e_machine"], "entry": h["e_entry"],
                     "flags": h["e_flags"]}
    programs, memory, regions = [], [], [{"name": "ELF header", "kind": "header",
                                          "offset": 0, "size": h["e_ehsize"]}]
    regions += [{"name": name, "kind": "header", "offset": h[offset], "size": h[count] * h[width]}
                for name, offset, count, width in (
                    ("Program headers", "e_phoff", "e_phnum", "e_phentsize"),
                    ("Section headers", "e_shoff", "e_shnum", "e_shentsize"))]
    has_relro, stack, dynamic_sources = False, None, []
    load_segments = []
    for i, seg in enumerate(elf.iter_segments()):
        if i >= 256:
            break
        flags = seg["p_flags"]
        rec = {"type": seg["p_type"], "flags": "".join(letter if flags & bit else "-"
               for letter, bit in (("R", 4), ("W", 2), ("X", 1))), "offset": seg["p_offset"],
               "vaddr": seg["p_vaddr"], "filesz": seg["p_filesz"], "memsz": seg["p_memsz"],
               "align": seg["p_align"]}
        programs.append(rec)
        if seg["p_type"] == "PT_GNU_RELRO":
            has_relro = True
        if seg["p_type"] == "PT_GNU_STACK":
            stack = not bool(flags & 1)
        if seg["p_type"] == "PT_LOAD":
            load_segments.append(seg)
            memory.append({"name": f"LOAD {i}", "rva": seg["p_vaddr"], "virtual_size": seg["p_memsz"],
                           "r": bool(flags & 4), "w": bool(flags & 2), "x": bool(flags & 1)})
            if flags & 3 == 3:
                anomaly("wx_load", "Writable and executable LOAD segment", i, 2, ["T1027.002"])
        if isinstance(seg, DynamicSegment):
            dynamic_sources.append(seg)
    out["program_headers"] = programs
    out["memory_layout"] = memory
    out["program_headers_truncated"] = elf.num_segments() > 256
    needed, rpath, runpath, dynamic_flags = [], [], [], []
    bind_now = False
    imports, exports, all_names, notes = [], [], set(), []
    seen_imports, seen_exports = set(), set()
    imported_total, exported_total, symbols_scanned = 0, 0, 0
    sections, executable_ranges = [], []
    symbol_tables_present = False
    languages = set()
    for i, sec in enumerate(elf.iter_sections()):
        if i >= 512:
            break
        name, typ, flags = sec.name, sec["sh_type"], sec["sh_flags"]
        rec = {"name": name, "type": typ, "size": sec["sh_size"], "offset": sec["sh_offset"],
               "rva": sec["sh_addr"], "characteristics": flags,
               "r": bool(flags & 2), "w": bool(flags & 1), "x": bool(flags & 4), "flags": [],
               # Read the file range directly: do not decompress untrusted SHF_COMPRESSED data.
               "entropy": byte_entropy(data, sec["sh_offset"], sec["sh_size"]) if typ != "SHT_NOBITS" else 0.0}
        if flags & 4:
            executable_ranges.append((sec["sh_addr"], sec["sh_addr"] + sec["sh_size"]))
        if flags & 5 == 5:
            rec["flags"].append("writable_executable")
            anomaly("wx_section", "Writable and executable section", name, 2)
        if name.upper().startswith(("UPX", ".UPX")):
            rec["flags"].append("upx")
        if name and not name.startswith((".", "__")):
            rec["flags"].append("unusual_name")
        if name in (".gopclntab", ".note.go.buildid", ".go.buildinfo"):
            languages.add("Go")
        if name.startswith(".rust"):
            languages.add("Rust")
        if typ != "SHT_NOBITS" and sec["sh_size"]:
            regions.append({"name": name, "kind": "section", "offset": sec["sh_offset"], "size": sec["sh_size"]})
        if isinstance(sec, DynamicSection) and not dynamic_sources:
            dynamic_sources.append(sec)
        if typ in ("SHT_DYNSYM", "SHT_SYMTAB"):
            symbol_tables_present = True
            for j, sym in enumerate(sec.iter_symbols()):
                if j >= 20000 or symbols_scanned >= 40000:
                    break
                symbols_scanned += 1
                if not sym.name:
                    continue
                all_names.add(sym.name)
                if sym["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE"):
                    continue
                undefined = sym["st_shndx"] == "SHN_UNDEF"
                seen, target = (seen_imports, imports) if undefined else (seen_exports, exports)
                # .symtab spells versioned symbols "memcpy@@GLIBC_2.14" while .dynsym says "memcpy": one entry.
                base_name = sym.name.split("@", 1)[0]
                if base_name in seen:
                    continue
                seen.add(base_name)
                if undefined:
                    imported_total += 1
                else:
                    exported_total += 1
                if len(target) < 3000:
                    target.append({"name": sym.name, "value": sym["st_value"], "size": sym["st_size"],
                                   "binding": sym["st_info"]["bind"], "type": sym["st_info"]["type"],
                                   **K.annotation(K.symbol(sym.name)), "lib": K.symbol(sym.name).get("lib")})
        if typ == "SHT_NOTE" and sec["sh_size"] <= 1 << 20:
            try:
                for j, note in enumerate(sec.iter_notes()):
                    if j >= 64 or len(notes) >= 100:
                        break
                    desc = note["n_desc"]
                    notes.append({"name": note["n_name"], "type": note["n_type"],
                                  "value": (desc.hex() if isinstance(desc, bytes) else str(desc))[:500]})
                    if note["n_name"] == "Go":
                        languages.add("Go")
            except (ValueError, TypeError):
                pass
        sections.append(rec)
    # Segment-based dynamic parsing also works when section headers were removed.
    dynamic_values = {}
    for source in dynamic_sources[:1]:
        for i, tag in enumerate(source.iter_tags()):
            if i >= 4096:
                break
            typ = tag.entry.d_tag
            dynamic_values[typ] = tag.entry.d_val
            if typ == "DT_NEEDED":
                if len(needed) < 100:
                    needed.append(tag.needed)
            elif typ == "DT_RPATH":
                rpath.append(tag.rpath[:1000])
            elif typ == "DT_RUNPATH":
                runpath.append(tag.runpath[:1000])
            elif typ == "DT_BIND_NOW":
                bind_now = True
            elif typ in ("DT_FLAGS", "DT_FLAGS_1"):
                value = tag.entry.d_val
                dynamic_flags.append({"tag": typ, "value": value})
                bind_now |= bool(value & (8 if typ == "DT_FLAGS" else 1))
    if not symbol_tables_present and dynamic_sources and isinstance(dynamic_sources[0], DynamicSegment):
        source = dynamic_sources[0]
        _, offset = source.get_table_offset("DT_SYMTAB")
        symbol_rva = dynamic_values.get("DT_SYMTAB")
        symbol_size = dynamic_values.get("DT_SYMENT", 24 if elf.elfclass == 64 else 16)
        expected_size = 24 if elf.elfclass == 64 else 16
        if offset is not None and symbol_rva is not None and symbol_size == expected_size:
            upper = min(len(data) - offset, 20000 * symbol_size)
            # The next dynamic table pointer is a conservative boundary for the symbol table.
            pointers = [v for k, v in dynamic_values.items() if k in
                        ("DT_STRTAB", "DT_HASH", "DT_GNU_HASH", "DT_VERSYM", "DT_RELA", "DT_REL")
                        and v > symbol_rva]
            if pointers:
                upper = min(upper, min(pointers) - symbol_rva)
            count = max(0, upper // symbol_size)
            _, hash_offset = source.get_table_offset("DT_HASH")
            estimated = True
            if hash_offset is not None and hash_offset + 8 <= len(data):
                byteorder = "little" if elf.little_endian else "big"
                declared = int.from_bytes(data[hash_offset + 4:hash_offset + 8], byteorder)
                count = min(count, declared)
                estimated = False
            out["symbols_source"] = "dynamic_segment"
            out["symbols_count_estimated"] = estimated
            for index in range(count):
                sym = source.get_symbol(index)
                symbols_scanned += 1
                if not sym.name:
                    continue
                all_names.add(sym.name)
                if sym["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE"):
                    continue
                undefined = sym["st_shndx"] == "SHN_UNDEF"
                seen, target = (seen_imports, imports) if undefined else (seen_exports, exports)
                # .symtab spells versioned symbols "memcpy@@GLIBC_2.14" while .dynsym says "memcpy": one entry.
                base_name = sym.name.split("@", 1)[0]
                if base_name in seen:
                    continue
                seen.add(base_name)
                if undefined:
                    imported_total += 1
                else:
                    exported_total += 1
                if len(target) < 3000:
                    target.append({"name": sym.name, "value": sym["st_value"], "size": sym["st_size"],
                                   "binding": sym["st_info"]["bind"], "type": sym["st_info"]["type"],
                                   **K.annotation(K.symbol(sym.name)), "lib": K.symbol(sym.name).get("lib")})
    out["sections_insight"] = sections[:128]
    for old, rec in zip(out["sections"], sections):
        old.update({k: v for k, v in rec.items() if k not in ("name", "type", "size", "entropy")})
    out["sections_truncated"] = elf.num_sections() > 128
    out["dynamic"] = {"needed": needed, "rpath": rpath[:100], "runpath": runpath[:100],
                      "bind_now": bind_now, "flags": dynamic_flags[:100]}
    out["imports_annotated"] = imports
    out["exports_annotated"] = exports
    out["exports_truncated"] = exported_total > 3000
    out["imports_summary"] = K.imports_summary(imports, imported_total)
    out["symbols_truncated"] = symbols_scanned >= 40000
    out["notes"] = notes
    if b"rust_begin_unwind" in data[:8 << 20] or b"panicked at" in data[:8 << 20]:
        languages.add("Rust")
    out["languages"] = sorted(languages)
    # ET_DYN alone also denotes a shared library; distinguish executables where possible.
    pie_flag = any(f["tag"] == "DT_FLAGS_1" and f["value"] & 0x08000000 for f in dynamic_flags)
    pie = h["e_type"] == "ET_DYN" and bool(out["interpreter"] or pie_flag)
    out["security"] = {"pie": pie, "position_independent": h["e_type"] == "ET_DYN", "nx": stack,
                       "relro": "full" if has_relro and bind_now else "partial" if has_relro else "none",
                       "stack_canary": "__stack_chk_fail" in all_names,
                       "fortify": any(name.split("@")[0].endswith("_chk") for name in all_names),
                       "stripped": out["stripped"]}
    if stack is False:
        anomaly("executable_stack", "GNU_STACK requests an executable stack", severity=2)
    if not h["e_shoff"] or not h["e_shnum"]:
        anomaly("section_table_missing", "Section header table is absent", severity=2)
    if out["stripped"]:
        anomaly("stripped", "Static symbol table is absent")
        for rec in out["sections"]:
            if rec["name"] == ".dynsym":
                rec["flags"].append("stripped_symtab")
    if h["e_entry"] and not any(start <= h["e_entry"] < end for start, end in executable_ranges):
        anomaly("entry_outside_text", "Entry point is outside executable sections", hex(h["e_entry"]), 2)
    if out.get("packer") == "UPX":
        anomaly("upx", "UPX packing markers", severity=2, attack=["T1027.002"])
    for path in rpath + runpath:
        if any(p == "" or p == "." or p.startswith(("/tmp", "/var/tmp")) for p in path.split(":")):
            anomaly("unsafe_search_path", "Runtime library search path contains a writable location", path, 2)
    # With no sections, LOAD ranges still provide a useful file diagram.
    for i, seg in enumerate(load_segments):
        regions.append({"name": f"LOAD {i}", "kind": "section", "offset": seg["p_offset"], "size": seg["p_filesz"]})
    out["layout"] = layout(data, regions)
    out["anomalies"] = anomalies[:1000]
    out["insight_limits"] = {"functions": 3000, "sections": 128, "entropy_sample_bytes": 1 << 20}
