"""Additive PE metadata for analyst inspection; never executes embedded content."""

import datetime
import hashlib
import re
import struct
import uuid
import xml.etree.ElementTree as ET

import pefile

from .. import knowledge as K
from ..insight import byte_entropy, layout, magic

MAX_FUNCTIONS = 3000
STANDARD_SECTIONS = {".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc",
                     ".tls", ".pdata", ".xdata", ".CRT", ".debug", "CODE", "DATA", ".sdata", ".didat"}
DLL_FLAGS = {0x20: "high_entropy_va", 0x40: "aslr", 0x80: "force_integrity", 0x100: "dep",
             0x200: "no_isolation", 0x400: "no_seh", 0x800: "no_bind", 0x1000: "appcontainer",
             0x2000: "wdm_driver", 0x4000: "cfg", 0x8000: "terminal_server_aware"}
# Product identifiers are the high word of each Rich compid, not the build number.
RICH_PRODUCTS = {0x01: "Import0", 0x02: "Linker510", 0x03: "Cvtomf510", 0x04: "Linker600",
                 0x05: "Cvtomf600", 0x06: "Cvtres500", 0x07: "Utc11_Basic", 0x08: "Utc11_C",
                 0x09: "Utc12_Basic", 0x0A: "Utc12_C", 0x0B: "Utc12_CPP", 0x0C: "AliasObj60"}
SUPPORTED_OS = {"e2011457-1546-43c5-a5fe-008deee3d3f0": "Windows Vista",
                "35138b9a-5d96-4fbd-8e2d-a2440225f93a": "Windows 7",
                "4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38": "Windows 8",
                "1f676c76-80e1-4239-95bb-83d0f6d0da78": "Windows 8.1",
                "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a": "Windows 10 / Windows 11"}


def text(value):
    return value.rstrip(b"\0").decode("utf-8", "replace")[:1000] if isinstance(value, bytes) else str(value)[:1000]


def decoded(value, table, prefix):
    return [name.removeprefix(prefix).lower() for bit, name in table.items()
            if isinstance(bit, int) and bit and value & bit == bit]


def manifest(blob):
    out = {"requestedExecutionLevel": None, "uiAccess": None, "dependencies": [], "supportedOS": []}
    if len(blob) > 1 << 20:
        return {**out, "error": "manifest exceeds 1 MiB"}
    # Reject DTDs even for UTF-16 documents; ElementTree must not expand sample entities.
    if b"<!DOCTYPE" in blob.replace(b"\0", b"").upper():
        return {**out, "error": "DTD not parsed"}
    try:
        root = ET.fromstring(blob)
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag == "requestedExecutionLevel":
                out["requestedExecutionLevel"] = node.get("level")
                out["uiAccess"] = node.get("uiAccess", "false").lower() == "true"
            elif tag == "dependentAssembly":
                for child in node:
                    if child.tag.rsplit("}", 1)[-1] == "assemblyIdentity":
                        out["dependencies"].append(dict(child.attrib))
            elif tag == "supportedOS":
                guid = node.get("Id", "").strip("{}").lower()
                out["supportedOS"].append({"guid": guid, "version": SUPPORTED_OS.get(guid, "unknown")})
        out["dependencies"] = out["dependencies"][:100]
        out["supportedOS"] = out["supportedOS"][:100]
    except (ET.ParseError, ValueError) as exc:
        out["error"] = str(exc)[:200]
    return out


def rich_details(pe, data):
    rich = pe.parse_rich_header()
    if not rich:
        return {"present": False, "entries": [], "checksum_valid": None}
    values = rich.get("values", [])
    entries = [{"product_id": comp >> 16, "build": comp & 0xffff, "count": count,
                "product": RICH_PRODUCTS.get(comp >> 16, "unknown")}
               for comp, count in zip(values[::2][:256], values[1::2][:256])]
    checksum_valid = None
    # Rich checksum: DOS bytes excluding e_lfanew, plus rotated compids weighted by count.
    end = data.find(b"Rich", 0x40, pe.DOS_HEADER.e_lfanew)
    if end >= 0 and end + 8 <= len(data):
        key = struct.unpack_from("<I", data, end + 4)[0]
        marker = struct.pack("<I", 0x536e6144 ^ key)
        start = data.rfind(marker, 0x40, end)
        if start >= 0:
            def rol(v, n):
                n &= 31
                return ((v << n) | (v >> ((32 - n) & 31))) & 0xffffffff
            check = start
            for off, byte in enumerate(data[:start]):
                if not 0x3c <= off < 0x40:
                    check = (check + rol(byte, off)) & 0xffffffff
            for comp, count in zip(values[::2], values[1::2]):
                check = (check + rol(comp, count)) & 0xffffffff
            checksum_valid = check == key
    return {"present": True, "entries": entries, "checksum": rich.get("checksum"),
            "checksum_valid": checksum_valid, "truncated": len(values) > 512}


def enrich(pe, data, out, file_info):
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    anomalies = []

    def anomaly(key, category, title, evidence="", severity=1, attack=()):
        anomalies.append({"id": "pe_" + key, "category": category, "title": title,
                          "detail": title, "evidence": str(evidence)[:300], "severity": severity,
                          "attack": list(attack)})

    debug = []
    for dbg in (getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or [])[:256]:
        s = dbg.struct
        rec = {"type": pefile.DEBUG_TYPE.get(s.Type, str(s.Type)), "type_id": s.Type,
               "size": s.SizeOfData, "offset": s.PointerToRawData, "flags": []}
        blob = data[s.PointerToRawData:s.PointerToRawData + min(s.SizeOfData, 65536)]
        if s.Type == 2 and blob.startswith(b"RSDS") and len(blob) >= 24:
            rec.update(guid=str(uuid.UUID(bytes_le=blob[4:20])), age=struct.unpack_from("<I", blob, 20)[0],
                       pdb_path=text(blob[24:].split(b"\0", 1)[0]))
        elif s.Type == 2 and blob.startswith(b"NB10") and len(blob) >= 16:
            rec.update(guid=None, age=struct.unpack_from("<I", blob, 12)[0],
                       pdb_path=text(blob[16:].split(b"\0", 1)[0]))
        path = rec.get("pdb_path", "").lower()
        if any(p in path.replace("/", "\\") for p in ("\\users\\", "\\desktop\\", "\\documents and settings\\")):
            rec["flags"].append("personal_build_path")
            anomaly("pdb_path", "header", "PDB path contains a user profile or Desktop path", rec.get("pdb_path"))
        if s.Type in (12, 13, 16):
            rec["flags"].append({12: "vc_feature", 13: "pogo", 16: "reproducible_build"}[s.Type])
        debug.append(rec)
    out["debug"] = debug
    out["debug_truncated"] = len(getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])) > 256
    reproducible = any(d["type_id"] == 16 for d in debug)
    timestamp_flags = []
    if not fh.TimeDateStamp:
        timestamp_flags.append("zero")
    if reproducible:
        timestamp_flags.append("reproducible_build")
    elif fh.TimeDateStamp > datetime.datetime.now(datetime.timezone.utc).timestamp() + 86400:
        timestamp_flags.append("future")
    for flag in timestamp_flags:
        anomaly("timestamp_" + flag, "header", "Timestamp: " + flag.replace("_", " "), fh.TimeDateStamp)
    stub = data[64:min(pe.DOS_HEADER.e_lfanew, 4096)]
    message = "This program cannot be run in DOS mode."
    stub_strings = re.findall(rb"[\x20-\x7e]{8,256}", stub)
    stub_message = next((text(p).strip().rstrip("$") for p in stub_strings if b"DOS" in p), None)
    out["headers"] = {
        "dos": {"e_lfanew": pe.DOS_HEADER.e_lfanew,
                "stub_message": stub_message,
                "standard_stub": message.encode() in stub, "rich_header_present": bool(out["rich_header"])},
        "file": {"machine": fh.Machine, "machine_name": pefile.MACHINE_TYPE.get(fh.Machine, "unknown"),
                 "number_of_sections": fh.NumberOfSections, "timestamp": fh.TimeDateStamp,
                 "timestamp_utc": out["timestamp_utc"], "timestamp_flags": timestamp_flags,
                 "characteristics": decoded(fh.Characteristics, pefile.IMAGE_CHARACTERISTICS, "IMAGE_FILE_")},
        "optional": {"magic": "PE32+" if oh.Magic == 0x20b else "PE32" if oh.Magic == 0x10b else hex(oh.Magic),
                     "linker_version": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
                     "os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
                     "subsystem_version": f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}",
                     "subsystem": out["subsystem"], "size_of_code": oh.SizeOfCode, "size_of_image": oh.SizeOfImage,
                     "size_of_headers": oh.SizeOfHeaders, "entry_point": oh.AddressOfEntryPoint,
                     "entry_section": out["entry_section"], "image_base": oh.ImageBase,
                     "file_alignment": oh.FileAlignment, "section_alignment": oh.SectionAlignment,
                     "stack_reserve": oh.SizeOfStackReserve, "stack_commit": oh.SizeOfStackCommit,
                     "heap_reserve": oh.SizeOfHeapReserve, "heap_commit": oh.SizeOfHeapCommit,
                     "dll_characteristics": [n for bit, n in DLL_FLAGS.items() if oh.DllCharacteristics & bit]},
        "data_directories": [{"name": pefile.DIRECTORY_ENTRY.get(i, str(i)), "rva": d.VirtualAddress,
                              "size": d.Size, "present": bool(d.VirtualAddress and d.Size),
                              "address_kind": "file_offset" if i == 4 else "rva"}
                             for i, d in enumerate(oh.DATA_DIRECTORY[:16])]}

    regions = [{"name": "Headers", "kind": "header", "offset": 0, "size": oh.SizeOfHeaders}]
    memory = []
    for s, rec in zip(pe.sections[:64], out["sections"]):
        size = s.Misc_VirtualSize
        rec.update(offset=s.PointerToRawData, rva=s.VirtualAddress,
                   characteristics=decoded(s.Characteristics, pefile.SECTION_CHARACTERISTICS, "IMAGE_SCN_"),
                   virtual_raw_ratio=round(size / s.SizeOfRawData, 4) if s.SizeOfRawData else None,
                   entry_point=s.VirtualAddress <= oh.AddressOfEntryPoint < s.VirtualAddress + max(size, s.SizeOfRawData),
                   md5=hashlib.md5(data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]).hexdigest(),
                   flags=[])
        checks = [(rec["w"] and rec["x"], "writable_executable", 2),
                  (rec["x"] and rec["name"] not in (".text", "CODE", ".code", "text"), "executable_noncode_name", 1),
                  (not s.SizeOfRawData and size > 0, "zero_raw_size", 1),
                  (size > 0 and s.SizeOfRawData > max(size * 4, size + 4096), "raw_larger_than_virtual", 1),
                  (rec["entropy"] > 7.2, "high_entropy", 2),
                  (rec["name"] not in STANDARD_SECTIONS, "unusual_name", 1)]
        for condition, flag, severity in checks:
            if condition:
                rec["flags"].append(flag)
                anomaly("section_" + flag, "sections", flag.replace("_", " ").capitalize(), rec["name"], severity)
        regions.append({"name": rec["name"], "kind": "section", "offset": s.PointerToRawData, "size": s.SizeOfRawData})
        memory.append({"name": rec["name"], "rva": s.VirtualAddress, "virtual_size": size,
                       "r": rec["r"], "w": rec["w"], "x": rec["x"]})
    out["sections_truncated"] = len(pe.sections) > 64
    out["memory_layout"] = memory
    ranges = sorted((s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData) for s in pe.sections if s.SizeOfRawData)
    vranges = sorted((s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)) for s in pe.sections)
    for label, spans in (("raw", ranges), ("virtual", vranges)):
        if any(b > c for (_, b), (c, _) in zip(spans, spans[1:])):
            anomaly("section_overlap_" + label, "sections", "Sections overlap in " + label + " layout", severity=2)
    if out["entry_section"] is None and oh.AddressOfEntryPoint:
        anomaly("entry_outside", "header", "Entry point is outside sections", hex(oh.AddressOfEntryPoint), 3)
    elif out["sections"] and out["sections"][-1]["entry_point"]:
        anomaly("entry_last", "header", "Entry point is in the last section", out["entry_section"])
    align = oh.SectionAlignment
    if align:
        end = max([oh.SizeOfHeaders] + [s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections])
        expected = (end + align - 1) // align * align
        if expected != oh.SizeOfImage:
            anomaly("image_size", "header", "SizeOfImage differs from aligned section extent",
                    f"reported {oh.SizeOfImage}, expected {expected}", 2)
    if out["checksum_valid"] is False:
        anomaly("checksum", "header", "PE checksum does not match")

    libraries, functions, total, ordinal_count = [], [], 0, 0
    for entry in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])[:512]:
        dll = text(entry.dll).lower()
        annotated = []
        for imp in entry.imports:
            total += 1
            ordinal_count += imp.name is None
            if len(functions) >= MAX_FUNCTIONS:
                continue
            name = text(imp.name) if imp.name else None
            rec = {"name": name, "ordinal": imp.ordinal, "by_ordinal": imp.name is None,
                   **K.annotation(K.api(name) if name else {})}
            annotated.append(rec)
            functions.append({**rec, "dll": dll})
        if len(libraries) < 100:
            libraries.append({"dll": dll, **{k: K.library(dll).get(k, default) for k, default in
                              (("description", ""), ("category", "misc"), ("severity", 0))},
                              "functions": annotated})
    out["imports_annotated"] = libraries
    out["imports_summary"] = K.imports_summary(functions, total)
    out["imports_summary"]["ordinal_count"] = ordinal_count
    out["imports_summary"]["libraries_truncated"] = len(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) > 100
    if total < 10 and not out["dotnet"]:
        anomaly("tiny_imports", "imports", "Empty or tiny import table", f"{total} functions", 2, ["T1027.002"])
    if ordinal_count > 5 and ordinal_count > total / 2:
        anomaly("ordinal_imports", "imports", "Many imports are resolved by ordinal", f"{ordinal_count}/{total}", 2)
    out["exports_annotated"] = [
        {"name": text(sym.name) if sym.name else None, "ordinal": sym.ordinal, "rva": sym.address,
         "forwarded_target": text(sym.forwarder) if sym.forwarder else None,
         "flagged": bool(K.api(text(sym.name))) if sym.name else False}
        for sym in (getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or [])[:3000]]
    out["exports_truncated"] = out["export_count"] > 3000

    resources, manifests = [], []
    resource_count, resource_bytes = 0, 0
    def walk(node, path=(), depth=0):
        nonlocal resource_count, resource_bytes
        if depth > 3:
            return
        for entry in (getattr(node, "entries", []) or [])[:2000]:
            if resource_count >= 2000:
                return
            ident = str(entry.name)[:256] if entry.name else entry.id
            current = path + (ident,)
            if hasattr(entry, "directory"):
                walk(entry.directory, current, depth + 1)
            elif hasattr(entry, "data"):
                resource_count += 1
                s = entry.data.struct
                resource_bytes += s.Size
                if len(resources) >= 500:
                    continue
                try:
                    off = pe.get_offset_from_rva(s.OffsetToData)
                    # A view avoids copying arbitrarily large resource contents.
                    blob = memoryview(data)[off:off + s.Size] if 0 <= off < len(data) else memoryview(b"")
                    language = current[2] if len(current) > 2 else None
                    rec = {"type": pefile.RESOURCE_TYPE.get(current[0], str(current[0])),
                           "id": current[1] if len(current) > 1 else None,
                           "language": (language & 0x3ff) if isinstance(language, int) else language,
                           "sublanguage": (language >> 10) if isinstance(language, int) else None,
                           "size": s.Size, "bytes_available": len(blob), "entropy": byte_entropy(blob),
                           "magic": magic(bytes(blob[:4096])), "sha256": hashlib.sha256(blob).hexdigest()}
                    resources.append(rec)
                    if current[0] == 24 and len(manifests) < 16:
                        manifests.append(manifest(bytes(blob[:(1 << 20) + 1])))
                except (ValueError, pefile.PEFormatError) as exc:
                    resources.append({"type": str(current[0]), "id": ident, "error": str(exc)[:200]})
    walk(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None))
    out["resources_annotated"] = resources
    out["resources_truncated"] = resource_count > 500
    out["manifest"] = manifests[0] if manifests else None
    out["manifests"] = manifests
    if resource_bytes > len(data) / 2:
        anomaly("large_resources", "resources", "Resources occupy more than half the file", resource_bytes)
    for rec in resources:
        if rec.get("magic") == "PE":
            anomaly("resource_pe", "resources", "PE content in a resource", rec.get("id"), 3, ["T1027.009"])
    fixed = []
    for info in (getattr(pe, "VS_FIXEDFILEINFO", []) or [])[:32]:
        fixed.append({key: getattr(info, key) for key in (
            "Signature", "StrucVersion", "FileVersionMS", "FileVersionLS", "ProductVersionMS",
            "ProductVersionLS", "FileFlagsMask", "FileFlags", "FileOS", "FileType", "FileSubtype",
            "FileDateMS", "FileDateLS")})
    # Keep version_info as the historical flat map of strings.
    version_tables = []
    for group in (getattr(pe, "FileInfo", []) or [])[:32]:
        for entry in group[:64]:
            for table in (getattr(entry, "StringTable", []) or [])[:32]:
                version_tables.append({"language": text(getattr(table, "LangID", "")),
                                       "fields": {text(k): text(v) for k, v in list(table.entries.items())[:256]}})
    out["version_details"] = {"string_tables": version_tables[:128], "fixed": fixed}
    out["version_fixed"] = fixed
    original = out["version_info"].get("OriginalFilename", "")
    mismatch = bool(original and file_info.get("name") and original.lower() != file_info["name"].lower())
    cert_dir = oh.DATA_DIRECTORY[4] if len(oh.DATA_DIRECTORY) > 4 else None
    cert_present = bool(cert_dir and cert_dir.VirtualAddress and cert_dir.Size)
    out["version_flags"] = {"original_filename_mismatch": mismatch,
                            "company_present_unsigned": bool(out["version_info"].get("CompanyName") and not cert_present)}
    for flag, condition in out["version_flags"].items():
        if condition:
            anomaly(flag, "version", flag.replace("_", " ").capitalize(), original)

    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    callbacks, callback_error = [], None
    if tls and tls.struct.AddressOfCallBacks:
        rva = tls.struct.AddressOfCallBacks - oh.ImageBase
        width = 8 if oh.Magic == 0x20b else 4
        for i in range(128):
            try:
                blob = pe.get_data(rva + i * width, width)
            except pefile.PEFormatError:
                callback_error = "callback array outside file-backed sections"
                break
            if len(blob) != width:
                callback_error = "callback array truncated"
                break
            address = int.from_bytes(blob, "little")
            if not address:
                break
            callbacks.append(address)
    out["tls"] = {"callbacks": callbacks, "truncated": len(callbacks) == 128, "error": callback_error}
    if callbacks:
        anomaly("tls", "header", "TLS callbacks execute before the entry point", callbacks, 1, ["T1622"])
    config = getattr(getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None), "struct", None)
    out["load_config"] = {key: getattr(config, attr, None) for key, attr in (
        ("security_cookie", "SecurityCookie"), ("cfg_function_count", "GuardCFFunctionCount"),
        ("seh_handler_count", "SEHandlerCount"))}
    out["rich_header_details"] = rich_details(pe, data)
    sig = out["signature"]
    out["certificate"] = {"present": cert_present, "signer": sig.get("subject", sig.get("signer")),
                          "issuer": sig.get("issuer"), "serial": sig.get("serial"),
                          "not_before": sig.get("not_before"), "not_after": sig.get("not_after"),
                          "thumbprint": sig.get("thumbprint"), "thumbprint_algorithm": sig.get("thumbprint_algorithm"),
                          "counter_signature_time": sig.get("counter_signature_time"),
                          "verified": sig.get("valid"), "reason": sig.get("verify_error") or sig.get("error")
                          or ("verification disabled" if not sig.get("checked") else
                              "no certificate" if not cert_present else "verified" if sig.get("valid") else "not verified")}
    if cert_present and sig.get("valid") is False:
        anomaly("signature_invalid", "signature", "Signature could not be verified", out["certificate"]["reason"], 2)
    overlay_start = max([min(oh.SizeOfHeaders, len(data))] +
                        [min(len(data), s.PointerToRawData + s.SizeOfRawData) for s in pe.sections])
    # Certificate bytes are a distinct region; data after a certificate is still an overlay.
    if overlay_start < len(data):
        regions.append({"name": "Overlay", "kind": "overlay", "offset": overlay_start,
                        "size": len(data) - overlay_start})
    if cert_present:
        regions.insert(0, {"name": "Certificate", "kind": "certificate",
                           "offset": cert_dir.VirtualAddress, "size": cert_dir.Size})
    out["layout"] = layout(data, regions)
    overlays = [r for r in out["layout"] if r["kind"] == "overlay"]
    out["overlay_regions"] = [{**r, "magic": magic(data[r["offset"]:r["offset"] + 4096]),
                               "percent": round(100 * r["size"] / max(1, len(data)), 3)} for r in overlays]
    if out.get("overlay"):
        overlay = out["overlay"]
        overlay.update(magic=magic(data[overlay["offset"]:overlay["offset"] + 4096]),
                       percent=round(100 * overlay["size"] / max(1, len(data)), 3))
    elif overlays:
        out["overlay"] = dict(out["overlay_regions"][0])
    for rec in out["overlay_regions"]:
        if rec["size"] > 65536 and rec["entropy"] > 7.2:
            anomaly("overlay_entropy", "overlay", "Large high-entropy overlay", rec["size"], 2)
    clr_dir = oh.DATA_DIRECTORY[14] if len(oh.DATA_DIRECTORY) > 14 else None
    if clr_dir and clr_dir.VirtualAddress:
        clr = pe.get_data(clr_dir.VirtualAddress, 24)
        if len(clr) >= 20 and struct.unpack_from("<I", clr, 16)[0] & 0x10:
            anomaly("native_clr_entry", "dotnet", "Managed PE declares a native entry point", severity=2)
    if out.get("packers"):
        anomaly("packer", "packer", "Known packer section names", ", ".join(out["packers"]), 2, ["T1027.002"])
    out["anomalies"] = anomalies[:1000]
    out["insight_limits"] = {"functions": 3000, "resources": 500, "sections": 64,
                              "entropy_sample_bytes": 1 << 20}
