"""PE / DLL / driver / .NET structure (pefile) and Authenticode (signify)."""

from __future__ import annotations

import datetime
import io
import hashlib

import pefile

from ..universal import entropy

try:
    from signify.authenticode import SignedPEFile
except Exception:  # pragma: no cover - optional
    SignedPEFile = None

PACKER_SECTIONS = {"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
                   ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".mpress1": "MPRESS",
                   ".mpress2": "MPRESS", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".themida": "Themida",
                   ".winlice": "WinLicense", ".enigma1": "Enigma", ".pec2": "PECompact", "pec2to": "PECompact",
                   ".packed": "generic", ".rlpack": "RLPack", ".yp": "Y0da", ".perplex": "Perplex",
                   ".spack": "Simple Pack", ".taz": "PESpin", ".boom": "Boomerang", ".ccg": "CCG"}
# imported API -> (category, ATT&CK)
SUSPICIOUS_IMPORTS = {
    "injection": (["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
                   "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
                   "NtQueueApcThread", "RtlCreateUserThread", "NtWriteVirtualMemory"], ["T1055"]),
    "anti_debug": (["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                    "OutputDebugStringA", "NtSetInformationThread"], ["T1622"]),
    "keylogging": (["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
                    "RegisterRawInputDevices"], ["T1056.001"]),
    "download": (["URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW",
                  "WinHttpOpenRequest", "HttpSendRequestA", "HttpSendRequestW"], ["T1105"]),
    "process_enum": (["CreateToolhelp32Snapshot", "Process32First", "Process32FirstW", "EnumProcesses"], ["T1057"]),
    "service": (["CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW", "ChangeServiceConfigA",
                 "ChangeServiceConfigW"], ["T1543.003"]),
    "crypto": (["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt", "BCryptDecrypt",
                "CryptAcquireContextA", "CryptAcquireContextW"], ["T1486", "T1027"]),
    "privilege": (["AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
                   "ImpersonateLoggedOnUser", "DuplicateTokenEx"], ["T1134"]),
    "dynamic_resolve": (["GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                         "LdrGetProcedureAddress"], ["T1027.007"]),
    "credential": (["CredEnumerateA", "CredEnumerateW", "CryptUnprotectData", "LsaRetrievePrivateData"], ["T1555"]),
    "screen": (["BitBlt", "GetDC", "CreateCompatibleBitmap"], ["T1113"]),
}
SUBSYSTEMS = {1: "native", 2: "windows_gui", 3: "windows_cui", 7: "posix", 9: "wince", 10: "efi_application",
              11: "efi_boot_driver", 12: "efi_runtime_driver", 14: "xbox", 16: "boot_application"}


def _name(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("latin-1", "replace")


def _ts(value: int) -> str | None:
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _signature(data: bytes) -> dict:
    if SignedPEFile is None:
        return {"checked": False, "error": "signify not installed"}
    out = {"checked": True, "present": False}
    try:
        spe = SignedPEFile(io.BytesIO(data))
        signed = list(spe.iter_signed_datas())
        out["present"] = bool(signed)
        if not signed:
            return out
        sd = signed[0]
        signer = sd.signer_info
        out["signer"] = str(getattr(signer, "issuer", ""))[:300]
        try:
            cert = next((c for c in sd.certificates if c.serial_number == signer.serial_number), None)
            if cert is not None:
                out["subject"] = str(cert.subject.dn)[:300]
                out["issuer"] = str(cert.issuer.dn)[:300]
                out["not_after"] = cert.valid_to.isoformat()
                out["not_before"] = cert.valid_from.isoformat()
                out["serial"] = str(cert.serial_number)
                fingerprint = getattr(cert, "sha256_fingerprint", None)
                if callable(fingerprint):
                    fingerprint = fingerprint()
                if fingerprint is None:
                    asn1 = getattr(cert, "asn1", None)
                    if asn1 is not None and hasattr(asn1, "dump"):
                        fingerprint = hashlib.sha256(asn1.dump()).hexdigest()
                if fingerprint is not None:
                    out["thumbprint"] = fingerprint.hex() if isinstance(fingerprint, bytes) else str(fingerprint)
                    out["thumbprint_algorithm"] = "sha256"
                countersigner = getattr(signer, "countersigner", None)
                signing_time = getattr(countersigner, "signing_time", None)
                if signing_time is not None:
                    out["counter_signature_time"] = signing_time.isoformat()
        except Exception:
            pass
        try:
            spe.verify()
            out["valid"] = True
        except Exception as exc:
            out["valid"] = False
            out["verify_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return out


def analyze_pe(data: bytes, file_info: dict, verify_signature: bool = True) -> tuple[dict, list[dict]]:
    findings: list[dict] = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence,
                         "attack": list(attack), "source": "pe"})

    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[d] for d in (
        "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "IMAGE_DIRECTORY_ENTRY_TLS", "IMAGE_DIRECTORY_ENTRY_DEBUG", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
        "IMAGE_DIRECTORY_ENTRY_SECURITY", "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")])
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    out: dict = {
        "machine": hex(fh.Machine), "timestamp": fh.TimeDateStamp, "timestamp_utc": _ts(fh.TimeDateStamp),
        "characteristics": hex(fh.Characteristics), "is_dll": pe.is_dll(), "is_driver": pe.is_driver(),
        "subsystem": SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)), "image_base": hex(oh.ImageBase),
        "entry_point": hex(oh.AddressOfEntryPoint), "dll_characteristics": hex(oh.DllCharacteristics),
        "aslr": bool(oh.DllCharacteristics & 0x40), "dep": bool(oh.DllCharacteristics & 0x100),
        "cfg": bool(oh.DllCharacteristics & 0x4000), "checksum_reported": oh.CheckSum,
    }
    try:
        out["checksum_valid"] = oh.CheckSum == 0 or pe.verify_checksum()
    except Exception:
        out["checksum_valid"] = None

    # sections
    ep = oh.AddressOfEntryPoint
    sections, ep_section, packers = [], None, set()
    for s in pe.sections:
        name = _name(s.Name)
        body = s.get_data()[:1 << 20]
        flags = s.Characteristics
        rec = {"name": name, "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
               "entropy": round(entropy(body), 3), "r": bool(flags & 0x40000000), "w": bool(flags & 0x80000000),
               "x": bool(flags & 0x20000000)}
        sections.append(rec)
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_section = name
        if name.lower() in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[name.lower()])
        if rec["w"] and rec["x"]:
            add("pe_wx_section", "Writable and executable section", "medium", name, ["T1027.002"])
        if rec["entropy"] > 7.2 and s.SizeOfRawData > 4096:
            add("pe_high_entropy_section", "Packed or encrypted section (entropy > 7.2)", "medium",
                f"{name} entropy {rec['entropy']}", ["T1027.002"])
        if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 65536 and rec["x"]:
            add("pe_empty_exec_section", "Large executable section with no data on disk (unpacks at run time)",
                "medium", name, ["T1027.002"])
    out["sections"] = sections[:64]
    out["entry_section"] = ep_section
    if ep_section is None and ep:
        add("pe_ep_outside", "Entry point is outside every section", "high", hex(ep), ["T1027.002"])
    elif ep_section and not ep_section.lower().startswith((".text", "code", ".code", "text")) and not packers:
        add("pe_ep_unusual", "Entry point in an unusual section", "low", ep_section)
    if packers:
        out["packers"] = sorted(packers)
        add("pe_packer", "Known packer/protector", "medium", ", ".join(sorted(packers)), ["T1027.002"])

    # imports
    imports, n_funcs, by_cat = {}, 0, {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace").lower()
        funcs = []
        for imp in entry.imports:
            fn = imp.name.decode("latin-1", "replace") if imp.name else f"ord{imp.ordinal}"
            funcs.append(fn)
        n_funcs += len(funcs)
        imports[dll] = funcs[:300]
    flat = {f for fs in imports.values() for f in fs}
    for cat, (apis, attack) in SUSPICIOUS_IMPORTS.items():
        hit = sorted(flat & set(apis))
        if hit:
            by_cat[cat] = hit
    out["imports"] = dict(list(imports.items())[:100])
    out["import_count"] = n_funcs
    out["import_categories"] = by_cat
    try:
        out["imphash"] = pe.get_imphash() or None
    except Exception:
        out["imphash"] = None
    sev = {"injection": "high", "keylogging": "medium", "anti_debug": "low", "download": "medium",
           "credential": "medium", "service": "low", "privilege": "low", "crypto": "low", "process_enum": "low",
           "screen": "low"}
    for cat, hit in by_cat.items():
        if cat in sev:
            add(f"pe_imports_{cat}", f"Imports {cat.replace('_', ' ')} APIs", sev[cat], ", ".join(hit[:6]),
                SUSPICIOUS_IMPORTS[cat][1])
    is_dotnet = bool(getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None)) or "mscoree.dll" in imports
    out["dotnet"] = is_dotnet
    if not is_dotnet and n_funcs and n_funcs < 10 and "dynamic_resolve" in by_cat:
        add("pe_few_imports", "Very few imports, resolved at run time (typical of packers)", "medium",
            f"{n_funcs} imports", ["T1027.002", "T1027.007"])
    if not imports and not is_dotnet and not pe.is_driver():
        add("pe_no_imports", "No import table", "medium", "", ["T1027.002"])

    # exports
    exports = []
    for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        exports.append(sym.name.decode("latin-1", "replace") if sym.name else f"ord{sym.ordinal}")
    out["exports"] = exports[:200]
    out["export_count"] = len(exports)

    # resources
    res_types, res_count, res_high, res_pe = {}, 0, 0, 0
    def walk(node, depth=0, rtype=None):
        nonlocal res_count, res_high, res_pe
        for e in getattr(node, "entries", []) or []:
            t = rtype if depth else (str(e.name) if e.name else pefile.RESOURCE_TYPE.get(e.id, str(e.id)))
            if hasattr(e, "directory") and depth < 3:
                walk(e.directory, depth + 1, t)
            elif hasattr(e, "data") and res_count < 2000:
                res_count += 1
                res_types[t] = res_types.get(t, 0) + 1
                try:
                    blob = pe.get_data(e.data.struct.OffsetToData, min(e.data.struct.Size, 16 * 1024 * 1024))
                except Exception:
                    continue
                if len(blob) > 1024 and entropy(blob) > 7.2:
                    res_high += 1
                if blob[:2] == b"MZ":
                    res_pe += 1
    walk(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None))
    out["resources"] = {"count": res_count, "types": res_types, "high_entropy": res_high, "embedded_pe": res_pe}
    if res_pe:
        add("pe_resource_pe", "Executable embedded in resources (dropper)", "high", f"{res_pe} resource(s)",
            ["T1027.009"])
    if res_high:
        add("pe_resource_encrypted", "Encrypted/compressed resources", "low", f"{res_high} resource(s)", ["T1027"])

    # version info
    vi = {}
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        vi[k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")[:200]
    except Exception:
        pass
    out["version_info"] = vi
    orig = (vi.get("OriginalFilename") or "").lower()
    name = (file_info.get("name") or "").lower()
    if orig and name and not name.endswith(".sample") and orig != name and orig.rsplit(".", 1)[0] not in name:
        add("pe_name_mismatch", "File name differs from its version-info OriginalFilename", "low",
            f"{vi.get('OriginalFilename')} vs {file_info.get('name')}", ["T1036.005"])

    # TLS, overlay, debug, rich header
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    out["tls_callbacks"] = bool(tls and tls.struct.AddressOfCallBacks)
    if out["tls_callbacks"]:
        add("pe_tls_callbacks", "TLS callbacks (code runs before the entry point)", "low", "", ["T1622"])
    overlay_off = pe.get_overlay_data_start_offset()
    if overlay_off:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        overlay = data[overlay_off:]
        # the Authenticode blob lives in the overlay; exclude it
        if sec_dir.VirtualAddress and sec_dir.VirtualAddress >= overlay_off:
            overlay = data[overlay_off:sec_dir.VirtualAddress]
        if overlay:
            out["overlay"] = {"offset": overlay_off, "size": len(overlay), "entropy": round(entropy(overlay[:8 << 20]), 3)}
            if len(overlay) > 65536 and out["overlay"]["entropy"] > 7.2:
                add("pe_overlay", "Large high-entropy overlay (appended payload)", "medium",
                    f"{len(overlay)} bytes", ["T1027"])
    pdb = None
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        entry = getattr(dbg, "entry", None)
        if entry is not None and hasattr(entry, "PdbFileName"):
            pdb = entry.PdbFileName.rstrip(b"\x00").decode("latin-1", "replace")[:300]
    out["pdb_path"] = pdb
    rich = pe.parse_rich_header()
    out["rich_header"] = bool(rich)
    if fh.TimeDateStamp == 0:
        add("pe_zero_timestamp", "Compile timestamp is zero", "info", "")
    elif fh.TimeDateStamp > datetime.datetime.now(datetime.timezone.utc).timestamp() + 86400:
        add("pe_future_timestamp", "Compile timestamp is in the future", "low", out["timestamp_utc"], ["T1070.006"])
    if out["checksum_valid"] is False:
        add("pe_bad_checksum", "PE checksum does not match", "info", "")

    sig = _signature(data) if verify_signature else {"checked": False}
    out["signature"] = sig
    if sig.get("checked") and not sig.get("present"):
        add("pe_unsigned", "Not digitally signed", "info", "")
    elif sig.get("present") and sig.get("valid") is False:
        add("pe_bad_signature", "Digital signature does not verify", "medium", sig.get("verify_error", ""),
            ["T1553.002"])
    from .pe_insight import enrich

    try:
        enrich(pe, data, out, file_info)
    except MemoryError:
        raise
    except Exception as exc:
        out["insight_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    pe.close()
    return out, findings
