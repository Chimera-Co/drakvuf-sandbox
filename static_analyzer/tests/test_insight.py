"""Offline analyst metadata tests using benign fixtures and synthetic bytes."""

import json
import struct
import sys
from pathlib import Path

import pefile
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chimera_static import knowledge as K
from chimera_static.analyze import analyze
from chimera_static.indicators import build
from chimera_static.insight import flagged_strings, layout, magic
from chimera_static.plugins.elf import analyze_elf
from chimera_static.plugins.pe import analyze_pe
from chimera_static.plugins.pe_insight import manifest

FIXTURES = Path(__file__).parent / "fixtures"
CATEGORIES = set("""injection memory process thread execution persistence service registry file network internet crypto
anti_debug anti_vm evasion enumeration credential keylogging_input screen_capture privilege dynamic_loading hooking
synchronization system_info ui com wmi driver_kernel ransomware misc""".split())


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, key
        result[key] = value
    return result


@pytest.mark.parametrize("name,minimum", [("winapi", 450), ("libraries", 90), ("linux_symbols", 190),
                                         ("strings_rules", 10)])
def test_knowledge(name, minimum):
    path = Path(K.__file__).with_name("knowledge") / (name + ".json")
    table = json.loads(path.read_text(), object_pairs_hook=no_duplicates)
    assert len(table) >= minimum
    assert K.load(name) is K.load(name)
    assert table == K.load(name)
    for key, entry in table.items():
        assert isinstance(key, str) and key
        assert 0 <= entry["severity"] <= 3
        if name == "strings_rules":
            assert {"keywords", "regexes", "severity", "attack"} <= entry.keys()
            continue
        assert {"category", "description", "severity"} <= entry.keys()
        assert entry["category"] in CATEGORIES
        assert entry["description"].endswith(".")
        if name != "libraries":
            assert {"attacker_use", "attack", "dll" if name == "winapi" else "lib"} <= entry.keys()
            assert all(__import__("re").fullmatch(r"T\d{4}(?:\.\d{3})?", t) for t in entry["attack"])


def test_normalization():
    assert K.normalize_api("CreateFileW") == K.normalize_api("CreateFileA") == "CreateFile"
    assert K.normalize_api("LoadLibraryExW") == "LoadLibraryEx"
    assert K.api("LoadLibraryExW") != K.api("LoadLibraryW")
    assert K.normalize_api("UnknownW") == "UnknownW"
    assert K.normalize_api("WSAStartup") == "WSAStartup"
    assert K.symbol("ptrace@GLIBC_2.2.5")["category"] == "anti_debug"
    assert K.library("USER32.DLL")["severity"] == 0
    with pytest.raises(ValueError):
        K.load("../outside")


def assert_partition(entries, size):
    cursor = 0
    for rec in entries:
        assert rec["offset"] == cursor
        assert rec["size"] > 0
        assert rec["kind"] in {"header", "section", "overlay", "certificate", "gap"}
        assert 0 <= rec["entropy"] <= 8
        cursor += rec["size"]
    assert cursor == size


def test_layout_malformed_ranges():
    data = bytes(range(256))
    regions = [{"name": "certificate", "kind": "certificate", "offset": 200, "size": 16},
               {"name": "a", "kind": "section", "offset": -10, "size": 100},
               {"name": "b", "kind": "section", "offset": 80, "size": 1000},
               {"name": "bad", "kind": "section", "offset": 2, "size": -5}]
    got = layout(data, regions)
    assert_partition(got, len(data))
    assert any(r["kind"] == "certificate" and r["size"] == 16 for r in got)


def test_pe_fixture():
    data = (FIXTURES / "test.exe").read_bytes()
    out, _ = analyze_pe(data, {"name": "test.exe"}, False)
    assert "insight_error" not in out
    assert out["headers"]["dos"]["e_lfanew"] > 0
    assert out["headers"]["dos"]["standard_stub"]
    assert out["headers"]["file"]["machine_name"] == "IMAGE_FILE_MACHINE_AMD64"
    assert out["headers"]["optional"]["magic"] == "PE32+"
    assert len(out["headers"]["data_directories"]) == 16
    assert out["imports"] and out["exports"] == []
    assert isinstance(out["rich_header"], bool)
    assert isinstance(out["resources"], dict)
    assert out["imports_summary"]["total_count"] == out["import_count"]
    funcs = [f for lib in out["imports_annotated"] for f in lib["functions"]]
    assert funcs
    assert all({"name", "ordinal", "by_ordinal", "severity", "attack", "description"} <= f.keys() for f in funcs)
    assert any(f["description"] for f in funcs)
    assert all(len(s["md5"]) == 32 for s in out["sections"])
    assert sum(s["entry_point"] for s in out["sections"]) == 1
    assert_partition(out["layout"], len(data))
    assert out["tls"]["callbacks"]
    json.dumps(out, allow_nan=False)


def test_analyzer_indicators():
    result = analyze(str(FIXTURES / "test.exe"), ember=False, verify_signature=False)
    assert not [e for e in result["errors"] if e["stage"] in ("pe", "pe_insight", "strings_insight")]
    items = result["indicators"]
    assert items and [i["severity"] for i in items] == sorted([i["severity"] for i in items], reverse=True)
    assert all({"id", "severity", "category", "title", "detail", "evidence", "attack"} == i.keys() for i in items)
    assert sum(result["indicators_summary"].values()) == len(items)
    # Indicators do not contribute to the findings score.
    from chimera_static.analyze import SEVERITY_POINTS
    findings = {f["id"]: f for f in result["findings"]}
    assert result["score"] == min(100, sum(SEVERITY_POINTS[f["severity"]] for f in findings.values()))


def minimal_elf():
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 121, 121, 0x1000)
    return header + program + b"\0"


def test_minimal_elf():
    data = minimal_elf()
    out, _ = analyze_elf(data)
    assert "insight_error" not in out
    assert out["header"]["class"] == 64
    assert out["header"]["machine"] == "EM_X86_64"
    assert out["program_headers"][0]["flags"] == "R-X"
    assert out["security"]["stripped"] and out["security"]["nx"] is None
    assert out["security"]["relro"] == "none"
    assert out["imports_summary"]["total_count"] == 0
    assert any(a["id"] == "elf_section_table_missing" for a in out["anomalies"])
    assert_partition(out["layout"], len(data))
    json.dumps(out, allow_nan=False)


def test_elf_fixture():
    data = (FIXTURES / "linux-x86_64.so").read_bytes()
    out, _ = analyze_elf(data)
    assert "insight_error" not in out
    assert out["needed"] == out["dynamic"]["needed"]
    assert out["imports_annotated"] and out["exports_annotated"]
    assert out["security"]["position_independent"]
    assert not out["security"]["pie"]  # This fixture is a shared library.
    assert out["security"]["nx"] is True
    assert out["security"]["relro"] in ("partial", "full")
    assert out["security"]["stripped"] is False
    assert_partition(out["layout"], len(data))


def test_strings_offsets_and_severity():
    first = b"VirtualAllocEx\0vssadmin delete shadows /all\0\0"
    utf = "powershell -enc ABCD".encode("utf-16-le")
    data = first + utf + b"\0\0/etc/ld.so.preload\0"
    out = flagged_strings(data)
    got = out["strings_flagged"]
    assert [s["severity"] for s in got] == sorted([s["severity"] for s in got], reverse=True)
    assert got[0]["category"] == "recovery_inhibition"
    assert any(s["category"] == "api_injection" and s["offset"] == 0 for s in got)
    assert any(s["encoding"] == "utf-16-le" and s["offset"] == len(first) for s in got)
    assert out["strings_summary"]["linux_persistence"] == 1
    assert len(got) <= 600


def test_strings_late_high_severity_is_retained():
    data = b"wireshark\0" * 650 + b"vssadmin delete shadows\0"
    out = flagged_strings(data)
    assert len(out["strings_flagged"]) == 600
    assert out["strings_flagged_truncated"]
    assert out["strings_flagged"][0]["severity"] == 3
    assert out["strings_summary"]["analysis_artefacts"] == 650


def test_manifest():
    blob = b"""<assembly xmlns="urn:schemas-microsoft-com:asm.v1">
    <dependency><dependentAssembly><assemblyIdentity name="Microsoft.Windows.Common-Controls" version="6.0.0.0"/>
    </dependentAssembly></dependency><trustInfo><requestedExecutionLevel level="requireAdministrator" uiAccess="true"/>
    </trustInfo><compatibility><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></compatibility></assembly>"""
    got = manifest(blob)
    assert got["requestedExecutionLevel"] == "requireAdministrator" and got["uiAccess"] is True
    assert got["dependencies"][0]["name"] == "Microsoft.Windows.Common-Controls"
    assert got["supportedOS"][0]["version"] == "Windows 10 / Windows 11"
    assert "error" in manifest(b'<!DOCTYPE x [<!ENTITY y "boom">]><x>&y;</x>')
    assert "error" in manifest(b"<broken")


def test_pe_certificate_layout_and_trailing_overlay():
    data = bytearray((FIXTURES / "test.exe").read_bytes())
    parsed = pefile.PE(data=bytes(data))
    sec = parsed.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    offset = sec.get_file_offset()
    cert_off = (len(data) + 7) & ~7
    data += bytes(cert_off - len(data)) + struct.pack("<IHH", 16, 0x200, 2) + bytes(8) + b"PK\x03\x04tail"
    struct.pack_into("<II", data, offset, cert_off, 16)
    out, _ = analyze_pe(bytes(data), {"name": "test.exe"}, False)
    assert_partition(out["layout"], len(data))
    cert = next(r for r in out["layout"] if r["kind"] == "certificate")
    assert cert["offset"] == cert_off and cert["size"] == 16
    assert any(r["magic"] == "ZIP" for r in out["overlay_regions"])
    assert out["certificate"]["verified"] is None


@pytest.mark.parametrize("data,kind", [(b"MZxx", "PE"), (b"MSCFxx", "CAB"), (b"7z\xbc\xaf\x27\x1c", "7z"),
                                       (b"NullsoftInst", "NSIS"), (b"Inno Setup", "Inno"),
                                       (b"InstallShield", "InstallShield"), (b"<assembly/>", "manifest XML")])
def test_content_magic(data, kind):
    assert magic(data) == kind


def test_elf_recovers_dynamic_symbols_without_section_headers():
    data = bytearray((FIXTURES / "linux-x86_64.so").read_bytes())
    # ELF64 section table offset, section count and string table index.
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<HH", data, 60, 0, 0)
    out, _ = analyze_elf(bytes(data))
    assert out["sections"] == []
    assert out["symbols_source"] == "dynamic_segment"
    assert out["imports_annotated"]
    assert out["dynamic"]["needed"]
    assert_partition(out["layout"], len(data))


def test_package_data_installed():
    # The knowledge base ships as package data; a wheel built without it would silently lose every description.
    from importlib.resources import files

    names = {p.name for p in files("chimera_static").joinpath("knowledge").iterdir()}
    assert {"winapi.json", "libraries.json", "linux_symbols.json", "strings_rules.json"} <= names


def test_string_candidate_scan_limit():
    out = flagged_strings(b"abcd\0" * 100001)
    assert out["strings_candidates_scanned"] == 100000
    assert out["strings_scan_truncated"]


@pytest.mark.parametrize("kind,filename", [("pe", "test.exe"), ("elf", "linux-x86_64.so")])
def test_optional_insight_failure_preserves_existing_fields(kind, filename, monkeypatch):
    def broken(*args):
        raise ValueError("malformed optional metadata")

    monkeypatch.setattr("chimera_static.plugins." + kind + "_insight.enrich", broken)
    result = analyze(str(FIXTURES / filename), ember=False, verify_signature=False)
    assert kind in result and result[kind]["imports" if kind == "pe" else "sections"]
    assert any(e["stage"] == kind + "_insight" for e in result["errors"])


def test_pe_annotation_limits_and_forwarded_export():
    from types import SimpleNamespace as NS
    from chimera_static.plugins.pe_insight import enrich

    data = (FIXTURES / "test.exe").read_bytes()
    out, _ = analyze_pe(data, {"name": "test.exe"}, False)
    pe = pefile.PE(data=data)
    pe.DIRECTORY_ENTRY_IMPORT = [
        NS(dll=b"kernel32.dll", imports=[NS(name=b"CreateRemoteThread", ordinal=None)] * 3001)]
    pe.DIRECTORY_ENTRY_EXPORT = NS(symbols=[
        NS(name=b"CreateFileW", ordinal=7, address=0x1000, forwarder=b"KERNELBASE.CreateFileW")])
    leaf = NS(id=1033, name=None, data=NS(struct=NS(OffsetToData=0x1000, Size=16)))
    names = [NS(id=i, name=None, directory=NS(entries=[leaf])) for i in range(501)]
    pe.DIRECTORY_ENTRY_RESOURCE = NS(entries=[NS(id=10, name=None, directory=NS(entries=names))])
    enrich(pe, data, out, {"name": "test.exe"})
    funcs = [f for lib in out["imports_annotated"] for f in lib["functions"]]
    assert len(funcs) == 3000
    assert out["imports_summary"]["total_count"] == 3001
    assert out["imports_summary"]["truncated"]
    assert len(out["resources_annotated"]) == 500 and out["resources_truncated"]
    exp = out["exports_annotated"][0]
    assert exp["flagged"] and exp["ordinal"] == 7
    assert exp["forwarded_target"] == "KERNELBASE.CreateFileW"
    pe.close()


def test_indicators_sum_up_ordinary_imports_and_skip_imported_api_strings():
    from chimera_static.indicators import build

    def fn(name, severity, category="process"):
        return {"name": name, "severity": severity, "category": category, "description": "d",
                "attacker_use": "", "attack": ["T1057"]}

    result = {
        "pe": {"imports_annotated": [{"dll": "kernel32.dll", "severity": 0, "description": "", "functions": [
            fn("GetCurrentProcess", 1), fn("LoadLibraryA", 1, "dynamic_loading"),
            fn("WriteProcessMemory", 2, "injection"), fn("CloseHandle", 0)]}]},
        "universal": {"strings_flagged": [
            {"value": "LoadLibraryA", "category": "api_dynamic_loading", "severity": 1, "offset": 1,
             "encoding": "ascii"},
            {"value": "VirtualAllocEx", "category": "api_injection", "severity": 2, "offset": 2,
             "encoding": "ascii"},
            {"value": "vssadmin delete shadows", "category": "shell_command", "severity": 3, "offset": 3,
             "encoding": "ascii"},
            {"value": "bcdedit /set", "category": "shell_command", "severity": 2, "offset": 4,
             "encoding": "ascii"}]},
    }
    items, summary = build(result)
    titles = [item["title"] for item in items]
    assert "Import: WriteProcessMemory" in titles
    assert "Import: GetCurrentProcess" not in titles  # ordinary: summed up instead
    noted = next(item for item in items if item["id"] == "pe_api_noted")
    assert noted["title"] == "2 imports worth noting" and noted["attack"] == []
    assert "String: api dynamic loading (1)" not in titles  # the file imports LoadLibraryA anyway
    assert "String: api injection (1)" in titles  # resolved at run time: worth a look
    shell = next(item for item in items if item["id"] == "string_shell_command")
    assert shell["severity"] == 3 and shell["title"] == "String: shell command (2)"
    assert (summary["high"], summary["medium"]) == (1, 2)  # low also has the ASLR/DEP/CFG header checks
