"""Synthetic AXML/ZIP fixtures; no external APKs or executable code."""

import io
import struct
import zipfile

import pytest

from chimera_static.plugins.apk import _strings, analyze_apk

NS = "http://schemas.android.com/apk/res/android"


def manifest(permissions=(), binding=None):
    """Encode Android ResXMLTree chunks with a UTF-8 string pool and typed string attributes.

    Chunk layouts follow Android ResourceTypes.h: string pool (0x001), namespace (0x100/101),
    start/end element (0x102/103), under an XML (0x003) header. Values are literal, never resources.
    """
    strings = []

    def idx(value):
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    def chunk(kind, header_size, body):
        return struct.pack("<HHI", kind, header_size, len(body) + 8) + body

    def node(kind, body):
        return chunk(kind, 16, struct.pack("<II", 1, 0xffffffff) + body)

    def start(tag, attrs=()):
        packed = b""
        for namespace, name, value in attrs:
            packed += struct.pack("<IIIHBBI", idx(namespace) if namespace else 0xffffffff,
                                  idx(name), idx(value), 8, 0, 3, idx(value))
        return node(0x102, struct.pack("<IIHHHHHH", 0xffffffff, idx(tag), 20, 20, len(attrs), 0, 0, 0) + packed)

    def end(tag):
        return node(0x103, struct.pack("<II", 0xffffffff, idx(tag)))

    prefix, uri = idx("android"), idx(NS)
    tree = node(0x100, struct.pack("<II", prefix, uri))
    tree += start("manifest", [(None, "package", "org.example.test"), (NS, "versionName", "1.0"),
                               (NS, "versionCode", "1")])
    tree += start("uses-sdk", [(NS, "minSdkVersion", "23"), (NS, "targetSdkVersion", "33")]) + end("uses-sdk")
    for permission in permissions:
        tree += start("uses-permission", [(NS, "name", "android.permission." + permission)]) + end("uses-permission")
    tree += start("application", [(NS, "label", "Synthetic app")])
    if binding:
        tree += start("service", [(NS, "name", ".Access"), (NS, "exported", "true"),
                                  (NS, "permission", "android.permission." + binding)]) + end("service")
    tree += end("application") + end("manifest") + node(0x101, struct.pack("<II", prefix, uri))
    offsets, encoded = [], b""
    for value in strings:
        raw = value.encode()
        assert len(raw) < 128
        offsets.append(len(encoded))
        encoded += bytes([len(value), len(raw)]) + raw + b"\0"
    encoded += b"\0" * (-len(encoded) % 4)
    pool = chunk(1, 28, struct.pack("<IIIII", len(strings), 0, 0x100, 28 + 4 * len(strings), 0)
                 + b"".join(struct.pack("<I", offset) for offset in offsets) + encoded)
    return chunk(3, 8, pool + tree)


def apk_bytes(permissions=(), binding=None, members=()):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest(permissions, binding))
        for name, data in members:
            archive.writestr(name, data)
    return stream.getvalue()


def dex_bytes(values):
    """Minimal string-table fixture; deliberately contains no bytecode, never executed."""
    header = bytearray(112)
    header[:8] = b"dex\n035\0"
    struct.pack_into("<II", header, 56, len(values), 112)
    table, body = b"", b""
    for value in values:
        raw = value.encode()
        assert len(raw) < 128
        table += struct.pack("<I", 112 + 4 * len(values) + len(body))
        body += bytes([len(raw)]) + raw + b"\0"
    return bytes(header) + table + body


def test_benign_internet():
    out, findings = analyze_apk(apk_bytes(["INTERNET"]))
    assert out["package"] == "org.example.test"
    assert out["app_name"] == "Synthetic app"
    assert out["target_sdk"] == "33"
    assert out["permissions"] == ["android.permission.INTERNET"]
    assert not out["dangerous_permissions"]
    assert not any(f["severity"] == "high" for f in findings)
    assert any(f["id"] == "apk_signature" for f in findings)


def test_sms_and_accessibility_binding():
    out, findings = analyze_apk(apk_bytes(["SEND_SMS", "INTERNET"], "BIND_ACCESSIBILITY_SERVICE"))
    high = {f["id"] for f in findings if f["severity"] == "high"}
    assert high == {"apk_sms_internet", "apk_bind_accessibility_service"}
    assert "android.permission.SEND_SMS" in out["dangerous_permissions"]
    assert out["services"] == {"count": 1, "names": ["org.example.test.Access"]}
    assert out["exported_components"][0]["name"] == "org.example.test.Access"
    assert all(set(f) == {"id", "title", "severity", "evidence", "attack", "source"} for f in findings)


def test_missing_manifest_raises():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("ordinary.txt", "not an APK")
    with pytest.raises(ValueError, match="AndroidManifest"):
        analyze_apk(stream.getvalue())


def test_dex_strings_and_assets():
    dex = dex_bytes(["DexClassLoader", "https://example.org/a", "https://192.0.2.1/a", "/system/bin/su"])
    out, findings = analyze_apk(apk_bytes(members=[("classes.dex", dex), ("classes2.dex", dex),
                                                  ("assets/payload", b"\x7fELF"), ("lib/arm64-v8a/a.so", b"")]))
    assert out["dex_count"] == 2
    assert "example.org" in out["domains"]
    assert out["ips"] == ["192.0.2.1"]
    assert out["asset_payloads"] == ["assets/payload"]
    assert out["native_libraries"] == ["lib/arm64-v8a/a.so"]
    assert {"apk_dynamic_code", "apk_packed"} <= {f["id"] for f in findings}


@pytest.mark.parametrize("limit", ["MAX_APK", "MAX_DEX"])
def test_dex_size_skip(monkeypatch, limit):
    monkeypatch.setattr("chimera_static.plugins.apk." + limit, 1)
    out, _ = analyze_apk(apk_bytes(members=[("classes.dex", b"not parsed")]))
    assert out["dex_scan_skipped"] == ["classes.dex"]
    assert not out["strings"]


def test_permission_caps_and_collection():
    permissions = ["CUSTOM_" + str(i) for i in range(110)] + ["CAMERA", "READ_CONTACTS", "RECORD_AUDIO"]
    out, findings = analyze_apk(apk_bytes(permissions))
    assert len(out["permissions"]) == 100
    assert any(f["id"] == "apk_collection_combination" and f["severity"] == "medium" for f in findings)


def test_invalid_dex_table():
    dex = bytearray(dex_bytes(["hello"]))
    struct.pack_into("<I", dex, 60, 0xffffffff)
    with pytest.raises(ValueError, match="table"):
        list(_strings(bytes(dex)))


def test_full_analyzer_routes_apk_and_never_reports_complete(tmp_path):
    from chimera_static.analyze import analyze

    path = tmp_path / "app.apk"
    path.write_bytes(apk_bytes(["SEND_SMS", "INTERNET"], "BIND_ACCESSIBILITY_SERVICE"))
    path.chmod(0o440)
    r = analyze(str(path), file_name="app.apk", timeout_s=60, ember=False)
    assert r["type"]["format"] == "apk" and "apk" in r
    assert any(f["source"] == "apk" and f["severity"] == "high" for f in r["findings"])
    assert r["coverage"]["type_plugin"] == "apk" and r["coverage"]["complete"] is False


def test_multidex_alone_is_low_and_native_libs_are_not_embedded_executables():
    dex = dex_bytes(["ordinary"])
    out, findings = analyze_apk(apk_bytes(members=[("classes.dex", dex), ("classes2.dex", dex),
                                                  ("lib/arm64-v8a/a.so", b"\x7fELF" + b"\0" * 60)]))
    severities = {f["id"]: f["severity"] for f in findings}
    assert severities.get("apk_multidex") == "low" and "apk_packed" not in severities
