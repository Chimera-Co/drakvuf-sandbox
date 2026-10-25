"""In-memory Android metadata and bounded DEX string inspection. No execution or decompilation."""

from __future__ import annotations

# Severity rationale (capabilities are not proof of malicious behavior):
# high   SMS + network, accessibility binding: unusually sensitive control/exfiltration combinations.
# medium Admin, installs, overlays, 3+ collection permissions: broad privileged capabilities.
# medium Debug/absent signatures, dynamic code/exec, multidex/assets payloads: review-worthy heuristics.
# low    Individual collection permissions, boot receiver, pre-23 target: common legitimate capabilities.

import hashlib
import io
import ipaddress
import re
import struct
import zipfile
from urllib.parse import urlsplit

from androguard.core.apk import APK

MAX_APK = 64 * 1024 ** 2
MAX_DEX = 32 * 1024 ** 2
ANDROID = "{http://schemas.android.com/apk/res/android}"
SPY = ("READ_CONTACTS", "READ_CALL_LOG", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION")


def _strings(data):
    """Walk only the DEX string table, without building a bytecode analysis graph."""
    if len(data) < 112 or not data.startswith(b"dex\n"):
        raise ValueError("invalid DEX header")
    count, offset = struct.unpack_from("<II", data, 56)
    if count > (len(data) - offset) // 4 or offset > len(data):
        raise ValueError("invalid DEX string table")
    for index in range(min(count, 200000)):
        pos = struct.unpack_from("<I", data, offset + index * 4)[0]
        for _ in range(5):
            if pos >= len(data):
                raise ValueError("invalid DEX string offset")
            byte = data[pos]
            pos += 1
            if byte < 128:
                break
        else:
            raise ValueError("invalid DEX string length")
        end = data.find(b"\0", pos, min(pos + 4097, len(data)))
        if end >= 0:
            yield data[pos:end].decode("utf-8", "replace")


def analyze_apk(data: bytes) -> tuple[dict, list[dict]]:
    findings = []

    def add(fid, title, severity, evidence):
        findings.append({"id": "apk_" + fid, "title": title, "severity": severity, "evidence": evidence[:300],
                         "attack": [], "source": "apk"})

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > 10000 or sum(i.file_size for i in infos) > 256 * 1024 ** 2:
            raise ValueError("APK exceeds member or uncompressed size budget")
        manifests = [i for i in infos if i.filename == "AndroidManifest.xml"]
        if len(manifests) != 1 or manifests[0].file_size > 4 * 1024 ** 2:
            raise ValueError("missing, duplicate or oversized AndroidManifest.xml")
        apk = APK(data, raw=True)
        if not apk.is_valid_APK():
            raise ValueError("invalid AndroidManifest.xml")
        root = apk.get_android_manifest_xml()
        permissions = set(apk.get_permissions())
        details = apk.get_details_permissions()
        dangerous = sorted(p for p in permissions if "dangerous" in details.get(p, [""])[0].split("|"))
        bindings = {e.get(ANDROID + "permission", "") for e in root.iter()}
        short = {p.removeprefix("android.permission.") for p in permissions | bindings}
        out = {"package": apk.get_package(), "app_name": apk.get_app_name(),
               "version_name": apk.get_androidversion_name(), "version_code": apk.get_androidversion_code(),
               "min_sdk": apk.get_min_sdk_version(), "target_sdk": apk.get_target_sdk_version(),
               "main_activity": apk.get_main_activity(), "permissions": sorted(permissions)[:100],
               "dangerous_permissions": dangerous[:100]}
        exported = []
        for kind in ("activity", "service", "receiver", "provider"):
            nodes = root.findall("application/" + kind)
            if kind == "activity":
                nodes += root.findall("application/activity-alias")
            names = [apk._format_value(e.get(ANDROID + "name", "")) for e in nodes]
            key = {"activity": "activities", "service": "services", "receiver": "receivers",
                   "provider": "providers"}[kind]
            out[key] = {"count": len(names), "names": names[:50]}
            for node, name in zip(nodes, names):
                explicit = node.get(ANDROID + "exported")
                try:
                    legacy_provider = int(out["target_sdk"] or out["min_sdk"] or 1) < 17
                except ValueError:
                    legacy_provider = False
                implicit = legacy_provider if kind == "provider" else node.find("intent-filter") is not None
                if explicit == "true" or (explicit is None and implicit):
                    if len(exported) < 100:
                        exported.append({"type": kind, "name": name,
                                         "permission": node.get(ANDROID + "permission")})
        out["exported_components"] = exported
        schemes = {"v1": False, "v2": False, "v3": False}
        certs = []
        signature_error = None
        try:
            for scheme in schemes:
                schemes[scheme] = getattr(apk, "is_signed_" + scheme)()
            parsed_certs = apk.get_certificates()[:20]
        except (ValueError, IndexError, KeyError, struct.error) as exc:
            signature_error = type(exc).__name__
            parsed_certs = []
        for cert in parsed_certs:
            debug = cert.subject.native.get("common_name", "").lower() == "android debug"
            certs.append({"subject": cert.subject.human_friendly[:1000], "issuer": cert.issuer.human_friendly[:1000],
                          "sha256": hashlib.sha256(cert.dump()).hexdigest(), "debug": debug, **schemes})
        out.update({"certificates": certs, "signature_schemes": schemes,
                    "signature_verification": "certificate extraction only; APK integrity not verified",
                    "signature_error": signature_error})
        if not certs or not any(schemes.values()):
            add("signature", "No parseable APK signing certificate", "medium", "Absent or malformed signing material")
        if any(c["debug"] for c in certs):
            add("debug_certificate", "Android debug signing certificate", "medium", "CN=Android Debug")
        dex = [i for i in infos if re.fullmatch(r"classes(?:[1-9][0-9]*)?\.dex", i.filename)]
        out["dex_count"] = len(dex)
        out["native_libraries"] = [i.filename[:300] for i in infos
                                   if re.fullmatch(r"lib/[^/]+/[^/]+\.so", i.filename)][:100]
        payloads = []
        for member in infos:
            if member.filename.startswith("assets/") and not member.is_dir():
                with z.open(member) as stream:
                    magic = stream.read(4)
                if magic in (b"dex\n", b"\x7fELF") and len(payloads) < 100:
                    payloads.append(member.filename[:300])
        out["asset_payloads"] = payloads
        # DEX or ELF code hidden in assets/ is how Android packers and droppers carry a second stage; several
        # classesN.dex alone is ordinary multidex in any large app.
        if payloads:
            add("packed", "Executable code hidden in assets", "medium",
                f"{len(payloads)} DEX/ELF file(s) in assets/: {', '.join(payloads[:5])}")
        elif len(dex) > 1:
            add("multidex", "Multiple DEX files (multidex)", "low", f"{len(dex)} DEX files; usual for large apps")
        urls, domains, ips, samples, markers, skipped = set(), set(), set(), [], set(), []
        runtime, exec_method = False, False
        for member in dex:
            if len(data) > MAX_APK or member.file_size > MAX_DEX:
                if len(skipped) < 100:
                    skipped.append(member.filename[:300])
                continue
            for value in _strings(z.read(member)):
                runtime |= "java/lang/Runtime" in value or "java.lang.Runtime" in value
                exec_method |= value == "exec"
                for marker in ("DexClassLoader", "Runtime;->exec", "Runtime.exec", "/system/bin/su",
                               "/system/xbin/su", "java/lang/reflect", "Class.forName"):
                    if marker in value:
                        markers.add(marker)
                if len(samples) < 100:
                    samples.append(value[:300])
                for match in re.finditer(r"https?://[^\s<>\"']{1,2000}", value):
                    url = match.group()
                    if len(urls) < 100:
                        urls.add(url)
                    try:
                        host = urlsplit(url).hostname
                    except ValueError:
                        continue
                    if host:
                        try:
                            ip = str(ipaddress.ip_address(host))
                            if len(ips) < 100:
                                ips.add(ip)
                        except ValueError:
                            if len(domains) < 100:
                                domains.add(host)
                for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", value):
                    try:
                        ip = str(ipaddress.ip_address(token))
                        if len(ips) < 100:
                            ips.add(ip)
                    except ValueError:
                        pass
                for host in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b", value):
                    if len(domains) < 100:
                        domains.add(host.lower())
        out.update({"urls": sorted(urls), "domains": sorted(domains), "ips": sorted(ips), "strings": samples,
                    "dex_scan_skipped": skipped})
        if runtime and exec_method:
            markers.add("Runtime.exec")
        if markers:
            add("dynamic_code", "Dynamic loading, reflection or command execution strings", "medium",
                ", ".join(sorted(markers)))
    if {"SEND_SMS", "READ_SMS"} & short and "INTERNET" in short:
        add("sms_internet", "SMS access with Internet permission", "high", "SMS send/read and INTERNET")
    for permission, severity, title in (
        ("BIND_ACCESSIBILITY_SERVICE", "high", "Accessibility service binding"),
        ("BIND_DEVICE_ADMIN", "medium", "Device administrator binding"),
        ("REQUEST_INSTALL_PACKAGES", "medium", "Package installation capability"),
        ("SYSTEM_ALERT_WINDOW", "medium", "Screen overlay capability"),
        ("RECEIVE_BOOT_COMPLETED", "low", "Boot persistence capability"),
    ):
        if permission in short:
            add(permission.lower(), title, severity, permission)
    collection = sorted(set(SPY) & short)
    for permission in collection:
        add(permission.lower(), "Sensitive data collection capability", "low", permission)
    if len(collection) >= 3:
        add("collection_combination", "Multiple sensitive collection capabilities", "medium", ", ".join(collection))
    try:
        if int(out["target_sdk"] or out["min_sdk"] or 1) < 23:
            add("legacy_target", "Targets Android before runtime permissions", "low", "targetSdk < 23")
    except ValueError:
        pass
    return out, findings
