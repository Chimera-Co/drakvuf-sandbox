"""Layer 1: checks that apply to every file, whatever its type."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import struct
from collections import Counter

try:
    import tlsh  # py-tlsh
except Exception:  # pragma: no cover - optional
    tlsh = None
try:
    import ppdeep  # pure-Python ssdeep
except Exception:  # pragma: no cover - optional
    ppdeep = None
try:
    import yara
except Exception:  # pragma: no cover - optional
    yara = None

STRINGS_SCAN_BYTES = 32 * 1024 * 1024
MAX_STRINGS_KEPT = 300
MAX_IOCS = 100
ASCII_RX = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RX = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
URL_RX = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>\\^`{|}]{3,300}")
IP_RX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,10}\b")
DOMAIN_RX = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|top|xyz|io|cc|tk|"
                       r"pw|su|club|online|site|live|onion|duckdns\.org|ngrok\.io|in|de|uk|br|ir|kp)\b", re.I)
REG_RX = re.compile(r"(?i)\b(?:HKLM|HKCU|HKEY_[A-Z_]+|SOFTWARE\\Microsoft\\Windows(?: NT)?\\CurrentVersion)"
                    r"\\[^\s\"'<>|]{3,200}")
WINPATH_RX = re.compile(r"(?i)\b[a-z]:\\(?:[^\\/:*?\"<>|\r\n\x00]{1,100}\\)*[^\\/:*?\"<>|\r\n\x00]{1,100}")
BTC_RX = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
B64_RX = re.compile(r"(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# string keywords that are worth a finding (lowercase substring, finding id, severity, title, ATT&CK)
KEYWORDS = [
    ("vssadmin delete shadows", "str_shadow_delete", "high", "Deletes shadow copies", ["T1490"]),
    ("wmic shadowcopy delete", "str_shadow_delete", "high", "Deletes shadow copies", ["T1490"]),
    ("bcdedit /set {default} recoveryenabled no", "str_recovery_off", "high", "Disables Windows recovery", ["T1490"]),
    ("powershell -enc", "str_ps_encoded", "medium", "Encoded PowerShell command", ["T1059.001", "T1027"]),
    ("-encodedcommand", "str_ps_encoded", "medium", "Encoded PowerShell command", ["T1059.001", "T1027"]),
    ("frombase64string", "str_base64_decode", "low", "Decodes Base64 at run time", ["T1140"]),
    ("schtasks /create", "str_schtask", "medium", "Creates a scheduled task", ["T1053.005"]),
    ("\\currentversion\\run", "str_run_key", "medium", "References a Run key (autostart)", ["T1547.001"]),
    ("netsh advfirewall set", "str_firewall", "medium", "Changes firewall settings", ["T1562.004"]),
    ("set-mppreference", "str_defender", "high", "Changes Defender settings", ["T1562.001"]),
    ("disableantispyware", "str_defender", "high", "Changes Defender settings", ["T1562.001"]),
    ("sbiedll.dll", "str_anti_sandbox", "medium", "Looks for analysis tools / sandboxes", ["T1497"]),
    ("vboxservice", "str_anti_vm", "medium", "Looks for virtual machine artefacts", ["T1497.001"]),
    ("vmtoolsd", "str_anti_vm", "medium", "Looks for virtual machine artefacts", ["T1497.001"]),
    ("wireshark", "str_anti_sandbox", "low", "Looks for analysis tools / sandboxes", ["T1497"]),
    ("procmon", "str_anti_sandbox", "low", "Looks for analysis tools / sandboxes", ["T1497"]),
    ("mimikatz", "str_mimikatz", "high", "Mimikatz strings", ["T1003"]),
    ("sekurlsa", "str_mimikatz", "high", "Mimikatz strings", ["T1003"]),
    ("\\login data", "str_browser_creds", "medium", "Reads browser credential stores", ["T1555.003"]),
    ("\\cookies", "str_browser_creds", "low", "Reads browser credential stores", ["T1555.003"]),
    ("wallet.dat", "str_wallet", "medium", "Looks for cryptocurrency wallets", ["T1005"]),
    ("your files have been encrypted", "str_ransom_note", "high", "Ransom note text", ["T1486"]),
    ("/etc/crontab", "str_cron", "medium", "Touches cron (persistence)", ["T1053.003"]),
    ("/etc/ld.so.preload", "str_ld_preload", "high", "LD_PRELOAD persistence/hijack", ["T1574.006"]),
    ("authorized_keys", "str_ssh_keys", "medium", "Touches SSH authorized_keys", ["T1098.004"]),
    ("/dev/tcp/", "str_bash_revshell", "high", "Bash reverse-shell pattern", ["T1059.004"]),
    ("stratum+tcp://", "str_miner", "high", "Cryptominer pool URL", ["T1496"]),
    ("xmrig", "str_miner", "high", "Cryptominer strings", ["T1496"]),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(data).values()))


def entropy_profile(data: bytes, block: int = 4096) -> dict:
    if not data:
        return {"blocks": 0}
    values = [entropy(data[i:i + block]) for i in range(0, min(len(data), 64 * 1024 * 1024), block)]
    high = sum(v > 7.2 for v in values)
    return {"blocks": len(values), "mean": round(sum(values) / len(values), 3), "max": round(max(values), 3),
            "high_entropy_ratio": round(high / len(values), 4)}


def hashes(data: bytes) -> dict:
    out = {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
           "sha256": hashlib.sha256(data).hexdigest()}
    if tlsh is not None and len(data) >= 50:
        try:
            value = tlsh.hash(data)
            out["tlsh"] = value if value and value != "TNULL" else None
        except Exception:
            pass
    if ppdeep is not None and len(data) <= 32 * 1024 * 1024:
        try:
            out["ssdeep"] = ppdeep.hash(data)
        except Exception:
            pass
    return out


def strings(data: bytes) -> tuple[list[str], dict]:
    window = data[:STRINGS_SCAN_BYTES]
    ascii_ = [m.decode("ascii") for m in ASCII_RX.findall(window)]
    utf16 = []
    for m in UTF16_RX.findall(window):
        try:
            utf16.append(m.decode("utf-16-le"))
        except UnicodeDecodeError:
            continue
    return ascii_ + utf16, {"ascii": len(ascii_), "utf16": len(utf16), "scanned_bytes": len(window)}


def _uniq(values, limit=MAX_IOCS):
    out, seen = [], set()
    for v in values:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            out.append(v)
            if len(out) >= limit:
                break
    return out


def iocs(all_strings: list[str]) -> dict:
    text = "\n".join(all_strings)
    ips = []
    for ip in IP_RX.findall(text):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not (addr.is_unspecified or addr.is_loopback or addr.is_multicast or ip.startswith(("0.", "255."))
                or re.fullmatch(r"\d\.\d\.\d\.\d", ip)):  # skip version-number-looking quads like 1.0.0.0
            ips.append(ip)
    urls = _uniq(URL_RX.findall(text))
    domains = _uniq(d.lower() for d in DOMAIN_RX.findall(text))
    return {"urls": urls, "ips": _uniq(ips), "domains": domains, "emails": _uniq(EMAIL_RX.findall(text)),
            "registry": _uniq(REG_RX.findall(text)), "paths": _uniq(WINPATH_RX.findall(text), 50),
            "btc": _uniq(BTC_RX.findall(text), 20),
            "base64_blobs": len(B64_RX.findall(text[:4_000_000]))}


def keyword_findings(all_strings: list[str]) -> list[dict]:
    lowered = "\n".join(all_strings).lower()
    found, seen = [], set()
    for needle, fid, severity, title, attack in KEYWORDS:
        if fid not in seen and needle in lowered:
            seen.add(fid)
            found.append({"id": fid, "title": title, "severity": severity, "evidence": needle,
                          "attack": attack, "source": "strings"})
    return found


EMBED_MAGICS = [(b"MZ", "pe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"%PDF-", "pdf"),
                (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
                (b"{\\rtf", "rtf")]


def embedded(data: bytes, own_format: str, limit: int = 20) -> list[dict]:
    """Other files inside this one (validated where cheap). Offset 0 is the file itself."""
    out = []
    scan = data[:STRINGS_SCAN_BYTES]
    for magic, kind in EMBED_MAGICS:
        start = 1
        while len(out) < limit:
            off = scan.find(magic, start)
            if off < 0:
                break
            start = off + 1
            if kind == "pe":  # MZ is common: require a valid PE header
                if off + 0x40 > len(scan):
                    continue
                e_lfanew = struct.unpack_from("<I", scan, off + 0x3C)[0]
                if e_lfanew > 4096 or scan[off + e_lfanew:off + e_lfanew + 4] != b"PE\0\0":
                    continue
            if kind == "zip" and own_format in ("zip", "ooxml", "apk", "jar"):
                continue  # local headers are expected inside archives
            out.append({"offset": off, "type": kind})
    return sorted(out, key=lambda e: e["offset"])[:limit]


_yara_rules = None


def yara_matches(data: bytes, timeout_s: int = 15) -> tuple[list[dict], str | None]:
    """YARA with the ruleset baked into the image (CHIMERA_STATIC_YARA = compiled file or folder)."""
    global _yara_rules
    if yara is None:
        return [], "yara-python not installed"
    source = os.environ.get("CHIMERA_STATIC_YARA", "/opt/chimera-static/rules")
    if _yara_rules is None:
        if os.path.isfile(source):
            _yara_rules = yara.load(source)
        elif os.path.isdir(source):
            files = {}
            for root, _dirs, names in os.walk(source):
                for n in sorted(names):
                    if n.endswith((".yar", ".yara")):
                        files[os.path.relpath(os.path.join(root, n), source)] = os.path.join(root, n)
            if not files:
                return [], f"no YARA rules in {source}"
            _yara_rules = yara.compile(filepaths=files)
        else:
            return [], f"no YARA rules at {source}"
    matches = _yara_rules.match(data=data, timeout=timeout_s)
    return [{"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags),
             "meta": {k: v for k, v in m.meta.items() if isinstance(v, (str, int, bool))}} for m in matches[:100]], None
