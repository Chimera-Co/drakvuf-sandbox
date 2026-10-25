"""Scripts (PowerShell, JScript, VBScript, batch, HTA/HTML, shell, Python): source preview, decoded layers and
rule findings. Text is only read and pattern-matched; nothing is evaluated. Decoding covers the static encodings
droppers use most (PowerShell -EncodedCommand, FromBase64String literals, long base64 blobs); anything computed at
run time stays for the dynamic run, so the analyzer reports scripts as rule-only coverage."""

from __future__ import annotations

import base64
import binascii
import re

MAX_SOURCE_CHARS = 64 * 1024
MAX_LAYER_CHARS = 32 * 1024
MAX_LAYERS = 6
MAX_DEPTH = 3
LANGS = {"powershell", "javascript", "vbscript", "batch", "hta", "html", "shell", "python"}

ENC_CMD_RX = re.compile(r"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/]{20,}={0,2})")
FROMB64_RX = re.compile(r"(?i)frombase64string\(\s*['\"]([A-Za-z0-9+/\s]{20,}={0,2})['\"]")
B64_RX = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# (id, title, severity, regex, ATT&CK, languages or None for all)
RULES = [
    ("script_download_cradle", "Downloads content from the network", "high",
     r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|start-bitstransfer|"
     r"net\.webclient|msxml2\.(server)?xmlhttp|winhttp\.winhttprequest|urldownloadtofile|\bcurl\s+-|\bwget\s+",
     ["T1105"], None),
    ("script_exec_string", "Executes a constructed string", "high",
     r"invoke-expression|\biex\b\s*[(\$'\"]|\|\s*iex\b|\beval\s*\(|\bexecute(global)?\s*[(\"]|new\s+function\s*\(",
     ["T1059"], None),
    ("script_hidden_window", "Starts a hidden window", "medium",
     r"-w(indowstyle)?\s+h(idden)?\b|\.run\s*\([^)]*,\s*0\s*[,)]|createnowindow", ["T1564.003"], None),
    ("script_encoded_powershell", "Launches PowerShell with an encoded command", "high",
     r"powershell[^\n]{0,80}\s-e(nc(odedcommand)?|c)?\s+[a-z0-9+/]{20}", ["T1059.001", "T1027"], None),
    ("script_defender_tamper", "Changes Microsoft Defender settings", "high",
     r"set-mppreference|add-mppreference|disablerealtimemonitoring|exclusionpath", ["T1562.001"], None),
    ("script_shadow_delete", "Deletes shadow copies or disables recovery", "high",
     r"vssadmin[^\n]{0,30}delete|wmic[^\n]{0,30}shadowcopy[^\n]{0,20}delete|bcdedit[^\n]{0,40}recoveryenabled|"
     r"wbadmin[^\n]{0,20}delete", ["T1490"], None),
    ("script_run_key", "Writes a Run key (persistence)", "high",
     r"currentversion\\\\?run|reg(\.exe)?\s+add[^\n]{0,80}\\run\b", ["T1547.001"], None),
    ("script_scheduled_task", "Creates a scheduled task", "medium",
     r"schtasks[^\n]{0,20}/create|register-scheduledtask|new-scheduledtask", ["T1053.005"], None),
    ("script_lolbin", "Uses a signed binary proxy (LOLBin)", "medium",
     r"\b(mshta|regsvr32|rundll32|certutil|bitsadmin|msiexec|installutil|regasm|odbcconf|cmstp|wmic)(\.exe)?\b",
     ["T1218"], None),
    ("script_certutil_decode", "Decodes or downloads with certutil", "high",
     r"certutil[^\n]{0,40}(-decode|-urlcache|-f\s)", ["T1140", "T1105"], None),
    ("script_wsh_shell", "Runs commands through WScript.Shell / Shell.Application", "medium",
     r"wscript\.shell|shell\.application|\.shellexecute\b", ["T1059.005", "T1059.007"],
     ("javascript", "vbscript", "hta", "html")),
    ("script_adodb_stream", "Writes binary data to disk (ADODB.Stream)", "medium", r"adodb\.stream",
     ["T1105"], ("javascript", "vbscript", "hta", "html")),
    ("script_amsi_bypass", "AMSI bypass pattern", "high", r"amsiutils|amsiinitfailed|amsiscanbuffer",
     ["T1562.001"], None),
    ("script_reflection_load", "Loads code in memory (.NET reflection)", "high",
     r"reflection\.assembly\]::load|\[system\.reflection\.assembly\]|virtualalloc|getdelegateforfunctionpointer",
     ["T1620"], ("powershell",)),
    ("script_credential_access", "Reads credentials or browser data", "high",
     r"mimikatz|sekurlsa|lsass|login data|cookies\.sqlite|\\credentials\\|cryptunprotectdata", ["T1555", "T1003"],
     None),
    ("script_reverse_shell", "Reverse shell pattern", "high",
     r"/dev/tcp/|\bnc\b[^\n]{0,30}\s-e\s|socket\.socket\([^\n]{0,80}connect|pty\.spawn|bash\s+-i\s+>&",
     ["T1059.004"], ("shell", "python")),
    ("script_cron_persistence", "Installs cron or systemd persistence", "high",
     r"crontab\s+-|/etc/cron|systemctl\s+enable|/etc/systemd/system/|\.bashrc|/etc/rc\.local",
     ["T1053.003", "T1543.002"], ("shell", "python")),
    ("script_chmod_exec", "Marks a downloaded file executable and runs it", "medium",
     r"chmod\s+(\+x|[0-7]*7[0-7]*)\s", ["T1222.002"], ("shell", "python")),
    ("script_miner", "Cryptominer indicators", "high", r"stratum\+tcp|xmrig|cryptonight|--donate-level",
     ["T1496"], None),
    ("script_kill_security", "Stops security tools or logging", "medium",
     r"(taskkill|stop-process|kill(all)?)[^\n]{0,40}(defender|msmpeng|antivirus|sysmon|auditd|apparmor)|"
     r"setenforce\s+0|wevtutil\s+cl|clear-eventlog", ["T1562.001", "T1070.001"], None),
]
COMPILED = [(fid, title, sev, re.compile(rx, re.I), attack, langs) for fid, title, sev, rx, attack, langs in RULES]

OBFUSCATION = [
    ("char_codes", r"\[char\]\s*\d+|string\.fromcharcode|\bchrw?\s*\(\s*\d+", 5),
    ("string_concat", r"['\"]\s*\+\s*['\"]|['\"]\s*&\s*['\"]", 20),
    ("backtick_escapes", r"\w`\w", 10),
    ("format_operator", r"['\"]\s*-f\s*['\"(]|\{\d\}\{\d\}", 3),
    ("reverse_or_join", r"-join\s*\(|\.reverse\(\)|\[-1\.\.|strreverse\(", 2),
    ("replace_chains", r"\.replace\(|-replace\s", 6),
    ("caret_escapes", r"\^[a-z]\^[a-z]", 3),
    ("env_var_slicing", r"%[a-z_]+:~-?\d+,\d+%", 2),
    ("long_base64", r"[A-Za-z0-9+/]{200,}={0,2}", 1),
]
OBF_COMPILED = [(name, re.compile(rx, re.I), threshold) for name, rx, threshold in OBFUSCATION]


def _text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _b64(blob: str, utf16: bool) -> str | None:
    try:
        raw = base64.b64decode(re.sub(r"\s", "", blob), validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in (("utf-16-le", "utf-8") if utf16 else ("utf-8", "utf-16-le")):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        sample = text[:2000]
        if sample and sum(c.isprintable() or c in "\r\n\t" for c in sample) / len(sample) > 0.9:
            return text
    return None


def _guess_language(text: str, fallback: str) -> str:
    low = text[:4000].lower()
    if re.search(r"\$\w+\s*=|invoke-|new-object|\[system\.", low):
        return "powershell"
    if re.search(r"createobject\(|\bdim\s|wscript\.echo", low):
        return "vbscript"
    if re.search(r"\bvar\s|\bfunction\s*\(|activexobject", low):
        return "javascript"
    return fallback


def _layers(text: str, language: str) -> list[dict]:
    """Decode static encodings breadth-first, up to MAX_DEPTH levels and MAX_LAYERS layers."""
    out, seen, queue = [], set(), [(text, language, 0)]
    while queue and len(out) < MAX_LAYERS:
        current, lang, depth = queue.pop(0)
        if depth >= MAX_DEPTH:
            continue
        candidates = [("base64 -EncodedCommand", m, True) for m in ENC_CMD_RX.findall(current)]
        candidates += [("FromBase64String", m, False) for m in FROMB64_RX.findall(current)]
        if not candidates:
            candidates = [("base64 blob", m, False) for m in B64_RX.findall(current[:2_000_000])[:10]]
        for method, blob, utf16 in candidates:
            key = blob[:200]
            if key in seen or len(out) >= MAX_LAYERS:
                continue
            seen.add(key)
            decoded = _b64(blob, utf16)
            if not decoded:
                continue
            layer_lang = "powershell" if method.endswith("EncodedCommand") else _guess_language(decoded, lang)
            out.append({"method": method, "language": layer_lang, "depth": depth + 1,
                        "text": decoded[:MAX_LAYER_CHARS], "truncated": len(decoded) > MAX_LAYER_CHARS})
            queue.append((decoded, layer_lang, depth + 1))
    return out


def _obfuscation(text: str) -> dict:
    indicators = []
    for name, rx, threshold in OBF_COMPILED:
        n = len(rx.findall(text[:2_000_000]))
        if n >= threshold:
            indicators.append({"name": name, "count": n})
    lines = text.splitlines() or [""]
    longest = max(len(line) for line in lines)
    if longest > 1000:
        indicators.append({"name": "very_long_line", "count": longest})
    letters = sum(c.isalpha() for c in text[:200_000]) or 1
    symbols = sum(c in "+&^`'\"[](){}%$" for c in text[:200_000])
    density = round(symbols / letters, 3)
    if density > 0.6:
        indicators.append({"name": "symbol_density", "count": density})
    return {"score": min(100, 15 * len(indicators)), "indicators": indicators, "symbol_density": density,
            "longest_line": longest}


def analyze_script(data: bytes, file_info: dict, iocs_fn) -> tuple[dict, dict, list[dict]]:
    """Return (script block, source block, findings). iocs_fn is universal.iocs, run on the decoded layers."""
    language = file_info.get("format", "").split(":", 1)[-1]
    if language not in LANGS:
        language = "text"
    text = _text(data)
    findings: list[dict] = []

    def add(fid, title, severity, evidence, attack=()):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence[:200],
                         "attack": list(attack), "source": "script"})

    layers = _layers(text, language)
    corpus = "\n".join([text] + [layer["text"] for layer in layers])
    suspicious = []
    for fid, title, sev, rx, attack, langs in COMPILED:
        if langs and language not in langs and not any(layer["language"] in langs for layer in layers):
            continue
        m = rx.search(corpus)
        if m:
            evidence = corpus[max(0, m.start() - 40):m.end() + 40].replace("\n", " ")
            suspicious.append({"name": fid, "title": title, "attack": attack, "evidence": evidence[:200]})
            add(fid, title, sev, evidence, attack)
    obf = _obfuscation(text)
    if obf["score"] >= 45:
        add("script_obfuscated", "Heavily obfuscated script", "high" if obf["score"] >= 60 else "medium",
            ", ".join(i["name"] for i in obf["indicators"]), ["T1027"])
    if layers:
        add("script_encoded_layers", "Script hides code in encoded layers", "medium",
            f"{len(layers)} layer(s): " + ", ".join(sorted({layer['method'] for layer in layers})), ["T1027", "T1140"])
    if text.lstrip().startswith("#@~^"):
        add("script_windows_encoded", "Windows Script Encoder (.jse/.vbe) encoded script", "medium",
            "#@~^ header", ["T1027"])

    decoded_iocs = iocs_fn([layer["text"] for layer in layers]) if layers else {}
    script = {"language": language, "size": len(data), "lines": text.count("\n") + 1, "obfuscation": obf,
              "suspicious": suspicious, "layers": len(layers),
              "iocs": {k: v for k, v in decoded_iocs.items() if v and k != "base64_blobs"}}
    source = {"language": language, "text": text[:MAX_SOURCE_CHARS], "truncated": len(text) > MAX_SOURCE_CHARS,
              "layers": layers}
    return script, source, findings
