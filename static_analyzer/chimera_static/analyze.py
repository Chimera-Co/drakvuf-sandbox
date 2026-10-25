"""Run every applicable static analysis on one file and build `chimera-static/1`."""

from __future__ import annotations

import json
import os
import time

from . import ANALYZER_VERSION, SCHEMA
from . import universal as U
from .identify import identify
from .safety import read_sample, write_output

SEVERITY_POINTS = {"info": 0, "low": 4, "medium": 12, "high": 25}
ML_FORMATS = {"pe", "elf", "pdf"}
TYPE_PLUGINS = {"pe", "elf", "pdf", "ole", "ooxml", "zip", "ipa", "apk", "lnk", "rtf", "script"}
# Formats analyzed by rules only (no ML model, run-time behaviour unknown): never full coverage.
RULE_ONLY = {"lnk", "rtf", "script"}
EMBER_MAX_BYTES = 128 * 1024 * 1024


def _level(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 35 else "low" if score >= 15 else "clean"


def _yara_severity(meta: dict) -> str:
    """Rule metadata -> finding severity. ReversingLabs rules carry category + tc_detection_factor (1-5)."""
    sev = str(meta.get("severity", meta.get("threat_level", ""))).lower()
    if sev in SEVERITY_POINTS:
        return sev
    category = str(meta.get("category", "")).upper()
    if category in ("MALWARE", "EXPLOIT"):
        try:
            factor = int(meta.get("tc_detection_factor", 0))
        except (TypeError, ValueError):
            factor = 0
        return "high" if factor >= 4 else "medium"
    return "medium"  # e.g. ReversingLabs "INFO" certificate rules: signer seen on malware, or leaked


def _type_findings(t: dict) -> list[dict]:
    out = []

    def add(fid, title, severity, evidence, attack):
        out.append({"id": fid, "title": title, "severity": severity, "evidence": evidence, "attack": attack,
                    "source": "identify"})

    exe_like = t["format"] in ("pe", "elf", "macho", "lnk") or t["format"].startswith("script:")
    if t.get("extension_mismatch"):
        sev = "high" if exe_like else "low"
        add("type_extension_mismatch", "File type does not match its extension", sev,
            f"{t['format']} named *{t.get('extension') or '(none)'}", ["T1036.008"])
    if t.get("double_extension"):
        add("type_double_extension", "Double extension (e.g. invoice.pdf.exe)", "high", "", ["T1036.007"])
    if t.get("rtlo_in_name"):
        add("type_rtlo", "Right-to-left override character in the name", "high", "", ["T1036.002"])
    return out


def analyze(path: str, out_dir: str | None = None, file_name: str = "", timeout_s: float = 60.0,
            verify_signature: bool = True, ember: bool = True, hardening: dict | None = None) -> dict:
    t0 = time.monotonic()
    result: dict = {"schema": SCHEMA, "analyzer_version": ANALYZER_VERSION,
                    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "errors": [], "findings": [],
                    "hardening": hardening or {}}

    def over_budget(fraction=0.8):
        return time.monotonic() - t0 > timeout_s * fraction

    def stage(name, fn, heavy=False):
        if heavy and over_budget():
            result["errors"].append({"stage": name, "error": "skipped: time budget"})
            return None
        s = time.monotonic()
        try:
            return fn()
        except MemoryError:
            result["errors"].append({"stage": name, "error": "MemoryError (limit reached)"})
        except Exception as exc:  # one parser failing must not lose the rest
            result["errors"].append({"stage": name, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
        finally:
            result.setdefault("timings_s", {})[name] = round(time.monotonic() - s, 3)
        return None

    data, info = read_sample(path)
    name = file_name or os.path.basename(path)
    result["file"] = {"name": name, **info}
    t = stage("identify", lambda: identify(data, name)) or {"format": "unknown"}
    result["type"] = t
    result["findings"] += _type_findings(t)
    result["file"].update(stage("hashes", lambda: U.hashes(data)) or {})

    universal = {"entropy": round(U.entropy(data), 4)}
    universal["entropy_profile"] = stage("entropy_profile", lambda: U.entropy_profile(data)) or {}
    strs, stats = stage("strings", lambda: U.strings(data)) or ([], {})
    universal["strings"] = {**stats, "sample": [s[:200] for s in strs[:U.MAX_STRINGS_KEPT]]}
    universal["iocs"] = stage("iocs", lambda: U.iocs(strs)) or {}
    result["findings"] += stage("keywords", lambda: U.keyword_findings(strs)) or []
    universal["embedded"] = stage("embedded", lambda: U.embedded(data, t["format"])) or []
    universal["yara_ruleset"] = U.yara_ruleset()
    ymatch = stage("yara", lambda: U.yara_matches(data, timeout_s=int(max(5, timeout_s / 4))), heavy=True)
    if ymatch:
        universal["yara"], note = ymatch
        if note:
            result["errors"].append({"stage": "yara", "error": note})
        for m in universal["yara"]:
            result["findings"].append({"id": f"yara_{m['rule']}", "title": f"YARA: {m['rule']}",
                                       "severity": _yara_severity(m["meta"]),
                                       "evidence": str(m["meta"].get("description", ""))[:200], "attack": [],
                                       "source": "yara"})
    from .insight import flagged_strings

    universal.update(stage("strings_insight", lambda: flagged_strings(data)) or {})
    result["universal"] = universal
    # APKs carry native libraries (lib/<abi>/*.so) as stored ELF files by design; only a PE inside one is odd.
    # ELF code in assets/ is the APK plugin's "packed" finding.
    embedded_exec = [e for e in universal["embedded"]
                     if e["type"] in (("pe",) if t["format"] == "apk" else ("pe", "elf"))]
    if embedded_exec and t["format"] not in ("pe", "elf"):
        result["findings"].append({"id": "embedded_executable", "title": "Executable embedded in a non-executable file",
                                   "severity": "high", "evidence": f"{len(embedded_exec)} at offset(s) "
                                   f"{[e['offset'] for e in embedded_exec[:5]]}", "attack": ["T1027.009"],
                                   "source": "universal"})
    elif len(embedded_exec) > 1 and t["format"] == "pe":
        result["findings"].append({"id": "embedded_executable", "title": "Further executables embedded in this one",
                                   "severity": "medium", "evidence": f"{len(embedded_exec)} found",
                                   "attack": ["T1027.009"], "source": "universal"})

    # ---- type plugins
    fmt = t["format"]
    if fmt == "pe":
        from .plugins.pe import analyze_pe
        got = stage("pe", lambda: analyze_pe(data, result["file"], verify_signature), heavy=True)
        if got:
            result["pe"], f = got
            if result["pe"].get("insight_error"):
                result["errors"].append({"stage": "pe_insight",
                                         "error": result["pe"]["insight_error"]})
            result["findings"] += f
        if t.get("dotnet"):
            import pefile

            from .plugins.dotnet import analyze_dotnet
            dn = stage("dotnet", lambda: analyze_dotnet(pefile.PE(data=data, fast_load=True)), heavy=True)
            if dn:
                result["dotnet"] = dn
                strs_dn = dn["user_strings"]
                dn_iocs = U.iocs(strs_dn)
                result["dotnet"]["iocs"] = {k: v for k, v in dn_iocs.items() if v and k != "base64_blobs"}
                result["findings"] += U.keyword_findings(strs_dn)
    elif fmt == "elf":
        from .plugins.elf import analyze_elf
        got = stage("elf", lambda: analyze_elf(data), heavy=True)
        if got:
            result["elf"], f = got
            if result["elf"].get("insight_error"):
                result["errors"].append({"stage": "elf_insight",
                                         "error": result["elf"]["insight_error"]})
            result["findings"] += f
    elif fmt == "pdf":
        from .plugins.pdf import analyze_pdf
        got = stage("pdf", lambda: analyze_pdf(data), heavy=True)
        if got:
            result["pdf"], f = got
            result["findings"] += f
    elif fmt in ("ole", "ooxml"):
        from .plugins.office import analyze_office
        got = stage("office", lambda: analyze_office(data, fmt), heavy=True)
        if got:
            result[fmt], f = got
            result["findings"] += f
    elif fmt == "apk":
        from .plugins.apk import analyze_apk
        got = stage("apk", lambda: analyze_apk(data), heavy=True)
        if got:
            result["apk"], f = got
            result["findings"] += f
        # The manifest, permissions and DEX strings are read; DEX code is not analyzed and APK signatures are
        # parsed, not cryptographically verified.
        result["errors"].append({"stage": "archive-contents",
                                 "error": "DEX code is not decompiled or analyzed; signatures are not verified"})
    elif fmt == "lnk":
        from .plugins.lnk import analyze_lnk
        got = stage("lnk", lambda: analyze_lnk(data), heavy=True)
        if got:
            result["lnk"], f = got
            result["findings"] += f
    elif fmt == "rtf":
        from .plugins.rtf import analyze_rtf
        got = stage("rtf", lambda: analyze_rtf(data), heavy=True)
        if got:
            result["rtf"], f = got
            result["findings"] += f
    elif fmt.startswith("script:"):
        from .plugins.script import analyze_script
        got = stage("script", lambda: analyze_script(data, t, U.iocs), heavy=True)
        if got:
            result["script"], result["source"], f = got
            result["findings"] += f
    elif fmt in ("zip", "ipa"):
        # An iOS app is a ZIP (Payload/<name>.app/); MobSF reads the app itself on the deep queue.
        from .plugins.archive import analyze_zip
        got = stage("zip", lambda: analyze_zip(data), heavy=True)
        if got:
            result[fmt], f = got
            result["findings"] += f
        # Members are listed, never unpacked: nothing inside was analyzed, so this is never full coverage.
        result["errors"].append({"stage": "archive-contents",
                                 "error": "archive members are listed, not unpacked or analyzed"})
    else:
        result["errors"].append({"stage": "plugins", "error": f"no type plugin for {fmt} yet (layers 0-1 only)"})

    if fmt in ("pe", "elf"):
        from .indicators import build

        result["indicators"], result["indicators_summary"] = build(result)

    # ---- ML features (EMBER2024 / thrember v3), for formats that have a trained static model
    if ember and fmt in ML_FORMATS:
        if len(data) > EMBER_MAX_BYTES:
            result["errors"].append({"stage": "ember", "error": "skipped: file too large"})
        else:
            from .ember import ember_vector
            vec = stage("ember", lambda: ember_vector(data), heavy=True)
            if vec:
                result["ml"] = {"ember_v3": vec}

    # ---- score (rule-based, MobSF-style); the ML score is added by the classifier
    seen, score = set(), 0
    for f in result["findings"]:
        if f["id"] not in seen:
            seen.add(f["id"])
            score += SEVERITY_POINTS.get(f["severity"], 0)
    result["score"] = min(100, score)
    result["level"] = _level(result["score"])
    # ---- coverage: a low score only means "nothing found" if the layers that look for things ran.
    # The classifier takes benign evidence only from a complete run (YARA is reported, not required).
    failed = sorted({e["stage"] for e in result["errors"]} - {"plugins"})
    family = "script" if fmt.startswith("script:") else fmt
    supported = family in TYPE_PLUGINS
    if family in RULE_ONLY and family in result:
        result["errors"].append({"stage": "rule-only",
                                 "error": f"{family}: rules only, no trained model; run-time behaviour comes from "
                                          "the dynamic run"})
        failed = sorted({e["stage"] for e in result["errors"]} - {"plugins"})
    wants_ml = ember and fmt in ML_FORMATS
    complete = (supported and family in result and (not wants_ml or "ml" in result)
                and not {"identify", "hashes", "strings", "archive-contents", "rule-only"} & set(failed))
    result["coverage"] = {"complete": bool(complete), "type_plugin": family if supported else None,
                          "failed_stages": failed}
    result["duration_s"] = round(time.monotonic() - t0, 3)
    if out_dir:
        write_output(os.path.join(out_dir, "static.json"), json.dumps(result, allow_nan=False).encode())
    return result
