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
EMBER_MAX_BYTES = 128 * 1024 * 1024


def _level(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 35 else "low" if score >= 15 else "clean"


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
    ymatch = stage("yara", lambda: U.yara_matches(data, timeout_s=int(max(5, timeout_s / 4))), heavy=True)
    if ymatch:
        universal["yara"], note = ymatch
        if note:
            result["errors"].append({"stage": "yara", "error": note})
        for m in universal["yara"]:
            sev = str(m["meta"].get("severity", m["meta"].get("threat_level", "medium"))).lower()
            result["findings"].append({"id": f"yara_{m['rule']}", "title": f"YARA: {m['rule']}",
                                       "severity": sev if sev in SEVERITY_POINTS else "medium",
                                       "evidence": str(m["meta"].get("description", ""))[:200], "attack": [],
                                       "source": "yara"})
    result["universal"] = universal
    embedded_exec = [e for e in universal["embedded"] if e["type"] in ("pe", "elf")]
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
            result["findings"] += f
    elif fmt == "elf":
        from .plugins.elf import analyze_elf
        got = stage("elf", lambda: analyze_elf(data), heavy=True)
        if got:
            result["elf"], f = got
            result["findings"] += f
    elif fmt == "pdf":
        from .plugins.pdf import analyze_pdf
        got = stage("pdf", lambda: analyze_pdf(data), heavy=True)
        if got:
            result["pdf"], f = got
            result["findings"] += f
    else:
        result["errors"].append({"stage": "plugins", "error": f"no type plugin for {fmt} yet (layers 0-1 only)"})

    # ---- ML features (EMBER2024 / thrember v3), for formats that have a trained static model
    if ember and fmt in ML_FORMATS:
        if len(data) > EMBER_MAX_BYTES or info.get("truncated"):
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
    result["duration_s"] = round(time.monotonic() - t0, 3)
    if out_dir:
        write_output(os.path.join(out_dir, "static.json"), json.dumps(result, allow_nan=False).encode())
    return result
