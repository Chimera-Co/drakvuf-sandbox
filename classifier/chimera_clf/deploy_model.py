"""CHIMERA classifier: dynamic (DRAKVUF behaviour) + static (file) models, fused into one verdict.

Deployed as /etc/drakrun/classifier/model.py next to featurize.py, hooks.txt, model.txt, meta.json,
family.txt and, for the static part, static_meta.json + static_<pe|elf|pdf>.txt. CPU only, no network,
no pickles: boosters are LightGBM text files, calibrations are JSON tables.

    dynamic  features.json behaviour   -> LightGBM (WinMET + CHIMERA benign)       -> calibrated p_d
    static   features["static"] vector -> LightGBM per format (EMBER2024)         -> calibrated p_s
             (formats without a model:  rule score from static findings, half weight, caps at "suspicious")
    fusion   each part on its own threshold scale: m = logit(p) - logit(t_malicious)
             combined m = weighted mean -> score = sigmoid(m), so 0.5 = "at the malicious threshold"

Weights are fixed (equal) until they can be fitted on paired CHIMERA runs; the result says so.

Check from this folder:
    python -c "import model, json; print(model.classify(json.load(open('features.json')), '.'))"
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import featurize as fz  # noqa: E402  (sibling file)

FUSION_VERSION = "0.1"
RULE_WEIGHT = 0.5
_STATE: dict = {}


def _logit(p: float) -> float:
    p = min(1 - 1e-6, max(1e-6, float(p)))
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-max(-50.0, min(50.0, x))))


def _load():
    if not _STATE:
        import lightgbm as lgb
        import numpy as np

        meta = json.loads((HERE / "meta.json").read_text(encoding="utf-8"))
        if meta.get("featurize_version") != fz.FEATURIZE_VERSION:
            raise RuntimeError(f"featurize.py version {fz.FEATURIZE_VERSION} != model's {meta.get('featurize_version')}")
        _STATE.update(meta=meta, np=np, booster=lgb.Booster(model_file=str(HERE / "model.txt")), static={})
        if meta.get("family") and (HERE / "family.txt").exists():
            _STATE["family"] = lgb.Booster(model_file=str(HERE / "family.txt"))
        smeta_path = HERE / "static_meta.json"
        if smeta_path.exists():
            smeta = json.loads(smeta_path.read_text(encoding="utf-8"))
            _STATE["static_meta"] = smeta
            for name, m in smeta["models"].items():
                path = HERE / f"static_{name}.txt"
                if path.exists():
                    _STATE["static"][name] = lgb.Booster(model_file=str(path))
    return _STATE


def _label(margin_mal: float, margin_sus: float) -> str:
    return "malicious" if margin_mal >= 0 else "suspicious" if margin_sus >= 0 else "benign"


def _component(label, score, model, version, explanation, family=None, weight=None, **extra):
    out = {"label": label, "score": None if score is None else round(float(min(1.0, max(0.0, score))), 4),
           "family": family, "model": model, "model_version": str(version), "weight": weight,
           "explanation": [e for e in explanation if e][:6]}
    out.update(extra)
    return out


# ------------------------------------------------------------------ dynamic part
def _dynamic(features: dict, s: dict) -> dict:
    meta, np = s["meta"], s["np"]
    model, version = meta.get("model", "chimera-lgbm"), meta.get("model_version", "0")
    run = features.get("run") or {}
    if run.get("guest_os") == "linux":
        return _component("unknown", None, model, version, ["Linux run: the dynamic model knows Windows behaviour only."])
    names, allowed = meta["feature_names"], meta.get("api_vocabulary")
    # Gate on the calls the model can see: the vector keeps only api_vocabulary, so a run whose calls
    # are all outside it (e.g. only loader calls) has no API behaviour to judge however many it made.
    raw_calls, calls = fz.hooked_call_count(features), fz.hooked_call_count(features, allowed)
    need = meta.get("min_hooked_calls", 10)
    if calls < need:
        return _component("unknown", None, model, version,
                          [f"No verdict: too little behaviour to judge ({calls} usable of {raw_calls} monitored API "
                           f"calls in the sample's process tree; at least {need} needed)."])
    x = np.asarray([fz.vectorize(features, names, allowed)], dtype=np.float32)
    seen = fz.restrict(features, allowed)
    booster = s["booster"]
    raw = float(booster.predict(x, num_iteration=meta.get("num_iteration"))[0])
    cal = meta["calibration"]
    p = float(np.interp(raw, cal["x"], cal["y"])) if cal.get("x") else raw
    thr = meta["thresholds"]
    m_mal, m_sus = _logit(p) - _logit(thr["malicious"]), _logit(p) - _logit(thr["suspicious"])
    label = _label(m_mal, m_sus)

    contrib = booster.predict(x, num_iteration=meta.get("num_iteration"), pred_contrib=True)[0][:-1]
    per_concept: dict[str, float] = {}
    for name, c in zip(names, contrib):
        if c:
            key = fz.concept(name)
            per_concept[key] = per_concept.get(key, 0.0) + float(c)
    direction = 1 if label in ("malicious", "suspicious") else -1
    reasons, seen_text = [], set()
    for key, _v in sorted(((k, v) for k, v in per_concept.items() if v * direction > 0), key=lambda kv: -abs(kv[1])):
        text = fz.describe(key, seen, direction)
        if text and text not in seen_text:
            seen_text.add(text)
            reasons.append(text)
        if len(reasons) == 4:
            break
    family = None
    fam_meta = meta.get("family")
    if label == "malicious" and "family" in s and fam_meta:
        probs = s["family"].predict(x, num_iteration=fam_meta.get("num_iteration"))[0]
        best = int(np.argmax(probs))
        cls = fam_meta["classes"][best]
        if cls not in ("other", "(n/a)") and probs[best] >= fam_meta.get("min_prob", 0.6):
            family = cls.capitalize()
            reasons.append(f"Closest known family: {family} (p={probs[best]:.2f}, WinMET-trained).")
    if not run.get("complete", True) or run.get("vm_stalled"):
        reasons.append("Telemetry incomplete (VM stall or missing plugin output); behaviour may be under-observed.")
    return _component(label, p, model, version, reasons, family, 1.0, margin_malicious=m_mal, margin_suspicious=m_sus)


# ------------------------------------------------------------------ static part
_SEV = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


def _findings_text(static: dict, n=4) -> list[str]:
    found = [f for f in (static.get("findings") if isinstance(static.get("findings"), list) else []) if isinstance(f, dict)]
    found.sort(key=lambda f: -_SEV.get(f.get("severity"), 0))
    out = []
    for f in found:
        if _SEV.get(f.get("severity"), 0) >= 1 and len(out) < n:
            ev = f" ({str(f['evidence'])[:60]})" if f.get("evidence") else ""
            out.append(f"{str(f.get('title', f.get('id')))[:120]}{ev}")
    return out


def _static(features: dict, s: dict):
    static = features.get("static")
    if not isinstance(static, dict):
        return None
    if static.get("error"):
        return _component("unknown", None, "chimera-static", static.get("analyzer_version", "?"),
                          [f"Static analysis failed: {str(static['error'])[:200]}"])
    fmt = _obj(static.get("type")).get("format", "unknown")
    smeta = s.get("static_meta")
    vec = _obj(_obj(static.get("ml")).get("ember_v3")).get("vector")
    if not (isinstance(vec, list) and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vec)):
        vec = None
    route = (smeta or {}).get("routes", {}).get(fmt)
    findings = _findings_text(static)
    if route and route in s["static"] and vec and len(vec) == smeta["feature"]["dim"]:
        m = smeta["models"][route]
        np = s["np"]
        raw = float(s["static"][route].predict(np.asarray([vec], dtype=np.float32), num_iteration=m["num_iteration"])[0])
        p = float(np.interp(raw, m["calibration"]["x"], m["calibration"]["y"]))
        m_mal, m_sus = _logit(p) - _logit(m["thresholds"]["malicious"]), _logit(p) - _logit(m["thresholds"]["suspicious"])
        label = _label(m_mal, m_sus)
        text = [f"Static {route.upper()} model (EMBER2024): p={p:.2f}."] + findings
        return _component(label, p, f"chimera-static-{route}", smeta.get("model_version", "0"), text, None, 1.0,
                          margin_malicious=m_mal, margin_suspicious=m_sus)
    # no ML model for this format: rule score (MobSF-style), half weight, never more than "suspicious"
    score = static.get("score")
    if not isinstance(score, (int, float)):
        return None
    p = 0.05 + 0.9 * min(100, max(0, score)) / 100
    m_sus = _logit(p) - _logit(0.35)                 # rule level "medium" starts at 35
    m_mal = min(m_sus, -1e-3)                        # rules alone never reach "malicious"
    label = "suspicious" if m_sus >= 0 else "benign" if score < 15 else "unknown"
    return _component(label, p, "chimera-static-rules", static.get("analyzer_version", "?"),
                      [f"Static rules ({fmt}): score {score}/100 ({static.get('level')})."] + findings, None,
                      RULE_WEIGHT, margin_malicious=m_mal, margin_suspicious=m_sus)


# ------------------------------------------------------------------ fusion
def classify(features: dict, analysis_dir: str) -> dict:
    s = _load()
    meta = s["meta"]
    parts = {"dynamic": _dynamic(features, s)}
    st = _static(features, s)
    if st is not None:
        parts["static"] = st
    voting = {k: v for k, v in parts.items() if v["label"] != "unknown" and "margin_malicious" in v}
    version = f"{meta.get('model_version', '0')}+fusion{FUSION_VERSION}"
    clean = {k: {kk: vv for kk, vv in v.items() if not kk.startswith("margin")} for k, v in parts.items()}

    if not voting:
        reasons = [line for v in parts.values() for line in v["explanation"][:2]]
        return {"schema": "chimera-verdict/1", "label": "unknown", "score": 0.0, "family": None,
                "model": "chimera-fusion", "model_version": version, "explanation": reasons[:8], "components": clean}

    wsum = sum(v["weight"] for v in voting.values())
    m_mal = sum(v["weight"] * v["margin_malicious"] for v in voting.values()) / wsum
    m_sus = sum(v["weight"] * v["margin_suspicious"] for v in voting.values()) / wsum
    label = _label(m_mal, m_sus)
    if label == "malicious" and all(v["model"] == "chimera-static-rules" for v in voting.values()):
        label = "suspicious"
    score = _sigmoid(m_mal)  # 0.5 = at the malicious threshold
    used = " + ".join(voting)
    lead = {"malicious": "Malicious", "suspicious": "Suspicious", "benign": "Benign"}[label]
    explanation = [f"{lead} (combined score {score:.2f} from {used}; 0.50 = malicious threshold)."]
    labels = {v["label"] for v in voting.values()}
    if len(voting) > 1 and len(labels) > 1:
        explanation.append("Dynamic and static disagree: " + ", ".join(f"{k} says {v['label']}" for k, v in voting.items()) + ".")
    for name in ("dynamic", "static"):
        if name in parts:
            explanation += [f"{name.capitalize()}: {line}" for line in parts[name]["explanation"][:3]]
    if len(voting) > 1:
        explanation.append("Fusion weights are fixed (not yet fitted on paired CHIMERA runs).")
    family = parts["dynamic"].get("family") if label == "malicious" else None
    return {"schema": "chimera-verdict/1", "label": label, "score": round(score, 4), "family": family,
            "model": "chimera-fusion", "model_version": version, "explanation": explanation[:10], "components": clean}
