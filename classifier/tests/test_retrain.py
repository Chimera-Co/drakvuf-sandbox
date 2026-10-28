"""Retraining changes: CHIMERA malware in training, product/family groups, Platt calibration, cross-fitted
thresholds, fitted fusion, and an end-to-end run of 03_train.py on synthetic data."""

import gzip
import importlib.util
import json
import math
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


loader = _load("load_chimera", ROOT / "scripts" / "02_load_chimera.py")
train = _load("train_v1", ROOT / "scripts" / "03_train.py")
from chimera_clf import deploy_model  # noqa: E402
from chimera_clf import featurize as fz  # noqa: E402


# ------------------------------------------------------------------ loader
@pytest.mark.parametrize("program,product", [
    ("aria2 1.37.0", "aria2"), ("SumatraPDF-3.6.1-64-install.exe", "sumatrapdf"), ("handle latest", "handle"),
    ("x64dbg 2026.05.27", "x64dbg"), ("7-zip 24.08", "7zip"), ("network-reset 1.0", "networkreset"),
    ("Mozilla Firefox v121", "mozillafirefox")])
def test_product_key_strips_versions(program, product):
    assert loader.product_key(program) == product


def _features(sha="ab" * 32):
    return {"schema": "chimera-features/1", "sample": {"sha256": sha, "file_name": "x.exe"},
            "run": {"guest_os": "windows"}, "api_calls": {}}


def test_calibration_role_is_chimera_malware_for_training():
    labels = {"sha256": "ab" * 32, "role": "calibration", "family": "Agent Tesla", "arm": "H3", "run": 1,
              "executed": True, "telemetry_complete": True}
    cls = {"components": {"static": {"label": "malicious", "score": 0.99, "model": "chimera-static-pe"}}}
    r = loader._record(_features(), labels, "o", "benign", {}, cls)
    assert r["label"]["malicious"] == 1 and r["split"] == "train"
    assert r["group"] == "fam:agenttesla"
    assert r["aux"]["static"] == {"label": "malicious", "score": 0.99, "model": "chimera-static-pe"}
    assert r["aux"]["executed"] is True


def test_stage1_roles_stay_held_out():
    for role in ("test", "control"):
        r = loader._record(_features(), {"role": role, "family": "Vidar"}, "o", "benign", {})
        assert r["label"]["malicious"] == 1 and r["split"] == "chimera_test"


def test_benign_runs_group_by_product_across_versions():
    a = loader._record(_features("01" * 32), {"role": "benign", "family": "aria2 1.36.0"}, "o", "benign", {})
    b = loader._record(_features("02" * 32), {"role": "benign"}, "o", "benign", {"program": "aria2 1.37.0"})
    assert a["group"] == b["group"] == "prog:aria2" and a["split"] == "train" and a["label"]["malicious"] == 0
    assert a["label"]["family"] is None


# ------------------------------------------------------------------ trainer helpers
def _rec(i, y, group, executed=True, split="train", calls=20):
    api = sorted(fz._HOOKED)[i % 5]
    return {"id": f"r{i}", "group": group, "split": split, "label": {"malicious": y, "family": None},
            "aux": {"program": group, "arm": "H3", "executed": executed},
            "features": {"run": {"guest_os": "windows"}, "api_calls": {api: calls}}}


def test_training_loads_chimera_malware_and_skips_unrun_and_stage1(tmp_path):
    path = tmp_path / "c.jsonl"
    rows = [_rec(0, 0, "prog:a"), _rec(1, 1, "fam:x"), _rec(2, 1, "fam:x", executed=False),
            _rec(3, 1, "fam:y", split="chimera_test")]
    path.write_text("\n".join(json.dumps(r) for r in rows))
    _, meta = train.load_chimera(path)
    assert meta["id"] == ["r0", "r1"] and meta["y"] == [0, 1]


def test_class_weights_give_chimera_malware_its_share():
    y = np.array([1] * 100 + [1] * 4 + [0] * 6)
    src = np.array(["winmet"] * 100 + ["chimera"] * 4 + ["chimera"] * 6)
    groups = [f"fam:w{i % 10}" for i in range(100)] + ["fam:a", "fam:a", "fam:b", "fam:c"] + ["prog:p"] * 3 + ["prog:q"] * 3
    w = train.class_weights(y, groups, src, 0.5)
    chi, cape = w[100:104].sum(), w[:100].sum()
    assert math.isclose(chi, cape, rel_tol=1e-9)
    assert math.isclose(w[y == 1].sum(), w[y == 0].sum(), rel_tol=1e-9)
    assert math.isclose(w[100] + w[101], w[102], rel_tol=1e-9)  # each family weighs the same
    assert math.isclose(w[104:107].sum(), w[107:110].sum(), rel_tol=1e-9)  # each product weighs the same


def test_platt_is_monotone_and_calibrates_separable_scores():
    rng = np.random.default_rng(0)
    raw = np.concatenate([rng.uniform(0.6, 0.95, 200), rng.uniform(0.05, 0.4, 200)])
    y = np.array([1] * 200 + [0] * 200)
    cal = train.fit_platt(raw, y)
    p = train.apply_platt(np.sort(raw), cal)
    assert cal["method"] == "platt" and cal["a"] > 0
    assert np.all(np.diff(p) >= 0)
    assert train.apply_platt(np.array([0.9]), cal)[0] > 0.9 and train.apply_platt(np.array([0.1]), cal)[0] < 0.1
    # the deployed model computes the same number
    assert math.isclose(deploy_model.calibrate(0.7, cal), float(train.apply_platt(np.array([0.7]), cal)[0]),
                        rel_tol=1e-9)


def test_crossfit_thresholds_ignore_the_fold_they_score():
    # fold 0's benign runs score very high; its own threshold must come from fold 1 only
    oof = np.array([0.99, 0.98, 0.2, 0.3, 0.97, 0.95, 0.1, 0.25])
    y = np.array([0, 0, 0, 0, 1, 1, 0, 0])
    fold = np.array([0, 0, 1, 1, 1, 1, 1, 1])
    ident = lambda *_: None  # noqa: E731
    _cal, t_mal, _ = train.crossfit(oof, y, np.ones(8), fold, 0.0, 0.0, fit=ident, apply=lambda s, _c: s)
    assert t_mal[0] < 0.98  # fitted on fold 1, whose highest benign is 0.3, so fold 0's benign runs are flagged


def test_wilson_interval():
    lo, hi = train.wilson(0, 84)
    assert lo == 0.0 and 0.04 < hi < 0.05


# ------------------------------------------------------------------ deployed fusion
def test_fusion_vector_marks_abstentions():
    assert fz.fusion_vector(None, "unknown", 0.3, "chimera-static-pe") == [0.0, 1.0, 0.0, 1.0, 0.0]
    v = fz.fusion_vector(0.8, "suspicious", 0.6, "chimera-static-rules")
    assert v[1] == 0.0 and v[3] == 0.0 and v[4] == 1.0 and math.isclose(v[0], math.log(4))


def test_fitted_fusion_reports_calibrated_probability():
    fusion = {"coef": [1.0, -0.5, 1.0, 0.0, 0.0], "intercept": 0.0, "thresholds": {"malicious": 0.7, "suspicious": 0.4},
              "calibration": "test"}
    parts = {"dynamic": {"label": "suspicious", "score": 0.6, "model": "chimera-lgbm"},
             "static": {"label": "malicious", "score": 0.9, "model": "chimera-static-pe"}}
    p, m_mal, m_sus = deploy_model.fuse_fitted(parts, fusion)
    expected = 1 / (1 + math.exp(-(math.log(0.6 / 0.4) + math.log(9))))
    assert math.isclose(p, expected, rel_tol=1e-6)
    assert m_mal > 0 and m_sus > 0
    parts["dynamic"] = {"label": "unknown", "score": None}
    p2, _, _ = deploy_model.fuse_fitted(parts, fusion)
    assert math.isclose(p2, 1 / (1 + math.exp(-(-0.5 + math.log(9)))), rel_tol=1e-6)


# ------------------------------------------------------------------ end to end
def _synthetic(tmp_path, rng):
    hooked = sorted(fz._HOOKED)
    mal_apis, ben_apis = hooked[:40], hooked[40:80]

    def feats(apis, n):
        chosen = rng.choice(apis, size=n, replace=False)
        calls = {str(a): int(rng.integers(5, 50)) for a in chosen}
        seq = [a for a, c in calls.items() for _ in range(min(c, 5))]
        return {"schema": "chimera-features/1", "sample": {"sha256": "", "file_type": "PE32"},
                "run": {"guest_os": "windows"}, "api_calls": calls, "api_sequence": seq,
                "files": {"created": int(rng.integers(0, 5))}, "registry": {}, "processes": {"count": 1}}

    winmet = tmp_path / "v1.jsonl.gz"
    with gzip.open(winmet, "wt") as f:
        for i in range(120):
            fam = f"fam{i % 12}"
            f.write(json.dumps({"id": f"w{i}", "label": {"family": fam, "avclass": fam},
                                "features": feats(mal_apis + ben_apis[:5], 12)}) + "\n")
    chimera = tmp_path / "chimera.jsonl"
    rows = []
    for i in range(60):
        f = feats(ben_apis + mal_apis[:5], 12)
        st = {"label": "benign" if i % 3 else "unknown", "score": float(rng.uniform(0.01, 0.3)), "model": "chimera-static-pe"}
        rows.append({"id": f"b{i}", "group": f"prog:p{i // 2}", "split": "train", "label": {"malicious": 0},
                     "aux": {"program": f"p{i // 2}", "static": st}, "features": f})
    for i in range(24):
        f = feats(mal_apis + ben_apis[:10], 12)
        st = {"label": "malicious", "score": float(rng.uniform(0.6, 1.0)), "model": "chimera-static-pe"}
        rows.append({"id": f"m{i}", "group": f"fam:fam{i % 6}", "split": "train", "label": {"malicious": 1, "family": f"fam{i % 6}"},
                     "aux": {"program": "", "static": st, "executed": True}, "features": f})
    chimera.write_text("\n".join(json.dumps(r) for r in rows))
    return winmet, chimera


def test_train_end_to_end_on_synthetic_data(tmp_path):
    rng = np.random.default_rng(1)
    winmet, chimera = _synthetic(tmp_path, rng)
    out = tmp_path / "model"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "03_train.py"), "--winmet", str(winmet),
                        "--chimera", str(chimera), "--out", str(out), "--ablations", "--folds", "3",
                        "--cap-per-family", "20"], capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    meta = json.loads((out / "meta.json").read_text())
    assert meta["calibration"]["method"] == "platt"
    assert meta["training"]["malicious_chimera"] == 24
    assert meta["fusion"] and len(meta["fusion"]["coef"]) == len(fz.FUSION_FEATURES)
    assert 0 < meta["thresholds"]["suspicious"] <= meta["thresholds"]["malicious"] <= 1
    ablation = json.loads((out / "ablation.json").read_text())
    assert set(ablation["sets"]) == {"written_log", "totals", "registry_volume"}
    report = (out / "report.md").read_text()
    assert "CHIMERA only" in report and "Fusion" in report
    for name in ("model.txt", "oof.csv", "metrics.json"):
        assert (out / name).exists()
