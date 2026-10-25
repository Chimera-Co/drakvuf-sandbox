"""Train the static models (PE, ELF, PDF) on EMBER2024 raw features (thrember v3 vectors).

    .venv/bin/python scripts/07_train_static.py --out models/static_v0

Vectors are computed with thrember's PEFeatureExtractor.process_raw_features, the same code
(vendored, unmodified) that chimera_static runs on CHIMERA uploads, so train and deploy match.

Splits are by time (EMBER week_id): a model is tested on weeks after the ones it learned from.
  PE  (Win32 + Win64 + .NET): train weeks <= 57, validation 58-59, test 60-63
  ELF, PDF:                    train weeks <= 45, validation 46-51, test 52-63 (EMBER's test split)
Validation sets early stopping, the isotonic calibration and the thresholds; test is only scored.
The challenge set (evasive malware, all malicious) is scored at the chosen threshold.
Subsampling is by SHA-256 hash, so reruns pick the same files.
"""

from __future__ import annotations

import argparse
import glob
import json
import multiprocessing as mp
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from chimera_clf.paths import EMBER_DATA as DATA  # noqa: E402
DIM = 2568
MODELS = {
    # name: (file globs, sampling rate per glob, (train_max_week, val_weeks, test_weeks), challenge file types)
    "pe": ({"*_Win32_test.jsonl": 0.125, "*_Win64_test.jsonl": 0.17, "*_Dot_Net_train.jsonl": 0.08,
            "*_Dot_Net_test.jsonl": 0.15}, (57, range(58, 60), range(60, 64)), {"Win32", "Win64", "Dot_Net"}),
    "elf": ({"*_ELF_train.jsonl": 1.0, "*_ELF_test.jsonl": 1.0}, (45, range(46, 52), range(52, 64)), {"ELF"}),
    "pdf": ({"*_PDF_train.jsonl": 1.0, "*_PDF_test.jsonl": 1.0}, (45, range(46, 52), range(52, 64)), {"PDF"}),
}
PARAMS = dict(objective="binary", learning_rate=0.05, num_leaves=64, min_data_in_leaf=50, feature_fraction=0.5,
              bagging_fraction=0.8, bagging_freq=1, lambda_l2=1.0, verbose=-1, num_threads=6, seed=7,
              deterministic=True, force_row_wise=True)

_extractor = None


def _init():
    global _extractor
    from thrember.features import PEFeatureExtractor
    _extractor = PEFeatureExtractor()


def _vectorize(line: str):
    r = json.loads(line)
    if r.get("label") not in (0, 1):
        return None
    vec = _extractor.process_raw_features(r).astype(np.float32)
    return vec.tobytes(), r["label"], r["week_id"], r.get("family"), r.get("file_type"), r["sha256"]


def _lines(globs: dict, keep_types=None):
    for pattern, rate in globs.items():
        threshold = int(rate * 2 ** 32)
        for path in sorted(glob.glob(str(DATA / pattern))):
            with open(path) as fh:
                for line in fh:
                    sha = line[line.find('"sha256"') + 11:][:64]  # cheap pre-filter before parsing
                    try:
                        if int(sha[:8], 16) >= threshold:
                            continue
                    except ValueError:
                        pass
                    if keep_types is not None and not any(f'"file_type": "{t}"' in line for t in keep_types):
                        continue
                    yield line


def load(globs, pool, keep_types=None, expected=0):
    cap = max(1024, int(expected * 1.15) + 1024)
    X = np.empty((cap, DIM), dtype=np.float32)
    meta = defaultdict(list)
    n = 0
    t = time.time()
    for out in pool.imap(_vectorize, _lines(globs, keep_types), chunksize=256):
        if out is None:
            continue
        if n >= len(X):
            X = np.concatenate([X, np.empty((len(X) // 2, DIM), dtype=np.float32)])
        X[n] = np.frombuffer(out[0], dtype=np.float32)
        for k, v in zip(("y", "week", "family", "file_type", "sha256"), out[1:]):
            meta[k].append(v)
        n += 1
        if n % 50000 == 0:
            print(f"    {n} vectors ({time.time() - t:.0f}s)", flush=True)
    return X[:n], {k: np.array(v) for k, v in meta.items()}


def threshold_for_fpr(benign_scores, target):
    s = np.sort(np.asarray(benign_scores, dtype=np.float64))
    if not len(s):
        return 0.5
    idx = int(np.ceil(len(s) * (1 - target)))
    return float(np.nextafter(s[min(idx, len(s) - 1)], np.inf)) if idx < len(s) else float(np.nextafter(s[-1], np.inf))


def rates(y, score, thr):
    y, score = np.asarray(y), np.asarray(score)
    pred = score >= thr
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    return {"threshold": thr, "tpr": tp / max(1, tp + fn), "fpr": fp / max(1, fp + tn),
            "precision": tp / max(1, tp + fp), "f1": 2 * tp / max(1, 2 * tp + fp + fn),
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def tpr_at(y, score, fpr):
    y, score = np.asarray(y), np.asarray(score)
    return float((score[y == 1] >= threshold_for_fpr(score[y == 0], fpr)).mean())


def train_one(name, pool, out_dir, challenge):
    globs, (train_max, val_weeks, test_weeks), ch_types = MODELS[name]
    print(f"[{name}] loading", flush=True)
    expected = sum(rate * sum(1 for _ in open(p)) for pat, rate in globs.items()
                   for p in sorted(glob.glob(str(DATA / pat)))) if name != "pe" else 230000
    X, m = load(globs, pool, expected=expected)
    week = m["week"]
    tr, va, te = week <= train_max, np.isin(week, list(val_weeks)), np.isin(week, list(test_weeks))
    print(f"[{name}] {len(X)} vectors: train {tr.sum()}, val {va.sum()}, test {te.sum()}; "
          f"malicious share {m['y'].mean():.2f}", flush=True)
    dtrain = lgb.Dataset(X[tr], m["y"][tr], free_raw_data=True)
    dval = lgb.Dataset(X[va], m["y"][va], reference=dtrain)
    t = time.time()
    booster = lgb.train(PARAMS, dtrain, 1500, valid_sets=[dval],
                        callbacks=[lgb.early_stopping(100, verbose=False), lgb.log_evaluation(0)])
    best = booster.best_iteration or 1500
    print(f"[{name}] trained {best} rounds in {time.time() - t:.0f}s", flush=True)
    p_val = booster.predict(X[va], num_iteration=best)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p_val, m["y"][va])
    cal = lambda p: np.interp(p, iso.X_thresholds_, iso.y_thresholds_)  # noqa: E731
    c_val = cal(p_val)
    t_mal = max(0.5, threshold_for_fpr(c_val[m["y"][va] == 0], 0.01))
    t_sus = min(t_mal, max(0.2, threshold_for_fpr(c_val[m["y"][va] == 0], 0.05)))
    p_te = booster.predict(X[te], num_iteration=best)
    c_te = cal(p_te)
    y_te = m["y"][te]
    metrics = {
        "n": {"train": int(tr.sum()), "val": int(va.sum()), "test": int(te.sum())},
        "test": {"roc_auc": float(roc_auc_score(y_te, p_te)), "pr_auc": float(average_precision_score(y_te, p_te)),
                 "tpr_at_fpr_1pct": tpr_at(y_te, p_te, 0.01), "tpr_at_fpr_0.1pct": tpr_at(y_te, p_te, 0.001),
                 "at_malicious_threshold": rates(y_te, c_te, t_mal), "at_suspicious_threshold": rates(y_te, c_te, t_sus)},
    }
    if name == "pe":
        metrics["test_by_type"] = {}
        for ft in sorted(set(m["file_type"][te])):
            sel = m["file_type"][te] == ft
            if len(set(y_te[sel])) > 1:
                metrics["test_by_type"][ft] = {"n": int(sel.sum()), "roc_auc": float(roc_auc_score(y_te[sel], p_te[sel])),
                                               **{k: v for k, v in rates(y_te[sel], c_te[sel], t_mal).items()
                                                  if k in ("tpr", "fpr")}}
    del X, dtrain, dval
    # challenge set: evasive malware of this model's formats
    Xc, mc = challenge
    sel = np.isin(mc["file_type"], list(ch_types)) if len(Xc) else np.zeros(0, bool)
    if sel.any():
        c_ch = cal(booster.predict(Xc[sel], num_iteration=best))
        metrics["challenge"] = {"n": int(sel.sum()), "detected_at_malicious": float((c_ch >= t_mal).mean()),
                                "detected_at_suspicious": float((c_ch >= t_sus).mean())}
    booster.save_model(str(out_dir / f"{name}.txt"), num_iteration=best)
    fams = Counter(f for f, yy in zip(m["family"][te], y_te) if yy == 1 and f)
    print(f"[{name}] test ROC-AUC {metrics['test']['roc_auc']:.4f}, TPR@1%FPR {metrics['test']['tpr_at_fpr_1pct']:.3f}, "
          f"at threshold {metrics['test']['at_malicious_threshold']['tpr']:.3f}/{metrics['test']['at_malicious_threshold']['fpr']:.4f}"
          f"; challenge {metrics.get('challenge')}", flush=True)
    return {"file": f"{name}.txt", "num_iteration": int(best), "file_types": sorted(ch_types),
            "calibration": {"x": iso.X_thresholds_.tolist(), "y": iso.y_thresholds_.tolist()},
            "thresholds": {"malicious": t_mal, "suspicious": t_sus}, "metrics": metrics,
            "test_top_families": fams.most_common(10)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "models" / "static_v0")
    ap.add_argument("--models", nargs="+", default=["elf", "pdf", "pe"])
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    t0 = time.time()
    import thrember
    with mp.get_context("spawn").Pool(a.workers, initializer=_init) as pool:
        print("loading challenge set", flush=True)
        challenge = load({"*_challenge_malicious.jsonl": 1.0}, pool, expected=7000)
        models = {name: train_one(name, pool, a.out, challenge) for name in a.models}
    meta = {"schema": "chimera-static-models/1", "model": "chimera-static-lgbm", "model_version": "0.1",
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "feature": {"name": "ember_v3", "dim": DIM,
            "extractor": "thrember@0ef753e", "thrember_version": getattr(thrember, "__version__", "0.1.0")},
            "dataset": "EMBER2024 subset (Win32/Win64 test weeks, .NET, ELF, PDF, challenge)",
            "routes": {"pe": "pe", "elf": "elf", "pdf": "pdf"}, "models": models,
            "lightgbm": lgb.__version__, "params": PARAMS}
    (a.out / "static_meta.json").write_text(json.dumps(meta, indent=1))
    write_report(a.out, meta, time.time() - t0)
    print(f"done in {time.time() - t0:.0f}s -> {a.out}")


def write_report(out, meta, elapsed):
    L = ["# Static models (EMBER2024) — training report", "",
         f"{meta['created']}, {elapsed / 60:.0f} min. LightGBM on thrember v3 vectors ({meta['feature']['dim']} features). "
         "Time-split: tested only on weeks after training. Thresholds set on validation weeks "
         "(malicious: ≤1% benign above, suspicious: ≤5%).", "",
         "| model | train / val / test | ROC-AUC | PR-AUC | TPR @1% FPR | TPR @0.1% FPR | threshold | TPR | FPR | challenge detected |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in meta["models"].items():
        t, n, at = m["metrics"]["test"], m["metrics"]["n"], m["metrics"]["test"]["at_malicious_threshold"]
        ch = m["metrics"].get("challenge", {})
        L.append(f"| {name} | {n['train']} / {n['val']} / {n['test']} | {t['roc_auc']:.4f} | {t['pr_auc']:.4f} | "
                 f"{t['tpr_at_fpr_1pct']:.3f} | {t['tpr_at_fpr_0.1pct']:.3f} | {at['threshold']:.3f} | {at['tpr']:.3f} | "
                 f"{at['fpr']:.4f} | {ch.get('detected_at_malicious', float('nan')):.3f} (n={ch.get('n', 0)}) |")
    pe = meta["models"].get("pe", {}).get("metrics", {}).get("test_by_type")
    if pe:
        L += ["", "PE by file type (test weeks):", "", "| type | n | ROC-AUC | TPR | FPR |", "|---|---|---|---|---|"]
        L += [f"| {k} | {v['n']} | {v['roc_auc']:.4f} | {v['tpr']:.3f} | {v['fpr']:.4f} |" for k, v in pe.items()]
    L += ["", "Caveats: EMBER labels come from AV vendor consensus (ClarAVy); ELF/PDF vectors carry only "
          "byte/entropy/string statistics (thrember's PE-specific groups are zero for them); the challenge set is "
          "malicious-only, so it measures detection, not false positives."]
    (out / "report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
