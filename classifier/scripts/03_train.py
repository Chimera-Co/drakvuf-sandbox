"""Train the CHIMERA malicious-vs-benign model (LightGBM), its calibration, the fusion and an optional family model.

    .venv/bin/python scripts/03_train.py --chimera data/chimera/chimera.jsonl --out models/v1 --grid --ablations --family

Malicious: WinMET records (data/winmet/v*.jsonl.gz), capped per family so a few huge families
(Redline, Vbclone, ...) don't dominate, plus CHIMERA's own malware runs (split == "train", label 1:
the October cohort). Benign: CHIMERA runs with split == "train". Stage 1 runs (split == "chimera_test")
are never loaded here. Runs whose sample never started (aux.executed false) are skipped.

Leakage controls:
  - Cross-validation keeps every malware family (WinMET and CHIMERA share one group per family) and every
    benign product on one side of a split.
  - The API vocabulary (APIs both sandboxes can observe) is recomputed inside each fold from that fold's
    training runs only.
  - Platt calibration and the thresholds are cross-fitted: the metrics for fold k use a calibration and
    thresholds fitted on the other folds' out-of-fold scores. The shipped calibration is fitted on all of them.
Model choice (--grid) and feature-set ablations (--ablations) are decided by fixed rules on out-of-fold
scores of CHIMERA runs (the deployment domain), never by hand. The final model is refit on everything.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import itertools
import json
import math
import platform
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
import orjson
import scipy.sparse as sp
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from chimera_clf import featurize as fz  # noqa: E402
from chimera_clf.cape_adapter import hooks_sha256  # noqa: E402

RF_PARAMS = dict(boosting="rf", bagging_fraction=0.632, bagging_freq=1, feature_fraction=0.3, num_leaves=127,
                 min_data_in_leaf=5, min_sum_hessian_in_leaf=1e-3, lambda_l2=0.0, verbose=-1, deterministic=True,
                 force_col_wise=True)
RF_TREES = 500
LGB_PARAMS = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10,
                  min_sum_hessian_in_leaf=1e-3, feature_fraction=0.5, bagging_fraction=0.8, bagging_freq=1,
                  lambda_l2=1.0, verbose=-1, deterministic=True, force_col_wise=True)
# --grid: the LightGBM random forest (v0's algorithm) plus this boosting grid
GRID = {"num_leaves": (15, 31, 63), "min_data_in_leaf": (10, 20, 50), "feature_fraction": (0.3, 0.5),
        "lambda_l2": (1.0, 5.0), "learning_rate": (0.05,)}
# --ablations: feature sets suspected of measuring the sandbox rather than the sample
ABLATION_SETS = {
    "written_log": ["file:written_log"],
    "totals": ["tot:*"],
    "registry_volume": ["reg:set_value_log", "reg:create_key_log", "reg:delete_log"],
}
# a set is dropped when removing it costs at most this much (it is suspect; prefer the model without it)
ABLATION_MAX_AUC_LOSS = 0.01
ABLATION_MAX_TPR_LOSS = 0.01
NAME_INDEX = {n: i for i, n in enumerate(fz.ALL_FEATURE_NAMES)}


def family_key(family: str | None) -> str:
    """Same normalisation as 02_load_chimera.py: 'Agent Tesla' and 'agenttesla' are one group."""
    return re.sub(r"[^a-z0-9]+", "", (family or "").lower())


# ------------------------------------------------------------------ loading
def _sparse_row(features, allowed=None):
    s = fz.featurize(features, allowed)
    idx = np.fromiter((NAME_INDEX[k] for k in s), dtype=np.int32, count=len(s))
    val = np.fromiter(s.values(), dtype=np.float32, count=len(s))
    return idx, val


def _csr(rows):
    indptr = np.zeros(len(rows) + 1, dtype=np.int64)
    for i, (idx, _v) in enumerate(rows):
        indptr[i + 1] = indptr[i] + len(idx)
    indices = np.concatenate([r[0] for r in rows]) if rows else np.zeros(0, np.int32)
    data = np.concatenate([r[1] for r in rows]) if rows else np.zeros(0, np.float32)
    return sp.csr_matrix((data, indices, indptr), shape=(len(rows), len(fz.ALL_FEATURE_NAMES)))


def compute_cape_coverage(files: list[Path], cache_dir: Path, min_calls: int) -> tuple[dict, int]:
    """Share of WinMET reports in which each hooked API appears at all."""
    key = hashlib.sha256(json.dumps([[str(f), f.stat().st_size, f.stat().st_mtime] for f in files]
                                    + [min_calls]).encode()).hexdigest()[:16]
    cache = cache_dir / f"cape_coverage_{key}.json"
    if cache.exists():
        cape, n = json.loads(cache.read_text()).values()
        return cape, n
    counts, n = Counter(), 0
    for f in files:
        try:
            with gzip.open(f, "rb") as fh:
                for line in fh:
                    try:
                        a = orjson.loads(line)["features"]["api_calls"]
                    except (orjson.JSONDecodeError, KeyError):
                        continue
                    if sum(a.values()) >= min_calls:
                        n += 1
                        counts.update(a.keys())
        except (EOFError, OSError):
            pass  # truncated gzip tail (converter still running)
    cape = {k: v / max(1, n) for k, v in counts.items()}
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"cape": cape, "n": n}))
    return cape, n


def chimera_coverage(features_list) -> dict:
    """Share of CHIMERA Windows runs in which each hooked API appears at all."""
    chi = Counter()
    for f in features_list:
        chi.update((f.get("api_calls") or {}).keys())
    return {k: v / max(1, len(features_list)) for k, v in chi.items()}


def make_vocabulary(cape: dict, chimera: dict, extra_drop) -> tuple[list[str], dict]:
    vocab, dropped = fz.coverage_vocabulary(cape, chimera)
    for api in extra_drop:
        if api in vocab:
            vocab.remove(api)
            dropped[api] = "dropped by hand (--extra-drop): suspected partial blind spot"
    return vocab, dropped


def load_winmet(files: list[Path], cache_dir: Path, allowed=None):
    """Featurize every WinMET record once per vocabulary; cache as sparse matrix + metadata."""
    key = hashlib.sha256(json.dumps([[str(f), f.stat().st_size, f.stat().st_mtime] for f in files]
                                    + [fz.FEATURIZE_VERSION, list(fz.ALL_FEATURE_NAMES)[:5],
                                       len(fz.ALL_FEATURE_NAMES), sorted(allowed) if allowed else None,
                                       "calls=usable"]
                                    ).encode()).hexdigest()[:16]
    cache = cache_dir / f"winmet_{key}.npz"
    meta_cache = cache_dir / f"winmet_{key}.meta.json"
    if cache.exists() and meta_cache.exists():
        return sp.load_npz(cache).tocsr(), json.loads(meta_cache.read_text())
    rows, meta = [], {"id": [], "family": [], "avclass": [], "calls": [], "file_type": [], "volume": []}
    t = time.time()
    for f in files:
        try:
            with gzip.open(f, "rb") as fh:
                for line in fh:
                    try:
                        r = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue  # partial last line while the converter is still writing
                    feats = r["features"]
                    rows.append(_sparse_row(feats, allowed))
                    meta["id"].append(r["id"])
                    meta["family"].append(r["label"].get("family"))
                    meta["avclass"].append(r["label"].get("avclass"))
                    # usable calls (inside the vocabulary), the count the deployed gate uses: a run whose calls
                    # are all outside it has an empty vector and must not be learned from
                    meta["calls"].append(fz.hooked_call_count(feats, allowed))
                    meta["file_type"].append(feats["sample"].get("file_type", ""))
                    meta["volume"].append(r.get("volume"))
        except (EOFError, OSError):
            pass  # truncated gzip tail (converter still running); complete records were read
        print(f"  {f.name}: {len(rows)} records so far ({time.time() - t:.0f}s)", flush=True)
    X = _csr(rows)
    cache_dir.mkdir(parents=True, exist_ok=True)
    sp.save_npz(cache, X)
    meta_cache.write_text(json.dumps(meta))
    return X, meta


def load_chimera_records(path: Path | None) -> list[dict]:
    """CHIMERA Windows training runs of both classes. Stage 1 (chimera_test) and never-started samples are skipped."""
    if not path or not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("split") != "train" or r["label"].get("malicious") not in (0, 1):
            continue
        if (r["features"].get("run") or {}).get("guest_os") != "windows":
            continue
        if (r.get("aux") or {}).get("executed") is False:
            continue
        out.append(r)
    return out


def featurize_chimera(records: list[dict], allowed=None):
    rows = [_sparse_row(r["features"], allowed) for r in records]
    meta = {"id": [r["id"] for r in records], "group": [r["group"] for r in records],
            "calls": [fz.hooked_call_count(r["features"], allowed) for r in records],
            "program": [(r.get("aux") or {}).get("program") for r in records],
            "arm": [(r.get("aux") or {}).get("arm") for r in records],
            "y": [int(r["label"]["malicious"]) for r in records],
            "family": [r["label"].get("family") for r in records],
            "static": [(r.get("aux") or {}).get("static") for r in records]}
    return _csr(rows), meta


def load_chimera(path: Path | None, allowed=None):
    """Featurized CHIMERA training runs (benign and CHIMERA malware)."""
    return featurize_chimera(load_chimera_records(path), allowed)


# ------------------------------------------------------------------ helpers
def sample_malware(meta, rng, cap_per_family, max_total, min_calls):
    by_group = defaultdict(list)
    for i, (fam, av, calls) in enumerate(zip(meta["family"], meta["avclass"], meta["calls"])):
        if calls < min_calls:
            continue
        by_group[f"fam:{family_key(fam or av) or 'unknown'}"].append(i)
    chosen = []
    for g, idx in by_group.items():
        idx = list(idx)
        rng.shuffle(idx)
        chosen += idx[:cap_per_family]
    rng.shuffle(chosen)
    chosen = sorted(chosen[:max_total])
    groups = [f"fam:{family_key(meta['family'][i] or meta['avclass'][i]) or 'unknown'}" for i in chosen]
    # unlabeled reports are their own group (no family to leak across folds)
    groups = [g if g not in ("fam:unknown", "fam:na") else f"sha:{meta['id'][i]}" for g, i in zip(groups, chosen)]
    return np.array(chosen, dtype=int), groups


def class_weights(y, groups, sources, chimera_malware_share):
    """Benign: each product counts equally regardless of run count. Malware: CHIMERA runs carry
    `chimera_malware_share` of the malware weight (each family equally), WinMET the rest.
    Classes sum to the same weight."""
    y, sources = np.asarray(y), np.asarray(sources)
    w = np.ones(len(y), dtype=np.float64)
    for cls_mask in ((y == 0), (y == 1) & (sources == "chimera")):
        runs = Counter(g for g, m in zip(groups, cls_mask) if m)
        for i, (g, m) in enumerate(zip(groups, cls_mask)):
            if m:
                w[i] = 1.0 / runs[g]
    chi_mal, cape_mal = (y == 1) & (sources == "chimera"), (y == 1) & (sources != "chimera")
    if chi_mal.any() and cape_mal.any():
        total = cape_mal.sum()
        w[chi_mal] *= chimera_malware_share * total / ((1 - chimera_malware_share) * w[chi_mal].sum())
    pos, neg = w[y == 1].sum(), w[y == 0].sum()
    if neg > 0:
        w[y == 0] *= pos / neg
    return w / w.mean()


def train_lgb(X, y, w, Xv=None, yv=None, wv=None, rounds=800, seed=0, params=None, algo="gbdt"):
    if algo == "rf":  # LightGBM random forest: fixed tree count, no early stopping
        b = lgb.train({**RF_PARAMS, "objective": "binary", "seed": seed}, lgb.Dataset(X, y, weight=w), RF_TREES)
        return b, RF_TREES
    p = {**LGB_PARAMS, **(params or {}), "seed": seed}
    dtrain = lgb.Dataset(X, y, weight=w, free_raw_data=False)
    if Xv is not None and len(set(yv)) > 1:
        dval = lgb.Dataset(Xv, yv, weight=wv, reference=dtrain)
        b = lgb.train(p, dtrain, rounds, valid_sets=[dval], callbacks=[lgb.early_stopping(100, verbose=False)])
        return b, b.best_iteration or rounds
    b = lgb.train(p, dtrain, rounds)
    return b, rounds


def threshold_for_fpr(benign_scores, target, floor):
    s = np.sort(np.asarray(benign_scores, dtype=np.float64))
    # just above each benign score, so "everything above the highest benign" is a candidate
    candidates = sorted(set(s.tolist()) | set(np.nextafter(s, np.inf).tolist()) | {floor, 1.0})
    for t in candidates:
        if t >= floor and (s >= t).mean() <= target:
            return float(t)
    return 1.0


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def binary_metrics(y, score, groups, thr):
    """Rates at one threshold; `thr` may be an array (one threshold per row, for cross-fitted thresholds)."""
    y, score = np.asarray(y), np.asarray(score)
    pred = score >= np.asarray(thr)
    out = {"n": int(len(y)), "n_malicious": int(y.sum()), "n_benign": int((y == 0).sum()),
           "threshold": float(np.median(thr)) if np.ndim(thr) else thr}
    if len(set(y)) > 1:
        out["roc_auc"] = float(roc_auc_score(y, score))
        out["pr_auc"] = float(average_precision_score(y, score))
    out["tpr"] = float(pred[y == 1].mean()) if (y == 1).any() else None
    out["tpr_ci"] = wilson(int(pred[y == 1].sum()), int((y == 1).sum()))
    out["fpr_runs"] = float(pred[y == 0].mean()) if (y == 0).any() else None
    out["fpr_runs_ci"] = wilson(int(pred[y == 0].sum()), int((y == 0).sum()))
    ben_groups = defaultdict(list)
    for g, p, yy in zip(groups, pred, y):
        if yy == 0:
            ben_groups[g].append(p)
    out["fpr_programs"] = float(np.mean([any(v) for v in ben_groups.values()])) if ben_groups else None
    out["f1"] = float(f1_score(y, pred)) if len(set(y)) > 1 else None
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    out["confusion"] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
    out["precision"] = tp / (tp + fp) if tp + fp else None
    return out


def tpr_at_fpr(y, score, fpr):
    y, score = np.asarray(y), np.asarray(score)
    if not (y == 0).any() or not (y == 1).any():
        return None
    t = threshold_for_fpr(score[y == 0], fpr, 0.0)
    return float((score[y == 1] >= t).mean())


def _logit(p):
    p = np.clip(np.asarray(p, dtype=np.float64), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def fit_platt(raw, y, w=None) -> dict:
    """Platt scaling on the logit of the raw score: p = sigmoid(a * logit(raw) + b). Weighted with the
    class-balanced weights, so p is the probability under equal class priors."""
    lr = LogisticRegression(C=1e4, max_iter=1000)
    lr.fit(_logit(raw).reshape(-1, 1), np.asarray(y), sample_weight=w)
    return {"method": "platt", "a": float(lr.coef_[0][0]), "b": float(lr.intercept_[0])}


def apply_platt(raw, cal: dict):
    z = cal["a"] * _logit(raw) + cal["b"]
    return 1 / (1 + np.exp(-np.clip(z, -50, 50)))


def reliability(p, y, w, bins=10):
    p, y, w = np.asarray(p), np.asarray(y), np.asarray(w)
    out = []
    edges = np.linspace(0, 1, bins + 1)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if m.any():
            out.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": int(m.sum()), "mean_p": float(np.average(p[m], weights=w[m])),
                        "observed": float(np.average(y[m], weights=w[m]))})
    return out


def crossfit(oof, y, w, fold_of, fpr_mal, fpr_sus, fit=fit_platt, apply=apply_platt):
    """Calibration and thresholds for fold k fitted on the other folds only; returns per-row calibrated
    scores and thresholds. This is what the reported metrics use. Rows with fold -1 are left out."""
    cal = np.full(len(y), np.nan)
    t_mal, t_sus = np.full(len(y), np.nan), np.full(len(y), np.nan)
    for k in sorted(set(fold_of[fold_of >= 0])):
        test, other = fold_of == k, (fold_of >= 0) & (fold_of != k)
        if len(set(y[other])) < 2:
            continue
        c = fit(oof[other], y[other], w[other])
        cal[test] = apply(oof[test], c)
        ben = apply(oof[other & (y == 0)], c)
        tm = threshold_for_fpr(ben, fpr_mal, 0.5)
        t_mal[test], t_sus[test] = tm, min(tm, threshold_for_fpr(ben, fpr_sus, 0.2))
    return cal, t_mal, t_sus


def calibrated_report(cal, t_mal, t_sus, y, w, groups, sources):
    ok = ~np.isnan(cal)
    g = [gg for gg, o in zip(groups, ok) if o]
    rep = {"all": {"at_malicious": binary_metrics(y[ok], cal[ok], g, t_mal[ok]),
                   "at_suspicious": binary_metrics(y[ok], cal[ok], g, t_sus[ok]),
                   "brier": float(brier_score_loss(y[ok], cal[ok], sample_weight=w[ok])),
                   "reliability": reliability(cal[ok], y[ok], w[ok])}}
    chi = ok & (np.asarray(sources) == "chimera")
    if len(set(y[chi])) > 1 and (np.asarray(sources) != "chimera").any():
        gc = [gg for gg, o in zip(groups, chi) if o]
        rep["chimera_only"] = {"at_malicious": binary_metrics(y[chi], cal[chi], gc, t_mal[chi]),
                               "at_suspicious": binary_metrics(y[chi], cal[chi], gc, t_sus[chi]),
                               "brier": float(brier_score_loss(y[chi], cal[chi]))}
    return rep


def selection_key(oof, y, sources):
    """Model choice and ablations: ROC-AUC on CHIMERA runs (the deployment domain), then TPR at 1% FPR on all."""
    chi = np.asarray(sources) == "chimera"
    ok = ~np.isnan(oof)
    auc_c = roc_auc_score(y[chi & ok], oof[chi & ok]) if len(set(y[chi & ok])) > 1 else float("nan")
    tpr = tpr_at_fpr(y[ok], oof[ok], 0.01)
    return {"chimera_roc_auc": float(auc_c), "tpr_at_fpr_1pct": tpr,
            "roc_auc": float(roc_auc_score(y[ok], oof[ok])) if len(set(y[ok])) > 1 else float("nan")}


def drop_columns(names, patterns):
    return [n for n in names if not any(fnmatch.fnmatchcase(n, p) for p in patterns)]


# ------------------------------------------------------------------ data with fold-local vocabularies
class Data:
    """Feature matrices per API vocabulary. WinMET rows are fixed (mal_idx); the vocabulary only changes
    which APIs are kept, so a fold whose vocabulary equals another's reuses its matrix."""

    def __init__(self, winmet_files, cache_dir, mal_idx, chimera_records, groups):
        self.winmet_files, self.cache_dir, self.mal_idx = winmet_files, cache_dir, mal_idx
        self.records, self.groups = chimera_records, np.asarray(groups)
        self._cache = {}

    def matrix(self, vocab):
        key = tuple(sorted(vocab)) if vocab is not None else None
        if key not in self._cache:
            Xw, _ = load_winmet(self.winmet_files, self.cache_dir, vocab)
            Xc, _ = featurize_chimera(self.records, vocab)
            self._cache[key] = sp.vstack([Xw[self.mal_idx], Xc]).tocsr().astype(np.float32)
        return self._cache[key]


def run_cv(data, folds, cols, y, w, candidate, seed):
    """Out-of-fold raw scores for one candidate, each fold with its own vocabulary."""
    oof = np.full(len(y), np.nan)
    best_iters = []
    for k, (tr, te, vocab) in enumerate(folds):
        X = data.matrix(vocab)[:, cols]
        groups_tr = data.groups[tr]
        inner = StratifiedGroupKFold(n_splits=max(2, min(5, len(set(groups_tr[y[tr] == 0])))), shuffle=True,
                                     random_state=seed + k)
        itr, ival = next(inner.split(X[tr], y[tr], groups_tr))
        itr, ival = tr[itr], tr[ival]
        booster, best = train_lgb(X[itr], y[itr], w[itr], X[ival], y[ival], w[ival], seed=seed + k,
                                  params=candidate["params"], algo=candidate["algo"])
        best_iters.append(best)
        oof[te] = booster.predict(X[te], num_iteration=best)
    return oof, best_iters


def candidates(a):
    if not a.grid:
        return [{"name": a.algo, "algo": a.algo, "params": None}]
    out = [{"name": "rf", "algo": "rf", "params": None}]
    keys = list(GRID)
    for values in itertools.product(*(GRID[k] for k in keys)):
        p = dict(zip(keys, values))
        out.append({"name": "gbdt " + " ".join(f"{k}={v}" for k, v in p.items()), "algo": "gbdt", "params": p})
    return out


def better(new, old):
    """Higher CHIMERA ROC-AUC (to 3 decimals) wins; ties go to TPR at 1% FPR on all runs."""
    if old is None:
        return True
    a, b = round(new["chimera_roc_auc"], 3), round(old["chimera_roc_auc"], 3)
    if a != b:
        return a > b
    return (new["tpr_at_fpr_1pct"] or 0) > (old["tpr_at_fpr_1pct"] or 0)


# ------------------------------------------------------------------ fusion
def fusion_rows(records_all, dyn_p_by_id):
    """CHIMERA runs that have a static result. Older runs (before the static analyzer) are left out:
    their missing static part would otherwise read as evidence of "benign"."""
    rows = [r for r in records_all if (r.get("aux") or {}).get("static")]
    X = np.array([fz.fusion_vector(dyn_p_by_id.get(r["id"]), r["aux"]["static"].get("label"),
                                   r["aux"]["static"].get("score"), r["aux"]["static"].get("model")) for r in rows],
                 dtype=np.float64).reshape(len(rows), len(fz.FUSION_FEATURES))
    y = np.array([int(r["label"]["malicious"]) for r in rows], dtype=int)
    return rows, X, y


def fit_fusion(records_all, dyn_p_by_id, folds_by_group, n_folds, fpr_mal, fpr_sus):
    """Logistic regression on fz.fusion_vector, cross-fitted on the dynamic model's folds (a run's dynamic
    score and its fusion score both come from models that never saw its family or product)."""
    rows, X, y = fusion_rows(records_all, dyn_p_by_id)
    if (y == 1).sum() < 10 or (y == 0).sum() < 10:
        return None, {"skipped": f"too few CHIMERA runs with a static result ({int((y == 1).sum())} malware, "
                                 f"{int((y == 0).sum())} benign; need 10 each)"}
    groups = [r["group"] for r in rows]
    w = class_weights(y, groups, ["chimera"] * len(y), 0.5)
    # groups the dynamic CV never saw (all their runs below the call gate) are spread over the folds by hash
    fold_of = np.array([folds_by_group[g] if g in folds_by_group
                        else int(hashlib.sha256(g.encode()).hexdigest(), 16) % n_folds for g in groups])

    def fit(Xs, ys, ws):
        lr = LogisticRegression(C=1.0, max_iter=2000)
        lr.fit(Xs, ys, sample_weight=ws)
        return lr

    oof = np.full(len(y), np.nan)
    for k in sorted(set(fold_of)):
        test, other = fold_of == k, fold_of != k
        if len(set(y[other])) < 2:
            continue
        oof[test] = fit(X[other], y[other], w[other]).predict_proba(X[test])[:, 1]
    ok = ~np.isnan(oof)
    cal, t_mal, t_sus = crossfit(oof, y, w, np.where(ok, fold_of, -1), fpr_mal, fpr_sus,
                                 fit=lambda *_: None, apply=lambda s, _c: s)
    report = calibrated_report(cal, t_mal, t_sus, y, w, groups, ["chimera"] * len(y))
    report["n_runs"] = {"malware": int((y == 1).sum()), "benign": int((y == 0).sum())}
    final = fit(X, y, w)
    ben = oof[ok & (y == 0)]
    tm = threshold_for_fpr(ben, fpr_mal, 0.5)
    meta = {"method": "logreg", "features": list(fz.FUSION_FEATURES), "coef": final.coef_[0].tolist(),
            "intercept": float(final.intercept_[0]),
            "thresholds": {"malicious": tm, "suspicious": min(tm, threshold_for_fpr(ben, fpr_sus, 0.2))},
            "n": int(len(y)), "folds": int(len(set(fold_of))),
            "calibration": f"platt + fusion LR, grouped {len(set(fold_of))}-fold, CHIMERA runs, equal class priors"}
    return meta, report


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--winmet", type=Path, nargs="*", default=sorted((ROOT / "data" / "winmet").glob("v*.jsonl.gz")))
    ap.add_argument("--chimera", type=Path, default=ROOT / "data" / "chimera" / "chimera.jsonl")
    ap.add_argument("--out", type=Path, default=ROOT / "models" / "v1")
    ap.add_argument("--groups", nargs="+", default=list(fz.DEFAULT_GROUPS), help=f"feature groups, from {fz.ALL_GROUPS}")
    ap.add_argument("--drop-features", nargs="*", default=[], help="feature-name patterns to remove (fnmatch)")
    ap.add_argument("--cap-per-family", type=int, default=300)
    ap.add_argument("--max-malware", type=int, default=12000)
    ap.add_argument("--chimera-malware-share", type=float, default=0.5,
                    help="share of the malware class weight carried by CHIMERA malware runs (when there are any)")
    ap.add_argument("--min-calls", type=int, default=10, help="same gate model.py uses for 'unknown'")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--fpr-malicious", type=float, default=0.01)
    ap.add_argument("--fpr-suspicious", type=float, default=0.05)
    ap.add_argument("--grid", action="store_true", help="choose between LightGBM RF and the GRID boosting settings")
    ap.add_argument("--ablations", action="store_true", help="test removing each ABLATION_SETS group; drop by rule")
    ap.add_argument("--baselines", action="store_true", help="also cross-validate sklearn RF and logistic regression")
    ap.add_argument("--family", action="store_true", help="also train the family model")
    ap.add_argument("--family-top", type=int, default=20)
    ap.add_argument("--family-min", type=int, default=50)
    ap.add_argument("--model-version", default="1.0")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--algo", choices=["gbdt", "rf"], default="rf",
                    help="without --grid: LightGBM boosting (gbdt) or LightGBM random forest (rf)")
    ap.add_argument("--extra-drop", nargs="*", default=[], help="APIs to remove from the vocabulary as well")
    ap.add_argument("--no-vocabulary", action="store_true", help="keep APIs one sandbox cannot observe (ablation)")
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    t_start = time.time()
    a.out.mkdir(parents=True, exist_ok=True)
    cache_dir = ROOT / "data" / "cache"

    print("loading CHIMERA runs ...", flush=True)
    records_all = load_chimera_records(a.chimera)
    print("API coverage per sandbox ...", flush=True)
    cape_cov, n_cape = compute_cape_coverage(list(a.winmet), cache_dir, a.min_calls)
    if a.no_vocabulary or not records_all:
        vocab, dropped = None, {}
    else:
        vocab, dropped = make_vocabulary(cape_cov, chimera_coverage([r["features"] for r in records_all]), a.extra_drop)
    print(f"  vocabulary: {len(vocab) if vocab else 'all'} APIs kept, {len(dropped)} dropped "
          f"({n_cape} WinMET reports, {len(records_all)} CHIMERA runs)", flush=True)

    print("loading WinMET ...", flush=True)
    Xw_all, mw = load_winmet(list(a.winmet), cache_dir, vocab)
    print(f"  {Xw_all.shape[0]} WinMET records", flush=True)
    calls = [fz.hooked_call_count(r["features"], vocab) for r in records_all]
    records = [r for r, c in zip(records_all, calls) if c >= a.min_calls]
    dropped_low = dict(Counter("malware" if r["label"]["malicious"] else "benign"
                               for r, c in zip(records_all, calls) if c < a.min_calls))
    _, mc = featurize_chimera(records, vocab)
    yc = np.array(mc["y"], dtype=int)
    n_programs = len({g for g, yy in zip(mc["group"], yc) if yy == 0})
    print(f"  CHIMERA: {int((yc == 0).sum())} benign runs from {n_programs} products, {int((yc == 1).sum())} malware "
          f"runs from {len({g for g, yy in zip(mc['group'], yc) if yy == 1})} families "
          f"(dropped below {a.min_calls} usable calls: {dropped_low})", flush=True)
    if n_programs < 2:
        raise SystemExit("need benign runs from at least 2 products: run 02_load_chimera.py first")

    mal_idx, mal_groups = sample_malware(mw, rng, a.cap_per_family, a.max_malware, a.min_calls)
    y = np.concatenate([np.ones(len(mal_idx)), yc]).astype(int)
    groups = list(mal_groups) + list(mc["group"])
    ids = [mw["id"][i] for i in mal_idx] + list(mc["id"])
    sources = np.array(["winmet"] * len(mal_idx) + ["chimera"] * len(records))
    w = class_weights(y, groups, sources, a.chimera_malware_share)
    data = Data(list(a.winmet), cache_dir, mal_idx, records, groups)
    names_all = drop_columns(fz.feature_names(a.groups), a.drop_features)
    print(f"training set: {len(mal_idx)} WinMET + {int((yc == 1).sum())} CHIMERA malicious "
          f"({len(set(g for g, yy in zip(groups, y) if yy == 1))} groups), {int((y == 0).sum())} benign; "
          f"{len(names_all)} features", flush=True)

    # ---- folds, each with a vocabulary from its own training runs
    k = max(2, min(a.folds, n_programs))
    cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=a.seed)
    folds, fold_of, fold_vocab_diff = [], np.full(len(y), -1), []
    chi_offset = len(mal_idx)
    for f, (tr, te) in enumerate(cv.split(np.zeros(len(y)), y, groups)):
        fold_of[te] = f
        if vocab is None:
            fv = None
        else:
            tr_chi = [records[i - chi_offset]["features"] for i in tr if i >= chi_offset]
            fv, _ = make_vocabulary(cape_cov, chimera_coverage(tr_chi), a.extra_drop)
            fold_vocab_diff.append({"fold": f, "added": sorted(set(fv) - set(vocab)),
                                    "removed": sorted(set(vocab) - set(fv))})
        folds.append((tr, te, fv))
    folds_by_group = {g: int(fo) for g, fo in zip(groups, fold_of)}

    def cols_for(names):
        return np.array([NAME_INDEX[n] for n in names])

    # ---- model choice
    trials, best, best_cand, best_oof, best_iters = [], None, None, None, None
    for cand in candidates(a):
        t = time.time()
        oof, iters = run_cv(data, folds, cols_for(names_all), y, w, cand, a.seed)
        key = selection_key(oof, y, sources)
        trials.append({"candidate": cand["name"], **key, "seconds": round(time.time() - t, 1)})
        print(f"  {cand['name']}: CHIMERA AUC {key['chimera_roc_auc']:.4f}, TPR@1% {key['tpr_at_fpr_1pct']}, "
              f"AUC {key['roc_auc']:.4f} ({time.time() - t:.0f}s)", flush=True)
        if better(key, best):
            best, best_cand, best_oof, best_iters = key, cand, oof, iters
    print(f"chosen: {best_cand['name']}", flush=True)

    # ---- ablations
    ablation = {"base": {"features": len(names_all), "candidate": best_cand["name"], **best}, "sets": {}, "dropped": []}
    names = names_all
    if a.ablations:
        for set_name, patterns in ABLATION_SETS.items():
            reduced = drop_columns(names_all, patterns)
            if len(reduced) == len(names_all):
                continue
            oof, _ = run_cv(data, folds, cols_for(reduced), y, w, best_cand, a.seed)
            key = selection_key(oof, y, sources)
            auc_loss = best["chimera_roc_auc"] - key["chimera_roc_auc"]
            tpr_loss = (best["tpr_at_fpr_1pct"] or 0) - (key["tpr_at_fpr_1pct"] or 0)
            drop = bool(auc_loss <= ABLATION_MAX_AUC_LOSS and tpr_loss <= ABLATION_MAX_TPR_LOSS)
            ablation["sets"][set_name] = {"patterns": patterns, "features": len(reduced), **key,
                                          "chimera_auc_loss": auc_loss, "tpr_loss": tpr_loss, "dropped": drop}
            print(f"  ablation {set_name}: CHIMERA AUC loss {auc_loss:+.4f}, TPR@1% loss {tpr_loss:+.4f} -> "
                  f"{'drop' if drop else 'keep'}", flush=True)
            if drop:
                ablation["dropped"].append(set_name)
        if ablation["dropped"]:
            names = drop_columns(names_all, [p for s in ablation["dropped"] for p in ABLATION_SETS[s]])
            best_oof, best_iters = run_cv(data, folds, cols_for(names), y, w, best_cand, a.seed)
            ablation["final"] = {"features": len(names), **selection_key(best_oof, y, sources)}
    (a.out / "ablation.json").write_text(json.dumps(ablation, indent=1))
    oof = best_oof
    cols = cols_for(names)

    # ---- calibration and thresholds (cross-fitted for the report, all folds for the shipped model)
    ok = ~np.isnan(oof)
    cal_cf, tm_cf, ts_cf = crossfit(oof, y, w, np.where(ok, fold_of, -1), a.fpr_malicious, a.fpr_suspicious)
    calib_report = calibrated_report(cal_cf, tm_cf, ts_cf, y, w, groups, sources)
    platt = fit_platt(oof[ok], y[ok], w[ok])
    ben = apply_platt(oof[(y == 0) & ok], platt)
    t_mal = threshold_for_fpr(ben, a.fpr_malicious, 0.5)
    t_sus = min(t_mal, threshold_for_fpr(ben, a.fpr_suspicious, 0.2))

    metrics = {"lightgbm": {"crossfit": calib_report,
                            "tpr_at_fpr_1pct": tpr_at_fpr(y[ok], oof[ok], 0.01),
                            "tpr_at_fpr_5pct": tpr_at_fpr(y[ok], oof[ok], 0.05)}}
    if a.baselines:
        metrics.update(run_baselines(data, folds, cols, y, w, sources, a.seed))
    # per malware family recall (cross-fitted) at the malicious threshold, by source
    fam_recall = defaultdict(list)
    for g, yy, s, t, src in zip(groups, y, cal_cf, tm_cf, sources):
        if yy == 1 and g.startswith("fam:") and not np.isnan(s):
            fam_recall[(g[4:], src)].append(s >= t)
    fam_table = sorted(((f, src, len(v), float(np.mean(v))) for (f, src), v in fam_recall.items()),
                       key=lambda r: (r[1] != "chimera", -r[2]))[:60]
    benign_table = sorted({(p, g) for p, g, yy in zip(mc["program"], mc["group"], yc) if yy == 0})
    benign_scores = defaultdict(list)
    for g, yy, s in zip(groups, y, cal_cf):
        if yy == 0 and not np.isnan(s):
            benign_scores[g].append(float(s))

    # ---- univariate separation (sandbox-artefact check), on the global vocabulary
    X_global = data.matrix(vocab)[:, cols]
    Xd = X_global.toarray() if X_global.shape[0] * X_global.shape[1] < 4e8 else None
    sep = []
    if Xd is not None:
        chi = sources == "chimera"
        for j, n in enumerate(names):
            col = Xd[:, j]
            if col.max() == col.min():
                continue
            auc_c = (float(roc_auc_score(y[chi], col[chi]))
                     if len(set(y[chi])) > 1 and col[chi].max() > col[chi].min() else None)
            sep.append((n, float(roc_auc_score(y, col)), auc_c))
        sep.sort(key=lambda r: -abs(r[1] - 0.5))

    # ---- fusion on CHIMERA runs (cross-fitted calibrated dynamic scores as input)
    dyn_p_by_id = {i: float(s) for i, s, src in zip(ids, cal_cf, sources) if src == "chimera" and not np.isnan(s)}
    fusion, fusion_report = fit_fusion(records_all, dyn_p_by_id, folds_by_group, k, a.fpr_malicious, a.fpr_suspicious)
    if fusion is None:
        print(f"fusion not fitted: {fusion_report['skipped']}", flush=True)

    # ---- final model on everything, global vocabulary
    rounds = RF_TREES if best_cand["algo"] == "rf" else max(50, int(np.median(best_iters) * 1.1))
    final, _ = train_lgb(X_global, y, w, rounds=rounds, seed=a.seed, params=best_cand["params"], algo=best_cand["algo"])
    final.save_model(str(a.out / "model.txt"))
    gain = final.feature_importance("gain")
    importance = sorted(zip(names, gain.tolist()), key=lambda r: -r[1])

    family_meta = train_family(Xw_all, mw, cols, a, rng) if a.family else None

    meta = {
        "schema": "chimera-model-meta/1",
        "model": "chimera-lgbm" if best_cand["algo"] == "gbdt" else "chimera-lgbm-rf",
        "algorithm": best_cand["algo"],
        "params": best_cand["params"],
        "model_version": a.model_version,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "featurize_version": fz.FEATURIZE_VERSION,
        "hooks_sha256": hooks_sha256(),
        "feature_groups": a.groups,
        "feature_names": names,
        "features_dropped": {"by_hand": a.drop_features, "by_ablation": ablation["dropped"]},
        "api_vocabulary": vocab,
        "api_dropped": dropped,
        "api_coverage": {"n_cape": n_cape, "n_chimera": len(records_all)},
        "min_hooked_calls": a.min_calls,
        "num_iteration": rounds,
        "calibration": platt,
        "thresholds": {"malicious": t_mal, "suspicious": t_sus},
        "fusion": fusion,
        "family": family_meta,
        "training": {
            "winmet_records_available": int(Xw_all.shape[0]), "malicious_winmet": int(len(mal_idx)),
            "malicious_chimera": int((yc == 1).sum()),
            "malicious_groups": len(set(g for g, yy in zip(groups, y) if yy == 1)),
            "benign_runs": int((y == 0).sum()), "benign_programs": n_programs,
            "chimera_dropped_low_calls": dropped_low, "chimera_malware_share": a.chimera_malware_share,
            "folds": k, "best_iterations": best_iters, "cap_per_family": a.cap_per_family, "seed": a.seed,
            "fpr_targets": {"malicious": a.fpr_malicious, "suspicious": a.fpr_suspicious},
            "fold_vocabulary_differences": fold_vocab_diff, "candidates": trials,
        },
        "versions": {"python": platform.python_version(), "lightgbm": lgb.__version__,
                     "scikit-learn": sklearn.__version__, "numpy": np.__version__},
    }
    (a.out / "meta.json").write_text(json.dumps(meta, indent=1))
    (a.out / "metrics.json").write_text(json.dumps({"metrics": metrics, "fusion": fusion_report,
                                                    "family_recall": fam_table, "benign_scores": benign_scores}, indent=1))
    with (a.out / "oof.csv").open("w") as f:
        f.write("id,source,group,y,fold,raw,calibrated_crossfit,threshold_malicious_crossfit\n")
        for row in zip(ids, sources, groups, y, fold_of, oof, cal_cf, tm_cf):
            f.write(",".join(str(v) for v in row) + "\n")
    with (a.out / "feature_importance.csv").open("w") as f:
        f.write("feature,gain\n" + "".join(f"{n},{g:.4f}\n" for n, g in importance))
    write_report(a.out, meta, metrics, fusion_report, ablation, trials, fam_table, benign_table, benign_scores, sep,
                 importance, family_meta, time.time() - t_start)
    print(f"done in {time.time() - t_start:.0f}s -> {a.out}")
    head = calib_report.get("chimera_only", calib_report["all"])["at_malicious"]
    print(json.dumps({k: v for k, v in head.items() if k != "confusion"}, indent=1))


def run_baselines(data, folds, cols, y, w, sources, seed):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import MaxAbsScaler

    out = {"random_forest": np.full(len(y), np.nan), "logistic_regression": np.full(len(y), np.nan)}
    for tr, te, vocab in folds:
        X = data.matrix(vocab)[:, cols]
        rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=seed)
        rf.fit(X[tr], y[tr], sample_weight=w[tr])
        out["random_forest"][te] = rf.predict_proba(X[te])[:, 1]
        lr = make_pipeline(MaxAbsScaler(), LogisticRegression(max_iter=3000, C=0.5))
        lr.fit(X[tr], y[tr], logisticregression__sample_weight=w[tr])
        out["logistic_regression"][te] = lr.predict_proba(X[te])[:, 1]
    return {name: {**selection_key(s, y, sources), "pr_auc": float(average_precision_score(y, s)),
                   "tpr_at_fpr_5pct": tpr_at_fpr(y, s, 0.05)} for name, s in out.items()}


def train_family(Xw_all, mw, cols, a, rng):
    fam = [(f or "").lower() for f in mw["family"]]
    counts = Counter(f for f, c in zip(fam, mw["calls"]) if f and c >= a.min_calls)
    top = [f for f, n in counts.most_common(a.family_top) if n >= a.family_min]
    if len(top) < 2:
        print("family model skipped: not enough labelled families")
        return None
    classes = top + ["other"]
    cidx = {c: i for i, c in enumerate(classes)}
    picked, labels = [], []
    per = defaultdict(list)
    for i, (f, c) in enumerate(zip(fam, mw["calls"])):
        if c >= a.min_calls and f:
            per[f if f in cidx else "other"].append(i)
    for c, idx in per.items():
        rng.shuffle(idx)
        cap = 400 if c != "other" else 1500
        picked += idx[:cap]
        labels += [cidx[c]] * len(idx[:cap])
    picked, labels = np.array(picked), np.array(labels)
    Xf = Xw_all[picked][:, cols].tocsr().astype(np.float32)
    params = {"objective": "multiclass", "num_class": len(classes), "metric": "multi_logloss"}
    oof = np.zeros((len(labels), len(classes)))
    iters = []
    for fold, (tr, te) in enumerate(StratifiedKFold(3, shuffle=True, random_state=a.seed).split(Xf, labels)):
        cut = int(len(tr) * 0.85)
        perm = rng.permutation(tr)
        b, best = train_lgb(Xf[perm[:cut]], labels[perm[:cut]], None, Xf[perm[cut:]], labels[perm[cut:]], None,
                            rounds=1000, seed=a.seed, params=params)
        oof[te] = b.predict(Xf[te], num_iteration=best)
        iters.append(best)
    pred, conf = oof.argmax(1), oof.max(1)
    sure = conf >= 0.6
    fm = {"accuracy": float((pred == labels).mean()), "macro_f1": float(f1_score(labels, pred, average="macro")),
          "coverage_at_0.6": float(sure.mean()), "accuracy_at_0.6": float((pred[sure] == labels[sure]).mean())}
    rounds = max(50, int(np.median(iters) * 1.1))
    final, _ = train_lgb(Xf, labels, None, rounds=rounds, seed=a.seed, params=params)
    final.save_model(str(a.out / "family.txt"))
    print(f"family model: {len(classes)} classes, {fm}")
    return {"classes": classes, "min_prob": 0.6, "num_iteration": rounds, "cv": fm, "n": int(len(labels))}


def _rate(x, key):
    v, ci = x.get(key), x.get(key + "_ci")
    if v is None:
        return "–"
    return f"{v:.3f}" + (f" [{ci[0]:.3f}–{ci[1]:.3f}]" if ci else "")


def _metric_rows(label, block):
    rows = []
    for name in ("at_malicious", "at_suspicious"):
        x = block[name]
        rows.append(f"| {label} | {name[3:]} | {x['threshold']:.3f} | {_rate(x, 'tpr')} | {_rate(x, 'fpr_runs')} | "
                    f"{(x['fpr_programs'] or 0):.3f} | {(x['precision'] or 0):.3f} | {x.get('roc_auc', 0):.4f} | "
                    f"{block['brier']:.4f} |")
    return rows


def write_report(out, meta, metrics, fusion_report, ablation, trials, fam_table, benign_table, benign_scores, sep,
                 importance, family_meta, elapsed):
    tr = meta["training"]
    cf = metrics["lightgbm"]["crossfit"]
    L = [f"# {meta['model']} {meta['model_version']} — training report", "",
         f"Created {meta['created']}, {elapsed:.0f}s. Out-of-fold numbers, {tr['folds']}-fold; malware families and "
         "benign products never split across folds; API vocabulary recomputed inside each fold; calibration and "
         "thresholds cross-fitted (fold k scored with a calibration fitted on the other folds).", "",
         f"- Malicious: {tr['malicious_winmet']} WinMET reports (cap {tr['cap_per_family']}/family) + "
         f"{tr['malicious_chimera']} CHIMERA runs, {tr['malicious_groups']} family groups; CHIMERA runs carry "
         f"{tr['chimera_malware_share']:.0%} of the malware weight",
         f"- Benign: {tr['benign_runs']} CHIMERA runs from {tr['benign_programs']} products",
         f"- Dropped below {meta['min_hooked_calls']} usable calls: {tr['chimera_dropped_low_calls'] or 'none'}",
         f"- Model: {meta['model']} {json.dumps(meta['params']) if meta['params'] else '(LightGBM random forest)'}",
         f"- Features: {len(meta['feature_names'])} ({', '.join(meta['feature_groups'])}); dropped by ablation: "
         f"{', '.join(meta['features_dropped']['by_ablation']) or 'none'}; by hand: "
         f"{', '.join(meta['features_dropped']['by_hand']) or 'none'}",
         f"- API vocabulary: {len(meta['api_vocabulary']) if meta['api_vocabulary'] else 'all'} hooked APIs kept, "
         f"{len(meta['api_dropped'])} dropped as sandbox blind spots (list at the end)",
         f"- Thresholds at {tr['fpr_targets']['malicious']:.0%} / {tr['fpr_targets']['suspicious']:.0%} benign-run FPR: "
         f"malicious {meta['thresholds']['malicious']:.3f}, suspicious {meta['thresholds']['suspicious']:.3f}; "
         f"Platt a={meta['calibration']['a']:.3f} b={meta['calibration']['b']:.3f}", "",
         "**Read the CHIMERA-only rows first.** WinMET malware comes from CAPE and benign from CHIMERA, so the 'all' "
         "rows can be inflated by sandbox differences. The CHIMERA-only rows compare malware and benign recorded on "
         "the same sandbox. Model choice and ablations were decided on CHIMERA out-of-fold AUC, so those rows are "
         "slightly optimistic too; the Stage 1 runs are the untouched test.", "",
         "## Metrics (dynamic model, calibrated, cross-fitted)", "",
         "Rates with Wilson 95% intervals. Probabilities assume equal class priors.", "",
         "| runs | level | threshold (median) | TPR | FPR (runs) | FPR (products) | precision | ROC-AUC | Brier |",
         "|---|---|---|---|---|---|---|---|---|"]
    L += _metric_rows("all", cf["all"])
    if "chimera_only" in cf:
        L += _metric_rows("CHIMERA only", cf["chimera_only"])
    L += ["", f"TPR at 1% / 5% FPR (uncalibrated, all runs): {metrics['lightgbm']['tpr_at_fpr_1pct']} / "
              f"{metrics['lightgbm']['tpr_at_fpr_5pct']}", "",
          "### Reliability (all runs, cross-fitted)", "", "| bin | runs | mean predicted | observed |", "|---|---|---|---|"]
    L += [f"| {r['bin']} | {r['n']} | {r['mean_p']:.3f} | {r['observed']:.3f} |" for r in cf["all"]["reliability"]]
    L += ["", "## Model choice (out of fold)", "",
          "Chosen by CHIMERA-only ROC-AUC (3 decimals), ties by TPR at 1% FPR on all runs.", "",
          "| candidate | CHIMERA ROC-AUC | TPR@1%FPR | ROC-AUC | s |", "|---|---|---|---|---|"]
    L += [f"| {t['candidate']} | {t['chimera_roc_auc']:.4f} | {t['tpr_at_fpr_1pct']} | {t['roc_auc']:.4f} | {t['seconds']} |"
          for t in sorted(trials, key=lambda t: -t["chimera_roc_auc"])]
    if ablation["sets"]:
        L += ["", "## Feature ablations (file: ablation.json)", "",
              f"A set is dropped when removing it costs at most {ABLATION_MAX_AUC_LOSS} CHIMERA ROC-AUC and "
              f"{ABLATION_MAX_TPR_LOSS} TPR at 1% FPR: these features are suspected sandbox artefacts.", "",
              "| set | features left | CHIMERA ROC-AUC | AUC loss | TPR loss | dropped |", "|---|---|---|---|---|---|"]
        L += [f"| {n} | {s['features']} | {s['chimera_roc_auc']:.4f} | {s['chimera_auc_loss']:+.4f} | "
              f"{s['tpr_loss']:+.4f} | {'yes' if s['dropped'] else 'no'} |" for n, s in ablation["sets"].items()]
    if "random_forest" in metrics:
        L += ["", "## Baselines (same folds, uncalibrated)", "",
              "| model | CHIMERA ROC-AUC | ROC-AUC | PR-AUC | TPR@1%FPR | TPR@5%FPR |", "|---|---|---|---|---|---|"]
        for name in ("random_forest", "logistic_regression"):
            b = metrics[name]
            L.append(f"| {name} | {b['chimera_roc_auc']:.4f} | {b['roc_auc']:.4f} | {b['pr_auc']:.4f} | "
                     f"{b['tpr_at_fpr_1pct']} | {b['tpr_at_fpr_5pct']} |")
    L += ["", "## Fusion (dynamic + static, CHIMERA runs with a static result)", ""]
    if meta["fusion"]:
        fu = meta["fusion"]
        L += [f"Logistic regression on {', '.join(fu['features'])}; coefficients "
              f"{', '.join(f'{c:+.3f}' for c in fu['coef'])}, intercept {fu['intercept']:+.3f}. "
              f"Thresholds malicious {fu['thresholds']['malicious']:.3f}, suspicious {fu['thresholds']['suspicious']:.3f}. "
              f"Runs: {fusion_report['n_runs']}.", "",
              "| runs | level | threshold (median) | TPR | FPR (runs) | FPR (products) | precision | ROC-AUC | Brier |",
              "|---|---|---|---|---|---|---|---|---|"]
        L += _metric_rows("fused", fusion_report["all"])
        L += ["", "| bin | runs | mean predicted | observed |", "|---|---|---|---|"]
        L += [f"| {r['bin']} | {r['n']} | {r['mean_p']:.3f} | {r['observed']:.3f} |" for r in fusion_report["all"]["reliability"]]
    else:
        L.append(f"Not fitted: {fusion_report['skipped']}. The sandbox keeps the fixed-weight fusion.")
    L += ["", "## Benign products (calibrated cross-fitted scores)", "", "| program | runs | max score |", "|---|---|---|"]
    for prog, g in benign_table:
        sc = benign_scores.get(g, [])
        if sc:
            L.append(f"| {prog} | {len(sc)} | {max(sc):.3f} |")
    L += ["", "## Recall per malware family at the malicious threshold (cross-fitted)", "",
          "| family | source | n | recall |", "|---|---|---|---|"]
    L += [f"| {f} | {src} | {n} | {r:.3f} |" for f, src, n, r in fam_table]
    L += ["", "## Features that alone separate the classes (check for sandbox artefacts)", "",
          "AUC far from 0.5 using one feature only. Fine for behaviour (injection, persistence); suspicious for "
          "loader/runtime noise and totals. A feature that separates all runs but not CHIMERA-only runs is measuring "
          "the sandbox.", "", "| feature | AUC all | AUC CHIMERA only |", "|---|---|---|"]
    L += [f"| {n} | {auc:.3f} | {'–' if auc_c is None else f'{auc_c:.3f}'} |" for n, auc, auc_c in sep[:25]]
    L += ["", "## Top features by gain (final model)", "", "| feature | gain |", "|---|---|"]
    L += [f"| {n} | {g:.1f} |" for n, g in importance[:25]]
    diffs = [d for d in tr["fold_vocabulary_differences"] if d["added"] or d["removed"]]
    L += ["", "## Fold vocabularies", "",
          f"{len(diffs)} of {tr['folds']} folds chose a vocabulary different from the global one."
          + "".join(f" Fold {d['fold']}: +{d['added']} −{d['removed']}." for d in diffs)]
    if meta["api_dropped"]:
        L += ["", "## APIs dropped from both sides (one sandbox cannot observe them)", "", "| API | reason |", "|---|---|"]
        L += [f"| {k} | {v} |" for k, v in sorted(meta["api_dropped"].items())]
    if family_meta:
        L += ["", "## Family model", "", f"{len(family_meta['classes'])} classes ({', '.join(family_meta['classes'])}), "
              f"n={family_meta['n']}. 3-fold CV: {family_meta['cv']}"]
    (out / "report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
