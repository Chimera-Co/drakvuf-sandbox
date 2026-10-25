"""Train the CHIMERA malicious-vs-benign model (LightGBM) and an optional family model.

    .venv/bin/python scripts/03_train.py --chimera data/chimera/chimera.jsonl --out models/v0 --baselines --family

Malicious: WinMET records (data/winmet/v*.jsonl.gz), capped per family so a few huge families
(Redline, Vbclone, ...) don't dominate. Benign: CHIMERA runs with split == "train".
CHIMERA malware runs (split == "chimera_test") are never loaded here.

Cross-validation keeps every family (malware) and every program (benign) on one side of a
split. Out-of-fold scores give the metrics, the isotonic calibration and the thresholds.
The final model is refit on everything with the median early-stopping round count.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import platform
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
import orjson
import scipy.sparse as sp
import sklearn
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from chimera_clf import featurize as fz  # noqa: E402
from chimera_clf.cape_adapter import hooks_sha256  # noqa: E402

RF_PARAMS = dict(boosting="rf", bagging_fraction=0.632, bagging_freq=1, feature_fraction=0.3, num_leaves=127,
                 min_data_in_leaf=5, min_sum_hessian_in_leaf=1e-3, lambda_l2=0.0, verbose=-1, deterministic=True,
                 force_col_wise=True)
RF_TREES = 500
ALGO = {"name": "gbdt"}
LGB_PARAMS = dict(objective="binary", learning_rate=0.05, num_leaves=31, min_data_in_leaf=10,
                  min_sum_hessian_in_leaf=1e-3, feature_fraction=0.5, bagging_fraction=0.8, bagging_freq=1,
                  lambda_l2=1.0, verbose=-1, deterministic=True, force_col_wise=True)
NAME_INDEX = {n: i for i, n in enumerate(fz.ALL_FEATURE_NAMES)}


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


def compute_coverage(files: list[Path], chimera_path: Path | None, cache_dir: Path, min_calls: int) -> dict:
    """Share of WinMET reports / CHIMERA Windows runs in which each hooked API appears at all."""
    key = hashlib.sha256(json.dumps([[str(f), f.stat().st_size, f.stat().st_mtime] for f in files]
                                    + [min_calls]).encode()).hexdigest()[:16]
    cache = cache_dir / f"cape_coverage_{key}.json"
    if cache.exists():
        cape, n = json.loads(cache.read_text()).values()
    else:
        counts, n = Counter(), 0
        for f in files:
            with gzip.open(f, "rb") as fh:
                for line in fh:
                    try:
                        a = orjson.loads(line)["features"]["api_calls"]
                    except (orjson.JSONDecodeError, KeyError):
                        continue
                    if sum(a.values()) >= min_calls:
                        n += 1
                        counts.update(a.keys())
        cape = {k: v / max(1, n) for k, v in counts.items()}
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"cape": cape, "n": n}))
    chi, m = Counter(), 0
    if chimera_path and chimera_path.exists():
        for line in chimera_path.read_text().splitlines():
            r = json.loads(line) if line.strip() else None
            if r and r.get("split") == "train" and (r["features"].get("run") or {}).get("guest_os") == "windows":
                m += 1
                chi.update(r["features"].get("api_calls", {}).keys())
    return {"cape": cape, "chimera": {k: v / max(1, m) for k, v in chi.items()}, "n_cape": n, "n_chimera": m}


def load_winmet(files: list[Path], cache_dir: Path, allowed=None):
    """Featurize every WinMET record once; cache as sparse matrix + metadata."""
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


def load_chimera(path: Path | None, allowed=None):
    if not path or not path.exists():
        return _csr([]), {"id": [], "group": [], "calls": [], "program": [], "arm": []}
    rows, meta = [], {"id": [], "group": [], "calls": [], "program": [], "arm": []}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("split") != "train" or r["label"].get("malicious") != 0:
            continue
        if (r["features"].get("run") or {}).get("guest_os") != "windows":
            continue
        rows.append(_sparse_row(r["features"], allowed))
        meta["id"].append(r["id"])
        meta["group"].append(r["group"])
        meta["calls"].append(fz.hooked_call_count(r["features"], allowed))
        meta["program"].append(r["aux"].get("program"))
        meta["arm"].append(r["aux"].get("arm"))
    return _csr(rows), meta


# ------------------------------------------------------------------ helpers
def sample_malware(meta, rng, cap_per_family, max_total, min_calls):
    by_group = defaultdict(list)
    for i, (fam, av, calls) in enumerate(zip(meta["family"], meta["avclass"], meta["calls"])):
        if calls < min_calls:
            continue
        by_group[f"fam:{(fam or av or 'unknown').lower()}"].append(i)
    chosen = []
    for g, idx in by_group.items():
        idx = list(idx)
        rng.shuffle(idx)
        chosen += idx[:cap_per_family]
    rng.shuffle(chosen)
    chosen = sorted(chosen[:max_total])
    groups = [f"fam:{(meta['family'][i] or meta['avclass'][i] or 'unknown').lower()}" for i in chosen]
    # unlabeled reports are their own group (no family to leak across folds)
    groups = [g if g != "fam:unknown" and g != "fam:(n/a)" else f"sha:{meta['id'][i]}" for g, i in zip(groups, chosen)]
    return np.array(chosen), groups


def balanced_weights(y, groups):
    """Benign: each program counts equally regardless of run count. Classes sum to the same weight."""
    w = np.ones(len(y), dtype=np.float64)
    runs = Counter(g for g, yy in zip(groups, y) if yy == 0)
    for i, (g, yy) in enumerate(zip(groups, y)):
        if yy == 0:
            w[i] = 1.0 / runs[g]
    pos, neg = w[y == 1].sum(), w[y == 0].sum()
    if neg > 0:
        w[y == 0] *= pos / neg
    return w / w.mean()


def train_lgb(X, y, w, Xv=None, yv=None, wv=None, rounds=800, seed=0, params=None):
    if ALGO["name"] == "rf" and not params:  # LightGBM random forest: fixed tree count, no early stopping
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


def binary_metrics(y, score, groups, thr):
    y, score = np.asarray(y), np.asarray(score)
    pred = score >= thr
    out = {"n": int(len(y)), "n_malicious": int(y.sum()), "n_benign": int((y == 0).sum()), "threshold": thr}
    if len(set(y)) > 1:
        out["roc_auc"] = float(roc_auc_score(y, score))
        out["pr_auc"] = float(average_precision_score(y, score))
    out["tpr"] = float(pred[y == 1].mean()) if (y == 1).any() else None
    out["fpr_runs"] = float(pred[y == 0].mean()) if (y == 0).any() else None
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
    if not (y == 0).any():
        return None
    t = threshold_for_fpr(score[y == 0], fpr, 0.0)
    return float((score[y == 1] >= t).mean())


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--winmet", type=Path, nargs="*", default=sorted((ROOT / "data" / "winmet").glob("v*.jsonl.gz")))
    ap.add_argument("--chimera", type=Path, default=ROOT / "data" / "chimera" / "chimera.jsonl")
    ap.add_argument("--out", type=Path, default=ROOT / "models" / "v0")
    ap.add_argument("--groups", nargs="+", default=list(fz.DEFAULT_GROUPS), help=f"feature groups, from {fz.ALL_GROUPS}")
    ap.add_argument("--cap-per-family", type=int, default=300)
    ap.add_argument("--max-malware", type=int, default=12000)
    ap.add_argument("--min-calls", type=int, default=10, help="same gate model.py uses for 'unknown'")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--fpr-malicious", type=float, default=0.02)
    ap.add_argument("--fpr-suspicious", type=float, default=0.10)
    ap.add_argument("--baselines", action="store_true", help="also cross-validate Random Forest and logistic regression")
    ap.add_argument("--family", action="store_true", help="also train the family model")
    ap.add_argument("--family-top", type=int, default=20)
    ap.add_argument("--family-min", type=int, default=50)
    ap.add_argument("--model-version", default="0.1")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--algo", choices=["gbdt", "rf"], default="gbdt",
                    help="LightGBM boosting (gbdt) or LightGBM random forest (rf); both save as text, no pickles")
    ap.add_argument("--extra-drop", nargs="*", default=[], help="APIs to remove from the vocabulary as well")
    ap.add_argument("--no-vocabulary", action="store_true", help="keep APIs one sandbox cannot observe (ablation)")
    ap.add_argument("--extra-benign", type=Path, help=argparse.SUPPRESS)  # smoke tests only
    a = ap.parse_args()
    ALGO["name"] = a.algo
    rng = np.random.default_rng(a.seed)
    t_start = time.time()
    a.out.mkdir(parents=True, exist_ok=True)

    print("API coverage per sandbox ...", flush=True)
    coverage = compute_coverage(list(a.winmet), a.chimera, ROOT / "data" / "cache", a.min_calls)
    if a.no_vocabulary or coverage["n_chimera"] == 0:
        vocab, dropped = None, {}
    else:
        vocab, dropped = fz.coverage_vocabulary(coverage["cape"], coverage["chimera"])
        for api in a.extra_drop:
            if api in vocab:
                vocab.remove(api)
                dropped[api] = "dropped by hand (--extra-drop): suspected partial blind spot"

    print(f"  vocabulary: {len(vocab) if vocab else 'all'} APIs kept, {len(dropped)} dropped "
          f"({coverage['n_cape']} WinMET reports, {coverage['n_chimera']} CHIMERA runs)", flush=True)
    print("loading WinMET ...", flush=True)
    Xw_all, mw = load_winmet(list(a.winmet), ROOT / "data" / "cache", vocab)
    print(f"  {Xw_all.shape[0]} WinMET records", flush=True)
    Xc, mc = load_chimera(a.chimera, vocab)
    if a.extra_benign:
        Xe, me = load_chimera(a.extra_benign, vocab)
        Xc, mc = sp.vstack([Xc, Xe]).tocsr(), {k: mc[k] + me[k] for k in mc}
    keep_c = np.array([c >= a.min_calls for c in mc["calls"]], dtype=bool)
    dropped_benign = int((~keep_c).sum())
    Xc = Xc[np.flatnonzero(keep_c)] if len(keep_c) else Xc
    mc = {k: [v for v, kk in zip(vals, keep_c) if kk] for k, vals in mc.items()}
    n_programs = len(set(mc["group"]))
    print(f"  {Xc.shape[0]} CHIMERA benign runs from {n_programs} programs (dropped {dropped_benign} with < {a.min_calls} calls)")
    if n_programs < 2:
        raise SystemExit("need benign runs from at least 2 programs: run 02_load_chimera.py first")

    mal_idx, mal_groups = sample_malware(mw, rng, a.cap_per_family, a.max_malware, a.min_calls)
    names = fz.feature_names(a.groups)
    cols = np.array([NAME_INDEX[n] for n in names])
    X = sp.vstack([Xw_all[mal_idx][:, cols], Xc[:, cols]]).tocsr().astype(np.float32)
    y = np.concatenate([np.ones(len(mal_idx)), np.zeros(Xc.shape[0])]).astype(int)
    groups = list(mal_groups) + list(mc["group"])
    ids = [mw["id"][i] for i in mal_idx] + list(mc["id"])
    sources = ["winmet"] * len(mal_idx) + ["chimera"] * Xc.shape[0]
    w = balanced_weights(y, groups)
    print(f"training set: {len(mal_idx)} malicious ({len(set(mal_groups))} groups), {int((y == 0).sum())} benign; "
          f"{len(names)} features", flush=True)

    # ---- cross-validation
    k = max(2, min(a.folds, n_programs))
    cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=a.seed)
    oof = np.full(len(y), np.nan)
    fold_of = np.full(len(y), -1)
    best_iters = []
    base_oof = {"random_forest": np.full(len(y), np.nan), "logistic_regression": np.full(len(y), np.nan)}
    for fold, (tr, te) in enumerate(cv.split(X, y, groups)):
        inner = StratifiedGroupKFold(n_splits=max(2, min(5, len({groups[i] for i in tr if y[i] == 0}))),
                                     shuffle=True, random_state=a.seed + fold)
        itr, ival = next(inner.split(X[tr], y[tr], [groups[i] for i in tr]))
        itr, ival = tr[itr], tr[ival]
        booster, best = train_lgb(X[itr], y[itr], w[itr], X[ival], y[ival], w[ival], seed=a.seed + fold)
        best_iters.append(best)
        oof[te] = booster.predict(X[te], num_iteration=best)
        fold_of[te] = fold
        if a.baselines:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import MaxAbsScaler
            rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=a.seed)
            rf.fit(X[tr], y[tr], sample_weight=w[tr])
            base_oof["random_forest"][te] = rf.predict_proba(X[te])[:, 1]
            lr = make_pipeline(MaxAbsScaler(), LogisticRegression(max_iter=3000, C=0.5))
            lr.fit(X[tr], y[tr], logisticregression__sample_weight=w[tr])
            base_oof["logistic_regression"][te] = lr.predict_proba(X[te])[:, 1]
        print(f"  fold {fold}: {len(te)} test, best_iter {best}, benign in test "
              f"{int((y[te] == 0).sum())}", flush=True)

    ok = ~np.isnan(oof)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(oof[ok], y[ok], sample_weight=w[ok])
    cal = np.interp(oof, iso.X_thresholds_, iso.y_thresholds_)
    ben = cal[(y == 0) & ok]
    t_mal = threshold_for_fpr(ben, a.fpr_malicious, 0.5)
    t_sus = min(t_mal, threshold_for_fpr(ben, a.fpr_suspicious, 0.2))

    g_ok = [g for g, o in zip(groups, ok) if o]
    metrics = {
        "lightgbm": {
            "at_malicious_threshold": binary_metrics(y[ok], cal[ok], g_ok, t_mal),
            "at_suspicious_threshold": binary_metrics(y[ok], cal[ok], g_ok, t_sus),
            "tpr_at_fpr_1pct": tpr_at_fpr(y[ok], oof[ok], 0.01),
            "tpr_at_fpr_5pct": tpr_at_fpr(y[ok], oof[ok], 0.05),
        }
    }
    for name, s in base_oof.items():
        if a.baselines:
            metrics[name] = {"roc_auc": float(roc_auc_score(y, s)), "pr_auc": float(average_precision_score(y, s)),
                             "tpr_at_fpr_1pct": tpr_at_fpr(y, s, 0.01), "tpr_at_fpr_5pct": tpr_at_fpr(y, s, 0.05)}
    # per malware family recall (out of fold) at the malicious threshold
    fam_recall = defaultdict(list)
    for g, yy, s in zip(groups, y, cal):
        if yy == 1 and g.startswith("fam:"):
            fam_recall[g[4:]].append(s >= t_mal)
    fam_table = sorted(((f, len(v), float(np.mean(v))) for f, v in fam_recall.items()), key=lambda r: -r[1])[:30]
    benign_table = sorted({(p, g) for p, g in zip(mc["program"], mc["group"])})
    benign_scores = defaultdict(list)
    for g, yy, s in zip(groups, y, cal):
        if yy == 0:
            benign_scores[g].append(float(s))

    # ---- univariate separation (sandbox-artefact check)
    Xd = X.toarray() if X.shape[0] * X.shape[1] < 4e8 else None
    sep = []
    if Xd is not None:
        for j, n in enumerate(names):
            col = Xd[:, j]
            if col.max() == col.min():
                continue
            auc = roc_auc_score(y, col)
            sep.append((n, float(auc)))
        sep.sort(key=lambda r: -abs(r[1] - 0.5))

    # ---- final model on everything
    rounds = RF_TREES if a.algo == "rf" else max(50, int(np.median(best_iters) * 1.1))
    final, _ = train_lgb(X, y, w, rounds=rounds, seed=a.seed)
    final.save_model(str(a.out / "model.txt"))
    gain = final.feature_importance("gain")
    importance = sorted(zip(names, gain.tolist()), key=lambda r: -r[1])

    # ---- family model
    family_meta = None
    if a.family:
        family_meta = train_family(Xw_all, mw, cols, a, rng)

    meta = {
        "schema": "chimera-model-meta/1",
        "model": "chimera-lgbm" if a.algo == "gbdt" else "chimera-lgbm-rf",
        "algorithm": a.algo,
        "model_version": a.model_version,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "featurize_version": fz.FEATURIZE_VERSION,
        "hooks_sha256": hooks_sha256(),
        "feature_groups": a.groups,
        "feature_names": names,
        "api_vocabulary": vocab,
        "api_dropped": dropped,
        "api_coverage": {"n_cape": coverage["n_cape"], "n_chimera": coverage["n_chimera"]},
        "min_hooked_calls": a.min_calls,
        "num_iteration": rounds,
        "calibration": {"x": iso.X_thresholds_.tolist(), "y": iso.y_thresholds_.tolist()},
        "thresholds": {"malicious": t_mal, "suspicious": t_sus},
        "family": family_meta,
        "training": {
            "winmet_records_available": int(Xw_all.shape[0]), "malicious": int(len(mal_idx)),
            "malicious_groups": len(set(mal_groups)), "benign_runs": int((y == 0).sum()),
            "benign_programs": n_programs, "benign_dropped_low_calls": dropped_benign,
            "folds": k, "best_iterations": best_iters, "cap_per_family": a.cap_per_family, "seed": a.seed,
        },
        "versions": {"python": platform.python_version(), "lightgbm": lgb.__version__,
                     "scikit-learn": sklearn.__version__, "numpy": np.__version__},
    }
    (a.out / "meta.json").write_text(json.dumps(meta, indent=1))
    (a.out / "metrics.json").write_text(json.dumps({"metrics": metrics, "family_recall": fam_table,
                                                    "benign_scores": benign_scores}, indent=1))
    with (a.out / "oof.csv").open("w") as f:
        f.write("id,source,group,y,fold,raw,calibrated\n")
        for row in zip(ids, sources, groups, y, fold_of, oof, cal):
            f.write(",".join(str(v) for v in row) + "\n")
    with (a.out / "feature_importance.csv").open("w") as f:
        f.write("feature,gain\n" + "".join(f"{n},{g:.4f}\n" for n, g in importance))
    write_report(a.out, meta, metrics, fam_table, benign_table, benign_scores, sep, importance, family_meta,
                 time.time() - t_start)
    print(f"done in {time.time() - t_start:.0f}s -> {a.out}")
    print(json.dumps(metrics["lightgbm"]["at_malicious_threshold"], indent=1))


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


def write_report(out, meta, metrics, fam_table, benign_table, benign_scores, sep, importance, family_meta, elapsed):
    m = metrics["lightgbm"]["at_malicious_threshold"]
    s = metrics["lightgbm"]["at_suspicious_threshold"]
    tr = meta["training"]
    L = [f"# {meta['model']} {meta['model_version']} — training report", "",
         f"Created {meta['created']}, {elapsed:.0f}s. Out-of-fold numbers, {tr['folds']}-fold, "
         "families and benign programs never split across folds.", "",
         f"- Malicious: {tr['malicious']} WinMET reports from {tr['malicious_groups']} groups "
         f"(cap {tr['cap_per_family']}/family)",
         f"- Benign: {tr['benign_runs']} CHIMERA runs from {tr['benign_programs']} programs "
         f"(dropped {tr['benign_dropped_low_calls']} with < {meta['min_hooked_calls']} hooked calls)",
         f"- Features: {len(meta['feature_names'])} ({', '.join(meta['feature_groups'])})",
         f"- API vocabulary: {len(meta['api_vocabulary']) if meta['api_vocabulary'] else 'all'} hooked APIs kept, "
         f"{len(meta['api_dropped'])} dropped as sandbox blind spots (list at the end)", "",
         "**Caveat:** all malicious examples come from CAPE and all benign ones from CHIMERA, so these numbers can "
         "be inflated by sandbox differences. The honest number is the frozen model on CHIMERA malware runs.", "",
         "## Metrics (LightGBM)", "",
         "| | threshold | TPR | FPR (runs) | FPR (programs) | precision | F1 | ROC-AUC | PR-AUC |",
         "|---|---|---|---|---|---|---|---|---|"]
    for label, x in (("malicious", m), ("suspicious", s)):
        L.append(f"| {label} | {x['threshold']:.3f} | {x['tpr']:.3f} | {x['fpr_runs']:.3f} | {x['fpr_programs']:.3f} | "
                 f"{(x['precision'] or 0):.3f} | {(x['f1'] or 0):.3f} | {x.get('roc_auc', 0):.4f} | {x.get('pr_auc', 0):.4f} |")
    L += ["", f"Confusion at the malicious threshold: {m['confusion']}",
          f"TPR at 1% / 5% FPR (uncalibrated): {metrics['lightgbm']['tpr_at_fpr_1pct']} / "
          f"{metrics['lightgbm']['tpr_at_fpr_5pct']}", ""]
    if "random_forest" in metrics:
        L += ["## Baselines (same folds)", "", "| model | ROC-AUC | PR-AUC | TPR@1%FPR | TPR@5%FPR |", "|---|---|---|---|---|"]
        for name in ("random_forest", "logistic_regression"):
            b = metrics[name]
            L.append(f"| {name} | {b['roc_auc']:.4f} | {b['pr_auc']:.4f} | {b['tpr_at_fpr_1pct']} | {b['tpr_at_fpr_5pct']} |")
        L.append("")
    L += ["## Benign programs (calibrated out-of-fold scores)", "", "| program | runs | max score |", "|---|---|---|"]
    for prog, g in benign_table:
        sc = benign_scores.get(g, [])
        if sc:
            L.append(f"| {prog} | {len(sc)} | {max(sc):.3f} |")
    L += ["", "## Recall per malware family (top 30 by size)", "", "| family | n | recall |", "|---|---|---|"]
    L += [f"| {f} | {n} | {r:.3f} |" for f, n, r in fam_table]
    L += ["", "## Features that alone separate the classes (check for sandbox artefacts)", "",
          "AUC far from 0.5 using one feature only. Fine for behaviour (injection, persistence); suspicious for "
          "loader/runtime noise (LdrGetDllHandle, GetSystemTimeAsFileTime, totals).", "",
          "| feature | AUC |", "|---|---|"]
    L += [f"| {n} | {auc:.3f} |" for n, auc in sep[:25]]
    L += ["", "## Top features by gain (final model)", "", "| feature | gain |", "|---|---|"]
    L += [f"| {n} | {g:.1f} |" for n, g in importance[:25]]
    if meta["api_dropped"]:
        L += ["", "## APIs dropped from both sides (one sandbox cannot observe them)", "", "| API | reason |", "|---|---|"]
        L += [f"| {k} | {v} |" for k, v in sorted(meta["api_dropped"].items())]
    if family_meta:
        L += ["", "## Family model", "", f"{len(family_meta['classes'])} classes ({', '.join(family_meta['classes'])}), "
              f"n={family_meta['n']}. 3-fold CV: {family_meta['cv']}"]
    (out / "report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
