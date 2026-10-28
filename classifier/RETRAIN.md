# Retraining v1: step by step

For the classifier owner's machine (the one with WinMET). Run every command from `classifier/`, unchanged, in
this order. Do not change code, tune beyond `--grid`, or pick thresholds or features by hand: the trainer
decides them by the rules written in `scripts/03_train.py` and records every decision in the report. If a
command fails, stop and send the exact command and its error.

Inputs:
- this repository (`master`), unzipped;
- WinMET volumes 1–5 (converted `data/winmet/v*.jsonl.gz`, or the 7z volumes for step 1);
- the sandbox team's folder `chimera-classifier-runs-2026-10-28/` (four `dataset-*.tar.gz` archives,
  `cohort-labels.csv`, `README.md`). It holds features and labels only, no samples. Below it is `$RUNS`.

## What changed from v0, and why

| Change | Why |
|---|---|
| CHIMERA malware runs (the October cohort, role `calibration`) are training data, grouped by family | v0 learned "CAPE report vs CHIMERA run": all malware came from CAPE, all benign from CHIMERA. On 84 CHIMERA malware runs it said benign for 73 and never malicious. |
| CHIMERA malware carries 50% of the malware class weight (`--chimera-malware-share`) | 84 runs against ~12,000 WinMET reports would otherwise barely count |
| Benign runs grouped by product (version stripped), malware by family; WinMET and CHIMERA runs of one family share a group | no product or family on both sides of a split |
| API vocabulary recomputed inside each fold | the vocabulary uses CHIMERA coverage; computed on all runs it leaks the test fold |
| Usable-calls filter `--min-calls 10` on both sources | v0 learned that an empty vector is benign (`docs/chimera/plan/classifier-audit.md` §3) |
| `--grid`: LightGBM random forest vs a boosting grid (`num_leaves` 15/31/63, `min_data_in_leaf` 10/20/50, `feature_fraction` 0.3/0.5, `lambda_l2` 1/5, learning rate 0.05), chosen by CHIMERA-only out-of-fold ROC-AUC | the deployment domain is CHIMERA; v0's choice was made on the confounded mix |
| `--ablations`: drop `file:written_log`, the `tot:*` totals and the registry-volume features when removing them costs ≤ 0.01 CHIMERA AUC and ≤ 0.01 TPR at 1% FPR | they are suspected sandbox artefacts; keep them only if they really help |
| Platt calibration instead of isotonic; thresholds at 1% / 5% benign-run FPR (was 2% / 10%) | Platt is stable with a few hundred benign runs; isotonic overfits steps |
| Calibration and thresholds cross-fitted for the report | the reported numbers never use a calibration fitted on the same fold |
| Fusion fitted (logistic regression on each component's logit plus an "abstained" flag) on CHIMERA runs with a static result, replacing the fixed 0.1 weights | the sandbox can now show `calibrated_probability` from a model fitted on its own runs |
| Report: CHIMERA-only metrics with Wilson 95% intervals, reliability tables, per-source family recall, single-feature AUC on all vs CHIMERA-only runs | the honest numbers, separated from the confounded ones |

Not changed: the feature extractor and `featurize.py` vectors (`FEATURIZE_VERSION` 2), the static EMBER models,
the family model's training (WinMET only; WinMET record ids are SHA-256 hashes, so there are no repeated samples
to group), and the abstention gate (fewer than 10 usable calls → no dynamic verdict).

## 0. Set up and test

```bash
python3.11 -m venv .venv && .venv/bin/pip install -r requirements-train.txt   # macOS: brew install libomp first
.venv/bin/python -m pytest -q tests
```

All tests must pass (one skip is fine when `thrember` is not importable). Report the summary line.

## 1. WinMET (skip if `data/winmet/v1..v5.jsonl.gz` and their `.done.json` files exist)

```bash
.venv/bin/python scripts/01_convert_winmet.py --volumes 1 2 3 4 5 --jobs 5
```

Then check whether the records carry a first-seen or submission date, and report yes/no and the field name:

```bash
.venv/bin/python -c "import gzip, json; r = json.loads(gzip.open('data/winmet/v1.jsonl.gz').readline()); print(sorted(r), sorted(r['label']), sorted(r['features']['sample']))"
```

This round does not use it (no time split). The answer decides whether the next round can hold out the newest
samples.

## 2. Load the CHIMERA runs (all four archives into one file)

```bash
.venv/bin/python scripts/02_load_chimera.py $RUNS/dataset-cohort.tar.gz $RUNS/dataset-benign-v4.tar.gz \
    $RUNS/dataset-benign-v3.tar.gz $RUNS/dataset-earlier-runs.tar.gz \
    --labels-csv $RUNS/cohort-labels.csv --out data/chimera/chimera.jsonl
```

Expected output: `written` = benign/linux 80, benign/windows 170, calibration/windows 84, not_executed 3;
`chimera_malware_families` 22, `chimera_malware_runs` 84. Report the printed JSON. The 3 not-executed runs
(BumbleBee DLLs) are skipped by the trainer; Linux runs are not used by the Windows model.

## 3. Train v1

```bash
.venv/bin/python scripts/03_train.py --chimera data/chimera/chimera.jsonl --out models/v1 --model-version 1.0 \
    --grid --ablations --baselines --family
```

The defaults are the agreed settings: `--min-calls 10`, `--fpr-malicious 0.01`, `--fpr-suspicious 0.05`,
`--chimera-malware-share 0.5`, 5 folds, seed 7. Do not pass other values.

Run time: the first run featurizes WinMET once per distinct fold vocabulary (about 3–5 min each, cached in
`data/cache/`), then trains 37 candidates × 5 folds, 3 ablations and the baselines. Each candidate's seconds are
printed; expect one to three hours on a laptop. Let it finish.

Outputs in `models/v1/`: `model.txt`, `family.txt`, `meta.json`, `report.md`, `ablation.json` (the ablation
summary), `metrics.json`, `oof.csv`, `feature_importance.csv`.

## 4. Package and test

```bash
.venv/bin/python scripts/05_package.py --model models/v1 --static-model models/static_v0 --out deploy
.venv/bin/python -m pytest -q tests
```

The static boosters are reused from the current `deploy/` (they are not retrained). Packaging runs the model
through CHIMERA's own runner and prints a verdict; it must show `"model_version": "1.0+fusionlr"` when the fusion
was fitted (`1.0+fusion0.1` means the report explains why it was not).

## 5. Zip and send back

```bash
zip -r chimera-classifier-v1.zip deploy models/v1/report.md models/v1/meta.json models/v1/ablation.json
unzip -l chimera-classifier-v1.zip | grep -Ei '\.(pkl|pickle|joblib|npz)$' && echo "STOP: remove these" || echo ok
shasum -a 256 deploy/MANIFEST.json
```

No WinMET data, no CHIMERA run data (`data/`, `oof.csv`, `metrics.json`), no `.venv`. Send the zip and print:
the `MANIFEST.json` fingerprint, the zip size, and from `models/v1/report.md` the chosen model, the dropped
feature sets, and the CHIMERA-only and fused rows of the metric tables. No claims beyond the report.

## Reading the report

- **CHIMERA-only rows first.** They compare malware and benign recorded on the same sandbox. The "all" rows mix
  in CAPE-recorded WinMET malware and stay inflated by sandbox differences.
- Model choice and ablations are decided on CHIMERA out-of-fold AUC, so the CHIMERA rows are slightly optimistic.
  The Stage 1 runs are the untouched test, evaluated once after this model is installed.
- **Small numbers.** At most 81 CHIMERA malware runs (21 families) and 170 benign Windows runs enter, fewer after
  the usable-calls filter (the trainer prints how many); intervals are wide. The fusion is fitted only on runs
  that have a static result (mostly benign v4 and the cohort), because older runs predate the static analyzer.
  A 1% FPR target cannot be resolved from about 80 such benign runs, so the fused "malicious" threshold lands
  just above the highest benign run and the "suspicious" level carries most detections. This is expected.
- Probabilities (`calibrated_probability`) assume equal class priors: they say how malware-like a run is, not
  how likely a random upload is malware.
- The source confound is reduced, not removed: most malware examples still come from CAPE.
