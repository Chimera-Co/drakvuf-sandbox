# Runbook: from benign runs to a deployable model

All commands from `classifier/`, using `.venv/bin/python` (Python 3.11, pinned versions):
`python3.11 -m venv .venv && .venv/bin/pip install -r requirements-train.txt` (macOS: `brew install libomp`).

Data is not in git. `CHIMERA_DATASETS` points at the folder with the WinMET 7z volumes, their label files and
`EMBER2024/data` (default: `Capstone_Classifier_Datasets` next to the repository checkout). Converted data and
caches go to `classifier/data/` (ignored by git; copy or symlink an existing one there to skip step 0).
Deploying to the CHIMERA host: `docs/chimera/classifier-static-quickstart.md`.

## 0. Converted WinMET (once)
```bash
.venv/bin/python scripts/01_convert_winmet.py --volumes 1 2 3 4 5 --jobs 5
```
Output `data/winmet/v1..v5.jsonl.gz`; `v<N>.done.json` appears when a volume is finished.

## 1. Load CHIMERA runs
Any mix of the `m5_eval.py export` archive, its folder, raw analysis folders (features are computed with
CHIMERA's own extractor if `features.json` is missing), or loose `features.json` files:
```bash
.venv/bin/python scripts/02_load_chimera.py ~/Downloads/chimera-dataset.tar.gz ~/benign_runs/ --out data/chimera/chimera.jsonl
```
Runs without `labels.json` count as benign (`--role`). Add `--labels-csv labels.csv` (columns
`key,role,family,program,category`; key = analysis folder name or sha256) to name programs or mark malware.
Stage 1 malware runs (`role` test/control) are stored with `split=chimera_test` and are never used for training.
The October cohort (`role` calibration) is CHIMERA malware for training (`split=train`, label 1). The v1 retrain
is written out step by step in [RETRAIN.md](RETRAIN.md).

Benign runs come from https://github.com/Chimera-Co/chimera-benign-dataset (Shreyas pushes them as the batch runs):
```bash
git -C ../chimera-benign-dataset pull
.venv/bin/python scripts/02_load_chimera.py ../chimera-benign-dataset/windows ../chimera-benign-dataset/linux \
    --index-csv ../chimera-benign-dataset/index.csv --out data/chimera/chimera.jsonl
```

## 2. Train
```bash
# dynamic model (v0 = LightGBM random forest; boosting overfits the small benign set)
.venv/bin/python scripts/03_train.py --out models/v0 --algo rf --baselines --family
# static models on EMBER2024 (scripts/06_download_ember.py first)
.venv/bin/python scripts/07_train_static.py --out models/static_v0
```
The dynamic trainer measures which hooked APIs each sandbox can observe and drops the blind spots from both
sides (`api_vocabulary` in meta.json, listed at the end of report.md), plus DLL-loader noise and the partly
invisible `FindFirstFileEx*`. Without this the model only learns to tell CAPE reports from CHIMERA runs.
Read `models/v0/report.md`: out-of-fold metrics, per-benign-program scores, per-family recall, features that
alone separate the classes (check those for sandbox artefacts), baselines, family model.
The first run featurizes all WinMET records (~3–5 min) and caches them in `data/cache/`.

## 3. Package and check
```bash
.venv/bin/python scripts/05_package.py --model models/v0 --static-model models/static_v0 --out deploy
.venv/bin/python -m pytest -q tests
```
`deploy/` is what goes to `/etc/drakrun/classifier/`: `model.py featurize.py hooks.txt model.txt meta.json static_meta.json static_{pe,elf,pdf}.txt
family.txt MANIFEST.json`. No pickles. Packaging runs the model through CHIMERA's own `runner.py`.

## Rules
- Never train or tune on `split=chimera_test` runs. Evaluate on them once, after the model is frozen.
- One benign program = one group: all its runs stay on the same side of every split.
- Thresholds come from out-of-fold benign scores (default: ≤2% runs above "malicious", ≤10% above "suspicious").
