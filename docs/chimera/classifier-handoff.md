# Classifier retrain and calibration: handoff to the classifier owner

> **Update 28 Oct 2026:** superseded for the v1 retrain by [`classifier/RETRAIN.md`](../../classifier/RETRAIN.md). As agreed with the classifier owner, the October cohort's CHIMERA malware runs are now training data (grouped by family), and calibration, thresholds and fusion are cross-fitted on grouped folds instead of fitted on a held-out cohort. Stage 1 stays the untouched holdout.

For Monty (classifier owner), from the sandbox side. Status 25 Oct 2026. The detailed plan is
[`plan/calibration-cohort.md`](plan/calibration-cohort.md); the training steps are in
[`classifier/RUNBOOK.md`](../../classifier/RUNBOOK.md); the model contract is in
[`classifier-interface.md`](classifier-interface.md). This page is the checklist and what changed on the
sandbox that affects you.

## What changed on the sandbox (affects training data)

- **Mobile apps are not classified.** Android APK and iOS IPA uploads are static-only and get
  `classification.json` with `"not_applicable": true` (label `unknown`). Leave them out of training and
  evaluation: the models are trained on Windows and Linux files.
- **Not features:** threat-intel results (VirusTotal, abuse.ch, OTX, ...), memory-dump scan results and MobSF
  findings are shown beside the verdict but never go into `features.json`. Keep it that way: an intel feature
  leaks the label, and most new samples are not on VirusTotal.
- **VirusTotal is available for labels.** A VirusTotal key is configured on the CHIMERA host. Use detections
  only as ground truth for training and evaluation (for example a consensus threshold per family), by hash
  lookup only. Never upload a sample.
- **The UI can now show a calibrated probability.** The verdict accepts an optional
  `calibrated_probability` (0..1) and `calibration` (short text). Return them only from a model calibrated as
  below; until then the card keeps saying the score is not a probability.
- The static-analysis VM now boots on demand and stops when idle; nothing changes for you.

## Checklist

1. **Retrain v1** with the usable-calls filter (only runs with at least `--min-calls` calls inside the API
   vocabulary, the same count the deployed gate uses):

   ```bash
   cd classifier
   .venv/bin/python scripts/03_train.py --out models/v1 --model-version 1.0 --min-calls 10
   ```

   Same data and splits as v0 otherwise. Compare `models/v1/report.md` with `models/v0/report.md`
   (out-of-fold metrics, per-program scores) and note the differences.
2. **Freeze and package:**

   ```bash
   .venv/bin/python scripts/05_package.py --model models/v1 --out deploy
   ```

   Check it with the deployment venv versions listed in `classifier-interface.md`, then send the `deploy/`
   folder and its `MANIFEST.json` fingerprint to Shreyas, who installs it on the host
   (`classifier-static-quickstart.md`). Stage 1 is planned only after this, because its plan records the
   fingerprint.
3. **Calibration cohort runs (Shreyas):** about 100 Windows malware (at most 4 per family, every Stage 1 hash
   excluded) plus about 100 new benign programs from `scripts/chimera/bench/benign-v4-candidates.csv`, about
   13 h of VM time. Downloading malware needs the written owner and mentor OK first. You receive the
   `m5_eval.py export` archive.
4. **Load the cohort** with labels:

   ```bash
   .venv/bin/python scripts/02_load_chimera.py cohort-export.tar.gz --labels-csv cohort-labels.csv \
       --out data/chimera/cohort.jsonl
   ```

   `cohort-labels.csv` columns: `key,role,family,program,category`.
5. **Fit calibration and fusion on the cohort only**, with grouped cross-validation (one group = one malware
   family or one benign program):
   - Platt scaling per component (dynamic, static) on its decision score, fitted inside the folds.
   - Fusion: logistic regression on the calibrated component scores plus an "abstained" indicator per
     component, replacing the fixed weights.
   - Report out of fold: reliability curve, Brier score, and the metrics at the chosen thresholds.
6. **Ship v1.1**: the model returns `calibrated_probability` and `calibration`
   (e.g. `"platt + fusion LR, grouped 5-fold, cohort 2026-10"`) next to the usual fields. Package and hand over
   as in step 2.
7. **Stage 1 stays untouched**: it is evaluated once, after calibration is frozen.

## Constraints

- abuse.ch terms: no training of models on their data without written permission. Calibration fits a few
  numbers on CHIMERA's own run scores, not on abuse.ch content; confirm this reading with the mentor before
  step 5 and record it.
- ~200 calibration runs give usable probabilities for this sandbox and these families, with wide uncertainty;
  they do not remove the source/label confound (WinMET malware vs CHIMERA benign). Say so in the report.
- No samples, keys or the sample register in git.
