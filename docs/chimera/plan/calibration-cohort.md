# Classifier retraining and calibration cohort

> **Update 28 Oct 2026:** superseded for the v1 retrain by [`classifier/RETRAIN.md`](../../../classifier/RETRAIN.md). As agreed with the classifier owner, the October cohort's CHIMERA malware runs are now training data (grouped by family), and calibration, thresholds and fusion are cross-fitted on grouped folds instead of fitted on a held-out cohort. Stage 1 stays the untouched holdout.

Owner of the model: classifier owner (Monty). Sandbox runs: Shreyas. Status 25 Oct 2026. Checklist and what changed on the sandbox: [`../classifier-handoff.md`](../classifier-handoff.md).

## Order

1. **Retrain the dynamic model with the usable-calls filter** (`classifier/scripts/03_train.py`, commit
   `d3cb3d6`): a training run is kept only if it has at least `--min-calls` calls *inside the API vocabulary*,
   the count the deployed gate uses (`deploy/model.py`). Before this, two benign training runs with 0 usable
   calls taught the model that an empty vector is benign (`classifier-audit.md` §3). Same data, same splits
   otherwise; compare `models/v1/report.md` with v0 (out-of-fold metrics, per-program scores).
2. **Freeze it**: package (`05_package.py`), record the `MANIFEST.json` fingerprint, deploy. Stage 1 is planned
   only after this, because its plan records the classifier fingerprint.
3. **Run the calibration cohort** (below): about 100 Windows malware + about 100 new benign programs, roughly
   13 h of VM time (about 200 runs of 2 min plus restore and postprocessing).
4. **Fit calibration and fusion on the cohort only**, with grouped cross-validation:
   - Platt scaling (logistic regression on the dynamic decision score) per component, fitted inside
     grouped folds (one group = one malware family or one benign program), so every reported probability
     comes from a fold that never saw that family or program.
   - Fusion weights for dynamic + static fitted the same way (logistic regression on the two calibrated
     scores, plus an "abstained" indicator per component), replacing the fixed weights.
   - Report reliability (calibration curve, Brier score) out of fold; only then may the UI show
     `calibrated_probability` (the frontend already renders it when present).
5. **Stage 1 stays the untouched holdout**: evaluated once, after calibration is frozen.

## Malware cohort (metadata first, then download)

```bash
# metadata only: about 24 MalwareBazaar queries (6 of the 30 families are already cached), 3 s apart
sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_samples.py cohort --max-queries 25
# review /var/lib/chimera-samples/cohort.csv and cohort-manifest.json, then
sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_samples.py download \
    --list cohort.csv --register register-cohort.csv --i-have-the-mentor-signoff
```

- At most 4 samples per family, spread over the family's first-seen dates; Windows EXE only; the excluded
  families and worm/ransomware tags of the Stage 1 protocol apply unchanged.
- Every Stage 1 hash (shortlist and register) is excluded. The families are the Stage 1 families plus any
  `--extra-families`: `cohort-manifest.json` lists the families shared with Stage 1, so the evaluation can
  report that calibration saw the same families (not the same samples).
- abuse.ch terms: not-for-profit use, no high-volume harvesting, and no training of models on their data
  without written permission. Calibration fits two numbers per component on CHIMERA's own run scores, not on
  abuse.ch content; confirm this reading with the mentor before step 4 and record it.

## Benign cohort (benign dataset v4)

Candidates: `scripts/chimera/bench/benign-v4-candidates.csv`: 102 Windows programs and admin scripts, none of
them in benign v3 (71 programs). They are chosen to look like malware in places (screen capture, keyboard hooks,
kernel drivers, service creation, disk-wide walks, credential stores, downloaders, file deletion), because the
model must not learn "does anything interesting = malicious". Each row has the official download page and a
silent-install command for `start_command`. Download from the official page only, check the publisher
signature, and drop any row whose installer bundles adware. The seven `team-written` admin scripts are written
by the team like the v3 ones.

## What this does not fix

Calibration on about 200 runs gives usable probabilities for this sandbox and these families, with wide
uncertainty; it does not remove the confounding between training source (WinMET for malware, CHIMERA for
benign) and label (`classifier-audit.md` §2). Only CHIMERA-run malware in training would.
