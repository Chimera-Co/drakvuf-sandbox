# CHIMERA classifier audit and redesign proposal

25 October 2026 • Group 3 • delivery horizon: 31 October 2026

> **Status 25 Oct, after this audit:** the zero-usable-calls defect (§3) is fixed in commit `4696288`: the gate
> now counts only calls in `api_vocabulary`, the dynamic component returns no verdict below 10 usable calls, and the
> UI shows "no verdict". Deployed to `/etc/drakrun/classifier/model.py`; rg.exe `0ea31f85` now gives
> "0 usable of 217" and no dynamic verdict. Model weights unchanged. The training filter (`03_train.py:125,153`)
> still counts raw calls and should use the same usable count at the next retraining: at least two benign
> training-era runs (TightVNC MSI, KeePassXC MSI) had 0 usable calls, which is how the model learned that an empty
> vector looks benign.

## Decision

Ship a conservative, explicitly abstaining classifier, with scores described as scores. Fix the vocabulary/gating mismatch before presenting benign verdicts. Keep the current trained artifacts frozen for the first CHIMERA malware evaluation; identify any code-only gate correction as a separately versioned policy. Do not claim that cross-sandbox CV establishes real-world detection or calibrated CHIMERA probabilities.

The strongest confirmed defect is that seven Windows fixture runs have zero usable API calls after vocabulary restriction yet receive **benign dynamic verdicts**. The strongest scientific limitation is perfect confounding of dynamic training source and binary label. Program/family grouping helps, but cannot remove that confounding. Evidence: `classifier/deploy/model.py:87-100`, `classifier/scripts/03_train.py:308-319`, and local probe evidence below.

## Scope and evidence

This was a read-only source/data audit plus inference on derived JSON features. No training, packaging, downloads of datasets/binaries/samples, service operations, or host deployment were performed. No repository changes were made; final `git status --short` was empty. Graph discovery began with `graphify query "classifier data training evaluation fusion abstention min_hooked_calls"`.

Read the requested classifier planning/runbook/design, training/conversion/package scripts, shared featurizer/adapter, deployment implementation, model reports/metadata, tests, runtime extractor/runner/stub, and interface. Existing ecosystem, static-analysis and threat-model documents informed scope; their historical assertions are not new host verification. In particular, telemetry integrity is already a documented concern (`docs/chimera/threat-model.md:80-83`).

Repository evidence uses `path:line` (ranges where needed). External assertions use [V] for a primary source read during this audit, [S] for secondary, [K] for background not reverified. Recommendations and calculations are identified as such and are not product feature claims. No [S]/[K] product claims are needed here.

Local evidence is kept in `evidence/`:

- `evidence/classifier-audit-probe.py`: reproducible inference/count/vector-collision probe; run from the repository root with `PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 .venv/bin/python docs/chimera/plan/evidence/classifier-audit-probe.py <benign-v3 dataset dir>`.
- `evidence/classifier-audit-evidence.txt:1-9`: its captured output; line 7 contains fixture paths and full seven-case verdicts. It contains derived features/verdicts, not sample contents.
- `F/` below means a read-only copy of `/var/lib/chimera-dataset-benign-v3/`. Fixture references use that prefix; these are supplied local observations, not external product assertions.

## 1. Data and labels

### Actual shipped dynamic model

| Item | Audited value | Evidence |
|---|---|---|
| Available converted records | 31,844 | `classifier/models/v0/meta.json`, `training.winmet_records_available`; `classifier/scripts/03_train.py:423` |
| Selected malware | 12,000, 1,145 groups; family cap 300 | `classifier/models/v0/report.md:5` |
| Selected benign | 38 Windows runs, 23 SHA-based groups; no raw-call exclusions | `classifier/models/v0/report.md:6`; `classifier/scripts/03_train.py:146-155` |
| Artifact | LightGBM random-forest mode, 500 trees, version 0.1 | `classifier/models/v0/meta.json`, `algorithm`/`num_iteration`; RF path `classifier/scripts/03_train.py:40-43,193-195` |
| Inputs | 1,853 feature coordinates; 224 of 262 hooked APIs retained | `classifier/models/v0/report.md:7-8` |
| Raw class balance | 315.8 malware runs per benign run; 99.684% malware | Calculation: 12,000 / 38 and 12,000 / 12,038 |

These numbers describe the artifact, not the latest fixture export. The trainer weights each benign group equally, then equalizes total class weight (`classifier/scripts/03_train.py:179-189`). That does not manufacture benign diversity or deployment prevalence.

[V] The primary WinMET v3 record describes CAPE malware execution traces and 31,844 JSON traces in five volumes, with AVClass/CAPE mappings and consensus labels: https://zenodo.org/records/16414116 . This supports dataset identity and advertised count; it does not verify this checkout's converted corpus contents.

Binary malware provenance is a corpus assumption: the adapter assigns `malicious=1` unconditionally. Family is populated only when AVClass and CAPE agree case-insensitively (`classifier/chimera_clf/cape_adapter.py:338-346`). Binary malware labels are therefore not independently established by that consensus check. The binary grouping fallback uses consensus family, otherwise AVClass, otherwise unknown/SHA (`classifier/scripts/03_train.py:160-176`). Family-name disagreements, aliases, mixed labels and unknown relatives remain possible.

CHIMERA benign provenance is operator/manifest role, not an independently adjudicated clean certificate. The loader defaults unlabelled input to benign, accepts role overrides, and maps `test`/`control` to malware test-only records (`classifier/scripts/02_load_chimera.py:10-17,38-58,103-120`). Require explicit verified manifests for new imports; do not let a missing labels file silently create a training negative.

### Latest benign-v3 fixtures: count the denominator correctly

Measured from `F/index.csv:1-134` and all 133 referenced `features.json` files:

| Measure | Windows | Linux | Total |
|---|---:|---:|---:|
| Indexed runs | 65 | 68 | 133 |
| Finished | 56 | 68 | 124 |
| Failed | 9 | 0 | 9 |
| Unique SHA values | 56 | 68 | 124 |
| Distinct index program labels (`family`) | 56 | 68 | 114 across both OSs |
| Index telemetry_complete=True | 56 | 67 | 123 |
| Feature run.complete=False | 42 | 1 | 43 |

The total program-label count is smaller than the sum because names overlap across OSs. Do not call 124 finished runs 124 independent programs. The nine extra Windows rows are repeated hashes; index status and feature completeness also disagree. Validate which metadata producer/version generated each flag before using either as ground truth. Captured counts: `audit-evidence.txt:1-4`; the index header and first failed rows are `F/index.csv:1-3`.

Every referenced feature file exists. None contains an attached `static` block. Frozen packaged inference on all 65 Windows feature files produced 64 benign and one suspicious; these include failures and previously seen program names, so this is a smoke/coverage diagnostic, **not** a held-out false-positive estimate. Linux dynamic inference is explicitly unsupported (`classifier/deploy/model.py:85-86`); comparing Linux syscalls with the Windows hook vocabulary is diagnostic only.

The latest index is incompatible with the loader's naming expectations: it has `family`, not `name`, `version`, `category` (`F/index.csv:1`). `--index-csv` consequently creates blank descriptive metadata from those nonexistent columns, then falls back to filename/SHA; grouping still uses SHA (`classifier/scripts/02_load_chimera.py:44,49,113-120`). Adapt the import contract rather than silently trusting named per-program tables.

### Duplicates, near-duplicates and program identity

The loader deduplicates record IDs and hashes of the **whole feature JSON**, not model vectors (`classifier/scripts/02_load_chimera.py:139-147`). Run metadata/path variations can preserve repeated behavioural vectors. The WinMET loader appends records without global SHA deduplication (`classifier/scripts/03_train.py:112-127`); resume tracking in conversion is per-volume (`classifier/scripts/01_convert_winmet.py:82-105`). Neither is a cross-corpus near-duplicate proof.

The probe hashes the actual deployed dynamic vectors and found 12 repeated-vector clusters, including repeated backup-documents, listdlls, accesschk and distinct Windows programs frpc/sdelete/frps. See `audit-evidence.txt:6`. These are **feature collisions**, not proof of duplicate binaries. Linux collisions reflect unsupported Windows featurization and must not drive Linux grouping. There was no malware corpus available under `classifier/data/`; cross-class/cross-source SHA and near-duplicate checks could not be completed (`audit-evidence.txt:9`).

Grouping as `prog:<sha>` holds repeat executions of an identical binary together, but splits different versions/builds of the same program. A stable normalized product/program ID must join versions, OS variants where appropriate, scripts derived from the same template, and shared payloads across arms (`classifier/scripts/02_load_chimera.py:44-50`). Do not infer independence from renamed executables.

### Static data is a separate experiment

The static trainer consumes 2,568-dimensional thrember vectors for PE/ELF/PDF. It samples deterministically by hash, then splits by week: PE train ≤57, validation 58–59, test 60–63; ELF/PDF train ≤45, validation 46–51, test 52–63 (`classifier/scripts/07_train_static.py:36-42,65-79,130-147`). It does not explicitly group families/products or globally deduplicate hashes. Reusing portions named EMBER “test” for local training means these are custom temporal results, not the official benchmark split.

| Static head | Train / validation / test | Reported fixed-threshold TPR / FPR |
|---|---|---|
| ELF | 46,000 / 6,000 / 12,000 | .899 / .0107 |
| PDF | 92,000 / 12,000 / 24,000 | .932 / .0177 |
| PE | 142,986 / 31,490 / 63,658 | .912 / .0056 |

Evidence: `classifier/models/static_v0/report.md:3-19`; metadata repeats counts under `models.<format>.metrics.n`. Exact per-split class counts are not recorded there, so cannot independently reconstruct class balance from these artifacts. The report attributes labels to AV consensus; this audit did not independently reproduce that label pipeline. [V] The upstream README verifies that families/tags use ClarAVy: https://github.com/FutureComputing4AI/EMBER2024#vectorizing-raw-features . Do not substitute a family-label statement for a verified binary-label specification.

## 2. Leakage and domain shift

**What is already correct:** binary outer CV uses StratifiedGroupKFold, with inner grouped validation for stopping; held-out `chimera_test` records are not loaded as training negatives (`classifier/scripts/03_train.py:146-149,317-331`). Known family labels stay on one side of binary folds. This is materially better than random run-level CV.

**What remains unsafe or unproved:**

1. Program grouping is SHA-based, not product-based; family aliases/unknown related samples may cross folds. Duplicate samples with conflicting family assignments can cross groups. No split-overlap assertion is implemented at loading time (`classifier/scripts/03_train.py:160-176,308-327`).
2. Dynamic CV is not chronological. No timestamp enters the split; the planned time split is not implemented (`classifier/PLAN.md:136-139`; `classifier/scripts/03_train.py:110,319`).
3. API coverage/vocabulary is selected using the entire available corpus before outer CV (`classifier/scripts/03_train.py:68-97,276-290`). Thus outer-fold feature distributions inform the preprocessing. Move selection into training folds or freeze vocabulary independently before evaluation.
4. The isotonic map is fitted to all OOF labels, then evaluated on those same calibrated OOF observations; thresholds are also selected there (`classifier/scripts/03_train.py:347-361`). Raw OOF rankings are useful, but calibrated/threshold metrics are selection-set results, not an independent calibrated evaluation.
5. Family-head CV is ordinary StratifiedKFold with a random inner cut, not duplicate/product/time grouping (`classifier/scripts/03_train.py:446-485`). Its reported confidence ≥.6 is not calibrated family confidence. It evaluates known-family recognition, not novel-family identification.
6. All malware is CAPE and all benign is CHIMERA (`classifier/scripts/03_train.py:308-312`). The same vector schema does not make the sensors equivalent. Source prediction is exactly label prediction here; a high “domain classifier AUC” alone cannot identify whether the cause is sandbox or true behaviour.

Concrete semantic gaps: the CAPE adapter synthesizes implied hook events, expands repeats and defaults to a 180-second window (`classifier/chimera_clf/cape_adapter.py:188,237-247`). Its file counters include directory/copy APIs and registry WinAPI operations (`:252-289`), whereas runtime uses NT filetracer/regmon events (`drakrun/analyzer/classifier/features.py:333-382`). Counts can represent different layers or double-count nested calls. CAPE process counts are constructed from the scoped process tree, not necessarily limited to processes created within the event window (`classifier/chimera_clf/cape_adapter.py:307-315`). The plan's approximate 135-second window is not the adapter default (`classifier/PLAN.md:83`).

Vocabulary removal is a useful mitigation, not proof of transportability. The current model still consumes absolute totals, file writes and n-grams; file writes rank first in gain (`classifier/models/v0/report.md:128-149`). Zero prevalence among benign programs cannot establish an instrumentation blind spot; it may reflect class composition. Avoid removing true malware indicators just because benign programs do not exercise them (`classifier/chimera_clf/featurize.py:214-237`).

### Checks runnable now, without samples or retraining production artifacts

- Build a row manifest from fixture index + labels + features; assert path/SHA/role/OS consistency, unique task IDs, arm/run identity and explicit failure reasons. Reconcile 42 Windows feature-incomplete flags against nine index-incomplete flags. Preserve failed attempts in coverage statistics.
- Join normalized program names to shipped report names and, when available, original training SHA manifest. Mark all overlaps as development/seen; do not call the entire benign-v3 export untouched. Existing report names include backup-documents/listdlls/accesschk (`classifier/models/v0/report.md:47-55`). Training IDs/OOF CSV are not supplied here, so exact overlap remains unresolved.
- Recompute raw and retained API counts, distinct counts and sequence lengths; bucket zero, 1–9, ≥10; compare completion/failure strata. This audit already found nine Windows rows below ten retained calls, seven with none (`audit-evidence.txt:4`).
- Hash full canonical features, model vectors and API-presence sets separately; distinguish repeated execution, feature collision and duplicate content. Compare sparse-vector cosine distance or presence-set Jaccard similarity within/between program groups; manually inspect high-similarity cross-group clusters. Do not automatically merge unrelated all-zero vectors.
- When converted text records/OOF manifests become available: assert SHA/product/family-cluster disjointness; report conflicting labels; compare duplicate vector clusters across folds; implement earlier/later split using retained collection timestamps. Do not claim a time split if timestamps were discarded.
- For source sensitivity, run fixed-model counterfactuals on copied feature dicts: remove loaders, truncate sequence, reduce event window, zero files/registry independently; report score/verdict changes. These diagnose fragility, not sensor equivalence. Compare API presence-only versus count/n-gram models later on identical grouped splits.
- Genuine source disentanglement needs both labels across sources or same-program paired sensor traces. Current benign-only CHIMERA fixtures cannot identify that causal effect. M5 supplies a target-domain malware test, not a paired CAPE bridge by itself.

## 3. Features and the zero-call defect

Dynamic features include hook presence, log counts, shares, totals, behaviour-group aggregates, file/registry counters, process count/depth, and repeat-collapsed hashed bigrams/trigrams (512 buckets each). Network capture features are optional and off in the artifact; network API groups remain. Paths, names, sample size/type, OS/arm and TTPs do not enter the selected dynamic vector (`classifier/chimera_clf/featurize.py:25-28,88-108,149-191`). This differs from the earlier plan's 4,096 buckets (`classifier/PLAN.md:104`).

Missing dynamic values become zero, and nonfinite/nonpositive numeric counts become zero (`classifier/chimera_clf/featurize.py:111-120,149-179`). This is robust parsing but conflates “not observed” with “observed absent.” Extractor missing/malformed inputs similarly produce empty features (`drakrun/analyzer/classifier/features.py:202-205`). The model gates Linux and low raw hook counts, but never gates on `drakvuf_errors`; incomplete/stalled telemetry only appends a warning (`classifier/deploy/model.py:84-90,126-128`). The planned error abstention therefore is not implemented (`classifier/PLAN.md:121-125`).

### Confirmed code path

1. `_dynamic` computes `hooked_call_count(features)` using all hook names, without `api_vocabulary` (`classifier/deploy/model.py:87`).
2. It compares that count with `min_hooked_calls=10` (`:88-90`).
3. Only afterwards does vectorization restrict APIs to metadata vocabulary (`:91-93`; `classifier/chimera_clf/featurize.py:135-155`).
4. Explanations use the restricted dict, so the total can now be zero (`classifier/deploy/model.py:111`; `classifier/chimera_clf/featurize.py:287`). Prediction proceeds using zero API features and any remaining file/registry/process features.
5. A dynamic-only vote becomes the final verdict (`classifier/deploy/model.py:195-210`). No static block exists in these fixture inputs, so this is not static overriding an abstention.

Example: `F/windows/benign/a5808da05fba9a5ea11019d6692f66b7447a2e517ca6c7c950087d5eeb04d682/H3-1/features.json:1` has 207 raw hooked calls, zero retained calls. Packaged inference returns dynamic benign score .3595 and final benign score .1057, explaining “0 monitored API calls in total” (`audit-evidence.txt:7`). Seven cases reproduced this pattern. A synthetic BGInfo feature copy with only ten `LdrLoadDll` calls also reproduces it (`audit-evidence.txt:8`).

**Precise conclusion:** a genuinely empty raw Windows API dict does abstain; an empty **usable vocabulary** does not. The observed message is correct about the vector but inconsistent with the gate's denominator. Fix both training filtering and inference gating to use the same retained vocabulary count; expose raw and retained counts separately. Retain ten as an initial policy threshold, not a scientifically validated sufficiency bound.

Static inference routes PE/ELF/PDF vectors of the expected dimension; error blocks abstain, absent/malformed vectors can fall back to a rule score (`classifier/deploy/model.py:150-184`). Numeric vector checks do not reject NaN/infinity there; the normal runner rejects nonfinite request serialization, but direct callers have weaker validation (`drakrun/analyzer/classifier/runner.py:106`). Wrong extractor revision with the right dimension is not explicitly rejected. Validate schema, version, dimensionality and finiteness, and never treat missing extraction as a clean scan.

## 4. Scores, fusion and unknown

Dynamic component scores are interpolated isotonic outputs trained on weighted OOF predictions; static scores use validation-fitted isotonic maps (`classifier/deploy/model.py:95-100,167-173`). A fitted calibrator is not evidence of target-domain calibration. Dynamic calibration equalizes class mass and benign-program mass, so it does not encode deployment base rates (`classifier/scripts/03_train.py:179-189,348-349`).

Thresholds in shipped metadata: dynamic malicious .8260718323332471, suspicious .3767097198656465; defaults target ≤2%/≤10% benign runs, not independent programs (`classifier/scripts/03_train.py:257-258,351-353`). The reported dynamic zero FPs among 38 is threshold-selected, not a certified ≤2% population FPR (`classifier/models/v0/report.md:16-20`).

For each available voting component, let `m_high = logit(score) − logit(high_threshold)` and similarly `m_low`. The implementation averages these margins with dynamic/static ML weight 1 and rule weight .5; malicious if mean high margin ≥0, suspicious if mean low margin ≥0, else benign. It reports `sigmoid(mean high margin)` as the top-level score (`classifier/deploy/model.py:32-43,68-75,195-224`). Therefore .5 means the malicious decision boundary, **not a 50% malware probability**, even when one component votes. Two conflicting strong scores can cancel. The fixed fusion is not the fitted logistic formula sketched in `classifier/STATIC_DESIGN.md:82-96`.

Rules map 0–100 linearly into .05–.95, with a capped malicious margin and special low/middle/high label logic; this is not calibration (`classifier/deploy/model.py:175-184`). With no votes the result is unknown with score 0.0; that zero must never appear as evidence of safety (`:199-202`). Linux dynamic unknown may still become a static-only final decision (`classifier/tests/test_deploy.py:72-78`). Runner errors/timeouts/invalid output return unknown plus error (`drakrun/analyzer/classifier/runner.py:89-136`).

SHAP-derived text is directional association, not proof of malicious intent. Missing API text currently acts as a benign explanation. Top-level slicing retains only three explanations per component, potentially dropping the incomplete-telemetry warning (`classifier/deploy/model.py:109-127,217-219`). Quality warnings need structured fields and priority rendering.

## 5. Tests actually run

Command exactly requested:

```text
cd classifier && ../.venv/bin/python -m pytest -q tests
```

Captured stdout verbatim (the first two dots arrived in the initial output chunk):

```text
..................s                                                      [100%]
18 passed, 1 skipped in 10.60s
```

Exit code: 0. The thrember parity test uses `pytest.importorskip("thrember.features")` (`classifier/tests/test_in_sync.py:47-50`); the suite output did not include a skip-reason summary, so the skipped dependency comparison was not independently verified with a verbose rerun.

Tests cover basic schema, truly empty raw input, Linux, static fallback and copy synchronization (`classifier/tests/test_deploy.py:26-47,63-111`; `classifier/tests/test_in_sync.py:20-44`). They do not exercise loader-only retained-zero telemetry, quality/error abstention or calibration validity. Passing tests therefore does not refute the confirmed defect. Full repository unit tests were not run: no code changes were made and the task specifically requested this classifier suite.

## 6. Proposed output contract

Proposal: introduce `chimera-verdict/2`, with exactly `malicious`, `benign`, `indeterminate`. Map legacy suspicious/unknown to indeterminate for summary reporting while preserving the original label/reason in provenance. Use a compatibility adapter until runner, API and UI all accept v2; current runner rejects new labels and drops extra fields (`drakrun/analyzer/classifier/runner.py:20,34,49-63`).

```json
{
  "schema": "chimera-verdict/2",
  "label": "indeterminate",
  "score": null,
  "score_kind": "unavailable",
  "probability": null,
  "reason_codes": ["INSUFFICIENT_USABLE_APIS"],
  "explanation": ["207 raw hooked calls; 0 usable calls; minimum 10."],
  "components": {
    "dynamic": {
      "status": "abstained",
      "score": null,
      "raw_hooked_calls": 207,
      "usable_hooked_calls": 0
    }
  }
}
```

Include model/artifact hashes, policy version, input/extractor versions, component thresholds, calibration ID/domain/date where one exists, coverage warnings and family provenance. Fields above are illustrative, not an implemented schema. Distinguish `model_score`, `threshold_margin_score`, `rule_score` and validated `calibrated_probability`; never overload them as the same quantity.

Proposed abstention/decision rules, in order:

1. Unsupported OS/format, model/extractor mismatch, nonfinite/malformed vector, execution/extraction failure, or untrusted process scope: component indeterminate, explicit reason, no fabricated zero score.
2. Windows dynamic: fewer than ten **retained** calls, missing required producer, or explicit DRAKVUF errors → abstain. For partial/stalled telemetry with otherwise sufficient calls, allow an evidence display but suppress a benign clearance unless quality meets a frozen policy. Do not blanket-reject every `complete=False`: fixture discrepancy must first be reconciled.
3. Eligible ML score ≥ frozen high threshold → malicious; ≤ frozen low threshold with adequate coverage → benign; between thresholds → indeterminate. Define boundary equality explicitly; high takes precedence if thresholds coincide. A benign label means no detected malicious behaviour under this policy, not a safety guarantee.
4. For 31 October, display component verdicts and use a conservative decision table: opposing decisive ML labels → indeterminate; any decisive malicious ML result without decisive opposition → malicious; benign only if every required component for that route is eligible and benign. Publish required routes before evaluation, e.g. Windows dynamic+supported static, ELF/PDF static-only with Windows dynamic marked not applicable. Missing required component → indeterminate. Rules provide findings only and cannot establish benign or malicious alone.
5. Preserve unavailable/abstained component records and quality reasons at the top level. Family is optional known-family similarity, not attribution; withhold for indeterminate and avoid `p=` wording without family calibration.

This deliberately reduces coverage. Report that cost rather than hiding it with a low score. Keep the existing weighted-margin result available as an experimental comparator; do not quietly change policy after seeing M5 outcomes.

## 7. Calibration plan and honest minimums

[V] scikit-learn describes independent calibration data and cautions that isotonic needs substantial data (roughly more than 1,000 samples); sigmoid uses a parametric logistic mapping: https://scikit-learn.org/stable/modules/calibration.html . [V] Beta calibration uses a richer map of scores and can preserve identity; its original study does not establish superiority for CHIMERA: https://proceedings.mlr.press/v54/kull17a.html .

Recommendations, **planning gates rather than universal statistical guarantees**:

| Method | Proposed use | Minimum planning gate |
|---|---|---|
| Platt/sigmoid | First candidate for Windows dynamic, static per-format and later fusion | Separate target-domain calibration cohort with ≥100 independent benign programs and ≥100 independent malware samples; enough families and score spread; grouped validation must still demonstrate improvement |
| Isotonic | Later, if stable reliability improvements justify flexibility | ≥1,000 independent calibration units, preferably ≥200 of each class; a large majority class alone is insufficient |
| Beta | Future alternative for bounded score distributions | At least the sigmoid cohort, preferably several hundred per class; regularize/constrain monotonicity and compare on separate validation data |

These gates are **not met** by 38 benign training runs or a prospective 20 Windows/8 Linux malware test. The latter cannot simultaneously be untouched headline evaluation and calibration data. Linux requires separate static-domain validation; do not combine Linux/Windows counts to claim adequate Windows calibration.

Use four disjoint roles: model fitting; hyperparameter/quality-policy selection; calibration/threshold selection; final evaluation. Group by product/sample/family-cluster as appropriate, and order by time for the final target-domain test. For a later target calibration set, use CHIMERA data from the same guest versions, hooks, observation windows and static extractor. Keep its samples out of M5. Calibrate per supported route; fit fusion only on paired component outputs from a separate cohort, and independently validate the final fused mapping.

Compare uncalibrated/sigmoid/isotonic/beta using grouped held-out log loss, Brier score and reliability bins with counts/intervals. Inspect per-format and low-coverage strata. Preserve deployment prevalence assumptions; an artificially balanced benchmark does not establish deployment posterior probability. Reassess after hook/guest/model changes.

By 31 October: retain existing isotonic artifacts as source-domain transformations, label them scores; leave `probability=null` for CHIMERA. Static temporal calibration has a better-separated test design, but validation serves stopping, calibration and threshold selection simultaneously (`classifier/scripts/07_train_static.py:138-155`), and target reliability is still unverified. Do not fit a new CHIMERA calibrator using benign-only data.

## 8. Frozen evaluation protocol

**Before new M5 telemetry arrives:** freeze artifact hashes, vocabulary, preprocessing, gate/policy versions, thresholds, required-component routes and evaluation script. Resolve program overlaps privately from training manifests. Existing model reports already use old benign programs (`classifier/models/v0/report.md:29-55`); divide benign-v3 into seen/development and genuinely unseen program groups. If provenance cannot establish disjointness, call it a retrospective benign audit, not a clean holdout.

The current task's planned M5 size (~20 Windows + 8 Linux samples, not yet run) supersedes historical plans for 108 Windows runs (`classifier/PLAN.md:75,139`). Record the actual authorized register and denominators when available. This audit did not execute M5 or inspect sample contents.

For future retraining, outer grouped splits must exclude entire normalized benign products and malware family/near-duplicate clusters. Fit vocabulary, filtering choices, imputation, feature selection and calibrator only inside outer training partitions; use grouped inner folds for tuning. Save split manifests and assert empty ID/hash/cluster intersections. Report known-family and unseen-family tests separately. Add a later-time holdout; time and group constraints must both hold, even if class balance worsens.

Evaluate each frozen configuration on the same inputs: dynamic-only Windows, static-only per format, current fusion, proposed conservative policy. Since fixtures lack static blocks, paired static/fusion metrics are **not available now**. Do not turn missing static evidence into low risk. Any code-only correction comparison must use prespecified variants; changes informed by M5 results make a second test exploratory.

Required tables:

- A 2×3 truth-by-verdict matrix (benign/malware × benign/malicious/indeterminate), plus explicit infrastructure failures, attempts and eligible inputs. Keep abstentions in denominators.
- End-to-end TPR = malicious decisions / all attempted malware; benign FPR = malicious decisions / all attempted benign; separately report determinate coverage and conditional TPR/FPR among eligible decisions. Report malware misclassified benign separately from abstained malware.
- Fixed-threshold TPR/FPR using development-selected thresholds. Also report exploratory ROC TPR@1% and @5% FPR with score ties and achieved FPR; threshold sweeps on final test labels are descriptive, not deployed operating-point validation.
- PR-AUC (state whether average precision) and ROC-AUC on scored samples with their coverage and class prevalence; never assign unknown score zero for ranking. Report score coverage so selective ranking cannot mask failed cases.
- Per-family/sample/OS/format metrics and counts, known-versus-unseen families, arm A0/H3 where actually collected, telemetry quality and rule-only/static-only strata. Aggregate repeats per sample with a frozen rule and show run-level results separately; do not assume repeated detonations are independent.

Confidence intervals: recommend 95% exact binomial intervals on independent sample/program outcomes, with Wilson as a declared alternative; cluster-bootstrap by sample/product for run-level and ranking metrics, resampling families for family-generalization sensitivity. With tiny strata give numerators/denominators and intervals rather than a smooth headline curve. Avoid a bootstrap interval that pretends zero observed errors proves zero risk.

Illustrative calculations under independent Bernoulli trials, **not measured outcomes**: zero FPs among 38 yields one-sided 95% upper bound `1−.05^(1/38)=7.58%`; among 23 independent programs, 12.21%; among 56, 5.21%. At least 299 independent negatives with zero FPs are needed for a one-sided 95% upper bound ≤1%. Even 20/20 detections has a two-sided exact 95% lower bound about 83.2%, and 8/8 about 63.1%. Repeats do not increase these effective sample counts. Existing threshold-selected training/CV outcomes cannot use those intervals as independent validation.

Limitations to state: tiny/curated target sample set; benign-program overlap; malware-family label noise; unavailable cross-source duplicates; perfect source-label confounding in dynamic training; 2026 target versus historical source data; short windows and evasion; missing/contradictory telemetry; no validated Linux dynamic model; missing paired static fixture outputs; unvalidated fusion/calibration; no population prevalence estimate; and selection effects from excluding failed/low-coverage runs.

## 9. Ranked work through 31 October

| Rank / time box | Change to propose | Acceptance test |
|---|---|---|
| P0, 25–26 Oct | Gate and training filter on retained vocabulary; expose both counts; keep model weights unchanged for first comparison | Empty raw, loader-only, exactly 9/10 retained calls, all seven recorded cases; no benign dynamic decision below retained minimum |
| P0, 25–26 Oct | Quality/failure reasons and score wording; pin warnings above truncated explanations | DRAKVUF error, missing scope/producer, stalled/incomplete input, unsupported OS; null abstention score in v2 and explicit legacy unknown display |
| P1, 26 Oct | Fixture manifest validation and stable program grouping; fix index schema mismatch and failure inclusion | Current index imports names from `family`; repeated failed/finished hashes stay in same program; missing labels cannot silently become benign |
| P1, 26–27 Oct | Versioned v2 contract/compatibility and conservative decision table | Runner/API/UI round-trip null score, reason codes, indeterminate; agreement/disagreement, one missing required component, Linux static-only, rule-only cases |
| P1, 27 Oct | Freeze manifests/policy, distinguish seen/unseen benign-v3, build evaluation from JSON only | Split overlap assertions, 2×3 matrix totals reconcile, duplicate-run clustering, CI tests with known counts; no model write path |
| P1, 28–30 Oct | Owner performs separately authorized M5 runs; evaluate frozen outputs once; publish limits | Actual per-sample denominators, artifacts/hashes, failures retained, component coverage; no threshold tuning on final outputs |
| P2, 30–31 Oct | If time permits, fold-local vocabulary and grouped/time evaluation of a separate candidate | Compare identical folds and independent scoring; label candidate exploratory if new data separation is unavailable |

This is a proposal, not authorization to deploy or run samples. Avoid spending the remaining days on a new architecture or probability fit with insufficient target data. A documented abstaining score with a small honest test is a stronger deliverable than an unsupported probability claim.

## 10. Future work

Collect independent benign product diversity and separate CHIMERA malware development/calibration cohorts; retain timestamps and label provenance. Build same-sample paired sensor evidence under the project's separate handling procedure. Train a Linux syscall-specific dynamic model, validate per-format static reliability, improve missingness/coverage representations, and test presence-only/count/window ablations under domain transfer. Only then fit/validate fusion or beta/isotonic calibration. Family identification needs duplicate-safe known-family validation and a separate novel-family rejection study.

Do not treat static feature-extractor identity as “no domain gap”: it removes one implementation mismatch, while corpus composition, collection date, labels and format distributions still differ. The stronger wording in `classifier/STATIC_DESIGN.md:89-91` should be narrowed in future documentation.

## Completion record

Files produced: this report and `evidence/classifier-audit-probe.py`, `evidence/classifier-audit-evidence.txt`. Source files changed during the audit: none. Tests: requested classifier suite, exit 0, **18 passed, 1 skipped in 10.60s**; derived-feature inference/count/collision probe completed. No model was trained or overwritten.

Not done/verified: actual root deployment/model manifest and UI rendering; live producer quality flags and their discrepancy with exports; raw sensor logs/VM state; original WinMET/EMBER converted-corpus duplicate/label/split manifests; source-target paired traces; static paired fixture inference; target calibration; full repository unit suite; M5 malware detection. Root checks for the owner: compare installed model/meta/hooks hashes with the frozen package, inspect telemetry producer/version and plugin availability for affected run IDs, and verify that the deployed API/UI preserves abstention and quality warnings. No root action is required to reproduce the retained-vocabulary defect from these fixtures.
