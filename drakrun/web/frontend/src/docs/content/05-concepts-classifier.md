---
title: Classifier and fusion
group: Concepts
---
# Classifier and fusion

When a detonation finishes, the `classify_sample` postprocessing step builds a feature document, runs the
deployed model and stores its verdict next to the report. Code: `drakrun/analyzer/classifier/` on the sandbox
side, `classifier/` for training and the deployable model.

## Features: `chimera-features/1`

`drakrun/analyzer/classifier/features.py` turns one analysis into a JSON document:

- `api_calls` and `api_sequence`: the hooked API calls of the sample's process tree, counted and in order
  (the sequence capped at 2,000);
- `files`, `registry`: counters from `filetracer` and `regmon` (NT syscalls such as `NtCreateFile`,
  `NtSetValueKey`), a second channel next to the API calls;
- process-tree shape, network observations and `ttps` (ATT&CK techniques found by capa on DRAKVUF's logs);
- `run`: whether the run completed, stalled, how long it took;
- `static`: the static analysis result, if it arrived within `[static] wait_s` seconds of the detonation's end.

Paths and user names are never features: they describe the sandbox, not the sample.

## The models

| Part | Input | Model | Trained on |
|---|---|---|---|
| Dynamic | API, file, registry and process features, API n-grams | LightGBM (random-forest mode in v0) | WinMET (CAPEv2 reports converted into `chimera-features/1`) for malware, CHIMERA's own benign runs for benign |
| Family | Same features | LightGBM multiclass over the top WinMET families; returned only for a confident malicious verdict | WinMET |
| Static | EMBER2024 feature vector (PE, ELF, PDF) | One gradient-boosted model per format | EMBER2024 |
| Static rules | Static findings score | Rule score at half weight, never more than "suspicious" | For formats without a model (LNK, RTF, scripts) |

The main risk is a model that learns **which sandbox** produced a record instead of **malicious or not**: all
public malware data comes from other sandboxes, all benign data from CHIMERA. The trainer therefore keeps only
the hooked APIs that both sides can observe, drops loader noise, and reports features that alone separate the
classes so they can be checked for sandbox artefacts. The v1 retrain (`classifier/RETRAIN.md`) goes further:
CHIMERA's own malware runs become training data, splits are grouped by product and family, thresholds are set
at 1% and 5% benign false-positive rate, and probabilities are Platt-calibrated.

Runs with too little behaviour (fewer than 10 usable calls) get no dynamic vote rather than a guess.

## Fusion

The parts are combined into one verdict on each part's own threshold scale:

- **Fixed fusion (v0).** For each voting part, `m = logit(p) − logit(t_malicious)`; the combined margin is the
  weighted mean, and `score = sigmoid(m)`, so 0.5 means "exactly at the malicious threshold".
- **Fitted fusion (v1).** A logistic regression over each component's logit and an "abstained" flag, fitted on
  CHIMERA runs that have a static result. Only such a model may report `calibrated_probability`.

## The verdict: `chimera-verdict/1`

The model is one Python file with one function, run in its own process with a timeout (`[classifier]
timeout_s`):

```python
def classify(features: dict, analysis_dir: str) -> dict:
    return {
        "label": "malicious",          # malicious | suspicious | benign | unknown
        "score": 0.93,                 # 0..1
        "family": "AgentTesla",        # or None
        "model": "chimera-fusion",
        "model_version": "1.0",
        "explanation": ["process injection APIs: WriteProcessMemory x4"],
        "components": {
            "dynamic": {"label": "malicious", "score": 0.88, "weight": 1.0},
            "static": {"label": "suspicious", "score": 0.67, "weight": 1.0},
        },
    }
```

An exception, a timeout or an invalid result becomes `label: "unknown"` with the error; the analysis never fails
because of the model. Mobile apps get `not_applicable` (no model is trained on them). The verdict is stored in
`classification.json` and mirrored into the analysis metadata; the console shows it in the verdict card with
each component's label, score and reasons.

## Turning it on

```toml
# /etc/drakrun/config.toml
[classifier]
enabled = true
model_path = "/etc/drakrun/classifier/model.py"   # unset or missing: the labelled demonstration stub
timeout_s = 60
```

`scripts/chimera/install-classifier-static.sh` installs `classifier/deploy/` there; see
[workers and services](build-services.md).
