# Classifier + static analysis: setting it up on the CHIMERA host

Branch `classifierUndStatico`. What it adds: a trained classifier (dynamic behaviour model + static file models,
fused into one verdict) and static analysis of every upload in a locked-down container. Details:
`classifier-interface.md`, `static-analysis.md`, threat model T12, `classifier/RUNBOOK.md` (training).

## 1. Get the code

```bash
cd /opt/chimera/src          # the root-owned deployment checkout (or wherever you deploy from)
sudo git fetch origin
sudo git checkout classifierUndStatico
sudo git pull
```

## 2. Install

```bash
sudo apt install podman      # once, if it is not there yet
sudo scripts/chimera/install-classifier-static.sh --drakrun
```

What it does, in order (safe to run again):

1. `--drakrun`: rebuilds drakrun from this checkout (`make`) and reinstalls it into `/opt/chimera/venv`,
   so the workers and the web API get the new code. Leave it out if you deploy drakrun some other way.
2. checks `lightgbm` / `numpy` in `/opt/chimera/venv` (installs 4.7.0 / 2.4.6 if missing);
3. copies `classifier/deploy/` to `/etc/drakrun/classifier/` (the old folder is kept as `.bak-<date>`) and
   runs the model once;
4. builds the static image `localhost/chimera-static:0.1.0` with Podman;
5. installs and enables `drakrun-static-worker.service`;
6. adds `[classifier]` and `[static]` to `/etc/drakrun/config.toml` **only if they are missing**
   (backup next to it; existing values are never changed, only reported);
7. runs the end-to-end check (below).

It does not restart services (an analysis might be running). When nothing is running:

```bash
sudo systemctl restart drakrun-static-worker drakrun-web 'drakrun-worker@*'
```

Options: `--restart` (restart for you), `--engine docker`, `--venv`, `--classifier-dir`, `--config`, `--no-check`.

## 3. Check

```bash
sudo /opt/chimera/venv/bin/python scripts/chimera/e2e_classifier_static.py                         # quick
sudo /opt/chimera/venv/bin/python scripts/chimera/e2e_classifier_static.py \
     --analysis-dir /var/lib/drakrun/analyses/<a finished analysis> --sample <that sample file>    # full path
```

It must end with `ALL PASSED`:

- **isolation:** from inside the analyzer container, network, DNS, writing the root fs, changing or executing
  the sample, executing from `/tmp`, forking and allocating 4 GiB are all blocked; uid 65534, no capabilities;
- **static:** the real static job stages the sample (0440, never executable), runs the container, writes
  `static.json` and deletes the staged copy;
- **classify:** the real `classify_sample` plugin adds the static report to `features.json`, runs the
  deployed model through CHIMERA's runner, and the verdict has `components.dynamic` and `components.static`.

Then submit a sample normally. Results: `GET /api/classification/<id>` (combined verdict + components),
`GET /api/static/<id>` (static report), `GET /api/features/<id>`.

## Turning it off

`[static] enabled = false` and/or `[classifier] enabled = false` in `config.toml`, restart the services.
To go back to the old model: `sudo mv /etc/drakrun/classifier.bak-<date> /etc/drakrun/classifier`.

## Known limits (v0)

- The dynamic model learned malware from CAPE reports (WinMET) and benign software from 23 CHIMERA programs.
  Its out-of-fold numbers (`classifier/models/v0/report.md`) are optimistic; the honest test is the frozen
  model on CHIMERA malware runs (the M5 samples, not gathered yet).
- Static ML covers PE, ELF and PDF (`classifier/models/static_v0/report.md`); other types get rule findings.
- Fusion weights are fixed (equal) until paired CHIMERA runs exist to fit them.
