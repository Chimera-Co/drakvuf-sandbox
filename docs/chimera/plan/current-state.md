# CHIMERA current state (verified 25 Oct 2026)

Everything below was checked on the CHIMERA host on 25 Oct 2026 with the command or file named. Historical results
from earlier documents are marked as such and were not re-run.

## 1. Code and deployment

| Item | State | How verified |
|---|---|---|
| Working branch | `sprint/final` at `4696288` (one commit ahead of `origin/sprint/final`) | `git log` |
| Deployed source | `/opt/chimera/src` at `b1ee4d3`, installed into `/opt/chimera/venv` | `git -C /opt/chimera/src log -1` |
| Deployed classifier | `/etc/drakrun/classifier/`; `model.py` replaced with the `4696288` version (sha256 `be411b68…`), backup `classifier.bak-20261025-035159` | `sha256sum` |
| Deployed web bundle | Rebuilt 25 Oct with the "no verdict" label; previous bundle kept as `dist.prev-20261025` | bundle grep |
| Classifier and static analysis | Merged from `classifierUndStatico`; static image `localhost/chimera-static:0.1.0`; `drakrun-static-worker` running | services, image |
| Upstream DRAKVUF fixes | tklengyel/drakvuf#1886 (use-after-free in `refresh_shadow_copy`) and #1887 (libvmi bump) **merged 24 Oct** | `gh pr view` |

## 2. Host

| Item | Value |
|---|---|
| Hypervisor | Xen 4.19.2 (CHIMERA patch for the altp2m freeze, `vm-freeze-root-cause.md`) |
| DRAKVUF | `v1.1-da982ab` with the local use-after-free fix (now upstream) |
| Memory | 16 GiB total, dom0 6 GiB; guests: Windows 5 GiB, Linux 4 GiB |
| CPUs | 16 logical (dom0 has 8 vCPUs) |
| Disk | 488 GB free of 901 GB |
| Services (all `active`) | `chimera-inetsim`, `chimera-net`, `chimera-xenstat`, `drakrun-web`, `drakrun-worker@1`, `@2`, `drakrun-evasion-worker@1`, `@2`, `drakrun-static-worker`, `redis-server` |

## 3. Tests

| Suite | Result | Note |
|---|---|---|
| `test/unit` (drakrun) | **613 passed** | `.venv/bin/python -m pytest -q test/unit --confcutdir=test/unit` |
| `classifier/tests` | **19 passed, 1 skipped** | includes the new gate test; the skip is the optional thrember parity test |
| Frontend (vitest) | **23 passed** | |
| `static_analyzer/tests` | **9 failed, 11 passed** in the dev venv | Not regressions: they need the container's packages (scikit-learn etc.). There is no documented way to run them outside the image yet (see `testing-strategy.md` §3) |

## 4. Data and experiments

| Item | State |
|---|---|
| Analyses on disk | 256 under `/var/lib/drakrun/analyses` |
| Benign dataset for the classifier | v3: 133 indexed runs, 124 finished (56 Windows, 68 Linux), published at Chimera-Co/chimera-benign-dataset |
| Malware register (Stage 1) | 35 samples: 22 Windows test, 5 Windows control, 8 Linux test. The protocol's 15 Linux samples became 8 (3 controls were 32-bit or ARM64; the third sample per family was not fetched) |
| M5 Stage 1 malware batch | **Not run yet** (no `m5` evidence folder). Starts after approval; the owner runs the download and the batch start |
| Evasion (historical, `hardening-design.md` §7) | H3b: PERDEDOR 100.0, al-khaser 20; after guest clock sync al-khaser 21 (`nt_yield_execution` returns) |
| Containment (historical, 19–20 Oct) | Windows C-1…C13 pass; Linux C0–C6 pass. To be re-run on the demo boot |

## 5. Defects found in this audit

| Defect | Where | Status |
|---|---|---|
| Runs with 0 usable API calls scored "benign" (gate counted calls the model cannot see) | `classifier/chimera_clf/deploy_model.py:87` | **Fixed** `4696288`, deployed |
| Offline `report.html` embeds guest-controlled JSON inside `<script>` without escaping `</script>` | `drakrun/analyzer/postprocessing/plugins/generate_html_report.py:46` | Open, P0 (also present upstream) |
| Static worker reports success ("Job OK") when `static.json` holds an error | `drakrun/analyzer/static/worker.py:52-68` | Open, P0 |
| Static rule fallback votes "benign" when the score is < 15, even for formats it could not parse | `deploy_model.py` rules fallback | Open, P0 |
| No YARA rules in the static image | `static_analyzer/rules/README.txt` | Open, P0 |
| Static or classifier results are fetched once; a report opened early shows "not classified yet" until reload | `drakrun/web/frontend/src/AnalysisVerdict.jsx:19` | Open, P0 |
| Files over 256 MiB are hashed on a prefix but reported with the full size | `static_analyzer/chimera_static/safety.py:23` | Open, P1 |
| Offline HTML report has no static or verdict section | `generate_html_report.py:20`, `AnalysisReport.jsx:349` | Open, P1 (combined report) |
| Classifier training filter counts raw calls, so empty vectors were learned as benign | `classifier/scripts/03_train.py:125,153` | For the next retraining |

Details and evidence: `classifier-audit.md`, `static-engine-design.md`, `report-intel-orchestration.md`.
