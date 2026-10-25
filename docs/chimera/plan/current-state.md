# CHIMERA current state (verified 25 Oct 2026, updated after the P0/P1 work the same day)

Everything below was checked on the CHIMERA host on 25 Oct 2026 with the command or file named. Historical results
from earlier documents are marked as such and were not re-run.

## 1. Code and deployment

| Item | State | How verified |
|---|---|---|
| Working branch | `sprint/final` at `16ccf04` (18 commits ahead of `origin/sprint/final`, not pushed) | `git log` |
| Deployed source | `/opt/chimera/src` (files copied per change, then installed into `/opt/chimera/venv`); every change up to `16ccf04` is deployed, backups under `/var/backups/chimera-*` | file compare, services |
| Deployed classifier | `/etc/drakrun/classifier/`, `model.py` sha256 `74dba488…` (`f09beb4`: partial static never votes benign; static-only runs say the sample was not executed) | `sha256sum` |
| Deployed web bundle | Rebuilt 25 Oct with R4, R6, R7, R8, R10 | browser check |
| Classifier and static analysis | Merged from `classifierUndStatico`; static image `localhost/chimera-static:0.1.0` (id `7d3d92a26f94`, ReversingLabs YARA, libfuzzy ssdeep, oletools; previous images tagged `pre-r2`, `pre-r3`, `pre-ssdeep`, `pre-r12`); `drakrun-static-worker` running | services, image |
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
| `test/unit` (drakrun) | **646 passed** | `.venv/bin/python -m pytest -q test/unit --confcutdir=test/unit -p no:cacheprovider` |
| `classifier/tests` | **21 passed, 1 skipped** | the skip is the optional thrember parity test |
| Frontend (vitest) | **47 passed** | Node 22 |
| `static_analyzer/tests` | **33 passed** | inside the image: `podman build --network=host --target test -f static_analyzer/Containerfile static_analyzer` (R5) |

## 3a. Roadmap progress (25 Oct)

| Item | State |
|---|---|
| P0 R1–R5 | Done and deployed |
| P1 R6 combined report, R7 analysis modes, R8 hashes and list filters, R9 classifier freeze | Done and deployed; R7 checked live with a static-only run (VM workers never saw the job) |
| P2 R10 IOC export, R12 Office macros and ZIP listing | Done and deployed |
| P2 R11 offline intelligence | Not started: needs a dated feed snapshot (download needs the owner's OK; abuse.ch rate limits) |
| P2 R13 one dynamic analysis at a time | Not started: changes VM scheduling close to the freeze |
| Static analysis isolation | Per-sample rootful podman container in dom0 (no network, read-only, no capabilities, uid 65534, limits). Stronger options for later: gVisor runtime, rootless podman, or a static-analysis domU |

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
| Offline `report.html` embeds guest-controlled JSON inside `<script>` without escaping `</script>` | `drakrun/analyzer/postprocessing/plugins/generate_html_report.py:46` | **Fixed** `a50db46`, deployed 25 Oct |
| Static worker reports success ("Job OK") when `static.json` holds an error | `drakrun/analyzer/static/worker.py:52-68` | **Fixed** `487f677`, deployed |
| Static rule fallback votes "benign" when the score is < 15, even for formats it could not parse | `deploy_model.py` rules fallback | **Fixed** `487f677`, deployed: no benign vote without complete coverage |
| No YARA rules in the static image | `static_analyzer/rules/` | **Fixed**: ReversingLabs rules pinned at `e0a0be54`, 1240 rules, build-time compile gate; no hits on 34 local benign files |
| Static or classifier results are fetched once; a report opened early shows "not classified yet" until reload | `drakrun/web/frontend/src/AnalysisVerdict.jsx:19` | **Fixed** `8149ade`, deployed: polls every 5 s for up to 15 min; scores labelled decision scores |
| Files over 256 MiB are hashed on a prefix but reported with the full size | `static_analyzer/chimera_static/safety.py:23` | **Fixed** `487f677`, deployed: refused with the reason |
| Hashing is slow on large files: pure-Python ssdeep (ppdeep) re-hashes repetitive input, about 90 s for 30 MiB of padding, so padding alone could spend the static budget | `static_analyzer/chimera_static/universal.py` `hashes` | **Fixed**, deployed 25 Oct: libfuzzy binding (`ssdeep` 3.4, Debian libfuzzy 2.14.1), same output as before, 0.34 s for the same input; size cap removed |
| Offline HTML report has no static or verdict section | `generate_html_report.py:20`, `AnalysisReport.jsx:349` | **Fixed** `206c6a3`, deployed 25 Oct: separate evidence-linked printable report (`chimera-report.json`/`.html`, R6) with verdict, static coverage, scoped behaviour and limitations |
| Classifier training filter counts raw calls, so empty vectors were learned as benign | `classifier/scripts/03_train.py:125,153` | For the next retraining |

Details and evidence: `classifier-audit.md`, `static-engine-design.md`, `report-intel-orchestration.md`.
