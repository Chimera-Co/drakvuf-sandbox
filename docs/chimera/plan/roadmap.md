# CHIMERA roadmap to 31 Oct 2026

**Written:** 25 Oct 2026 · **Freeze:** 29 Oct, 20:00 IST (no platform changes after this) · **Rehearsal:** 30 Oct ·
**Presentation:** 31 Oct

## Principles

1. **Correct and honest before new.** A wrong "benign", an unescaped report or a silent failure costs more in front
   of the panel than a missing feature.
2. **One change, one test, one deploy, one check** on the real host. Each item below has an acceptance test.
3. **Do not touch Xen, DRAKVUF, the guest images or containment** before the presentation. Hardening research is
   future work (`hardening-roadmap.md`).
4. **No retraining and no probability claims.** The classifier artifacts stay frozen for the malware evaluation;
   scores are decision scores, not probabilities (`classifier-audit.md` §4, §7).
5. **Nothing leaves the host.** No sample upload anywhere; the external comparison uses only reports that are already
   public (`benchmark-plan.md` §2).

## Done on 25 Oct

| Item | Evidence |
|---|---|
| Classifier gives **no verdict** when a run has fewer than 10 calls the model can use (was "benign" for 0 usable calls) | `4696288`; deployed; `classifier-audit.md` status note |
| Research and planning package (this folder) | `README.md` |

## P0: correctness (25–26 Oct)

| ID | Change | Why | Effort | Acceptance test |
|---|---|---|---|---|
| R1 | Escape the JSON embedded in the offline `report.html` (`<`, `>`, `&`, U+2028/2029) | Guest-controlled strings (process names, URLs) can close the `<script>` block when an analyst opens the report (`generate_html_report.py:46`); also an upstream fix | S | Unit test: a process name containing `</script><script>` renders as text; existing report tests pass |
| R2 | Static result truthfulness: an error result marks the job failed and is logged as such; a partial or unsupported static run never votes benign; reject inputs over 256 MiB instead of hashing a prefix | `static-engine-design.md` §1.4 P0 rows | S–M | Fake engine returning an error → RQ job failed, `static.json` kept; unsupported format with score 0 → static component "no verdict"; 257 MiB input → refused with reason |
| R3 | Ship a pinned YARA ruleset: ReversingLabs public rules (MIT) at commit `e0a0be54…`, licence and file manifest in the repo; image build fails on zero rules or compile errors; rule count in `static.json` and the UI | No rules today; MIT is the simplest licence to redistribute in a public image (`static-engine-design.md` §2.2) | M | Build log shows N rules compiled; synthetic positive rule matches a team-made test file; benign fixtures (BGInfo, rg, 7-Zip) give no new high findings |
| R4 | Verdict card: poll until the static and classifier results are final; say "decision score (0.50 = malicious threshold), not a probability"; show telemetry and coverage warnings above explanations | `report-intel-orchestration.md` §2.1; `competitive-landscape.md` §5 P0 | S | vitest: 404 then 200 updates without reload; warnings render first |
| R5 | Make `static_analyzer/tests` runnable: a test stage in the Containerfile (runtime image unchanged) | 9 of 20 tests cannot run in the dev venv (`current-state.md` §3) | S | `podman build --target test` runs all 20 and they pass |

## P1: what the panel sees (26–28 Oct)

| ID | Change | Why | Effort | Acceptance test |
|---|---|---|---|---|
| R6 | **Combined report**: a finaliser after classification writes `chimera-report.json` (`chimera-report/1`: identity, coverage, key findings with evidence links, static, dynamic, verdict and components, ATT&CK, IOCs, limitations) and a printable HTML page embedding all of it; browser Print → PDF | The largest gap in MS 360 and the place CHIMERA is already ahead (`ms360-study.md` §6); schema in `report-intel-orchestration.md` §2.3 | M–L | Golden-file test on a fixture analysis; offline file opens with no network requests; PDF of one Windows and one Linux run checked by eye |
| R7 | **Analysis modes**: `static-only` (no VM), `dynamic-only`, `combined` (default) in the API and the upload form | Static-only answers "what is this file" in seconds and keeps the VM free; `report-intel-orchestration.md` §3.3 | M | Enqueue-spy tests: static-only never touches the VM queues; list and status endpoints show static-only analyses |
| R8 | Dashboard: similarity hashes (imphash, TLSH, ssdeep) on the static tab; analysis list filters (OS, status, verdict) and hash search | Already computed, not shown; MS 360 has list filters (`ms360-study.md` §5) | S–M | vitest for filters; manual check on the host |
| R9 | Freeze the classifier for the malware evaluation: record artifact hashes and policy version in the evaluation output; map labels to malicious / benign / indeterminate for scoring | `classifier-audit.md` §8 | S | Evaluation report lists hashes; a 2×3 truth-by-verdict table renders from fixtures |

The visual design pass for R6 and R8 uses the installed design skills (Impeccable, UI/UX Pro Max, Taste) on top of the
existing CHIMERA theme; no new UI framework.

## P2: only if every P0 and P1 item is green (28–29 Oct)

| ID | Change | Effort |
|---|---|---|
| R10 | IOC export as JSON and CSV (spreadsheet-formula safe), from the combined report | S |
| R11 | Offline intelligence: match observed domains and IPs against a local, dated snapshot (no online lookups); show source and date | M |
| R12 | Office macro indicators (oletools, bounded) and ZIP listing without extraction | M |
| R13 | Optional host-wide "one dynamic analysis at a time" setting (default off, so Windows and Linux can still run side by side) | M |

## Owner and team work in parallel

| ID | Work | Who | When |
|---|---|---|---|
| O1 | M5 Stage 1 malware batch (A0 vs H3) after approval | Owner starts it; monitoring and report follow | As soon as approved |
| O2 | Comparison per `benchmark-plan.md`: CAPE lane on a teammate's spare machine (same files, matched settings; malware only with owner + mentor OK) and existing public sandbox reports (no uploads, no accounts) | Benchmark lead + CAPE teammates | CAPE setup 26–27 Oct; runs and report matching 28–29; score 30 |
| O3 | Containment check on the demo boot; benign rehearsal; recorded fallback demo | Owner | 30 Oct |
| O4 | Decide: Linux control samples (8 test + 0 controls today), benign dataset repository visibility, VNC password rotation | Owner | Any time before 29 Oct |
| O5 | Questions for the classifier owner: should a Windows run whose dynamic part abstains still get an overall verdict from static alone? Switch the training filter to usable calls at the next retraining | Classifier owner | Before the evaluation |

## Not before 31 Oct (future work)

APK analysis, URL mode, PCAP upload; IntelOwl or MISP deployment; capa or FLOSS on the submitted file, Ghidra or
rizin; new anti-evasion work (WMI sensors, CPUID exit timing, ACPI tables, launch parent); retraining, calibration
and fitted fusion (not enough target-domain data: `classifier-audit.md` §7); multi-user accounts and rate limits.

## Risks

| Risk | Mitigation |
|---|---|
| A late change breaks the demo | Freeze 29 Oct 20:00; every deploy keeps a backup (`dist.prev-*`, `classifier.bak-*`); rehearsal on 30 Oct |
| Malware batch not approved in time | The demo uses benign runs, the evasion results and the benign dataset; state the evaluation as pending, with the protocol |
| YARA rules match benign software | Benign gate in R3; severity policy capped; rules alone never produce "malicious" |
| Host sleeps during long runs | Keep the laptop on the charger with the sleep inhibitor (seen 23 Oct) |
