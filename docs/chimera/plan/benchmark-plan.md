# CHIMERA comparison plan (for the benchmark lead)

Prepared 25 October 2026. Freeze the register and protocol on 27 October; collect 28–29 October; score and report 30 October. This document proposes experiments; it reports no new sandbox results. A loss, tie, inconclusive result or unavailable comparator is an acceptable outcome.

**Revised 25 October:** the team has no MS 360 access, so MS 360 is not a comparator. `ms360-study.md` stays as background only. There are two comparisons:

1. **Controlled: CAPE lane.** Teammates run CAPEv2 on a spare machine. CAPEv2 is the maintained descendant of Cuckoo, the engine behind MS 360's dynamic part. They run the same Windows malware, benign controls and evasion tools as CHIMERA, under matched settings (§2a).
2. **Descriptive: public reports.** Reports public sandboxes have **already published** for the same SHA-256. Nothing is submitted to any external service and no account is used.

CAPE cannot run on the CHIMERA host itself. This Linux is Xen's dom0 (`systemd-detect-virt` = `xen`), and Xen does not expose VT-x to it (no `vmx` flag, no `/dev/kvm`). CAPE's VM backends are KVM/QEMU, VirtualBox, VMware, Hyper-V, Proxmox, cloud services or XenServer's XAPI, not the plain `xl` toolstack used here [V], https://github.com/kevoreilly/CAPEv2/tree/master/modules/machinery.

## Evidence and scope

Repository evidence is cited as `path:line`. External claims use [V] (primary source read for this audit), [S] (secondary account), or [K] (background not reverified), with a URL. Recommendations and proposed definitions below are not product claims.

- Triage search works without an account [V], https://tria.ge/s?q=sha256:<hash>. Checked on 25 Oct with one Linux register hash: the search returned two reports. The report page showed a score (10/10), a family, the behavioural OS (Ubuntu 18.04) and its own "Print to PDF" button.
- ANY.RUN public HTML reports show run configuration, verdict and static/behaviour/network sections without sign-in [V] (`docs/chimera/plan/competitive-landscape.md:269`).
- MalwareBazaar sample pages answer scripted clients with a browser check (`/verify-ua/`) [V], checked 25 Oct. Use a normal browser by hand, once per sample. Never automate around the check, and never use the authenticated API for this work.
- al-khaser describes Windows anti-analysis checks, including VM/sandbox detection [V], https://github.com/ayoubfaouzi/al-khaser. Pin the exact build and flags; do not fetch or execute it during planning.
- PERDEDOR measurements in this plan rely on local project evidence, not a newly verified external feature claim: `docs/chimera/hardening-design.md:55`. The external repository could not be retrieved: https://github.com/clustercoder/perdedor (unverified).
- CHIMERA's M5 is an internal A0–H3 experiment, with two 180-second runs per arm and a Linux descriptive lane (`docs/chimera/malware-evaluation-protocol.md:26`, `:41`). It is not automatically a controlled cross-platform experiment.

## 1. Questions and measurable comparisons

| Question | CHIMERA (prospective local runs) | Existing public reports (Triage, ANY.RUN, other) |
|---|---|---|
| Which behaviours are visible for the same file? | Raw logs + report, sample subtree | Visible fields only; absence is unobservable unless explicitly reported |
| Are verdicts useful with abstention? | Native fused verdict and each available component | Native label/score of the selected report; selected-case agreement only |
| Is the report useful to an analyst? | Offline HTML + JSON | Saved public page (PDF) |
| How detectable is the environment? | al-khaser/PERDEDOR under production monitoring | N/A: no matching tool runs can be requested |
| Reliability and time to usable report? | All scheduled attempts | N/A: no unseen submissions, queue or failures |
| Resource cost? | Host/guest allocation, CPU/RAM/disk | N/A |

The CAPE lane answers the same questions under matched conditions, plus evasion, reliability and time.

**Primary external endpoint (CAPE lane, only if its malware part runs):** per Windows `test` hash, "behaviour observed" (§4), CHIMERA H3 versus CAPE, both using the same two-run aggregation; exact McNemar (§6). Secondary: verdicts on malware and benign controls, early exits, known-action coverage of the probe, evasion checks failed.

Public reports are a descriptive stratum only. Each was produced at another time, on an unknown image, with real or simulated internet and an unknown run length, so it cannot establish platform superiority. The internal M5 endpoint, A0 versus H3 (§6), is unchanged. Linux public reports count only when the report shows a Linux behavioural run. CAPE runs Windows only in this plan.

## 2. Hard gates and sample register

- **No submissions.** Nothing (malware, benign program, evasion checker) is uploaded to any external service, and no "re-analyse" is requested. If that is wanted later, it needs a separately scoped decision by the owner and mentor.
- **No accounts and no sign-ins.** A report that needs sign-in is recorded as `signin_required` and skipped.
- **Report pages only.** Do not click sample, dropped-file, unpacked-payload or memory-dump download links. URLs inside a report are observations, not browsing destinations.
- **Hash lookups only for the frozen register.** A lookup discloses interest in that hash to the provider. Use only hashes that are already public; log provider, date and purpose. Never bypass quotas, access controls or browser checks.
- Local CHIMERA runs follow M5 controls and need the operator's own authorization (`docs/chimera/malware-evaluation-protocol.md`).

### 2a. CAPE lane (teammates, spare machine)

The CAPE machine is run by the team, not an external service, but malware leaves the CHIMERA host. The malware part therefore needs all of the following; without them the lane runs benign controls and evasion tools only:

- [ ] Written OK from the project owner **and** the mentor, recorded with names and dates.
- [ ] A dedicated machine or spare disk with a fresh Ubuntu 24.04: no personal accounts, credentials, VPN, cloud sync or personal files.
- [ ] Routing `inetsim` (preferred, closest to CHIMERA's simulated network) or `drop`; never `internet`, `tor` or `vpn`. A probe run must show only fake or no DNS answers before any malware. Host offline during malware runs.
- [ ] Samples handed over directly as encrypted archives, never extracted on the host, and deleted after the study. Only CAPE's `reports/` folders are copied back, never `binary`, `files/`, `CAPE/`, `procdump/` or memory dumps.

Matched settings: Windows 10 22H2 x64 from the same Microsoft ISO, 2 vCPU / 4 GiB, 180 s enforced timeout for malware and benign files, 900 s for evasion tools, one analysis at a time, no manual clicks. CAPE's own defaults stay as shipped and are recorded: its in-guest monitor and its "human" interaction module. Deliberate differences, recorded rather than removed: CAPE needs 32-bit Python, its agent and an unhardened guest (firewall/updates off), and CHIMERA's H3 guest has extra installed programs. CAPE is a rolling release, so the commit hash is recorded [V], https://capev2.readthedocs.io/en/latest/installation/host/installation.html. The teammates' kit has the step-by-step sheet, file lists and hashes.

Freeze these sets before seeing new results:

| Set | Size | Purpose and handling |
|---|---:|---|
| M-public | 35 hashes: 22 Windows test, 5 Windows control, 8 Linux test | The M5 Stage 1 register, all public on MalwareBazaar. Match each hash to an existing public report (§3); compare with the CHIMERA Stage 1 report for the same hash. The register is kept outside the public repo. |
| M-cape | The 27 Windows hashes of M-public (22 test, 5 control) | Same files on CHIMERA H3 and CAPE, 2 runs each. Primary external endpoint uses the 22 `test` hashes. Only with the §2a gates. |
| B-core | 7 Windows benign inputs | CHIMERA and CAPE: own behaviour probe (known actions) plus 6 programs drawn with seed `20261028` from the 26 benign-dataset Windows programs that finished and have a version-pinned download URL (zoxide 0.10.0, Python 3.14.9 installer, OBS Studio 32.2.2 installer, dust 1.2.6, ripgrep 15.2.0, PuTTYgen 0.85), with their dataset start commands. No replacement after results. |
| E | 2 tools × 5 runs | CHIMERA and CAPE: al-khaser (same build, SHA-256 `0cd8a40f…`) and PERDEDOR (PowerShell 7 agent), full suite; excluded from verdict accuracy. |
| L | 2 existing benign Linux probes × 2 runs | CHIMERA-only telemetry checks; no Windows/Linux pooled ranking. |

B-core: two scheduled repetitions per input at 180 s. E: 900 s execution budget, since historical combined scans took 501–562 s (`docs/chimera/hardening-design.md:173`); record per-tool budgets and any truncation.

M-public analysis unit is the distinct hash; show family groupings. The reference label is the register's family/role, frozen before results, with its public source. Uncertain labels become `reference_uncertain`, excluded from accuracy but kept in coverage tables. Neither platform's verdict is its own ground truth, and a public sandbox's verdict is not ground truth for CHIMERA. Check classifier training/evaluation hash and family overlap with the model owner; unknown overlap limits interpretation.

Do not shrink the existing M5 protocol silently. Its 27 Windows/15 Linux design (`docs/chimera/malware-evaluation-protocol.md:20`) is separate; Stage 1 is its first, smaller step. If fewer matched pairs exist than hoped, publish the actual count and the reasons; no replacement chosen for a favourable outcome.

## 3. Preregister and execute fairly

By 27 October, timestamp an immutable protocol/register copy outside the public repo. Include eligibility, exclusions, sample hashes, the public-report selection rule, CHIMERA settings, model hash, mapping rules, analysis code version, seed `20261028`, run schedule and deadlines. Hash this copy. Amendments get timestamps, reasons and "before/after results seen"; never overwrite the original.

**Public-report selection rule (frozen 27 Oct):** search Triage by SHA-256 first; if it has none, use the ANY.RUN or other public sandbox link on the sample's MalwareBazaar page. Take the **most recent** report that opens without sign-in, in the order Triage → ANY.RUN → any other public sandbox. Linux samples need a Linux behavioural run. Joe Sandbox is not used. Record the report URL, analysis date, retrieval date, visible OS/configuration/run length and the selection reason. Save the page as PDF, because public pages change. Keep every `none_found`, `signin_required` and exclusion. Do not swap a report after seeing CHIMERA's result.

CHIMERA runs use frozen H3 and production plugins; record A0 separately. No new hardening or model training after results begin. For every local run:

1. Confirm the exact payload SHA-256, launch name, arguments, architecture and input package. If an archive is needed, record payload and archive hashes separately; the payload must match.
2. Record date/time in UTC, commit/build/model/image/config hashes, OS build, privileges, tool/check inventory, network policy and time budget. Unknowns are `NA` with reasons. Do not export configuration containing secrets.
3. Randomize sample order from the frozen seed. One local dynamic analysis at a time; fresh snapshot per run; no hidden desktop interactions. Record any necessary clicks as interventions.
4. Observe until the report is usable or a fixed 30-minute deadline per attempt. A usable report has a matching hash, final status and readable output. Save every export, error and raw local log; hash an artifact manifest.
5. Record rejection, unsupported input, timeout, incomplete telemetry, missing fields and report failures. Preserve the failed first attempt. One diagnostic retry is allowed after the scheduled batch, linked to the first attempt; first attempts remain the reliability denominator.
6. Stop on a containment concern; the operator follows `docs/chimera/threat-model.md:130`. Do not continue to fill a quota.

No timing, reliability or evasion claim is made about public sandboxes from evidence their reports do not show.

**Fallback:** if Stage 1 has not produced CHIMERA reports by 29 Oct 12:00, the matched comparison is reported as not done, with the reason. The public-report inventory (how many register hashes have a usable public report, on which OS) and the rubric on available CHIMERA reports (benign set, earlier runs) are still reported.

## 4. Artifact-derived metric dictionary

Keep native values alongside normalized metrics. `0` means measured absence; `NA` means unavailable, unsupported or unobservable, with a reason. Do not replace NA with zero.

| Metric | Exact definition and artifact |
|---|---|
| Known-action coverage (B-core, CHIMERA) | Before runs, list expected actions in each B-core program from source: child creation, harmless file drop, Run-value write, DNS request, HTTP request for own probe (`scripts/chimera/bench/behaviour-probe/probe.c:2`). For each action record evidence yes/no/unobservable and an artifact locator. Coverage = observed / prespecified applicable actions; strict sensitivity treats unobservable as not demonstrated, labelled "demonstrated coverage". |
| Process depth / count | Sample root depth 0; longest observed descendant path is max depth; unique process instances by seqid or PID+start time, minus root for children. Broken/missing root => NA, not depth 0. Exclude unrelated system processes. For public reports, count what the saved page shows. |
| Unique APIs/events | CHIMERA only: cardinality of sample-subtree API names within the actual window. Report syscall names separately on Linux; never equate syscalls with user-mode APIs. |
| Network | Unique lowercased DNS names (strip final dot); distinct `(protocol,destination IP,port)` attempted endpoints; HTTP `(method,host,path)` tuples. Record process attribution versus whole-capture evidence separately. Attempts ≠ successful C2. Note real versus simulated internet per report. |
| ATT&CK techniques | Distinct technique IDs shown in the report. Mapping quality differs by platform; a count is not a correctness measure. |
| Evasion detection (E, CHIMERA) | Per pinned check ID: detected / clean / error / skipped / missing. Detection fraction = detected/(detected+clean); evaluated coverage = (detected+clean)/expected inventory. Missing/error never count as clean. |
| Behaviour observed (M5) | Persistence OR executable/script drop OR network intent, scoped to subtree; save component evidence. Early exit = ≤10 s, no descendants, no network intent. Local extractor: `scripts/chimera/bench/m5_eval.py:194`. |
| Telemetry integrity | Final status, `metadata.telemetry.complete`, return code, hard timeout/stall and postprocess failures. M5 eligibility: finished + rc=0 + no hard timeout (`scripts/chimera/bench/m5_eval.py:201`). |
| Verdict | Freeze mapping before outcomes: explicit malicious→M; explicit benign→B; suspicious/unknown/no verdict/absent numeric threshold→I (indeterminate). CHIMERA's native labels: `docs/chimera/classifier-interface.md:41`. Preserve native scores; never equate /10, /100 and CHIMERA decision scores, and never treat any of them as probabilities. A missing report is tracked separately. |
| Time, failure, resources | CHIMERA only. Time: report-ready minus submit (2 s poll); deadline exceedance is right-censored at 1800 s. Failure: first-attempt technical failures / scheduled first attempts. Resources: host peak RAM and idle baseline, worker RSS, Xen guest allocation, CPU-seconds, output bytes, peak disk delta. |

CHIMERA features are subtree-scoped and capped (`docs/chimera/classifier-interface.md:92`, `:99`); use raw artifacts for uncapped counts and flag truncation. Packet DNS attribution is conditional (`:107`); Linux fields have different semantics (`:120`).

Verdict table: truth rows {benign, malicious}; prediction columns {B,M,I}. TP=M on malicious; FN=B on malicious; FP=M on benign; TN=B on benign; record I separately by truth. Decisive coverage=(TP+TN+FP+FN)/all truth-labelled completed reports; selective accuracy=(TP+TN)/(TP+TN+FP+FN). Do not hide abstention by presenting only selective accuracy. For M-public, both platforms are tabulated **on the same matched hashes only**.

## 5. Blind report-quality rubric

Two people independently score all matched report bundles (CHIMERA and public); neither sees the other's scores or the metrics. The benchmark lead prepares neutral IDs, hides branding and platform names where practical, randomizes order and records residual clues. Freeze anchors on a practice pair before study scoring. Complete blinding is impossible: the team built CHIMERA.

| Dimension | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Evidence traceability | No supporting evidence | Findings without locators | Most findings linked to events | Every key conclusion has process/time/artifact locator |
| Behaviour reconstruction | No usable sequence | Isolated actions | Root/children and actions connect | Time-ordered chain with clear attribution and gaps |
| Verdict explanation | Absent or contradictory | Label/score only | Reasons tied to observations | Reasons, component limits and uncertainty explained |
| Network usefulness | No usable view | Endpoints only | DNS/HTTP/endpoints with context | Attribution/timing plus attempts vs responses/TLS limits |
| Reproducibility/export | Cannot preserve usable report | Screenshot only, identity unclear | Export with hash and run identity | Portable export, identity/settings and raw-evidence references |

Score 0–15 total, but publish each dimension and both raters' original values. An absent report has no rubric score; show the available-report denominator. An absent section within a usable report can score 0. Compute unweighted Cohen's κ per dimension and raw exact agreement; add linear-weighted κ as ordinal sensitivity. Undefined κ (zero denominator) is NA, not perfect agreement. Discuss disagreements only after storing original scores; consensus is a separate column. Scikit-learn documents Cohen's κ and weighting [V], https://scikit-learn.org/stable/modules/generated/sklearn.metrics.cohen_kappa_score.html.

## 6. Small-n analysis and limitations

Use 95% Clopper–Pearson exact binomial intervals for proportions on independent sample-level outcomes: `binomtest(k,n).proportion_ci(confidence_level=.95, method='exact')` [V], https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.binomtest.html. n=0 gives NA. Runs and checks from one sample are not independent new samples; report replicate frequencies descriptively.

M-public matched pairs: report per-hash paired values, median/range of differences and every pair. No significance test: the public reports were not produced under controlled, comparable conditions.

M-cape: per-hash 2×2 table of "behaviour observed" (CHIMERA H3 × CAPE) on `test` hashes with an eligible run on both platforms, exact McNemar as below, plus every pair listed. Verdicts, early exits and evasion checks are reported per hash and per check, descriptively. With 22 hashes a non-significant result is not evidence of equivalence.

Internal M5 (the primary inferential endpoint): preserve the implementation's two-run aggregation, complete-run majority **with ties counted observed** (`scripts/chimera/bench/m5_eval.py:289`). Show run-level data and a sensitivity requiring both runs complete and positive. Exclude pairs with no eligible run on either arm and list reasons. Role `test` only is the primary paired set (`:313`); controls separate. Report both/neither/A0-only/H3-only. Exact two-sided McNemar uses discordants b,c: `min(1,2*P[Binomial(b+c,.5)≤min(b,c)])`; zero discordants yields p=1 [V], https://www.statsmodels.org/stable/generated/statsmodels.stats.contingency_tables.mcnemar.html.

Small n cannot prove equivalence, calibrated probabilities, general malware detection, rare escape resistance or "undetectable" instrumentation. No observed failures does not establish zero failure risk.

Threats to validity: unknown public sandbox settings; different OS images, patches and privileges; real internet versus CHIMERA's simulated network; different run lengths and analysis dates (C2 servers go offline); the most recent public report is not necessarily the best one; selection of hashes that already have public reports; family/training overlap; monitor/API visibility differences; branding clues; team familiarity with CHIMERA. H3 changes resources and realism together, so A0–H3 is an environment-bundle effect, not proof of one hardening technique. Team-built checks and tuned thresholds invite teaching to the test (`docs/chimera/hardening-design.md:51`).

Historical figures are context only: BGInfo 10/10 finished at 120 s (`docs/chimera/benign-series-2026-10-19.md:18`); PERDEDOR 100 and al-khaser 20 on H3b (`docs/chimera/hardening-design.md:179`), later 21 detections after clock sync (`:195`). Linux documentation conflicts between early success and later pending dump validation (`docs/chimera/linux-sandbox.md:55`, `:173`). Reverify the frozen deployment; don't carry these forward as new results.

## 7. Existing script inventory — read, not executed

| File | What it does / caution |
|---|---|
| `scripts/chimera/bench/benign_series.py:93` | Repeated API submissions; status transitions, timing, telemetry, bytes and leftover domains/device models; per-run JSON + summary CSV. Default ten runs/120 s; change only in frozen run specification. |
| `scripts/chimera/bench/behaviour-probe/probe.c:2` | Positive control: child, harmless batch write, Run value, DNS/HTTP and 30 s sleep. Disposable guest only. |
| `scripts/chimera/bench/behaviour-probe/build.sh:1` | Builds the Windows probe using MinGW; no committed output required. |
| `scripts/chimera/bench/m4/scan.sh:2` | Requests full PERDEDOR+al-khaser scans with DRAKVUF attached, polls and writes summary/per-check JSONL; includes privileged reads and a 3000 s watchdog. |
| `scripts/chimera/bench/m4/arms.sh:2` | Backs up/modifies runtime plugin settings, restarts evasion worker, calls scan and restores config. Operator review required; not a read-only collector. |
| `scripts/chimera/bench/m5_samples.py:141` | shortlist/add/Linux shortlist from metadata; download command exists (`:287`). Operator only: authenticated metadata access and binary retrieval. |
| `scripts/chimera/bench/m5_eval.py:144` | Seeded schedules; labels (`:194`), exact McNemar (`:279`), run lanes (`:550`), export/report (`:603`, `:666`). Run path submits/decrypts samples and changes arms; never use for public hash lookup. |

Linux companion tooling: `scripts/chimera/linux/bench/run_linux.py:23` runs local analyses; `check_probe.py:31` checks 16 assertions. `probe.c:1` and `probe_ext.c:1` are source probes. Operator only for execution.

## 8. Data sheets and results templates

The benchmark lead's kit uses a reduced subset of these columns: `public-reports.csv`, `runs.csv`, `ratings.csv`, `blind-key.csv`. Use empty numeric cells plus `missing_reason`, never a numeric sentinel.

```csv
study_id,protocol_hash,attempt_id,parent_attempt_id,is_primary,sample_id,payload_sha256,reference_label,family,role,platform,arm,report_only,platform_build,model_hash,config_hash,image_hash,guest_os,guest_build,privilege,network_policy,seed,order_index,replicate,requested_window_s,actual_window_s,submit_utc,report_ready_utc,status,censored,failure_reason,telemetry_complete,root_locator,process_count,max_depth,native_api_unique,dns_unique,endpoints_unique,http_unique,attack_techniques,actions_expected,actions_observable,actions_observed,detected_checks,clean_checks,error_checks,skipped_checks,missing_checks,native_verdict,native_score,normalized_verdict,cpu_seconds,host_peak_ram_bytes,guest_allocation_bytes,artifact_bytes,report_url,report_date,retrieval_utc,selection_reason,artifact_manifest_sha256,missing_reason,intervention,exclusion_reason
```

Linked `public-reports.csv`: `sample_id,platform,report_url,analysis_date,os_shown,label_or_score_shown,opens_without_signin,saved_pdf,notes`.
Linked `actions.csv`: `attempt_id,action_id,applicable,observable,observed,artifact_locator`.
Linked `checks.csv`: `attempt_id,tool,build,check_id,status,artifact_locator`.
Linked `ratings.csv`: `blind_report_id,rater,traceability,behaviour,explanation,network,export,total,blinding_guess,consensus_ref`.

| Endpoint / stratum | CHIMERA H3 | CAPE (commit) | Public reports (service + URL) | Matched n / exclusions | Delta / uncertainty |
|---|---|---|---|---|---|
| Behaviour observed on `test` hashes: both / neither / CHIMERA-only / CAPE-only | — | — | NA | eligible pairs | exact McNemar |
| Register hashes with a usable report (of 35) | — | — | — | — | per OS |
| Processes, network items, ATT&CK on matched hashes | — | — | — | matched pairs | per-hash differences, median/range |
| Truth malicious: predicted B / M / I on matched hashes | — | — | — | matched pairs | descriptive only |
| Early exits (≤10 s, no children, no network) | — | — | NA | matched pairs | per hash |
| Truth benign (B-core): predicted B / M / I | — | — | NA | 7 inputs | descriptive |
| Report rubric, each dimension; κ | — | — | — | usable bundles | original raters + agreement |
| Known-action coverage (probe) | — | — | NA | — | per action |
| Evasion detected / evaluated (E) | — | — | NA | identical checks only | per-check frequencies |
| Report time median [range], censored n; failures | — | — | NA | attempted n | CI assumptions |
| CPU/RAM/disk | — | NA | NA | scope specified | — |
| M5: both / neither / A0-only / H3-only | A0 versus H3 | NA | NA | eligible test hashes | exact McNemar |

## 9. One-page runbook: 27–30 October

Planning estimates below are scheduling allowances, not measured performance. One local dynamic job at a time (`docs/chimera/parallel-analyses.md:3`).

| When | Step / owner | Allowance and stop condition |
|---|---|---|
| 26–27 Oct | CAPE teammates install CAPE and the matched guest on a spare machine; probe network check | About a day; malware part waits for the §2a gates |
| 27 Oct | Benchmark lead + owner freeze register, selection rule, configuration and hash manifest | 1 h |
| 27 Oct | Benchmark lead finds existing public reports for all 35 register hashes by hand, saves PDFs, fills `public-reports.csv` | 2–3 h; no sign-in, no upload, no download links |
| 27–28 Oct | Operator runs M5 Stage 1 on CHIMERA (owner-approved); validates containment, snapshot identity, clocks, disk/thermal health and a known benign probe first | Per the M5 protocol; stop on safety/telemetry failure |
| 28 Oct | Operator runs 6×2 B-core on H3 | 2 h; 30-minute per-attempt deadline, delays carried as censored |
| 28–29 Oct | Operator runs E: 2 tools × 5 runs | 3 h including overhead |
| 29 Oct morning | Operator runs local Linux probes ×2 | 1–1.5 h |
| 28–29 Oct | CAPE teammates run 27 malware ×2 (if gated), 7 benign ×2, 2 evasion tools ×5 | About 8 h of runs; stop rule in their sheet |
| 28–29 Oct | Benchmark lead fills `runs.csv` for every hash with both a CHIMERA and a public report | 2–3 h; fallback decision at 29 Oct 12:00 |
| 29 Oct end | Benchmark lead closes dataset at 18:00 local, manifests every attempt, lists deviations/missing pairs | 45 min; preserve failures |
| 29–30 Oct | Two scorers independently rate blinded bundles; benchmark lead computes metrics and agreement | 2 h per scorer + 1 h preparation; score all matched bundles, not highlights |
| 30 Oct 12:00 | Benchmark lead delivers CSVs, PDFs and a one-page summary with limitations | Neutral wording; losses and ties reported |

Do by 31 Oct: artifact integrity, honest missing data, small matched tables, two-rater report scores and limitations. Future work: Linux samples on CAPE, a hardened CAPE guest as a second arm, larger independent malware/family holdouts, matched guest images, more operating systems, longer windows and independently replicated evasion evaluation.
