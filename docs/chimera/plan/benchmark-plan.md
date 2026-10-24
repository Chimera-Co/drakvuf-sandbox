# CHIMERA comparison plan (for the benchmark lead)

Prepared 25 October 2026. Freeze the register and protocol on 27 October; collect 28–29 October; score and report 30 October. This document proposes experiments; it reports no new sandbox results. A loss, tie, inconclusive result or unavailable comparator is an acceptable outcome.

## Evidence and scope

Repository evidence is cited as `path:line`. External claims use [V] (primary source read for this audit), [S] (secondary account), or [K] (background not reverified), with a URL. Recommendations and proposed definitions below are not product claims.

- MS 360's team-observed interface reportedly offered separate static/dynamic submissions, dynamic process/API/network sections and PDF exports [S], https://sandbox.isea.app/; secondary evidence: `docs/chimera/plan/ms360-study.md:43`, `:55`, `:60`, `:68`. The public landing page timed out during this audit. The screenshots/recordings underlying the study were not independently inspected here. Reconfirm all fields from permissible existing exports; engine/version labels are observations, not proof of internal architecture.
- The study reports a Cuckoo 2.0.7 label [S], https://sandbox.isea.app/ (`docs/chimera/plan/ms360-study.md:34`). Do not infer current hypervisor, monitor implementation, guest image, Linux dynamic support, service accuracy or retention guarantees from that label or a client renderer. Those remain unverified.
- al-khaser describes Windows anti-analysis checks, including VM/sandbox detection [V], https://github.com/ayoubfaouzi/al-khaser. Pin the exact build and flags; do not fetch or execute it during planning.
- PERDEDOR measurements in this plan rely on local project evidence, not a newly verified external feature claim: `docs/chimera/hardening-design.md:55`. The external repository could not be retrieved: https://github.com/clustercoder/perdedor (unverified).
- CHIMERA's M5 is an internal A0–H3 experiment, with two 180-second runs per arm and a Linux descriptive lane (`docs/chimera/malware-evaluation-protocol.md:26`, `:41`). It is not automatically a controlled cross-platform experiment.

## 1. Questions and measurable comparisons

| Question | CHIMERA prospective | MS 360 approved prospective | Existing public reports only |
|---|---|---|---|
| Which known benign behaviours are visible? | Raw logs + report, sample subtree | Report/export fields actually exposed | Visible fields only; absence is unobservable unless explicitly reported |
| How detectable is the environment? | Tool output under active production monitoring | Same tool/build only if output can be recovered | Only exact matching tool/build reports; otherwise N/A |
| Are verdicts useful with abstention? | Native fused and available components separately | Each native engine separately, if available | Exact-hash, label-bearing reports; selected-case agreement only |
| Is the report useful to an analyst? | Offline HTML + JSON | Available export + screenshots | Saved public export/screenshots |
| Reliability and time to usable report? | All scheduled attempts | All authorized scheduled attempts | N/A: no unseen submissions, queue or failures |
| Resource cost? | Host/guest allocation, CPU/RAM/disk | Client operator time; backend N/A unless documented | N/A backend; no speculative price comparison |

Primary external endpoint: Windows benign-probe behaviour coverage in paired, prospective, comparable runs. Secondary: verdict outcomes, report rubric, time and failure rate. Public-report comparisons are a separate descriptive stratum and cannot establish platform superiority. Linux is a CHIMERA descriptive appendix unless a comparator's matching OS/image and execution mode are documented.

## 2. Hard gates and sample register

No external submission is authorized by this document. This audit makes no uploads, authenticated requests, sample downloads or executions. The operator must separately authorize local execution under M5 controls. If external access requires an account/authentication, do not sign in under this task; use already available exports or public reports. Approval for uploading does not override the no-authentication restriction; a separately scoped operator session is required.

Before **any file**, including a benign program or evasion checker, is submitted to MS 360 or another external service, retain explicit written approval from **both project owner and mentor**:

- [ ] Named service, operator, date window and permitted submission count.
- [ ] Exact SHA-256 allowlist, provenance and classification of every input.
- [ ] Confirmation of rights to redistribute; no private data, credentials, licensed private payloads or project secrets.
- [ ] Acknowledgement of retention, publication, redistribution and uncertain deletion terms; attach terms or mark unknown.
- [ ] Approval covers each wrapper/archive, password disclosure, command line and potentially generated public report.
- [ ] Owner signature/date and mentor signature/date; evidence reference recorded in register.
- [ ] Operator checks allowlist immediately before submission. Missing approval means skip, record `approval_missing`, continue report-only work.

Hash lookup is not a file upload, but discloses interest in that hash to the provider. Log provider/date/purpose, use only already public hashes and no authenticated API. Do not enumerate privately held hashes. Never bypass quotas, access controls or service policies.

Freeze these proposed sets before seeing new results:

| Set | Proposed minimum | Purpose and handling |
|---|---:|---|
| B-core | 6 Windows benign inputs | Own behaviour probe; own simple exit-only control; 4 already-held, provenance-checked benign utilities spanning CLI/GUI and file/network activity. Record exact names/hashes before starting; no arbitrary replacement after results. |
| E | 2 tools × 5 runs/platform | al-khaser and PERDEDOR, same pinned build/check inventory, full suite; exclude from malware-verdict accuracy. If full runs unavailable externally, mark that endpoint unavailable. |
| M-public | 10 already-public Windows malware hashes, preferably one/family | Select consecutively from a frozen eligible hash list with usable public evidence; do not fetch files. Compare existing reports and already-held authorized CHIMERA artifacts; prospective local runs only by separately authorized operator. |
| L | 2 existing benign Linux probes × 2 runs | CHIMERA-only telemetry checks; no Windows/Linux pooled ranking. |

B-core: two scheduled repetitions/input/platform at 180 s. E: use 900 s execution budget on both platforms if configurable, since historical combined CHIMERA scans took 501–562 s (`docs/chimera/hardening-design.md:173`); record per-tool budgets and any truncation. If external limits differ, retain evidence in an unmatched-budget stratum. E tests are not secretly given the B-core budget.

M-public primary analysis unit is distinct hash; show family groupings. Ground truth must be frozen independently of the compared verdicts: benign provenance/build record; malware hash plus original public source and corroborating independent published family/behaviour evidence. Uncertain labels become `reference_uncertain`, excluded from accuracy but retained in coverage tables. Never use a platform's own verdict as its reference truth. Check classifier training/evaluation hash and family overlap with the model owner; unknown overlap limits interpretation.

Do not shrink the existing M5 protocol silently. Its 27 Windows/15 Linux sample design (`docs/chimera/malware-evaluation-protocol.md:20`) remains separate; the small external subset is a named feasibility study. If ten usable malware pairs do not exist, publish the actual count and missing reasons; no replacement chosen for a favourable outcome.

## 3. Preregister and execute fairly

By 27 October, timestamp an immutable protocol/register copy outside the public repo. Include candidate order and eligibility, exclusions, sample hashes, platform settings, model hash, primary endpoint, mapping rules, analysis code version, seed `20261028`, run schedule, deadlines and approvals. Hash this copy. Amendments get timestamps, reasons and “before/after results seen”; never overwrite the original.

Use the best documented available configuration of each platform, chosen before runs, without tuning to individual outcomes. CHIMERA external comparison uses frozen H3 and production plugins; record A0 separately. No new hardening/model training after results begin. Unknown external settings stay unknown.

For every prospective pair:

1. Confirm exact payload SHA-256, launch name, arguments, architecture, input package and intended actions. If an archive is required, record payload and archive hashes separately; the payload must match. DLL launch conventions must match or be a separate stratum.
2. Record date/time in UTC, commit/build/model/image/config hashes, OS build, privileges, tools/check inventory, network policy, time budgets and visible external engine labels. Unknowns are `NA` with reasons. Do not export configuration containing secrets.
3. Randomize sample order and within-sample platform order from the frozen seed. Run pairs on the same day where feasible. One local dynamic analysis at a time; fresh snapshot per run; no hidden desktop interactions. Record any necessary clicks as interventions.
4. Request 180 s for B-core and the agreed E budget. Record requested and actual windows, queue delay, clock offsets and censoring. Different budgets/network/images stay explicitly unmatched; do not manufacture equal conditions from rounded duration labels.
5. Observe until report usable or fixed 30-minute deadline per attempt. A usable report has matching hash, final status and readable requested output. Save timestamps/screenshots at submit, start if visible, final report/error. Save every export available, errors and raw local logs; hash an artifact manifest.
6. Record rejection, unsupported input, timeout, incomplete telemetry, missing fields and report failures. Preserve original failed attempt. One diagnostic retry is allowed after the scheduled batch, linked to the first attempt; first attempts remain the primary reliability denominator. No discarded retries.
7. Stop on containment concern; the operator follows `docs/chimera/threat-model.md:130`. Do not continue to fill a quota.

For report-only cases, record exact hash/report URL, analysis date and retrieval date, visible OS/config/runtime and selection reason. Freeze “latest accessible report dated no later than 27 October” as the selection rule; retain all exclusions and hash-not-found cases. No timing/reliability/evasion claim from missing hidden evidence. No new upload or reanalysis request.

## 4. Artifact-derived metric dictionary

Keep native values alongside normalized metrics. `0` means measured absence; `NA` means unavailable, unsupported or unobservable, with a reason. Do not replace NA with zero.

| Metric | Exact definition and artifact |
|---|---|
| Known-action coverage (primary) | Before runs, list expected actions in each B-core program from source: child creation, harmless file drop, Run-value write, DNS request, HTTP request for own probe (`scripts/chimera/bench/behaviour-probe/probe.c:2`). For each eligible action record visible evidence yes/no/unobservable and artifact locator. Coverage = observed / prespecified applicable actions; publish observable/applicable too. Strict sensitivity = observed / all applicable actions, treating unobservable as not demonstrated, with label “demonstrated coverage”, not absence of behaviour. |
| Process depth / count | Sample root depth 0; longest observed descendant path is max depth; unique process instances by seqid or PID+start time, minus root for children. Save root-selection rule and tree locator. Broken/missing root => NA, not depth 0. Exclude unrelated system processes. |
| Unique APIs/events | Cardinality of sample-subtree API names within actual window; publish native count and intersection with frozen shared API-name mapping. No inferred API aliases unless mapping registered. Report syscall names separately on Linux; never equate syscalls with user-mode APIs. Raw event count is descriptive, not coverage. |
| Network | Unique lowercased DNS names (strip final dot); distinct `(protocol,destination IP,port)` attempted endpoints; HTTP `(method,host,path)` tuples. Record process attribution versus whole-capture evidence separately. Attempts ≠ successful C2. Report TLS metadata and decrypted contents separately. |
| Evasion detection | Per pinned check ID: detected / clean / error / skipped / missing. Detection fraction = detected/(detected+clean); evaluated coverage = (detected+clean)/expected applicable inventory. Publish both; missing/error never count as clean. Compare only intersection of identical checks and builds. Tool output is environment-detection evidence, not a verdict on malware. |
| Behaviour observed (M5) | Persistence OR executable/script drop OR network intent, scoped to subtree; save component evidence. Early exit = ≤10 s, no descendants, no network intent. Local extractor evidence: `scripts/chimera/bench/m5_eval.py:194`. Distinguish written paths from confirmed new files and persistence attempts from successful installation. |
| Telemetry integrity | Local: final status, `metadata.telemetry.complete`, return code, hard timeout/stall and postprocess failures, plus expected probe evidence. Keep native M5 eligibility separately: finished + rc=0 + no hard timeout (`scripts/chimera/bench/m5_eval.py:201`). External: explicit errors/completeness status only; unavailable internals => unknown. Empty optional plugin log alone is not failure. |
| Verdict | Freeze mapping before outcomes: explicit malicious→M; explicit benign→B; suspicious/unknown/absent numeric threshold→I (indeterminate). CHIMERA's native labels are documented at `docs/chimera/classifier-interface.md:41`. Preserve native scores; never equate /10, /100 and probabilities. Missing report = technical failure, tracked separately; all-attempt sensitivity treats it as not detected. |
| Time | Wall-clock report-ready minus submit; separately queue/start, execution and postprocessing where observable. Fixed poll interval 2 s locally; record external observation resolution. Deadline exceedance is right-censored ≥1800 s, not a 1800-second success. Report median/range among completed plus censored count. |
| Failure | First-attempt technical failures / scheduled eligible first attempts: rejected, stalled, timeout, missing/unreadable report, wrong hash. Unsupported inputs separate; also show denominator including them for operational availability. Approval-blocked runs are not attempts. |
| Resources | Local total host peak RAM and idle baseline, worker/container peak RSS where obtainable, Xen guest allocation separately, CPU-seconds, elapsed seconds, output bytes and peak disk delta. State polling interval (1 s), counters and scope; RSS alone excludes guest RAM. External backend NA; record operator minutes and observable limits, no guessed monetary cost. |

CHIMERA features are subtree-scoped and capped (`docs/chimera/classifier-interface.md:92`, `:99`); use raw artifacts for uncapped counts and flag truncation. Packet DNS attribution is conditional (`:107`); Linux fields have different semantics (`:120`). Keep these limitations in tables.

Verdict table: truth rows {benign, malicious}; prediction columns {B,M,I}. TP=M on malicious; FN=B on malicious; FP=M on benign; TN=B on benign; record I separately by truth. Decisive coverage=(TP+TN+FP+FN)/all truth-labelled completed reports; selective accuracy=(TP+TN)/(TP+TN+FP+FN). All-attempt malicious detection=TP/all scheduled malicious attempts; all-attempt false-alarm=FP/all scheduled benign attempts, alongside I/failure rates. Do not hide abstention by presenting only selective accuracy. Evasion/probe positives are not malware false positives.

## 5. Blind report-quality rubric

Two people independently score all available matched report bundles; neither sees the other's scores or benchmark metrics. The benchmark lead prepares neutral IDs, removes branding and native platform names, keeps technical evidence and layout as far as practical, randomizes order and records residual clues. Use a separate practice pair; freeze anchors before study scoring. Explain that complete blinding may be impossible.

| Dimension | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Evidence traceability | No supporting evidence | Findings without locators | Most findings linked to events | Every key conclusion has process/time/artifact locator |
| Behaviour reconstruction | No usable sequence | Isolated actions | Root/children and actions connect | Time-ordered chain with clear attribution and gaps |
| Verdict explanation | Absent or contradictory | Label/score only | Reasons tied to observations | Reasons, component limits and uncertainty explained |
| Network usefulness | No usable view | Endpoints only | DNS/HTTP/endpoints with context | Attribution/timing plus attempts vs responses/TLS limits |
| Reproducibility/export | Cannot preserve usable report | Screenshot only, identity unclear | Export with hash and run identity | Portable export, identity/settings and raw-evidence references |

Score 0–15 total, but publish each dimension and both raters' original values. An absent report is a technical failure and has no rubric score; show available-report denominator. An absent section within a usable report can score 0. Compute unweighted Cohen's κ per dimension and raw exact agreement; add linear-weighted κ as ordinal sensitivity. κ=(observed agreement−chance agreement)/(1−chance agreement); undefined κ when denominator zero is NA, not perfect agreement. Discuss disagreements only after storing original scores; consensus is a separate column. Scikit-learn documents Cohen's κ and weighting [V], https://scikit-learn.org/stable/modules/generated/sklearn.metrics.cohen_kappa_score.html.

## 6. Small-n analysis and limitations

Use 95% Clopper–Pearson exact binomial intervals for proportions on independent sample-level outcomes: `binomtest(k,n).proportion_ci(confidence_level=.95, method='exact')` [V], https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.binomtest.html. n=0 gives NA. Runs and checks from one sample are not independent new samples; report replicate frequencies descriptively. For repeated reliability runs of one program, any binomial CI assumes independent trials and says nothing about diverse programs.

For primary external coverage, first aggregate per sample across its two scheduled runs (mean demonstrated coverage), then report paired deltas, median/range and every pair; no significance test across individual actions. A secondary binary “all expected actions demonstrated in both runs” can use exact McNemar across samples. No significance testing on report-only selected cases.

For internal M5, preserve the implementation's two-run aggregation: complete-run majority **with ties counted observed** (`scripts/chimera/bench/m5_eval.py:289`), not an unstated strict majority. Show run-level data and sensitivity requiring both runs complete and positive. Exclude pairs with no eligible run on either arm and list reasons. Role `test` only is the primary M5 paired set (`:313`); controls separate. Report both/neither/A0-only/H3-only. Exact two-sided McNemar uses discordants b,c: `min(1,2*P[Binomial(b+c,.5)≤min(b,c)])`; zero discordants yields p=1. Exact option verified [V], https://www.statsmodels.org/stable/generated/statsmodels.stats.contingency_tables.mcnemar.html. Same rule can compare decisive-correct outcomes externally, with I as not correct; failures also count as not correct in all-attempt sensitivity. Do not test only favourable decisive pairs.

One primary endpoint; secondary p-values exploratory, no hunting across tools/checks. Hashes within a family and repeated runs are correlated: show one representative/hash-per-family sensitivity and family-level tables. Small n cannot prove equivalence, calibrated probabilities, general malware detection, rare escape resistance or “undetectable” instrumentation. No observed failures does not establish zero failure risk.

Threats to validity: black-box MS 360 settings; OS/privilege/patch/installed-app differences; network simulation versus remote Internet policy; monitor/API visibility differences (including any inferred Cuckoo-versus-VMI distinction); tools detecting benign virtual hardware; capped exports; stale public reports and survivor/selection bias; family/training overlap; changing C2/time; short windows; report branding; team familiarity with CHIMERA. H3 changes resources and realism together, so A0–H3 is an environment-bundle effect, not isolated proof of one hardening technique. Team-built checks and tuned thresholds invite teaching to the test (`docs/chimera/hardening-design.md:51`). No causal internals claim from vendor labels.

Historical figures are context only: BGInfo 10/10 finished at 120 s (`docs/chimera/benign-series-2026-10-19.md:18`); PERDEDOR 100 and al-khaser 20 on H3b (`docs/chimera/hardening-design.md:179`), but later clock sync produced 21 detections (`:195`). Linux documentation conflicts between early success and later pending dump validation (`docs/chimera/linux-sandbox.md:55`, `:173`); resource changes also affect evasion (`docs/chimera/parallel-analyses.md:83`). Reverify the frozen deployment; don't carry these forward as new results.

## 7. Existing script inventory — read, not executed

| File | What it does / caution |
|---|---|
| `scripts/chimera/bench/benign_series.py:93` | Repeated API submissions; status transitions, timing, telemetry, bytes and leftover domains/device models; per-run JSON + summary CSV. Default ten runs/120 s; change only in frozen run specification. |
| `scripts/chimera/bench/behaviour-probe/probe.c:2` | Positive control: child, harmless batch write, Run value, DNS/HTTP and 30 s sleep. Disposable guest only; benign does not mean no guest state changes. |
| `scripts/chimera/bench/behaviour-probe/build.sh:1` | Builds the Windows probe using MinGW; no committed output required. |
| `scripts/chimera/bench/m4/scan.sh:2` | Requests full PERDEDOR+al-khaser scans with DRAKVUF attached, polls and writes summary/per-check JSONL; includes privileged reads and a 3000 s watchdog. |
| `scripts/chimera/bench/m4/arms.sh:2` | Backs up/modifies runtime plugin settings, restarts evasion worker, calls scan and restores config. H1/H1S/H1SH are runtime labels, not A0/H3 snapshot switching. Operator review required; not a read-only collector. |
| `scripts/chimera/bench/m5_samples.py:141` | shortlist/add/Linux shortlist from metadata; download command exists (`:287`). Do not run here: it includes authenticated metadata access and binary retrieval, outside this audit's rules. |
| `scripts/chimera/bench/m5_eval.py:144` | Seeded schedules; labels (`:194`), exact McNemar (`:279`), run lanes (`:550`), export/report (`:603`, `:666`). Run path submits/decrypts samples and changes arms; never use for public hash lookup or this audit. |

Linux companion tooling: `scripts/chimera/linux/bench/run_linux.py:23` runs local analyses; `check_probe.py:31` checks 16 assertions. `probe.c:1` and `probe_ext.c:1` are source probes. Operator only for execution.

## 8. Data sheets and results templates

One row/attempt, including diagnostic retries; schema header below can be split physically into linked sheets keyed by `attempt_id`. Use empty numeric cells plus `missing_reason`, never a numeric sentinel.

```csv
study_id,protocol_hash,attempt_id,parent_attempt_id,is_primary,sample_id,payload_sha256,archive_sha256,source_url,hash_public_since,reference_label,reference_evidence,family,role,platform,arm,mode,report_only,approval_ref,platform_build,model_hash,config_hash,image_hash,guest_os,guest_build,privilege,network_policy,tool_build,check_inventory_hash,seed,order_index,replicate,requested_window_s,actual_window_s,submit_utc,start_utc,report_ready_utc,poll_resolution_s,status,censored,failure_reason,telemetry_complete,postprocess_ok,root_locator,process_count,max_depth,native_api_unique,shared_api_unique,event_count,dns_unique,endpoints_unique,http_unique,actions_expected,actions_observable,actions_observed,detected_checks,clean_checks,error_checks,skipped_checks,missing_checks,native_verdict,native_score,normalized_verdict,cpu_seconds,host_peak_ram_bytes,guest_allocation_bytes,worker_peak_rss_bytes,artifact_bytes,peak_disk_delta_bytes,operator_minutes,report_url,report_date,retrieval_utc,artifact_manifest_sha256,missing_reason,intervention,exclusion_reason
```

Linked `actions.csv`: `attempt_id,action_id,applicable,observable,observed,artifact_locator`.
Linked `checks.csv`: `attempt_id,tool,build,check_id,status,artifact_locator`.
Linked `ratings.csv`: `blind_report_id,rater,traceability,behaviour,explanation,network,export,total,blinding_guess,consensus_ref`.

| Endpoint / stratum | CHIMERA H3 | MS 360 | Public report service + URL | Paired n / exclusions | Delta / uncertainty |
|---|---|---|---|---|---|
| Expected actions demonstrated / applicable | — | — | descriptive only | — | paired per-sample deltas |
| Evasion detected / evaluated; evaluated / inventory | — | — or NA | — or NA | identical checks only | per-check frequencies |
| Truth benign: predicted B / M / I / failure | — | — | selected cases | — | exact CI where eligible |
| Truth malicious: predicted B / M / I / failure | — | — | selected cases | — | exact CI where eligible |
| Decisive coverage; selective accuracy | — | — | descriptive only | — | denominator explicit |
| Report rubric, each dimension; κ | — | — | — | usable bundles | original raters + agreement |
| Report time median [range], censored n | — | — | NA | attempted n | queue/window caveats |
| Failures / first attempts | — | — | NA | — | CI assumptions |
| CPU/RAM/disk; operator minutes | — | backend NA | NA | scope specified | no guessed cost |
| M5: both / neither / A0-only / H3-only | A0 versus H3 only | NA | NA | eligible test hashes | exact McNemar |

## 9. One-page runbook: 28–30 October

Planning estimates below are scheduling allowances, not measured platform performance. Cap at one local dynamic job at a time; do not adopt dual-slot execution just to accelerate this study (`docs/chimera/parallel-analyses.md:3`).

| When | Step / owner | Allowance and stop condition |
|---|---|---|
| Before 28 Oct | The benchmark lead + owner + mentor freeze register, approval, configuration and hash manifest | 1–2 h on 27 Oct; no upload without both signatures; if access unavailable, report-only route |
| 28 Oct morning | Operator validates containment on same boot, snapshot identity, clocks, free disk/thermal health, known benign probe and teardown | 60–90 min; stop on safety/telemetry failure |
| 28 Oct morning | The benchmark lead inventories exact-hash existing MS/public exports and public report links | 60–90 min; record missing/config unknown; no sign-in/upload |
| 28 Oct afternoon | Authorized operator runs 6×2 B-core on H3 and separately approved external lane | Budget 2 h local plus 2 h external operator time; 30-minute per-attempt deadline, carry delays as censored |
| 28–29 Oct | Operator runs E: 2 tools×5 runs, comparable budget where possible | Reserve 3 h/platform including overhead; platform quota/limit means smaller actual n, not hidden retries |
| 29 Oct morning | Operator local Linux two probes×2; benign reliability series if deployment changed | 1–1.5 h; no concurrent Windows guest required |
| 29 Oct afternoon | The benchmark lead matches up to ten M-public hashes to existing artifacts/reports; owner optionally performs already-approved local runs | 2 h extraction; optional local runs capped 2 h; no sample acquisition in this work |
| 29 Oct end | The benchmark lead closes dataset at 18:00 local, manifests every attempt, lists deviations/missing pairs | 45 min; preserve failures; late diagnostics separate |
| 30 Oct morning | Two scorers independently rate blinded bundles; the benchmark lead calculates metrics and agreement | 2 h/scorer + 1 h preparation; score all matched bundles, not highlights |
| 30 Oct afternoon | The benchmark lead reviews tables, denominators, exclusions, limitations with team; freeze demo evidence | 2–3 h; publish neutral result and fallback recording/report |

Do by 31 Oct: artifact integrity, comparable benign actions, honest missing data, approval record, small paired tables, two-rater report scores and limitations. Future work: larger independent malware/family holdouts, matched guest images, more operating systems, longer windows, instrumented resource/energy study and independently replicated evasion evaluation. The full M5 campaign is separately scheduled; its documented 8–9 h parallel estimate must not be reused for this serial runbook (`docs/chimera/malware-evaluation-protocol.md:42`).
