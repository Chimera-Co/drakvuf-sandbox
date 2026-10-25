# CHIMERA hardening and VMI roadmap

Audit date: 25 October 2026. Group 3; demo deadline: 31 October 2026.
This is a read-only checkout audit, not a new experiment or a deployment attestation.
Repository citations are `path:line`; measurements below are recorded results, not independently rerun results.
External claims use [V] (primary source read during this audit), [S] (secondary), or [K] (not re-verified).
Effort and risk are planning estimates for this project, not upstream promises.

## What is measured today

| Experiment | Recorded outcome | Interpretation and evidence |
|---|---|---|
| H1 runtime arms, five scans each, monitor attached | al-khaser 26–27 → 24 → 22–23 detections; PERDEDOR 94.48 → 94.48 → 95.0 | Adding `cpuidmon -s` clears two CPUID indicators; adding `hidsim` clears mouse/input indicators. `rdtsc_diff_vmexit` persists 5/5. No extra timing detection observed in this small experiment. `docs/chimera/hardening-design.md:53`, `:63`, `:73`. |
| H2c, five scans | PERDEDOR 99.48; al-khaser 20 per scan | Firmware identity and phantom-device cleanup clear two PERDEDOR and two al-khaser checks. Firmware/table detections persist. `docs/chimera/hardening-design.md:125`, `:138`, `:152`. |
| H3b, five scans | PERDEDOR 100.0, zero detections; al-khaser 20 per scan | 32 uninstall entries; settling the snapshot clears `nt_yield_execution` seen in H3a. This is checklist success, not invisibility. `docs/chimera/hardening-design.md:173`. |
| Subsequent clock-sync runs, five scans | PERDEDOR 100.0; guest time within 1 s; al-khaser 21 detections | Clock jump replays overdue Windows tasks; `nt_yield_execution` returns 5/5 and scans take about two minutes longer. Do not present the earlier 20-detection result as the latest clock-synced baseline. `docs/chimera/hardening-design.md:189`. |
| Freeze repair | Patched Xen with stock QEMU: 30/30 without a freeze | Excess altp2m mapcache invalidations were removed at Xen, rather than keeping the unsafe general QEMU no-drain workaround. `docs/chimera/vm-freeze-root-cause.md:46`, `:80`, `:93`. |
| Separate DRAKVUF stale-list repair | Unpatched 12/17 complete; patched diagnostic 20/20 and clean 5/5 | Separate from the guest freeze; return code zero did not prove complete telemetry. `docs/chimera/vm-freeze-root-cause.md:123`, `:160`. |
| Containment, 19 October | C-1 through C13 recorded PASS | Includes Internet/LAN redirection, host-port blocking, IPv6, spoofing, namespace pivot, reapplication and fail-closed cases. Evidence is root-only and was not read here. `docs/chimera/containment-results-2026-10-19.md:3`, `:36`. |
| Linux evasion progression | vmcheck 70.44 (17/34 detected) → PERDEDOR 97.42 (4/37 detected) after hiding → scan `71941dda` PERDEDOR 100.0 (0/31 applicable, 6 skipped), vmcheck 35/35 clean | Historical configurations differ, and primary tools changed: these scores are not a calibrated improvement scale. Final recorded fixes were link-local blocking, desktop-user context and 5120 MB RAM. `docs/chimera/linux-sandbox.md:51`, `:52`, `:53`. |
| Linux current qualification | Later configuration text specifies 4096 MB to allow parallel guests and accepts `linux.env.low_ram` | Do not advertise the earlier 5120 MB perfect score as current deployment evidence. No fresh score was measured. Full DRAKVUF evasion remains rejected, although a separate CPUID hider can be attached. `docs/chimera/linux-sandbox.md:118`; `drakrun/web/evasion_api.py:144`; `drakrun/evasion/linux_guest_runner.py:74`. |

### Remaining Windows detections and confidence in causes

The H3b residual set totals 20: 13 WMI checks, two Hyper-V object checks, three firmware/table checks, parent check and VM-exit timing. Clock-synced runs add the scheduling check. This grouping follows the recorded diagnosis, not a fresh raw-report census (`docs/chimera/hardening-design.md:95`, `:152`, `:179`, `:197`).

| Residual | Cause supported by current record | Confidence / next discriminating measurement |
|---|---|---|
| 13 `*_wmi` sensor/device checks | Missing thermal/fan/sensor classes in the guest | Recorded explanation, not proof that each check needs a firmware fix. Compare exact WMI queries, return values and physical-machine controls before proposing devices. `docs/chimera/hardening-design.md:95`; local specifications `drakrun/evasion/verifiers/alkhaser.py:618`, `:633`, `:687`. |
| `firmware_acpi`, `qemu_firmware_acpi`, `number_smbios_tables` | New OEM IDs/type-11 strings did not remove detections | Table counts/WAET are hypotheses. The record mixes table inventories and counts; enumerate precisely which API buffer each probe inspects. Do not assert that a QEMU string or table count is proven causal. `docs/chimera/hardening-design.md:108`, `:152`. |
| `hyperv_driver_objects`, `hyperv_global_objects` | Windows image components | Does not establish that Xen became Hyper-V. Compare image feature inventory with raw object evidence. `docs/chimera/hardening-design.md:96`. |
| `parent_is_explorer` | Launch/injection path | Launch ancestry differs from the probe expectation; inspect the actual parent PID and image for the selected start method. `docs/chimera/hardening-design.md:97`; `drakrun/evasion/verifiers/alkhaser.py:334`. |
| `rdtsc_diff_vmexit` | CPUID/VM-exit timing overhead | Persistent 5/5 with and without `-s`; this experiment does not isolate every timing contribution. `docs/chimera/hardening-design.md:74`. |
| `nt_yield_execution` after time sync | Overdue scheduled work creates runnable threads | Earlier idle snapshot cleared it, time jump restored it; preserve correct clock and document sensitivity. `docs/chimera/hardening-design.md:181`, `:196`. |

Linux remaining indicators depend on configuration: the four intermediate PERDEDOR detections were low RAM, a responding cloud metadata address and root-user activity/history deficiencies; the later record clears them, but subsequently accepts low RAM again for concurrency. The same document still contains a stale “not hardened” gap (`docs/chimera/linux-sandbox.md:52`, `:53`, `:118`, `:205`). No post-helper-build score or attached-full-monitor Linux score is established here. Retain the missing native probes in coverage reporting.

### Checkout corrections to older documentation

The threat model remains the policy authority, but several implementation gaps it lists are already addressed in this checkout:

- Shared per-VM `flock`, stale-domain reclamation and restore inside cleanup: `drakrun/analyzer/run_tools.py:210`, `:237`. This is not a host-wide one-analysis limit.
- Recorded postprocessing outcomes: `drakrun/analyzer/postprocessing/postprocess.py:44`; terminal evasion JSON/metadata after cleanup: `drakrun/evasion/worker.py:482`.
- Bounded report reads and nonzero Windows PERDEDOR exit rejection: `drakrun/evasion/verifiers/base.py:85`; `drakrun/evasion/verifiers/perdedor.py:247`, `:287`. Inventory completeness is still not established by schema/unique-ID checks (`:394`).
- Linux documentation says the native helper is omitted, but code now attempts a host static build, uploads it and sets `PERDEDOR_CPUID_HELPER`; build failure leaves probes unavailable. The Linux session also conditionally attaches a separate CPUID hider around checker execution; that is not the rejected full DRAKVUF instrumentation path (`drakrun/evasion/linux_guest_runner.py:74`, `:184`). No helper was built or executed in this audit. `docs/chimera/linux-evasion.md:52`; `drakrun/evasion/verifiers/perdedor_linux.py:41`; `drakrun/evasion/verifiers/perdedor.py:341`.

## Do by 31 October: reliability and truthful demo results

Ordered by importance; stop optional work when the rehearsal passes. All live operations belong to the host operator.

| Priority / owner | Work and estimated effort | Risk | Acceptance measurement |
|---|---|---|---|
| P0 / operator, 0.5 day | Freeze known-good deployment, H3 image/profile/config and patched binary identities; retain rollback and verify backup hashes. Reconcile boot/service state from current host, because historical service notes conflict. | Low if no guest changes | Same-boot containment C1–C8 and negative/fail-closed checks; localhost listeners; INetSim required; deployment root-owned. Save private evidence. Basis: `docs/chimera/threat-model.md:62`, `:89`, `:104`; `docs/chimera/containment-results-2026-10-19.md:68`; `docs/chimera/vm-freeze-root-cause.md:109`. |
| P0 / backend + operator, 0.5–1 day | Enforce one host-wide dynamic slot covering Windows, Linux and both evasion queues, through teardown. Until implemented, schedule these lanes exclusively in the rehearsal. Keep existing per-VM locks and memory admission. | Medium: lock lifetime/crash recovery | Submit competing benign jobs across lanes: no overlapping dynamic intervals; killing holder releases slot; restore failure still cleans up. Existing restore-only admission: `drakrun/analyzer/run_tools.py:251`; `drakrun/lib/memory_admission.py:37`. |
| P0 / backend + UI, 0.5–1 day | Make incomplete telemetry, failed postprocessors, missing static result and stub model visible in demo outputs. Avoid interpreting RQ `finished` as valid evidence. | Low–medium: report compatibility | Offline fixtures for failed/missing stages; operator rehearsal checks metadata, features and verdict agree. Existing producer order/outcomes: `drakrun/analyzer/postprocessing/plugins/__init__.py:103`; `drakrun/analyzer/postprocessing/postprocess.py:44`; `drakrun/analyzer/classifier/runner.py:93`. |
| P1 / operator, 0.5 day | Rehearse selected benign controls serially with correct clock, full intended plugins and explicit Windows instrumentation. Preserve per-check frequency and timing, not just score. | Low; host load | Five repeats of the chosen evasion configuration and a short combined-analysis rehearsal; report duration, stalls, attach status, per-plugin coverage and residual detections. Compare the clock-synced baseline, not only H3b. `docs/chimera/hardening-design.md:35`, `:189`. |
| P1 / backend, 0.5–1 day | Pin expected PERDEDOR check IDs to tool version/profile/platform; fail incomplete on omissions or unexpected inventory. Verify Windows truncation handling and native HTML escaping using hostile text fixtures. | Medium: custom-profile compatibility | Deleted check, forged summary, duplicate ID, nonfinite score, truncated output and nonzero exit must never yield a pass. Current validation: `drakrun/evasion/verifiers/perdedor.py:394`; remaining native HTML concern: `docs/chimera/threat-model.md:75`. |
| P2 / documentation + operator, 0.25 day | Reconcile stale Linux helper and threat-model status; document the known residuals and preflight procedure. Do not rebuild firmware to chase one score. | Low | Rehearsal can be repeated from recorded config; inventory, applicability and monitor state accompany scores. `docs/chimera/linux-evasion.md:78`; `drakrun/evasion/scoring.py:158`. |

Do not spend the final days changing the hypervisor, guest firmware, WMI providers or injection architecture solely for stealth. Those need regression campaigns beyond the rehearsal budget.

## Future VMI / DRAKVUF work

These are proposals. Effort is person-time excluding unavailable host access; each needs an isolated rollback-capable branch and benign controls.

| Priority | Improvement / effort | Risk | How to measure before adoption |
|---|---|---|---|
| F1 | Rebase the local stale-list repair onto an upstream version containing it; 1–3 days | Medium: plugin/profile compatibility | Full-hook WMI/registry workload, >=25 repetitions, no stale-list error, no unexpected shadow breakpoint and no telemetry loss. [V] [PR #1886](https://github.com/tklengyel/drakvuf/pull/1886) merged 24 October; [issue #1885](https://github.com/tklengyel/drakvuf/issues/1885) records the failure. Local evidence: `docs/chimera/upstream/drakvuf-refresh-shadow-copy-uaf.md:28`. |
| F1 | Evaluate injector completion repair; 1–2 days | Medium: process launch regressions | Stress benign createproc launches; measure completion latency, timeouts and correct PID attribution. [V] [DRAKVUF PR #1874](https://github.com/tklengyel/drakvuf/pull/1874) changes completion detection to avoid waiting indefinitely for a hijack breakpoint to recur. Local build predates it: `docs/chimera/vm-freeze-root-cause.md:185`. |
| F2 | Evaluate kernel-CR3 attach repair when applicable; 1–2 days | Medium: attach compatibility | KVA-shadowing control with vCPU0 in user mode; attach latency and success, with/without fix. [V] [LibVMI PR #1123](https://github.com/libvmi/libvmi/pull/1123) addresses slow fallback scanning during Windows initialization. Not proven to affect this host: `docs/chimera/vm-freeze-root-cause.md:87`. |
| F2 | Diagnose silent Linux `unixsocketmon` / `ebpfmon`; 2–5 days | Medium: kernel/profile coupling | Debug build; confirm hook resolution and entry callbacks; named Unix socket and permitted benign BPF workload; compare raw VMI events with syscall-derived report and guest ground truth. Silence must remain “unverified,” not “no activity.” Existing gap: `docs/chimera/linux-sandbox.md:198`. |
| F3 | CPUID exit timing study; 1–3 weeks | High: time coherence, correctness and monitor detectability | Paired monitor-off/on, `-s` off/on runs; record cycle distributions, load, CPU placement, false positives on physical controls and event throughput. No fixed-cycle subtraction or TSC manipulation without monotonicity/multicore tests. Existing residual: `docs/chimera/hardening-design.md:38`, `:74`. |
| F3 | WMI thermal/fan/sensor fidelity; 1–3 weeks | High: new device/provider surface and inconsistent identity | First map the 13 exact queries and separate empty classes from suspicious values. Prototype coherent ACPI/WMI exposure; compare raw query responses and independent checks, boot reliability, power management and telemetry. No demonstrated fix yet: `docs/chimera/hardening-design.md:95`. |
| F3 | ACPI/SMBIOS structural investigation; 3–7 days diagnosis, implementation unknown | High if table layout changes | Capture probe inputs; separate string matching, WAET presence and count thresholds with one change per arm. Validate firmware checksums, guest boot, interrupt/power behavior and VMI profiles. Counts are hypotheses: `docs/chimera/hardening-design.md:152`. |
| F3 | Parent-process realism from launch method; 3–7 days | Medium–high: ancestry, DLL search and job inheritance | Compare intended desktop launch against current injection; preserve true parent and sample PID in evidence. Verify no inherited job/DLL-directory state and same descendant telemetry. Earlier shell restart mistakes caused new detections: `docs/chimera/hardening-design.md:140`. |
| F2 | Maintain Xen fix separately and seek upstream review; 2–5 days preparation | High if invalidation rules regress | Stress altp2m trap churn with disk I/O; also test genuine host-p2m changes in a dedicated lab. Measure invalidations, disk integrity, stalls and cleanup. [V] [sandbox issue #1222](https://github.com/CERT-Polska/drakvuf-sandbox/issues/1222) reports a similar inactivity symptom; that does not establish the same root cause. Local diagnosis: `docs/chimera/vm-freeze-root-cause.md:46`. |

The human-interaction paper linked by `docs/chimera/hardening-design.md:204` could not be read through the public-page reader during this audit; no new paper-backed claim is made here. There is no verified upstream fix identified here for the timing, WMI, firmware-count or Linux plugin gaps.

## PERDEDOR improvements

[V] [al-khaser’s primary repository](https://github.com/ayoubfaouzi/al-khaser) describes Windows anti-analysis checks spanning debugging, virtualization and sandbox detection. Its breadth is corroboration, not a numerical conversion into PERDEDOR’s score. The checkout adapter also warns that selected `CODE_INJECTIONS` produces no machine-readable verdict in its pinned version (`drakrun/evasion/verifiers/alkhaser.py:1797`).

| When / effort | Improvement | Risk and acceptance |
|---|---|---|
| By deadline / included in P1 | Publish score numerator, denominator, severity weights, applicable/errored/skipped counts, tool version/profile and monitor state. | Low. Recompute displayed score from normalized findings. Existing formula excludes skips/errors and requires at least half of returned checks applicable; it cannot detect an omitted inventory by itself. `drakrun/evasion/scoring.py:62`, `:164`. |
| Future / 2–4 days inventory, 1–3 weeks probes | Build a versioned coverage matrix against the local al-khaser specifications: CPUID timing, WMI devices, raw firmware structure, parent/job/module artifacts and anti-debug checks. Distinguish equivalents, partial overlap and absent probes. | Medium: duplicate correlated checks can distort score. Require independent control tests and evidence for each new probe. Zero PERDEDOR detections versus 20 al-khaser detections motivates this work; it is not a verified count of 20 missing PERDEDOR checks. `docs/chimera/hardening-design.md:175`; `drakrun/evasion/verifiers/alkhaser.py:334`, `:753`. |
| Future / 3–7 days | Version and hash Linux zipapp/helper build inputs; record helper build availability and individual skip reasons. Test as the same desktop user and work directory as samples. | Medium: privilege-dependent probes and compiler availability. Four native probes must be explicitly unavailable on build failure; compare root/nonroot controls without using root-only visibility as the default score. `drakrun/evasion/verifiers/perdedor_linux.py:41`; `drakrun/evasion/verifiers/perdedor.py:312`, `:341`. |
| Future / 1–2 weeks | Add Linux instrumented scan support with the same phased transfer/attach/execute/collect discipline as Windows. | Medium–high: monitor lifecycle and injection interference. Paired no-monitor/monitor runs; prove attachment spans checker execution; attach failure must invalidate results. Current rejection: `drakrun/evasion/worker.py:292`; Windows failure handling: `:434`. |
| Future / 1–2 weeks | Calibrate heuristic severities and false positives using physical and virtual controls, preserving ambiguous interpretations for modules, serial consoles and ptrace failures. | Medium: overclaiming generalization. Publish per-check rates and coverage, not a probability of being undetectable or cross-OS ranking. `docs/chimera/linux-evasion.md:101`, `:163`. |

## What must never be done

- Never weaken INetSim redirection, guard ordering, IPv6 drops, anti-spoofing, guest-to-host blocking or namespace isolation to make connectivity look real. Fake-network detection is accepted; third-party exposure is not. `docs/chimera/threat-model.md:62`; `docs/chimera/containment-results-2026-10-19.md:43`.
- Never disable watchdogs, remove useful hooks or relabel incomplete/failed/skipped checks as clean to improve scores. Preserve raw artifacts and monitor state. `docs/chimera/threat-model.md:81`; `drakrun/evasion/scoring.py:150`; `drakrun/evasion/worker.py:434`.
- Never restore the retired general QEMU no-drain workaround as a routine stealth fix: genuine page reuse has unresolved safety implications. `docs/chimera/vm-freeze-root-cause.md:93`.
- Never treat a checker running inside a hostile guest as authoritative attestation. A syntactically valid inventory can still be forged by a compromised guest; retain host provenance and acknowledge that limit. `docs/chimera/threat-model.md:6`, `:75`.
- Never execute samples on dom0, relax static-container controls, expose management ports, run privileged workers from the editable checkout or commit private evidence. `docs/chimera/threat-model.md:89`, `:94`, `:120`.

## Verification still required on the host

No services, domains, samples or root-only evidence were accessed. The operator must verify the deployed commit/config, patched Xen/DRAKVUF identities, active guest snapshot/profile, loopback bindings, containment tests on the current boot, Windows clock/task baseline, Linux helper availability, per-plugin coverage and cross-lane exclusion. These are acceptance checks to run later, not results of this audit.
