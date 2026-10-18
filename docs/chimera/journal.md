# CHIMERA Development Journal (final sprint)

Concise, dated log of what was done, why, and where the evidence is. Newest last.
Evidence paths under `/var/lib/chimera-evidence/` are on the CHIMERA host (root-only).

## 2026-10-19

| Time (IST) | What | Evidence / commit |
|---|---|---|
| 01:57 | Fan control restored: `acer-fan-control.service` crash-looped after kernel 6.1.0-54; out-of-tree module rebuilt | journal of the service; memory note |
| 02:00–02:20 | Phase-1 recon (read-only) + Codex independent audit | `RECON-2026-10-19.md` (workspace root) |
| 02:21 | Dev tree backed up; CRLF-only noise normalised; ~3.7k uncommitted lines committed on `sprint/final` | backup `~/Documents/chimera-backups/…pre-normalise.tar.gz` (sha256 file alongside); `07e16c4` |
| 02:30 | Threat model, containment proposal (v1 → v2 after Codex adversarial review), ecosystem/market study | `f5f279b` |
| 02:45–03:08 | Containment applied: INetSim in netns, fail-closed guest firewall, VNC on localhost, dnsmasq off; tests C-1…C13 PASS | `containment-2026-10-19/`, `containment-results-2026-10-19.md`, `f74b639` |
| 03:12 | Baseline B1: benign BGInfo analysis under containment, rc 0, 8/9 plugins | `baseline-2026-10-19/B1` |
| 03:13 | **Root cause of historical "Failed to restore VM vm-1"** reproduced: stuck qemu device model keeps VNC port → next restore fails | `baseline-2026-10-19/R6-*` |
| 03:14–03:20 | Fixes: device-model reaping, restore inside cleanup, per-VM flock, drakshell connect timeout; telemetry completeness in metadata | `21fdc32`, `846754f` |
| 03:20 | Codex: evasion status consistency, guest-output caps, PERDEDOR report integrity, coverage guard (reviewed; exit-code semantics verified against a real run) | `bec004b` |
| 03:21–03:25 | Root-owned deployment `/opt/chimera/{src,venv}`; systemd units for web (127.0.0.1) and worker (requires containment check) | `4c39210`, `4944a32` |
| 03:26–03:52 | Benign reliability series: **10/10 finished**, submit→done 153.0 ± 4.0 s, 0 leftover domains/qemu, 0 egress drops | `benign-series-2026-10-19/`, `benign-series-2026-10-19.md` |
| 03:30 | al-khaser root cause: binary needs VC++ 2015–2022 runtime missing in guest → all checks "errored" | `/var/lib/drakrun/evasion/e1a35994…/raw/alkhaser/stdout.txt` |
| 03:35 | M4 design + H1 profile + arm switching; DRAKVUF `cpuidmon -s` verified from source to hide CPUID hypervisor bit + Xen leaves | `hardening-design.md`, `a70b8d9` |
| 03:50 | Codex task 04 (DRAKVUF-attached verification) **rejected at review**: injector file transfers inside the DRAKVUF window conflict (one VMI monitor per domain); redesign as stage/execute/collect phases sent back | scratchpad brief 05 |
| 03:53–03:55 | A0 golden image hashed (`A0-SHA256SUMS`), live files migrated into arm A0 (symlinks), cloned to H1, H1 hardware profile applied (4 vCPU / 5 GiB) | `arms-2026-10-19/` |
| 03:55–04:25 | H1 cold boot: qemu-xen accepted SMBIOS/MAC/disk-model/no-platform-PCI config; Windows serviced + rebooted, then **stopped at a password login** — build needs the owner to log in once. Rolled back cleanly; A0 hashes re-verified OK; worker back on A0 (smoke analysis finished, rc 0) | `arms-2026-10-19/H1-coldboot-*.png`, `A0-smoke/` |
| 04:30 | Codex phase-split redesign merged: DRAKVUF attached only during execute (drakshell), injector transfers guarded; 269 tests | `63d9bae` |
| 04:29–04:31 | E1: PERDEDOR on A0 without DRAKVUF → **89.48 "warn", identical to the 18 Sep run** (20 clean / 9 detected / 1 skipped): reproducible | `evasion-2026-10-19/E1-*`, scan `25f70692` |
| 04:30–04:45 | E2: PERDEDOR **with DRAKVUF attached** (default plugins) → DRAKVUF failed 3/3 (2× "Critical error in re-copying remapped gfn", 1× hang with `VMI_ERROR: xen_request_page_fault`); scans correctly marked incomplete; hang recovered (SIGKILL DRAKVUF, destroy, reap qemu) | `evasion-2026-10-19/E2-*` |
| 04:48–05:00 | Ablation: kernel-level plugins only → 3/3 clean, attached whole run, **score 89.48 = unchanged under instrumentation**; kernel + `apimon` → 3/3 failures. **Trigger: apimon (user-mode hooks)** under PERDEDOR's registry/WMI load. Upstream DRAKVUF has libusermode/libhook fixes after our build (#1879/#1880/#1882); Xen 4.19.2 vs DRAKVUF's 4.20.1 pin is a known compatibility risk (drakvuf #800) | `evasion-2026-10-19/ablation-*.txt` |
| 05:00–05:05 | Telemetry verdict: early exit + stderr errors + `complete`; fault injection F0 normal → complete; F1 SIGKILL DRAKVUF at 40 s → complete=false, rc −9, exited_early, no leftovers | `ba3391b`, `fault-injection-2026-10-19/` |

## Decisions
- **Downloads and real malware stay operator-initiated** (VC++ redistributable, app installers for guest realism, malware samples).
- **No host reboot** in autonomous work: the laptop boots Windows by default and needs a manual path into Xen.
- **Guest login is the owner's step**: the golden image has a password-protected account and no auto-logon; Claude never types guest credentials.
- **H1 identity mirrors the host laptop model** (consistent with the real CPU exposed by `cpuid=host`); serials are synthetic.
