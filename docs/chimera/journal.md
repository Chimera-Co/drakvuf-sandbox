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
| 03:50 | Codex task 04 (DRAKVUF-attached verification) **rejected at review**: injector file transfers inside the DRAKVUF window conflict (one VMI monitor per domain); redesign as stage/execute/collect phases sent back | scratchpad brief 05 |
| 03:35 | M4 design + H1 profile + arm switching; DRAKVUF `cpuidmon -s` verified from source to hide CPUID hypervisor bit + Xen leaves | `hardening-design.md`, `a70b8d9` |

## Decisions
- **Downloads and real malware stay operator-initiated** (VC++ redistributable, app installers for guest realism, malware samples).
- **No host reboot** in autonomous work: the laptop boots Windows by default and needs a manual path into Xen.
- **H1 identity mirrors the host laptop model** (consistent with the real CPU exposed by `cpuid=host`); serials are synthetic.
