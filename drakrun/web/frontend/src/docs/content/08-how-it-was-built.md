---
title: How it was built
group: Architecture
---
# How it was built

## Starting point

CHIMERA is a fork of **DRAKVUF Sandbox** (drakrun, by CERT Polska), which already provided the Windows
detonation pipeline: the `drakrun` CLI to install and snapshot a Windows guest, an RQ worker that restores the
guest and runs DRAKVUF, postprocessing into per-plugin logs and a process tree, and a React web interface. The
engine underneath is **DRAKVUF** (Tamas K Lengyel) on **LibVMI** and **Xen**.

Upstream supports Windows guests only, has no static analysis, no classifier, no threat intel and no network
containment beyond optional NAT. CHIMERA keeps its structure (the `drakrun` package, RQ queues, the
postprocessing plugin chain) and adds to it.

## What the project added

| Area | Added |
|---|---|
| Guests | A Linux pipeline: a Debian 12 desktop image built from the official cloud image, kernel profiles with dwarf2json, a serial helper, Linux DRAKVUF plugins and Linux behaviour postprocessing |
| Reliability | Per-VM locks, stale-domain reclamation, memory admission before restore, a stall monitor, guaranteed teardown, telemetry of every run |
| Containment | INetSim in its own network namespace and a fail-closed firewall, verified by a test matrix |
| Hardening | Firmware and device identity changes, CPUID hiding and human-input simulation, experiment arms to measure each step |
| Verification | PERDEDOR, and evasion workers that run PERDEDOR, al-khaser, Pafish and other suites in a guest, with or without DRAKVUF attached |
| Static analysis | `chimera_static`, the deep pass with capa, FLOSS and Ghidra, MobSF for mobile apps, memory-dump scanning, and the network-less static VM |
| Classifier | The feature extractor, the model interface, dynamic and static models, fusion and calibration |
| Threat intel | Offline feed bundles, Maltrail attribution, online lookups including VirusTotal |
| Console | A redesigned interface: verdict and static workspaces, decompiled code, memory dumps, ATT&CK matrix, threat-intel card, verification pages, colour themes, this Home page and these docs |

## How the work was done

**Measure first.** Each change started from a measurement of the current behaviour and ended with one of the new
behaviour, and the evidence was kept. The design notes in `docs/chimera/` record these: benign reliability
series, containment results (tests C-1 to C13, each with captures and counters), hardening arms with per-check
detection frequencies, and the malware evaluation protocol.

**Fix the platform before measuring on it.** Early benign runs froze the guest after 30–45 seconds. The cause was
traced to Xen: removing a DRAKVUF trap made Xen ask QEMU to invalidate its map cache even for altp2m views, and
QEMU deadlocked while doing so. A small Xen patch (`scripts/chimera/patches/`) fixed it. A use-after-free in
DRAKVUF's shadow-page handling, which ended some runs with a "re-copying remapped gfn" error, was fixed and
submitted upstream. A race in the injector's file read and the snapshot's stale DHCP lease were fixed in the
worker. Only then were the hardening and malware experiments run.

**Reversible steps.** Hardening arms are switchable snapshots (`chimera-arm use <ARM>`), configuration changes
keep backups, and new features are off by default in `config.toml` until enabled (`[static] enabled`,
`[classifier] enabled`, `[intel] enabled`).

**Isolation by default.** Guests never get the internet; parsers run in a VM without a network device; intel
lookups run on the host after the guest is gone and never upload samples; the API listens on loopback only.

## Testing

| Suite | Where | Runs with |
|---|---|---|
| Python unit tests | `test/unit/` | `pytest` |
| Static analyzer | `static_analyzer/tests/` | `pytest` in the analyzer's venv |
| Classifier | `classifier/tests/` | `pytest` in the training venv |
| PERDEDOR | `perdedor/tests/` | `pytest` |
| Console | `drakrun/web/frontend/src/**/*.test.jsx` | `npm test` (vitest) |
| On the host | `scripts/chimera/containment/`, `scripts/chimera/bench/` | Containment tests, hostile-guest tests, benign series, malware evaluation |

## The team

Mantek Singh Burn, Anusha Tiwari and Shreyas Tekawade. The engine credits belong to the DRAKVUF, LibVMI and Xen
projects and to CERT Polska's DRAKVUF Sandbox; their licences are kept in `LICENSE` and `COPYING`.
