---
title: Architecture
group: Architecture
---
# Architecture

CHIMERA is one Xen host. Everything except the guests runs in dom0: the web API, Redis, the workers, DRAKVUF,
the containment firewall and INetSim. The guests (Windows, Linux and the static-analysis VM) are separate Xen
domains.

```diagram architecture
```

## Components

| Component | Runs as | Role |
|---|---|---|
| Console | Browser | This React app, served by the web API |
| Web API | `drakrun-web.service` (gunicorn, `127.0.0.1:5000`) | Uploads, status, results, OpenAPI at `/openapi/swagger`, RQ dashboard at `/rq` |
| Redis + RQ | `redis-server.service` | Job queues and their registries |
| Analysis workers | `drakrun-worker@N.service`, one per VM slot | Restore `vm-N`, start the sample, run DRAKVUF, postprocess |
| Static workers | `drakrun-static-worker.service`, `drakrun-static-deep-worker.service` | Fast pass; capa, FLOSS, Ghidra, memory-dump scans, MobSF |
| Static VM | `chimera-static-vm.service` / on demand | Network-less Xen guest that runs the static analyzers |
| Intel worker | `drakrun-intel-worker.service` | Offline matching, Maltrail attribution, online lookups |
| Evasion workers | `drakrun-evasion-worker@N.service` | Verification scans with PERDEDOR, al-khaser, Pafish and others |
| Containment | `chimera-net.service`, `chimera-inetsim.service` | Fail-closed guest firewall and INetSim in netns `chimera-inet` |
| Timers | `chimera-intel-update.timer`, `chimera-trails-sync.timer`, `chimera-static-vm-idle.timer` | Daily feed refresh, trail sync every 6 h, static VM idle shutdown |

The unit files are in `scripts/chimera/systemd/`, `scripts/chimera/containment/`, `scripts/chimera/intel/` and
`scripts/chimera/static-vm/`. Every analysis and evasion worker refuses to start unless
`chimera-net-check --require-inetsim` passes.

## Queues

| Queue | Work | Consumer |
|---|---|---|
| `drakrun-analysis` | Windows detonations | Analysis worker bound to `windows` or `any` |
| `drakrun-analysis-linux` | Linux detonations | Analysis worker bound to `linux` or `any` |
| `chimera-static` | Fast static pass | Static worker |
| `chimera-static-only` | Static-only analyses (no detonation), listed with the others | Static worker |
| `chimera-static-deep` | capa, FLOSS, Ghidra, memory dumps, MobSF | Deep static worker |
| `chimera-intel` | Online lookups | Intel worker |
| `drakrun-evasion`, `drakrun-evasion-linux` | Verification scans | Evasion workers |

Workers are bound to guest types with `[worker] vm_guest_os`, for example `{1 = "windows", 2 = "linux"}` for one
Windows and one Linux slot. A bound worker refuses a job of the other OS.

## One analysis, end to end

1. **Upload.** `POST /api/upload` stores the sample as `uploads/<id>.sample` with mode `0400`, stages a copy for
   the static job and enqueues the static job and the OS-specific dynamic job under the same analysis ID.
2. **Static.** The static worker runs the fast pass in the static VM and publishes
   `static/<id>/static.json` atomically; the deep pass follows on its own queue.
3. **Detonation.** The analysis worker takes a per-VM lock, waits for memory admission, restores `vm-N` from the
   snapshot, prepares the guest (network renewal, clock sync), uploads and starts the sample with the injector,
   and runs DRAKVUF with the configured plugins for the analysis timeout while `tcpdump` records the guest
   bridge. A stall monitor ends runs whose guest stops making progress.
4. **Teardown.** DRAKVUF is stopped and the guest destroyed, whatever happened.
5. **Postprocessing** (`drakrun/analyzer/postprocessing/plugins/__init__.py`), in order: split DRAKVUF's output
   into per-plugin logs, export TLS keys, build the process tree, capa (ATT&CK), screenshots, memory dumps,
   HTTP/file/socket/TTP/TLS summaries, `report.json`, features and classification (waiting at most
   `[static] wait_s` for the static result), the HTML report, the CHIMERA report, the log index and statistics,
   then queue the memory-dump scan and the online intel lookup.
6. **Intel.** The intel worker matches the indicators and, if enabled, runs online lookups.
7. **Report.** The console reads everything through the API.

## Storage

| Path | Contents |
|---|---|
| `/var/lib/drakrun/analyses/<id>/` | `metadata.json`, per-plugin logs, `process_tree.json`, `report.json`, `features.json`, `classification.json`, `report.html`, `dump.pcap`, TLS keys, `dumps.zip`, `ttps.json`, screenshots |
| `/var/lib/drakrun/static/<id>/` | `static.json`, `deep.json`, `memdumps.json`, `mobsf.json` |
| `/var/lib/drakrun/evasion/<scan_id>/` | Verification scan results and raw tool output |
| `/var/lib/drakrun/volumes/`, `/var/lib/drakrun/linux/golden/` | Windows and Linux golden disks and snapshots |
| `/var/lib/drakrun/profiles/` | VMI profiles |
| `/var/lib/drakrun/intel/` | Intel database, Maltrail index, online cache |
| `/etc/drakrun/` | `config.toml`, guest configuration templates, install information, classifier model |

## Trust boundaries

Everything that comes out of a guest is treated as hostile, including well-formed JSON.

- **Hypervisor (guest → host).** The main boundary. Guests are unprivileged HVM domains; the device model runs in
  dom0, so a QEMU escape is the most serious risk.
- **Network (guest → world).** Guests reach only INetSim; the firewall fails closed even if drakrun's own network
  settings are wrong. See [network containment](build-network.md).
- **Parsers (sample → host).** Static parsers run in the network-less static VM; dynamic postprocessors parse
  guest output in dom0 and are written defensively.
- **API (browser → host).** The API and VNC listen on loopback only and have no application login; access to the
  host is the access control.
- **Artefacts (report → analyst).** PCAPs, dumps and dropped files are malware. Do not open them as root on dom0.

The full threat model, with each threat's controls and gaps, is `docs/chimera/threat-model.md` in the repository.
