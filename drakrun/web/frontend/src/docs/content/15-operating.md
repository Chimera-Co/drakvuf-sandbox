---
title: Operating the platform
group: Operating
---
# Operating the platform

## Submitting a sample

Open **Upload sample** in the sidebar (or `POST /api/upload`).

| Option | Meaning |
|---|---|
| Platform | Windows 10, Linux (Debian 12 desktop), Android APK or iOS IPA. Mobile apps are static-only |
| Mode | **Combined** (static and dynamic, then a fused verdict), **Dynamic only**, **Static only** |
| Analysis time | How long the sample runs: 5 minutes to 24 hours, or a custom length, up to `[analysis_time] max_timeout_s`. A run is refused if the disk lacks room for it |
| Shorten long sleeps | Experimental, Windows only, off by default: `delaymon` cuts the sample's own sleeps over 10 s down to 1 s. A sample can notice this |
| Start method | `createproc`, `shellexec` or `runas` (run elevated), or the default |
| Archives | Extract an archive in the guest, optionally a single entry and with a password |
| Plugins, preset | Override the DRAKVUF plugin list, or pick a `[preset.*]` from the configuration |
| No internet, no screenshots | Run with the guest network off, or without screenshots |
| Online intel | Allow online lookups of this analysis' indicators (see [threat intel](concepts-intel.md)) |

Long runs are for samples that wait before acting, such as loaders that hold back their fallback servers. A
one-hour run keeps about 3 GB on disk (more for busy samples) and takes about 15 minutes to post-process, and
capa skips its dynamic logs once they exceed `[capa] max_dynamic_log_mb`, so its report has no capa TTPs.
Sleep shortening only helps against samples that wait with long `Sleep` calls; many wait with short sleeps or
other work instead.

The analysis appears in **Analyses** at once. While it runs, its page shows the pipeline status and, for
dynamic runs, a live VNC view of the guest.

## Reading a report

The verdict card at the top shows the fused label and score, the parts that voted (dynamic, static) with their
reasons, and the family when the model is confident. The threat-intel card sits next to it. Below, the report
tabs:

| Tab | Contents |
|---|---|
| Summary report | Key facts, what the sample did, indicators, the MITRE ATT&CK matrix, and the limits of this run |
| Static analysis | File identity, hashes, findings and indicators, imports, sections, strings, IOCs, capa capabilities, FLOSS strings; MobSF for mobile apps |
| Decompiled code | Ghidra pseudo-code and disassembly (PE, ELF) or JADX sources (APK) |
| Process info | The process tree; per process its command line, API calls and per-plugin logs |
| General logs | Every DRAKVUF plugin log, filterable |
| Memory dumps | The memory-dump scan: what each dump contained |
| Screenshots | Guest screenshots taken when the screen changed |
| Analysis files | PCAP, TLS keys, dumps, the HTML report and other artefacts to download |

The self-contained HTML report (`report.html`) works offline and can be shared without the console.

> Downloads are live malware: PCAPs, dumps and dropped files. Open them only in an analysis VM, never as root on
> dom0 or on a personal machine.

## Verification scans

**Sandbox Evasion** starts a scan of a sandbox with PERDEDOR and the other suites; **Verification Runs** lists
past scans with their CHIMERA score and its trend. See [Evasion verification](verification.md).

## Changing a golden image

```bash
drakrun modify-vm0 begin                 # Windows; add --guest-os linux for Linux
# make changes through VNC
drakrun modify-vm0 commit                # or rollback
systemctl restart 'drakrun-worker@*'     # workers pick up the new snapshot and profiles
```

Stop the workers first so no analysis restores the snapshot while it is being replaced. On Windows, check
Explorer's state and Defender before committing (see [guest images](build-guests.md)).

## Services and logs

| What | Command |
|---|---|
| Overall state | `systemctl status 'drakrun-*' 'chimera-*'` |
| A worker's log | `journalctl -u drakrun-worker@1 -f` |
| One analysis | `/var/lib/drakrun/analyses/<id>/drakrun.log`, `drakvuf_stderr.log` |
| Running guests | `xl list` |
| Xen and QEMU logs | `/var/log/xen/` |
| Containment | `chimera-net-check --require-inetsim` |
| INetSim | `/var/log/chimera-inetsim/` |
| Queues | `/rq` (RQ dashboard) in the console's sidebar |
| API | `/openapi/swagger` |

## Troubleshooting

| Symptom | Look at |
|---|---|
| A worker does not start | `chimera-net-check --require-inetsim`: containment must be up, INetSim running, and no foreign FORWARD rule above `CHIMERA_GUARD` (a container build on a bridge network adds one) |
| Analysis waits for a long time | Memory admission: `xl info` free memory; the static VM or another guest may be holding it |
| Guest does not start | `/var/log/xen/*vm-N*.log`; out-of-memory messages mean a smaller guest or fewer slots |
| Run ended as stalled | The stall monitor stopped a guest that made no progress; see `drakrun.log` |
| No static result in the verdict | The static VM did not answer within `[static] wait_s`; check `drakrun-static-worker` and `xl list` |
| Verdict "unknown" | The model failed or timed out; the error is in `classification.json` |
| No online intel | Online intel not ticked, provider key missing (`drakrun intel providers`), or the host offline |
| Guest has a stale IP | A restored guest keeps its snapshot IP until DHCP renews; the worker renews it after restore |

## Safety rules

- Guests never get a route to the LAN or the internet. Never disable `chimera-net` to "fix" a run.
- Keep the API and VNC on loopback; use SSH tunnels.
- Never put real credentials, personal files or keys into a golden image.
- Treat every artefact as hostile, including JSON produced from guest output.
