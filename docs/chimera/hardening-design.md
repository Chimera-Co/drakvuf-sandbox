# Xen Guest Hardening — Design and Experiment Plan (M4)

**Date:** 2026-10-19, updated 2026-10-20 · **Status:** live arm H3 since 2026-10-20 02:08 (H2 host firmware IDs + everyday applications; validated 17/17; PERDEDOR score 100.0, al-khaser 20 detections per scan, §7). `cpuidmon -s` and `hidsim` in production since 2026-10-19 21:59 (§6) · **Depends on:** containment (done), lifecycle fixes (done), guest-freeze and DRAKVUF UAF fixes (done, `vm-freeze-root-cause.md`)

## 1. Problem (measured, not assumed)

PERDEDOR run `621b62cc` (18 Sep 2026, current Xen guest) detected:

| Check | Evidence | Root cause | Fix class |
|---|---|---|---|
| `win.env.smbios_vendor` | `Manufacturer=Xen Model=HVM domU BIOS=Xen` | hvmloader SMBIOS defaults (`tools/firmware/hvmloader/smbios.c:420,473,477`) | **config** `smbios=[…]` (xl.cfg 4.19.2 §smbios) |
| `win.env.pnp_virtual_devices` | `PCI\VEN_5853…` (Xen platform), `HDAUDIO…VEN_1AF4` | Xen platform PCI device; QEMU HDA codec | **config** `xen_platform_pci=0`; drop `soundhw` |
| `win.env.registry_artifacts` | `HKLM\HARDWARE\ACPI\DSDT\Xen` | ACPI OEM ID `"Xen"` (`tools/libacpi/acpi2_0.h:34`, `dsdt.asl:8`) | **source patch** of hvmloader/libacpi |
| `win.env.low_core_count` | 2 logical CPUs (threshold ≤ 2) | install.json `vcpus=2` | **config** 4 vCPUs |
| `win.env.low_ram` | 4 GiB (threshold ≤ 4) | install.json `memory=4096` | **config** > 4 GiB (dom0 balloon if needed) |
| `win.design.mac_oui` | `00:16:3E` | Xen default OUI | **config** `vif … mac=<real vendor OUI>` |
| `win.behavioural.aged_files` | 1 file older than 7 days (need ≥ 5) | fresh image | **guest realism** in modify-vm0 session |
| `win.behavioural.installed_programs` | 8 (need ≥ 20) | fresh image | **guest realism** |
| `win.behavioural.mouse_movement` | cursor static | no user | **runtime** DRAKVUF `hidsim` (Gruber & Freiling 2022) |
| *(not yet measured)* CPUID hypervisor bit + `XenVMMXenVMM` leaves | `cpuid="host,htt=0"` doesn't hide them | Xen | **runtime** DRAKVUF `cpuidmon -s` (`src/plugins/cpuidmon/cpuidmon.cpp:139-153` zeroes leaf-1 ECX[31] and leaves 0x40000000–0x40000004) |
| disk model `QEMU HARDDISK` | string in qemu-xen | qemu IDE default | **config** `device_model_args_hvm=["-global","ide-hd.model=…"]`: applied in H1, guest reports a WD model (`H1-identity-check-vm1.txt`) |

## 2. Experimental arms

```mermaid
flowchart LR
    A0["A0 baseline<br/>current snapshot<br/>(Xen defaults)"] --> H1
    H1["H1 hardened snapshot<br/>smbios, no Xen PCI, no HDA,<br/>4 vCPU / >4 GiB, real MAC OUI,<br/>disk model, guest realism,<br/>(+ hvmloader ACPI patch if built in time)"]
    H1 --> H1S["H1 + cpuidmon -s<br/>(runtime only)"]
    H1 --> H1H["H1 + hidsim<br/>(runtime only)"]
    H1S --> H1SH["H1 + -s + hidsim"]
    H1H --> H1SH
```

- Each arm runs **PERDEDOR, al-khaser and Pafish as samples through the normal analysis path, with the standard DRAKVUF plugin set active** (Codex finding: the existing evasion path never runs DRAKVUF, so its scores say nothing about stealth under instrumentation).
- n ≥ 5 runs per arm; report per-check detection frequency, not a single score.
- Telemetry check per arm: the hardened guest must still produce the same plugin coverage as A0 (BGInfo control sample).
- Timing checks are reported separately: `cpuidmon -s` traps every CPUID and may *worsen* RDTSC-around-CPUID detections. The experiment decides whether `-s` is kept.

## 3. Implementation sequence (each step reversible)

1. **Back up** `vm-0.img` (25.7 GiB), `snapshot.sav`, `/etc/drakrun/{install.json,cfg.template}`, `profiles/` → `/var/lib/chimera-backups/<date>/` with SHA-256s.
2. **cfg.template profile `H1`**: `smbios=[...]` with one *internally consistent* desktop identity (BIOS vendor/version/date, board, system, chassis, serials); `xen_platform_pci=0`; remove `audio`/`soundhw`; `mac=` with a real Intel OUI; `shadow_memory=128` (upstream #1222 VM-crash fix); `viridian` stays off (needed for `-s` coverage of the Xen leaves).
3. **install.json**: `vcpus=4`; `memory` > 4096 after checking free memory (balloon dom0 with `xl mem-set 0` if required; **never reboot**: the host boots Windows by default).
4. **New snapshot**: `drakrun modify-vm0 begin --cold-boot` → guest realism script via drakshell (≥ 20 installed programs from offline installers or portable apps registered normally, ≥ 5 user documents with realistic timestamps, browser profile) → wait > 10 min uptime → `drakrun modify-vm0 commit` → regenerate VMI profile.
5. **Runtime toggles** via `/etc/drakrun/config.toml`: `plugins += ["cpuidmon", "hidsim"]`, `extra_drakvuf_args = { "-s" = true, "--hid-random-clicks" = true }` per arm.
6. **Optional hvmloader patch** (ACPI OEM ID): build hvmloader only from `/opt/xen-4.19.2`, install alongside the original (keep a backup), new snapshot. Skip if time runs short; then the DSDT `Xen` OEM ID is a documented residual.

## 4. Known residuals (will be stated in the report)
- Xen CPUID leaves without `-s`; timing side channels (RDTSC/VM-exit cost); EPT/altp2m-specific detections; qemu-xen device set (e1000, stdvga) fingerprints beyond strings.
- **Teaching to the test:** PERDEDOR's thresholds are ours. Independent suites (al-khaser, Pafish, VMAware) are required to support any "harder to detect" claim.

## 6. Results: runtime arms on H1 (2026-10-19, 19:47–21:55)

- **Setup:** H1 snapshot, patched Xen + fixed DRAKVUF (`vm-freeze-root-cause.md`), DRAKVUF attached with the
  default plugin set, PERDEDOR then al-khaser (338 al-khaser verdicts) in one scan, 5 scans per arm.
  Arms differ only in `/etc/drakrun/config.toml` (backed up and restored by the run script).
- **Reliability:** 15/15 scans complete and attached for the whole run, 481–521 s each, no stalls.
- **Evidence:** `/var/lib/chimera-evidence/m4-2026-10-19/` (`summary.txt`, per-check `checks.jsonl`, `arms-config.txt`).

Checks that changed between arms (detected in N of 5 scans):

| Check | H1 | H1 + `cpuidmon -s` | H1 + `-s` + `hidsim` |
|---|---|---|---|
| al-khaser `cpuid_is_hypervisor` (leaf 1 bit 31) | 5 | **0** | **0** |
| al-khaser `cpuid_hypervisor_vendor` (leaf 0x40000000) | 5 | **0** | **0** |
| al-khaser `mouse_movement` | 5 | 5 | **0** |
| al-khaser `lack_user_input` | 5 | 5 | **0** |
| PERDEDOR `win.behavioural.mouse_movement` | 5 | 5 | **0** |
| al-khaser `rdtsc_diff_locky` (timing) | 1 | 0 | 0 |
| al-khaser `nt_yield_execution` | 1 | 0 | 1 |

- **Totals per scan:** al-khaser detections 26–27 → 24 → 22–23. PERDEDOR score 94.48 → 94.48 → 95.0.
- **Timing:** `-s` traps every CPUID (about 7.6k per scan) but added no timing detection. `rdtsc_diff_vmexit` is
  detected 5/5 in every arm (known residual, §4).
- **Telemetry:** the test tools' own events are the same in every arm (per scan: procmon ≈ 3,460, regmon ≈ 270.6k,
  apimon ≈ 256k, filetracer ≈ 62.1k). With `hidsim`, events from *other* processes drop by about half because
  Windows idle maintenance (`WinSAT`, `cleanmgr`, `TiWorker`, `wermgr`, `sdiagnhost`, `provtool`) no longer starts:
  the guest is not idle. That is less background noise, not lost sample telemetry.

**Decision (applied 21:59):** production `config.toml` now has `cpuidmon` and `hidsim` in `plugins` and
`extra_drakvuf_args = { "-s" = true }` (backup `config.toml.bak-pre-stealth-20261019`). Portal analysis
`95f9e10c` (BGInfo) complete, 120.8 s, all plugins produced. `drakrun-web` must be restarted after a plugin
change: it fixes each upload's plugin list from the config it loaded at start.

Still detected in every arm, by cause:

| Cause | Checks | Fix |
|---|---|---|
| ACPI OEM ID `Xen` from hvmloader (Windows shows it as `Win32_BIOS.Version = "Xen - 0"`) | PERDEDOR `smbios_vendor`, `registry_artifacts` (`HARDWARE\ACPI\DSDT\Xen`); al-khaser `firmware_acpi` | H2 (§7.1): both PERDEDOR checks **fixed**; `firmware_acpi` still detected |
| SMBIOS type 11 OEM string defaults to `Xen` (H1 sets no `oem=`) | likely al-khaser `number_smbios_tables` (raw SMBIOS scan) | H2 sets `oem=` (§7); still detected, so probably not the string (§7.1) |
| Enum entries of devices from earlier boots (Xen platform PCI, QEMU disk) | al-khaser `Enum\PCI\VEN_5853*`, `registry_disk_enum` | **fixed on H2** (`phantom-devices.ps1`, §7.1) |
| Few installed programs | PERDEDOR `installed_programs` (8, needs ≥ 20) | **fixed on H3** (§7.2, 32 programs) |
| QEMU strings in ACPI tables (source not yet located) | al-khaser `qemu_firmware_acpi` | still detected on H2 (§7.1) |
| No sensors/fans/thermal WMI classes in a VM | 13 al-khaser `*_wmi` checks | residual (would need emulated ACPI thermal devices) |
| Hyper-V objects present in the Windows image | al-khaser `hyperv_driver_objects`, `hyperv_global_objects` | residual (Windows component, not the hypervisor) |
| Sample launched by drakshell, not explorer | al-khaser `parent_is_explorer` | residual of the injection path |
| VM-exit cost | al-khaser `rdtsc_diff_vmexit` | residual (§4) |

## 7. H2: host firmware IDs (live 2026-10-20 00:19–02:08, now the rollback for H3)

What H2 adds to H1:

- `scripts/chimera/patches/xen-4.19.2-libacpi-host-oem-ids.patch`: ACPI OEM ID, table ID, revision and creator
  set to the host laptop's values (`ACRSYS`, `ACRPRDCT`, 2, `1025`/0x40000, read from `/sys/firmware/acpi/tables`).
- `scripts/chimera/arms/build-hvmloader-acpi.sh` built it as `/usr/local/lib/xen/boot/hvmloader-chimera-acpi`
  (sha256 `f2231d57…`); the stock `hvmloader` (`c77046bb…`) is unchanged. A throwaway diskless domain booted it:
  RSDP, RSDT, XSDT, FACP, DSDT, 6 SSDTs and WAET all carry `ACRSYS`/`ACRPRDCT`.
- `scripts/chimera/arms/H2/cfg.template`: H1 plus `firmware_override` (the patched hvmloader) and the host's
  SMBIOS type 11 strings. `xl -N create` parses it.
- `scripts/chimera/arms/H1/phantom-devices.ps1`: removes non-present Xen/QEMU devices; `identity.ps1` and
  `check_identity.py` now report `acpi_oem_version` and `phantom_vm_devices`.

Procedure (owner present for the Windows login):

1. `chimera-arm clone H1 H2`, copy `scripts/chimera/arms/H2/cfg.template` into `/var/lib/chimera-arms/H2/`,
   `chimera-arm use H2`.
2. `drakrun modify-vm0 begin --cold-boot`; the owner signs in.
3. `provision_guest.py H1/phantom-devices.ps1` (first with `-WhatIf`), then `H1/identity.ps1`, expecting
   `acpi_oem_version=ACRSYS - 2` and `phantom_vm_devices=0`.
4. `drakrun modify-vm0 commit`, `chimera-arm adopt`, `validate_arm.py` on vm-1.
5. `RUNS=5 scripts/chimera/bench/m4/arms.sh H1`: its `H1` arm runs the config as it is, which now includes `-s` and `hidsim`. Compare with the H1SH column above.
6. Rollback: `chimera-arm use H1` (H1 files are untouched).

### 7.1 Results (2026-10-19 22:15 – 2026-10-20 01:03)

Steps 1–3 went as planned (`acpi_oem_version=ACRSYS - 2`, `phantom_vm_devices=0`). Getting a clean snapshot took
three commits, because how explorer was started showed up in al-khaser (5 scans each, all complete and attached,
491–522 s; evidence `/var/lib/chimera-evidence/m4-h2{,b,c}-*`):

| Snapshot | explorer.exe started by | al-khaser / scan | PERDEDOR / scan | Detections not on H1SH |
|---|---|---|---|---|
| H1SH (§6) | logon | 22.2 | 3 | – |
| H2a, 22:50 | OneDrive, after it updated itself | 21 | 1 | `scan_modules_ldr_enumerate` 5/5 |
| H2b, 23:32 | a scheduled task | 21 | 1 | `process_in_job` 5/5 |
| **H2c, 00:19 (live)** | **winlogon** | **20** | **1** | none |

- **Cleared by H2 (5/5 → 0/5 in every H2 snapshot):** PERDEDOR `smbios_vendor` and `registry_artifacts`;
  al-khaser `Enum\PCI\VEN_5853` (`generic_bd4346103f8ecbf3`) and `registry_disk_enum`. PERDEDOR score 95.0 → 99.48.
- **H2a, injected libraries:** OneDrive restarted explorer as its own child and explorer inherited OneDrive's
  `SetDllDirectory`. drakshell runs inside explorer, so the samples it starts loaded `msvcp140`/`vcruntime140`
  from OneDrive's folder, and al-khaser reported them as injected.
- **H2b, job object:** explorer restarted from a scheduled task runs inside the Task Scheduler's job, which
  does not allow breakaway, so every sample also runs in a job.
- **H2c fix** (`H1/explorer-clean-restart.ps1`): a detached process force-stops explorer and activates
  explorer's COM class; winlogon then restarts the shell as at logon. `H1/explorer-state.ps1` checks the result:
  parent `winlogon.exe`, `child_in_job=False`, empty `child_dll_directory`. Run it before every commit.
- **Defender came back on after the cold boot.** `defender-off.ps1` used `New-Item -Force` on the existing
  policy key, which means "replace the key"; Defender refuses that for its own key, so no policy value had been
  written, and Windows re-enabled real-time protection within minutes. Fixed in `5e6d1d1`; protection then
  stayed off for the 8 minutes checked, and through the commit.
- **Still detected on H2c (5/5):** al-khaser `firmware_acpi`, `qemu_firmware_acpi` and `number_smbios_tables`
  are unchanged by the new IDs and strings. They probably count tables (H2 has 6 ACPI tables, including the
  VM-only `WAET`, and 15 SMBIOS structures) rather than match strings; not yet verified. Also unchanged: the 13
  WMI sensor checks, the 2 Hyper-V object checks, `parent_is_explorer` and `rdtsc_diff_vmexit` (§6), and
  PERDEDOR `installed_programs` (8, needs ≥ 20; §7.2).

### 7.2 H3: everyday applications (live 2026-10-20 02:08)

H3 is H2 with 14 everyday applications installed machine-wide, for PERDEDOR `installed_programs`: Chrome,
Firefox, 7-Zip, VLC, Notepad++, LibreOffice, Zoom, Python, Git, VS Code, Audacity, PuTTY, Temurin JRE and the
x86 VC++ runtime. The owner approved the downloads on 2026-10-20. H2 is kept unchanged as the rollback.

1. `scripts/chimera/arms/fetch-apps.sh DIR` downloads the installers from the vendors' sites (1.3 GB).
2. `chimera-arm clone H2 H3`, `chimera-arm use H3`, `drakrun modify-vm0 begin` (warm: the snapshot is signed in).
3. `provision_guest.py --upload-timeout 900 --upload FILE=<profile>\Downloads\FILE … H1/install-apps.ps1`,
   first with `--arg=-CheckOnly`: every installer must have a valid Authenticode signature (13 do; 7-Zip does
   not sign its installers and is checked against the sha256 GitHub publishes for the release). The installers
   stay in Downloads, as a user's would. The script switches the Google and Mozilla updaters off afterwards.
4. **`H1/wait-idle.ps1`**, then `explorer-state.ps1` and the Defender check; then commit, adopt, validate and
   5 scans as in §7.

Results (5 scans each, all complete and attached, 501–562 s; evidence `m4-h3-2026-10-20/`, `m4-h3b-2026-10-20/`):

| Snapshot | Uninstall entries | PERDEDOR / scan | al-khaser / scan | `nt_yield_execution` | backgroundTaskHost starts / scan |
|---|---|---|---|---|---|
| H2c (§7.1) | 8 | 1 (score 99.48) | 20 | 0/5 | – |
| H3a, committed 1 min after the installs | 32 | **0 (score 100.0)** | 21 | **5/5** | 9 |
| **H3b, committed after the guest went idle (live)** | 32 | **0 (score 100.0)** | **20** | **0/5** | 1–2 |

- **Installed programs cleared:** PERDEDOR reports "32 programs" (threshold 20) and no detections at all.
- **Settle before commit.** The installs left Windows work queued: search indexing, a Start-menu background task,
  EdgeUpdate, Update Orchestrator with TiWorker. H3a was committed before that work ran, so every analysis
  replayed it. In the H3a scans, backgroundTaskHost, RuntimeBroker, EdgeUpdate and MoUsoCoreWorker started while
  al-khaser ran. Its `NtYieldExecution` check then found other threads ready to run and reported a debugger, 5/5.
  In an idle modify session the same tasks ran within 5 minutes and stopped. H3b was committed after that, and
  the detection is gone. `wait-idle.ps1` now waits for 4 quiet 30 s windows. On H3b it reported idle within
  2 minutes.
- **Guest clock (found here, not fixed):** inside every analysis the guest clock is the snapshot's (al-khaser's
  guest log and PERDEDOR's report were 2 h 11 min behind the host on the H2c scans). drakrun does not set the
  guest time after restoring, so the gap grows as the snapshot ages.

## 8. Sources
- Xen 4.19.2 `xl.cfg` manual on this host: `smbios`, `xen_platform_pci`, `viridian`, `cpuid`, `device_model_args_hvm`.
- DRAKVUF source `/opt/drakvuf` (`da982ab`): `src/main.cpp:245,758`, `src/plugins/cpuidmon/cpuidmon.cpp:139-153`; `drakvuf -h` hidsim options.
- Gruber & Freiling, "Fighting Evasive Malware: How to Pass the Reverse Turing Test by Utilizing a VMI-Based Human Interaction Simulator", GI SICHERHEIT 2022 — https://dl.gi.de/items/f6dd1ed9-db6f-4555-bab4-5bf103c3e5c3/full
- DRAKVUF issue #1883 (Win11 lab with `hypervisor=0`, `viridian=0`, spoofed SMBIOS) — https://github.com/tklengyel/drakvuf/issues/1883
- drakvuf-sandbox issue #1222 (`shadow_memory` 32→128 fixes VM crashes) — https://github.com/CERT-Polska/drakvuf-sandbox/issues/1222
- Lindorfer, Kolbitsch, Milani Comparetti, "Detecting Environment-Sensitive Malware" (DISARM), RAID 2011 — https://seclab.cs.ucsb.edu/publications/lindorfer2011detecting_environment-sensitive
- Miramirkhani et al., "Spotless Sandboxes: Evading Malware Analysis Systems using Wear-and-Tear Artifacts", IEEE S&P 2017 (in `Chimera-docs/Research_Papers`)
