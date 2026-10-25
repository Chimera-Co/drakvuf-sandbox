# Static analysis

Every upload is also analysed **statically**, starting at the same moment as the DRAKVUF detonation. The static
analyzer never executes the file. It identifies what the file really is, runs every analysis that applies and
writes `static.json` (schema `chimera-static/1`). The classifier then sees it next to the dynamic features.

```
upload ──> api.py: chmod 0400, stage copy (0440 root:65534) ──> RQ queue "chimera-static"
                └─> enqueue_analysis (VM queue, unchanged)
drakrun static-worker ──> static VM "chimera-static" (or a locked-down dom0 container, see below)
                         chimera_static ──> /var/lib/drakrun/static/<id>/static.json
drakrun static-deep-worker ──> capa + FLOSS (PE/ELF), Ghidra 11.1 headless decompiler ──> deep.json
                           └─> after a detonation: memory-dump scan ──> memdumps.json
classify_sample (after detonation) ──> features["static"] = static.json (waits ≤ [static].wait_s)
GET /api/static/<id>, /api/static/<id>/deep, /api/static/<id>/memdumps ──> 404 until each exists
```

## What it analyses (v0.1)

| Layer | Applies to | Gives |
|---|---|---|
| 0 identify | every file | real format from magic bytes (PE/.NET/DLL/driver, ELF, Mach-O, PDF, OLE, OOXML, RTF, ZIP/APK/JAR, 7z, RAR, CAB, ISO, LNK, OneNote, DEX, gzip, scripts by content), platform, architecture, libmagic; findings for extension mismatch, double extension, right-to-left override |
| 1 universal | every file | MD5/SHA-1/SHA-256, TLSH, ssdeep; entropy and entropy profile; ASCII + UTF-16 strings; IOCs (URLs, domains, IPs, e-mails, registry keys, paths, BTC, base64 blobs); keyword findings (shadow-copy deletion, encoded PowerShell, Run keys, anti-VM, miners, ransom notes, cron, LD_PRELOAD, …); embedded files; YARA (rules baked into the image) |
| 2 PE | PE | headers, sections (entropy, W+X), packers, imports by category, imphash, exports, resources (embedded PE, encrypted), version info, TLS, overlay, PDB path, rich header, checksum, Authenticode (signify) |
| 2 ELF | ELF | class, machine, type, interpreter, static/stripped, needed libraries, symbols by category, W+X segments, executable stack, UPX |
| 2 PDF | PDF | pdfid-style keyword counts with `#xx` de-obfuscation, auto-run JavaScript, Launch, embedded files, URIs, header offset |
| 2 .NET | PE with a CLR header | runtime version, metadata streams, `#US` user strings (IOCs and keyword findings run on them) |
| 2 Office | OLE, OOXML | VBA macros (oletools), auto-exec and suspicious keywords, external relationships, DDE |
| 2 RTF | RTF | embedded OLE objects (`rtfobj`), exploit classes (`Equation.3` and others), package executables, embedded PE, `\objupdate` |
| 2 LNK | Windows shortcut | target, arguments, working directory, icon, show command, machine ID, times; interpreter targets, hidden window, document icon, and the script rules on the arguments |
| 2 script | PowerShell, VBScript, JScript, batch, shell, Python | about 20 ATT&CK-mapped rules (download cradles, `iex`/`eval`, encoded commands, Defender tampering, shadow-copy deletion, persistence, LOLBins, AMSI bypass, reverse shells, cron, miners); obfuscation indicators; decoded layers (`-EncodedCommand`, `FromBase64String`, base64 blobs, up to 3 levels); the source text for the code viewer |
| 2 archives | ZIP, APK, JAR | member listing, encrypted members, executables inside |
| deep | PE, ELF | capa capabilities with ATT&CK and MBC, FLOSS stack/tight/decoded strings |
| decompiler | PE, ELF | Ghidra 11.1 headless: up to 96 functions ranked by interest, C pseudo-code, disassembly (300 instructions per function), callers and callees |
| ML | PE, ELF, PDF | EMBER2024 feature vector (thrember v3, 2568 values, identical to the dataset's) for the static models |

`score` (0–100) and `level` (clean/low/medium/high) are a rule score from the findings. The classifier adds its
ML score. LNK, RTF and script files are judged by rules only, so their coverage is always "partial" and the
static side never votes benign for them.

## Memory dumps

DRAKVUF's memdump plugin saves memory regions on heuristics (remote thread creation, memory written and then
executed, freed images). Packed malware often shows its real code only there. After each detonation the
postprocessing step `queue_memdump_scan` puts a job on the deep queue. Every distinct dump up to
`memdump_scan_max_mb` MiB (default 64) goes through the same analyzer and sandbox as the upload (about 3-4 s per
dump in the static VM). The scan stops at `memdump_scan_max` dumps (default 512) or after `memdump_scan_budget_s`
seconds (default 1200), and `memdumps.json` records which (`stopped`), so a partial scan never looks complete.
Order: dumps of the sample's own process tree, then dumps that start with an MZ header, then injection-type
reasons, then size; identical contents are scanned once. Each dump keeps its YARA matches, analyzer findings,
insight indicators of severity 2+ (for example injection imports in unpacked code), embedded executables and
IOCs. Results go to `memdumps.json` (schema `chimera-memdumps/1`) and the
"Memory dumps" tab. They are **not** classifier features: they never change the verdict.

## Static VM lifecycle (on demand)

The static-analysis VM is not started at boot. The first static job (fast pass, deep pass, Ghidra, memory-dump
scan or MobSF) boots it (`vm_autostart`; measured: boot plus a trivial job in about 5 s), jobs run one at a time
under a lock, and `chimera-static-vm-idle.timer` (every 2 minutes) shuts it down once no job has used it for
`[static] vm_idle_shutdown_s` (600 s by default; 0 keeps it running). The idle check takes the same lock without
waiting, so it never stops the VM during a job. While it is down its 3584 MB go back to Xen, which is what lets a
Windows (5120 MB) and a Linux (4096 MB) detonation run at the same time on this 16 GB host. It is still restarted
after every 100 jobs and after any unhealthy job.

## Mobile apps: Android APK and iOS IPA (MobSF)

Choose **Android APK** or **iOS IPA** as the platform on the upload page (or send `guest_os=android|ios` with
`mode=static-only`; any other mode is refused). Mobile apps are never run. The fast pass identifies the file (an
IPA is a ZIP with `Payload/<name>.app/`) and, with `[static] mobsf_enabled = true`, the app goes to MobSF on the
deep queue (`drakrun/analyzer/static/mobsf.py`).

**Isolation.** With `[static] backend = "vm"` (the deployed setting) MobSF runs **inside the static-analysis Xen
VM**, not on the host: one podman step in the domU (`vm_backend.mobsf_in_vm`) starts MobSF and its driver in a
container with `--network none`, `--cap-drop ALL`, `no-new-privileges`, a 2816 MB / 1024-PID cap, a `noexec`
`/tmp`, the sample mounted read-only and `noexec`, and a random API key. The VM itself has no network device and
receives the sample on a read-only raw disk. If the VM is unavailable the scan **fails closed**: MobSF is never
started on the host, whatever `vm_fallback_container` says. (With `backend = "container"` the same hardened
container runs in dom0.)

**Report.** `mobsf.json` (schema `chimera-mobsf/1`) holds the security score, findings, permissions, code and
manifest findings with CWE/OWASP/MASVS, behaviour, Android API use, network security config, signing certificate,
APKiD, secrets, trackers, domains and URLs; for iOS also the Mach-O binary findings, binary hardening flags and
App Transport Security. It is shown on the "Android (MobSF)" / "iOS (MobSF)" tab of the static analysis.

**Decompiled code.** For APKs the driver also returns JADX's Java/Kotlin output: the app's own package first,
libraries last, at most 3000 files, 1 MiB each and 48 MiB in total. The host re-packs it into
`mobsf-sources.zip`, keeping only plain relative `.java`/`.kt` paths (never extracted), and lists the files in
`mobsf.json`. `GET /api/static/<id>/mobsf/source?path=...` serves one listed file as `text/plain`; the
**Decompiled code** tab of the analysis browses them with Java/Kotlin highlighting. iOS apps are native code and
MobSF does not decompile them on Linux. For PE and ELF files the same tab shows Ghidra's decompiled functions.

**No classifier.** The models are trained on Windows and Linux files, so mobile apps get
`classification.json` with `not_applicable: true` and the verdict card reads "Not classified"; the MobSF report
is the result.

**Not covered.** Dynamic Android or iOS analysis. Android would need an Android-x86 HVM guest under Xen (dom0
has no `/dev/kvm` for the usual emulator) with its own instrumentation; iOS needs Corellium-style virtual
devices or jailbroken hardware. Both are planned as separate work after the capstone.

The MobSF image is built locally from upstream v4.5.3 with JADX baked in (no download at scan time):

```bash
sudo podman build --network=host -t localhost/chimera-mobsf:4.5.3 scripts/chimera/mobsf
```

`scripts/chimera/static-vm/build-image.sh --images` copies it into the VM's read-only image store; then set
`mobsf_enabled = true` under `[static]` in `/etc/drakrun/config.toml` and restart `drakrun-static-worker` and
`drakrun-static-deep-worker`.

## Security

See threat model **T12**. In short: the analyzer runs in a container with `--network none`, read-only root,
no capabilities, no-new-privileges, uid 65534, PID/memory/CPU limits, `noexec` mounts and a wall-clock kill.
Inside it, the analyzer also limits itself (no new processes or threads, memory and CPU caps, no core dumps).
Every escape attempt was tested from inside the container on 2026-10-23 and blocked.
**Samples are never executable on the host**: uploads are `0400`, the static copy is `0440` and is deleted
after the run.

### Static-analysis VM (`[static] backend = "vm"`, live since 25 Oct)

The same containers run inside a dedicated Xen domU instead of dom0, so a parser exploit lands in a throwaway
guest with no network rather than on the host that controls the hypervisor.

- Debian 12 PVH guest `chimera-static`: 3584 MiB, 2 vCPUs, **no network interface** (`vif=[]`); root disk
  read-only, scratch disk reformatted at every boot; root locked, no getty.
- Per job, dom0 attaches a read-only job disk (header `CHIMJOB1`, JSON spec, sample at 1 MiB) and an empty result
  disk; the guest agent writes `CHIMRES1` + length + sha256 + JSON. The two sides signal through xenstore. The
  guest only runs podman argument lists built on the host, with the same lock-down as in dom0.
- dom0 checks the result's length and hash, restarts the VM after a timeout, an unhealthy job or every
  `vm_restart_every` jobs, and falls back to the dom0 container when the VM is down
  (`vm_fallback_container = true`; the result then says `backend: "container"`).
- Build: `sudo scripts/chimera/static-vm/build-image.sh` (debootstrap) or `--images` to reload only the analyzer
  images; service `chimera-static-vm`.
- Cost: 3.5 GiB of the 9.5 GiB Xen has free, so a Windows and a Linux detonation no longer fit at the same time;
  memory admission runs them one after the other. Timings through the VM: fast pass 3.7 s, deep pass 14.9 s,
  Ghidra 21.8 s.

## Deploy

`sudo scripts/chimera/install-classifier-static.sh --drakrun` does everything below and then runs the
end-to-end check; see `classifier-static-quickstart.md`. By hand:

```bash
sudo apt install podman
sudo podman build -t localhost/chimera-static:0.1.0 -f static_analyzer/Containerfile static_analyzer
sudo install -m 644 scripts/chimera/systemd/drakrun-static-worker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now drakrun-static-worker
```

```toml
# /etc/drakrun/config.toml
[static]
enabled = true        # default false: nothing changes until this is set
engine = "podman"
image = "localhost/chimera-static:0.1.0"
timeout_s = 90
wait_s = 120          # classify_sample waits at most this long after the detonation
backend = "vm"        # default "container" (dom0); "vm" needs the static VM built and running
memdump_scan_enabled = true   # scan the run's memory dumps on the deep queue (default false)
```

The analyzer needs no packages in the drakrun venv: they live in the image (`static_analyzer/requirements.txt`).

## Analyst insight in `chimera-static/1`

The fast pass adds structured metadata without changing existing fields or the scored `findings` subset.
PE output includes decoded headers and directories, section permissions and hashes, annotated imports and
exports, resource content types and hashes, manifests, version details, debug/PDB records, Rich toolchain
entries, TLS callbacks, load configuration, certificate status, overlays, and file and memory layouts.
Existing `imports`, `exports`, `resources`, `version_info`, and the boolean `rich_header` remain available;
expanded records use `imports_annotated`, `exports_annotated`, `resources_annotated`, `version_fixed`,
`version_flags`, and `rich_header_details`.

ELF output adds decoded headers and program headers, annotated symbols, dynamic linker paths and flags,
interpreter and build notes, Go/Rust hints, file and memory layouts, and PIE, NX, RELRO, canary, FORTIFY and
stripping information. A shared library's position independence is distinguished from executable PIE.
Absent GNU_STACK information leaves NX unknown.

Top-level `indicators` contains observations sorted by numeric severity (3 high, 2 medium, 1 low),
with categories, explanations, short evidence and technique IDs; `indicators_summary` counts each severity.
These observations do not alter the score. `universal.strings_flagged` records matched text, byte offset,
encoding, category and severity; `strings_summary` counts category matches. Existing strings and IOCs remain
unchanged. API names in strings suggest possible dynamic resolution, not proof that a function executes.

Bundled JSON tables under `chimera_static/knowledge/` supply Windows API, DLL, Linux symbol and string-rule
annotations. They are loaded lazily and require no network access or additional dependencies.
Function annotations are limited to 3,000, resource records to 500, and flagged strings to 600. Truncation and
scan limits are recorded alongside the output. String inspection examines at most 32 MiB and 100,000 string
candidates. Insight entropy samples at most the first MiB of each region; hashes cover the available bytes.
File layouts partition the file in offset order, splitting overlaps and separating certificate bytes from
overlays. Missing or malformed fields and unverified signatures must not be interpreted as benign evidence.

## Develop

```bash
cd static_analyzer && python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest && .venv/bin/pip install -e .
.venv/bin/python -m pytest -q tests
.venv/bin/python -I -m chimera_static <file> <out_dir> --name <original name>
```
