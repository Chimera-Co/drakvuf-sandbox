---
title: Static analysis
group: Concepts
---
# Static analysis

Every upload is also analysed **statically**: the file is parsed but never executed. The static job starts at
the same moment as the detonation, usually finishes long before it, and writes `static.json` (schema
`chimera-static/1`). The classifier later sees it next to the behaviour. Files CHIMERA cannot detonate, such as
Android and iOS apps, get a static-only analysis.

## Two passes and their layers

The **fast pass** (`drakrun static-worker`, queue `chimera-static`) runs the `chimera_static` analyzer:

| Layer | Applies to | Gives |
|---|---|---|
| Identify | Every file | The real format from magic bytes (PE, .NET, DLL, driver, ELF, Mach-O, PDF, OLE, OOXML, RTF, ZIP/APK/JAR, 7z, RAR, CAB, ISO, LNK, OneNote, DEX, gzip, scripts by content), platform and architecture; findings for extension mismatch, double extensions, right-to-left override |
| Universal | Every file | MD5, SHA-1, SHA-256, TLSH, ssdeep; entropy profile; ASCII and UTF-16 strings; IOCs (URLs, domains, IPs, e-mail addresses, registry keys, paths, wallets, base64 blobs); keyword findings; embedded files; YARA |
| Format | PE, ELF, PDF, .NET, Office, RTF, LNK, scripts, archives | PE headers, sections, imports by category, imphash, resources, Authenticode, overlay, Rich header; ELF segments, symbols, hardening flags; PDF auto-actions and JavaScript; VBA macros and DDE; RTF embedded objects; LNK targets and arguments; about 20 ATT&CK-mapped script rules with decoded layers |
| ML features | PE, ELF, PDF | The EMBER2024 feature vector used by the static models |

The **deep pass** (`drakrun static-worker --deep`) adds the slower tools for PE and ELF files:

- **capa** (Mandiant) matches rules for capabilities ("encrypt data using AES", "inject into another process")
  in the code and maps them to ATT&CK techniques and the Malware Behavior Catalog.
- **FLOSS** (Mandiant) recovers obfuscated strings: stack strings, tight strings and strings decoded by the
  sample's own decoding routines, which plain `strings` cannot see.
- **Ghidra** (11.1, headless) decompiles the most interesting functions into C pseudo-code with disassembly,
  callers and callees; the console shows them in the **Decompiled code** tab.

`score` (0–100) and `level` (clean, low, medium, high) are a rule score over the findings. LNK, RTF and script
files are judged by rules only.

## Mobile apps: MobSF

Android APK and iOS IPA uploads (static only) go to **MobSF** (Mobile Security Framework, built locally at
4.5.3 with JADX): permissions, manifest and code findings with CWE/OWASP/MASVS references, network security
configuration, signing certificate, trackers, secrets, domains and, for iOS, binary hardening and App Transport
Security. For APKs the JADX Java/Kotlin sources are browsable in the console. The classifier is not trained on
mobile apps, so they are marked "Not classified".

## Memory dumps

Packed malware often shows its real code only in memory. After each detonation the `memdump` regions DRAKVUF
saved are queued to the deep pass and run through the same analyzer (bounded by `memdump_scan_max`,
`memdump_scan_max_mb` and `memdump_scan_budget_s`), the sample's own processes first. The result,
`memdumps.json`, records whether the scan stopped early, so a partial scan never looks complete. Memory-dump
results are shown in the **Memory dumps** tab and do not change the verdict.

## Isolation: the static-analysis VM

Parsers of hostile files are attack surface. With `[static] backend = "vm"` the analyzers run inside a dedicated
Xen guest instead of dom0, so a parser exploit lands in a throwaway VM:

- Debian 12 **PVH** guest `chimera-static` with **no network interface** (`vif = []`), a read-only root disk and
  a scratch disk reformatted at every boot.
- Per job dom0 attaches a read-only job disk (a header, a JSON spec and the sample) and an empty result disk; the
  guest agent writes the result with its length and SHA-256, and the two sides signal through xenstore.
- Inside the VM each tool runs in a podman container with `--network none`, a read-only root, all capabilities
  dropped, `no-new-privileges`, an unprivileged UID, PID/memory/CPU limits and a wall-clock kill.
- The VM boots on demand for the first job, runs jobs one at a time, is restarted every `vm_restart_every` jobs
  or after an unhealthy job, and shuts down after `vm_idle_shutdown_s` without work, returning its memory to Xen.
- Samples are never executable on the host: uploads are stored `0400`, the staged copy `0440`, and the copy is
  deleted after the run.

With `backend = "container"` the same locked-down containers run in dom0. MobSF never falls back to dom0.

## Outputs and API

| File | Endpoint | Contents |
|---|---|---|
| `/var/lib/drakrun/static/<id>/static.json` | `GET /api/static/<id>` | Fast-pass result |
| `deep.json` | `GET /api/static/<id>/deep` | capa, FLOSS, Ghidra |
| `memdumps.json` | `GET /api/static/<id>/memdumps` | Memory-dump scan |
| `mobsf.json` | `GET /api/static/<id>/mobsf` | MobSF report (`…/mobsf/source?path=` serves one decompiled source file) |

Each endpoint returns 404 until its file exists.
