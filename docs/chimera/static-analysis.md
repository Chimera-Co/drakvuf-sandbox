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
postprocessing step `queue_memdump_scan` puts a job on the deep queue: up to `memdump_scan_max` dumps (default 16,
each at most `memdump_scan_max_mb` MiB) go through the same analyzer and sandbox as the upload. Dumps of the
sample's own process tree come first, then dumps that start with an MZ header, then injection-type reasons, then
size; identical contents are scanned once. Results go to `memdumps.json` (schema `chimera-memdumps/1`) and the
"Memory dumps" tab. They are **not** classifier features: they never change the verdict.

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

## Develop

```bash
cd static_analyzer && python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest && .venv/bin/pip install -e .
.venv/bin/python -m pytest -q tests
.venv/bin/python -I -m chimera_static <file> <out_dir> --name <original name>
```
