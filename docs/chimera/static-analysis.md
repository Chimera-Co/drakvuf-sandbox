# Static analysis

Every upload is also analysed **statically**, starting at the same moment as the DRAKVUF detonation. The static
analyzer never executes the file. It identifies what the file really is, runs every analysis that applies and
writes `static.json` (schema `chimera-static/1`). The classifier then sees it next to the dynamic features.

```
upload ──> api.py: chmod 0400, stage copy (0440 root:65534) ──> RQ queue "chimera-static"
                └─> enqueue_analysis (VM queue, unchanged)
drakrun static-worker ──> podman run (locked down, see below) chimera_static ──> /var/lib/drakrun/static/<id>/static.json
classify_sample (after detonation) ──> features["static"] = static.json (waits ≤ [static].wait_s)
GET /api/static/<id> ──> the report (404 until it exists)
```

## What it analyses (v0.1)

| Layer | Applies to | Gives |
|---|---|---|
| 0 identify | every file | real format from magic bytes (PE/.NET/DLL/driver, ELF, Mach-O, PDF, OLE, OOXML, RTF, ZIP/APK/JAR, 7z, RAR, CAB, ISO, LNK, OneNote, DEX, gzip, scripts by content), platform, architecture, libmagic; findings for extension mismatch, double extension, right-to-left override |
| 1 universal | every file | MD5/SHA-1/SHA-256, TLSH, ssdeep; entropy and entropy profile; ASCII + UTF-16 strings; IOCs (URLs, domains, IPs, e-mails, registry keys, paths, BTC, base64 blobs); keyword findings (shadow-copy deletion, encoded PowerShell, Run keys, anti-VM, miners, ransom notes, cron, LD_PRELOAD, …); embedded files; YARA (rules baked into the image) |
| 2 PE | PE | headers, sections (entropy, W+X), packers, imports by category, imphash, exports, resources (embedded PE, encrypted), version info, TLS, overlay, PDB path, rich header, checksum, Authenticode (signify) |
| 2 ELF | ELF | class, machine, type, interpreter, static/stripped, needed libraries, symbols by category, W+X segments, executable stack, UPX |
| 2 PDF | PDF | pdfid-style keyword counts with `#xx` de-obfuscation, auto-run JavaScript, Launch, embedded files, URIs, header offset |
| ML | PE, ELF, PDF | EMBER2024 feature vector (thrember v3, 2568 values, identical to the dataset's) for the static models |

`score` (0–100) and `level` (clean/low/medium/high) are a rule score from the findings. The classifier adds its
ML score. Office, script, LNK and archive plugins are next.

## Security

See threat model **T12**. In short: the analyzer runs in a container with `--network none`, read-only root,
no capabilities, no-new-privileges, uid 65534, PID/memory/CPU limits, `noexec` mounts and a wall-clock kill.
Inside it, the analyzer also limits itself (no new processes or threads, memory and CPU caps, no core dumps).
Every escape attempt was tested from inside the container on 2026-10-23 and blocked.
**Samples are never executable on the host**: uploads are `0400`, the static copy is `0440` and is deleted
after the run.

Container rather than VM: the analyzer only reads bytes, needs no hypervisor features and finishes in about a
second, while a domU would compete with analysis VMs for memory and add a transfer channel. The upgrade path is
gVisor or a dedicated domU.

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
```

The analyzer needs no packages in the drakrun venv: they live in the image (`static_analyzer/requirements.txt`).

## Develop

```bash
cd static_analyzer && python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest && .venv/bin/pip install -e .
.venv/bin/python -m pytest -q tests
.venv/bin/python -I -m chimera_static <file> <out_dir> --name <original name>
```
