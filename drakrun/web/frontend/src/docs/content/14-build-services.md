---
title: 6. Workers and services
group: Build from scratch
---
# Build step 6: workers, static VM, classifier and intel

With Xen, DRAKVUF, the package, containment and a golden image in place, the remaining pieces are services.
Install unit files from the checkout and reload systemd after each group:

```bash
cd /opt/chimera/src
systemctl daemon-reload
```

> **Build container images with `--network=host`.** A podman build on a bridge network makes netavark insert
> FORWARD rules ahead of `CHIMERA_GUARD`, and `chimera-net-check` then refuses to start the analysis workers. The
> analyzer containers themselves always run with `--network none`.

## Analysis workers

One worker per VM slot. Each requires containment and runs `chimera-net-check --require-inetsim` before it
starts.

```bash
install -m 644 scripts/chimera/systemd/drakrun-worker@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now drakrun-worker@1
```

For one Windows and one Linux slot at the same time, bind the workers to guest types and start a second one:

```toml
[worker]
vm_guest_os = {1 = "windows", 2 = "linux"}
```

```bash
systemctl enable --now drakrun-worker@2
```

Memory admission makes a worker wait (up to `memory_admission_timeout` seconds) until Xen has room for its guest,
so two slots never overcommit the host. `scripts/chimera/systemd/parallel/` has example drop-ins that also pin
each slot's CPUs.

## Static analysis

Build the analyzer images:

```bash
podman build --network=host -t localhost/chimera-static:0.1.0 -f static_analyzer/Containerfile static_analyzer
podman build --network=host -t localhost/chimera-ghidra:11.1.2 -f static_analyzer/ghidra/Containerfile static_analyzer/ghidra
podman build --network=host -t localhost/chimera-mobsf:4.5.3 scripts/chimera/mobsf
```

Build the static-analysis VM (Debian 12 by debootstrap, podman, the guest agent and the three images) and install
its service and idle timer:

```bash
scripts/chimera/static-vm/build-image.sh            # output in /var/lib/chimera-static-vm
install -d /etc/chimera && install -m 644 scripts/chimera/static-vm/chimera-static-vm.cfg /etc/chimera/static-vm.cfg
install -m 644 scripts/chimera/static-vm/chimera-static-vm*.service scripts/chimera/static-vm/chimera-static-vm-idle.timer /etc/systemd/system/
install -m 644 scripts/chimera/systemd/drakrun-static-worker.service scripts/chimera/systemd/drakrun-static-deep-worker.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now chimera-static-vm-idle.timer drakrun-static-worker drakrun-static-deep-worker
```

After changing an image, reload it into the VM with `build-image.sh --images` while the VM is stopped.

```toml
[static]
enabled = true
backend = "vm"                 # "container" runs the same containers in dom0
timeout_s = 90
wait_s = 120                   # how long classification waits for the static result
deep_enabled = true
ghidra_enabled = true
memdump_scan_enabled = true
mobsf_enabled = true
vm_idle_shutdown_s = 600       # 0 keeps the VM running
```

## Classifier

```bash
scripts/chimera/install-classifier-static.sh             # model, static image, worker, config sections
scripts/chimera/install-classifier-static.sh --drakrun   # also rebuild and reinstall drakrun from this checkout
```

The script is idempotent, backs up what it replaces, only adds missing `[classifier]` and `[static]` sections,
checks the model against a fixture, and finishes with an end-to-end test. The model files go to
`/etc/drakrun/classifier/`.

## Threat intel

```bash
install -m 644 scripts/chimera/systemd/drakrun-intel-worker.service scripts/chimera/systemd/chimera-intel-update.* \
               scripts/chimera/intel/chimera-trails-sync.* /etc/systemd/system/
install -d -m 700 /etc/chimera/keys
systemctl daemon-reload
systemctl enable --now drakrun-intel-worker chimera-intel-update.timer chimera-trails-sync.timer
```

Store provider keys in root-only files named after the provider, typed at a prompt so they never reach the shell
history:

```bash
read -rsp "VirusTotal key: " k && echo && printf '%s' "$k" > /etc/chimera/keys/virustotal && unset k
chmod 600 /etc/chimera/keys/virustotal
drakrun intel providers --test          # one live request per configured provider
```

The abuse.ch Auth-Key goes in `/etc/chimera/abusech-auth-key` the same way.

```toml
[intel]
enabled = true
online_enabled = true
online_default = false          # analysts opt in per upload
hash_providers = ["virustotal"] # the sample hash on every analysis
trails_db_path = "/var/lib/drakrun/intel/trails.db"

[intel.providers]
virustotal = true
malwarebazaar = true
threatfox = true
urlhaus = true
```

## Evasion verification

```bash
install -m 644 scripts/chimera/systemd/drakrun-evasion-worker@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now drakrun-evasion-worker@1
```

Point the tools at their files on dom0 (paths are examples):

```toml
[evasion.perdedor]
repo_path = "/opt/chimera/src/perdedor"

[evasion.alkhaser]
host_binary_path = "/opt/chimera-tools/al-khaser_x64.exe"

[evasion.pafish]
host_binary_path = "/opt/chimera-tools/pafish64.exe"
```

## Restart after changes

After a redeploy or a plugin change, restart the services that load the code or the configuration:

```bash
systemctl restart drakrun-web drakrun-static-worker drakrun-static-deep-worker drakrun-intel-worker 'drakrun-worker@*'
```

Do it while no analysis is running. Then upload a harmless file and check that the report has a process tree, a
static analysis and a verdict.
