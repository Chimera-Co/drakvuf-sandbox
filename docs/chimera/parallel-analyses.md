# Parallel Windows and Linux analyses

The default remains one `drakrun-worker@1` on vm-1, serving both guest types
serially. Windows jobs retain the `drakrun-analysis` RQ queue; Linux jobs use
`drakrun-analysis-linux`. Uploads use the shared `enqueue_analysis` helper.
The CLI `drakrun analyze` runs directly, without enqueueing. The console merges
both queues and their registries, newest first; status lookup by UUID is global
to Redis and works for either queue.

Worker bindings live in `/etc/drakrun/config.toml`:

```toml
[worker]
vm_guest_os = {1 = "any"}
memory_admission_timeout = 1800
memory_admission_poll_interval = 5
memory_admission_margin_mb = 192
```

An omitted VM binding means `any`. `drakrun worker --vm-id 1 --guest-os windows`
overrides the configuration for that process. A bound worker subscribes only
to its OS queue and refuses a mismatched job even if that job was put on the
wrong queue manually. `any` subscribes to both queues, using RQ's queue order
(Windows first); it still runs only one job at a time. Drain old jobs before
switching bindings: Linux jobs submitted by older deployments may still be on
the Windows queue.

## Two-slot layout

| Instance | VM slot | Queue | Guest image | vCPUs | pCPUs |
| --- | --- | --- | --- | ---: | --- |
| drakrun-worker@1 | vm-1 | drakrun-analysis | Windows | 4 | 8-11 |
| drakrun-worker@2 | vm-2 | drakrun-analysis-linux | Linux | 4 | 12-15 |
| dom0 | Domain-0 | — | Host services | 8 | 0-7 |

The equivalent config is `vm_guest_os = {1 = "windows", 2 = "linux"}`.
The example instance drop-ins in `scripts/chimera/systemd/parallel/` set these
bindings explicitly on the command line and preserve the base unit's containment
checks, dependencies and restart policy. They are examples only; nothing installs
them automatically. The deployment path in them is `/opt/chimera/venv/bin/drakrun`.

vm-2 already has a network/config slot. Its guest configuration is regenerated
from the Linux image's template at restore; do not hand-edit `vm-2.cfg`.
Verify that the Linux golden image, snapshot, matching kernel profile, and
storage backend can restore a disposable vm-2 overlay. A network slot alone
does not provision a second golden image. The existing per-VM lock still
prevents analysis and evasion workers from using the same slot simultaneously;
use vm-1 for Windows evasion verification in this layout.

## Memory and admission

| Allocation | GiB | MiB |
| --- | ---: | ---: |
| dom0 target | 7 | 7168 |
| Windows guest | 5 | 5120 |
| Linux guest | 4 | 4096 |
| Nominal total | **16** | **16384** |

This fills a nominal 16 GiB host **before Xen overhead**. It is not enough
headroom for reliable concurrency. Admission requires guest memory plus 192 MB
(64 MB shadow memory + 128 MB margin): Windows needs 5312 MB free and Linux
4288 MB free immediately before restore. Xen, device models, host services and
other domains need additional headroom. The current 10 GiB dom0 allocation
cannot support both guests together. The owner must choose a smaller dom0
allocation (for example, 6–6.5 GiB, after checking host service usage), reduce
guest RAM with compatible snapshots, or accept serialized admission. Check
actual `xl info` and concurrent restore behavior instead of relying on the sum.

`dom0_mem` is a Xen **boot parameter** changed by the owner through the host's
bootloader configuration, followed by its normal regeneration/reboot procedure.
This code does not change it. Keep `dom0_max_vcpus=8 dom0_vcpus_pin` for the
0-7 dom0 CPU plan; verify the actual affinity with `xl vcpu-list Domain-0`.

`run_vm` uses `/var/run/drakrun/admission.lock` for both analysis and evasion
workers. Under that lock it reads `xl info`'s `free_memory` in MB, checks the
image's `InstallInfo.memory` plus margin, and holds the lock through the entire
restore until the domain exists. It releases the lock between failed checks,
so another guest can fit while a larger one waits. Lock contention counts
toward the admission timeout. Polling defaults to five seconds, with one wait
message per minute. Invalid or failed `xl info` calls fail clearly rather than
restoring without a memory check. Locks are released when a process exits.

A stale domain belonging to the locked slot is destroyed before admission to
reclaim its memory. Restore failures still tear down the domain/network.
`no_restore` continues to use the already-running domain without admission.
After successful admission, waits of at least one second are recorded as `memory_admission_wait_seconds`
in the RQ job and analysis metadata. Newly enqueued analyses add the admission
timeout to their RQ execution budget. Existing queued jobs retain their old
RQ budgets. Evasion job budgets are set by their caller; allow the admission
timeout in addition to verifier runtime when scheduling evasion work.

Admission serializes creation, not execution: after a restore completes its
host lock is released while analysis continues. All workers must use the same
host runtime directory. Direct/manual Xen restores do not participate in this
lock and can still consume memory concurrently.

## CPU affinity

Set an optional `cpus` string in the image's install JSON:

```json
"cpus": "8-11"
```

Use `"12-15"` in `/var/lib/drakrun/linux/golden/install.json`. The Windows
image uses `/etc/drakrun/install.json`. These settings apply to every slot
restored from that install file, including vm-0 operations. Omit `cpus` or
use JSON `null` to keep the previous affinity behavior. CPU lists accept ranges
and commas, e.g. `"8,10-11"`.

The renderer replaces `{{ CPUS }}` in a template line such as
`cpus = "{{ CPUS }}"`. When the placeholder is absent it appends
`cpus = "8-11"`, so existing templates need no changes. When affinity is unset,
the placeholder line is omitted. Existing templates without that placeholder
render byte-for-byte as before when affinity is unset.

## Operator switch procedure

Deploy this code to the existing worker/web environment first; check that
`/opt/chimera/venv/bin/drakrun worker --help` shows `--guest-os`. Wait for
analysis/evasion jobs to finish and drain both queues before stopping services.
Keep submissions paused through the switch. The following are **operator
commands**, to run as root from this checkout; none were run as part of this change.

```sh
cd /home/shreyas/Documents/chimera/chimera-console
systemctl stop drakrun-worker@1.service drakrun-worker@2.service
```

If a Windows evasion worker is enabled, stop it while changing the slot setup:

```sh
systemctl stop drakrun-evasion-worker@1.service
```

Have the owner apply the dom0 boot-memory decision above and reboot as needed
before starting concurrent workers. Confirm the Linux image and vm-2 network
slot are ready. Set the affinity values, preserving all other install fields:

```sh
/opt/chimera/venv/bin/python - <<'PY'
import json
from pathlib import Path
for filename, cpus in [
    ("/etc/drakrun/install.json", "8-11"),
    ("/var/lib/drakrun/linux/golden/install.json", "12-15"),
]:
    path = Path(filename)
    data = json.loads(path.read_text())
    data["cpus"] = cpus
    path.write_text(json.dumps(data, indent=4) + "\n")
PY

install -d /etc/systemd/system/drakrun-worker@1.service.d
install -d /etc/systemd/system/drakrun-worker@2.service.d
install -m 0644 scripts/chimera/systemd/parallel/drakrun-worker@1.service.d/guest-os.conf /etc/systemd/system/drakrun-worker@1.service.d/guest-os.conf
install -m 0644 scripts/chimera/systemd/parallel/drakrun-worker@2.service.d/guest-os.conf /etc/systemd/system/drakrun-worker@2.service.d/guest-os.conf
systemctl daemon-reload
systemctl restart drakrun-web.service
systemctl enable --now drakrun-worker@1.service drakrun-worker@2.service
systemctl status drakrun-worker@1.service drakrun-worker@2.service --no-pager
xl info
```

The existing base `drakrun-worker@.service` must already be installed. If it
is missing, install the example from `scripts/chimera/systemd/` using the host's
normal service deployment procedure. Check for other local `ExecStart` drop-ins
with `systemctl cat drakrun-worker@1.service drakrun-worker@2.service` before switching.

Resume submissions and submit one known benign Windows sample and one Linux
sample together. Check both appear in `/api/list` and `/api/status/<uuid>`, and
that their metadata uses vm-1 and vm-2 respectively. While both domains exist:

```sh
xl list
xl vcpu-list Domain-0
xl vcpu-list vm-1
xl vcpu-list vm-2
journalctl -u drakrun-worker@1.service -u drakrun-worker@2.service -n 100 --no-pager
```

If admission times out, inspect Xen free memory and the dom0 budget. The gate
does not promise that a nominal 7 + 5 + 4 GiB allocation can run concurrently.
Restart the Windows evasion service on vm-1 when needed; it shares that slot's
exclusive lock with analyses.

To return to one serial worker after draining running work:

```sh
systemctl stop drakrun-worker@1.service
systemctl disable --now drakrun-worker@2.service
rm /etc/systemd/system/drakrun-worker@1.service.d/guest-os.conf
rm /etc/systemd/system/drakrun-worker@2.service.d/guest-os.conf
systemctl daemon-reload
systemctl start drakrun-worker@1.service
```

If config bindings were also set, restore `vm_guest_os = {1 = "any"}` before
starting worker@1. Remove the two install JSON `cpus` fields to return to the
previous guest CPU affinity behavior.
