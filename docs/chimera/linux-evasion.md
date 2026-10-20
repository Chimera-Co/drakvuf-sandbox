# Linux sandbox evasion verification

Linux scans run the bundled `chimera-vmcheck` Python 3 standard-library script
inside a disposable Debian guest. They use the existing `drakrun-evasion` queue
and `drakrun evasion-worker` process, separately from analysis results. No tool
or package download is performed by a scan.

## Run a scan on the host

With the console API and evasion worker already running, submit:

```sh
curl --fail-with-body -sS http://127.0.0.1:5000/api/evasion/scans \
  -H 'Content-Type: application/json' \
  -d '{"sandbox_id":"linux","guest_os":"linux","tools":["chimera-vmcheck"],"profile":"full"}'
```

The API returns `{"scan_id":"..."}`. Open `/evasion/<scan_id>` in the console,
or fetch `/api/evasion/scans/<scan_id>/status`, then
`/api/evasion/scans/<scan_id>/json` or `/report`.
Use the configured API address if it differs from the example. If the API
requires authentication, supply the same credentials as for other API calls.

The registry advertises a built-in sandbox named `linux` when
`/var/lib/drakrun/linux/golden/install.json` exists and no Linux sandbox is
explicitly configured. An explicit Linux sandbox must declare
`verifiers = ["chimera-vmcheck"]`; use that sandbox's id in the command above.
`GET /api/evasion/sandboxes` lists the actual ids and available tools.
`GET /api/evasion/tools?guest_os=linux` lists Linux adapters.

The worker needs an unused VM slot, just as Windows evasion does. If it is not
already running, an operator with the usual host permissions can start it with
`drakrun evasion-worker --vm-id 2`; choose a slot not used by another worker.
Do not run an analysis worker and an evasion worker against the same VM id.

## Execution and artifacts

The scan records `options.guest_os = "linux"`, resolves the sandbox, validates
its tools, loads the Linux golden `install.json`, and restores it through
`run_vm`. It uses `install_info.snapshot_dir/kernel.json` for injection.
The serial agent is prepared, the guest clock is synchronized unless disabled,
and network readiness is checked using the existing Linux agent protocol.
The verifier uploads the bundled script with the Linux analyzer's
`upload_sample` injector writefile integration, targeting the live agent PID;
the session verifies the uploaded file's size and SHA-256.

The agent's asynchronous `exec` launches a Python command runner. That runner
owns the timeout and terminates the checker's process group if it expires.
The host polls completion through `sh`. It retrieves files with guest-side
base64 in 32 KiB binary chunks (under the agent's 64 KiB stdout cap), validates
every chunk length and the full SHA-256, and rejects reports larger than 16 MiB.
The serial connection closes and `run_vm` destroys the disposable VM even when
the verifier fails.

Artifacts use the existing scan directory and download API:

- `raw/chimera-vmcheck/command.txt`, `stdout.txt`, `stderr.txt`, `linux-report.json`;
- `metadata.json`, normalized `evasion.json`, `report.html`, and the artifact ZIP.

Linux `with_drakvuf=true` is currently rejected. The optional Windows evasion
instrumentation path remains available for Windows; these Linux checks measure
the restored guest without an attached DRAKVUF monitor. Uploading via injector
happens before checker execution.

Old requests and stored scans default to Windows. Their serialization, Windows
adapters, scoring and report rendering keep the historical defaults.

## Checks and expected Xen findings

The raw JSON is `{tool, version, total, detected, checks}`. Every check has a
stable `id`, a group `category`, a boolean `detected`, `evidence`, `technique`, and
an availability `status` (`ok` or `skipped`). Detection means an indicator was
found, not that virtualization or malicious instrumentation has been proven.
Unavailable commands, unreadable files and inaccessible kernel logs are skipped
with their reason, rather than reported as clean. Evidence is bounded; shell
history content and arbitrary process arguments are not collected.

| Check id / group | What is examined | Expected on this Xen guest |
| --- | --- | --- |
| `cpu.hypervisor_flag` | Kernel-exposed CPUID hypervisor flag in `/proc/cpuinfo` | Usually detected unless the flag is hidden. No executable machine-code probe is required. |
| `cpu.hypervisor_vendor` | `lscpu` hypervisor vendor derived from CPUID/kernel information | Usually Xen; skipped if lscpu is unavailable. |
| `hypervisor.sysfs` | `/sys/hypervisor/*` names and readable values, including `type` | Xen entries commonly remain visible. |
| `hypervisor.proc_xen` | `/proc/xen` presence | Often detected with Xen guest support. |
| `kernel.vm_modules` | Xen, KVM, VBox and VMware module names in `/proc/modules` | Xen modules can fire; built-in drivers do not appear as modules. KVM modules can also mean a physical host. |
| `dmi.sys_vendor`, `product_name`, `bios_vendor`, `board_vendor`, `chassis_vendor`, `product_serial` | Corresponding `/sys/class/dmi/id` strings, matching known virtual vendors/products | Xen/HVM/QEMU strings may fire; firmware masking changes this. Serial files may require root. |
| `devices.mac_oui` | Interface addresses with Xen `00:16:3e`, QEMU `52:54:00`, VMware, VBox or Hyper-V prefixes | Depends on configured MAC; randomized/local MACs may avoid these prefixes. |
| `devices.disk_identity` | `/sys/block/*/device/{model,vendor}` | QEMU/Xen model strings may fire; paravirtual disks may omit these files. |
| `devices.pci_vendor` | PCI vendor IDs for Xen `5853`, virtio `1af4`, VMware `15ad`, VBox `80ee`, QEMU `1234` | Xen platform/QEMU devices commonly fire. |
| `kernel.hypervisor_log` | Readable dmesg, falling back to current-boot kernel journal, for hypervisor/Xen/KVM/QEMU/VMware/VBox lines | Usually Xen boot messages; skipped when logs cannot be read. |
| `kernel.clocksource` | Current clocksource for Xen/KVM names | Usually Xen clocksource. |
| `utilities.systemd_detect_virt` | `systemd-detect-virt --vm` result | Expected `xen`; missing utility skipped. Containers alone are excluded. |
| `utilities.virt_what` | `virt-what` facts | Expected Xen facts once installed in the next golden image; missing utility skipped. |
| `resources.cpu_count` | Fewer than 2 logical CPUs in `/proc/cpuinfo` | Depends on assigned vCPUs. |
| `resources.ram` | Less than 2 GiB MemTotal | Depends on guest memory; MemTotal excludes reserved memory. |
| `resources.disk_size` | Largest non-loop/RAM/optical/floppy block disk below 60 GiB; sysfs sectors are 512 bytes | Small golden disks may fire. |
| `activity.uptime` | `/proc/uptime` below 600 seconds | May fire after fresh boot; restored uptime belongs to the snapshot. |
| `activity.process_count` | Fewer than 50 readable numeric `/proc/*/cmdline` entries | Minimal images may fire; a desktop usually increases the count. |
| `activity.logged_in` | No sessions in `who`/utmp | XFCE autologin may provide a session; display managers differ. |
| `activity.shell_history` | No nonempty bash/zsh history in `/root` and `/home/*` | Fresh profiles may fire. Only sizes are recorded. |
| `activity.recent_files` | Desktop recently-used XBEL bookmarks in user homes | Fresh desktop profiles may fire. |
| `activity.desktop_session` | No XFCE/GNOME/KDE/X11/Wayland session process | Should become clean with XFCE/autologin; root agent environment variables alone do not decide this. |
| `timing.sleep_skew` | 250 ms sleep vs monotonic and wall clock; undersleep over 20% or divergence over 100 ms | Usually clean. Host scheduling delays alone do not fire the check. |
| `debug.tracer_pid` | Nonzero `/proc/self/status` TracerPid | Usually clean: VMI is not ptrace. |
| `debug.ld_preload` | LD_PRELOAD present in checker environment | Usually clean. Library paths are not collected. |
| `debug.ptrace_traceme` | PTRACE_TRACEME in an isolated child, the conventional Linux self-tracing anti-debug probe | Usually clean. Refusal can also indicate Yama/seccomp policy and is explicitly ambiguous. The checker itself does not stay traced. |
| `tools.analysis_binaries` | strace, gdb, tcpdump, wireshark in standard binary paths | Depends on guest packages; presence is only a heuristic. |
| `sandbox.identity` | Sandbox/analysis/malware/CHIMERA/drakrun/test host/account names | CHIMERA-named guest hosts/accounts may fire. |
| `sandbox.agent_processes` | Agent/VM tool process names, including **chimera-agent** | **Expected to fire**: our own agent is a legitimate detectable artifact. |
| `sandbox.serial_console` | Active ttyS/hvc/xvc entries in `/proc/consoles` | Expected with the serial agent console; also normal on some physical servers. |

The grouping follows the hardware, virtualization, timing, anti-debug, tool and
user-activity families seen in public checklists. The systemd implementation
uses CPUID, DMI and Xen interface probes; see its
[v252 virtualization detection source](https://github.com/systemd/systemd/blob/v252/src/basic/virt.c).
The [systemd-detect-virt manual](https://www.freedesktop.org/software/systemd/man/latest/systemd-detect-virt.html)
documents `--vm`, the Xen identifier and exit semantics. Local al-khaser check
specifications provide the analogous low-resource, sleep and activity families.

## Normalization and scoring

The adapter retains the raw report and maps CPU/firmware/devices/virtualization/
resources/tools/sandbox groups to `environment_artifact`, activity to
`behavioural_interaction`, sleep to `timing`, and anti-debug probes to
`design_specific`. Group names remain in normalized evidence.

`chimera-vmcheck` is the Linux primary. It uses the existing scoring function:

`score = 100 * (1 - sum(weights of detected applicable checks) / applicable_count)`

Resource, activity, analysis-tool and timing heuristics use severity `low`
(weight 0.15); other checks use `high` (0.65). Skipped/error checks are excluded.
A failed/timed-out/malformed run, zero applicable checks, or fewer than half
applicable checks yields `incomplete` with no numeric score. Default thresholds
remain pass at 90 and warn at 70. This is a heuristic checklist score, not a
probability, and Windows and Linux scores are not calibrated against each other.
The counts and every piece of evidence remain available independently of it.
