---
title: Anti-detection hardening
group: Concepts
---
# Anti-detection hardening

Evasive malware checks whether it is running in a sandbox and, if it is, does nothing interesting. Moving the
monitor out of the guest (VMI) removes the agent, but the virtual machine itself still has tell-tale signs:
firmware strings that say "Xen", emulated devices, two CPUs and little memory, a CPUID bit that announces a
hypervisor, an idle mouse, an empty user profile. Hardening means removing or disguising those signs, and then
**measuring** whether it worked.

## What sandbox detection looks for

PERDEDOR tags each of its checks with one of four categories. They are a useful map of the whole problem:

| Category | Examples | Typical fix |
|---|---|---|
| Environment artifact | SMBIOS vendor "Xen", ACPI OEM ID, Xen platform PCI device, virtual disk model, MAC address prefix of a hypervisor vendor, few CPUs, little RAM | Configuration of the VM and its firmware |
| Timing | RDTSC around an instruction that causes a VM exit, uptime | Hard; partly unavoidable under VMI |
| Behavioural interaction | No mouse movement, no recent files, few installed programs, fresh user profile | A lived-in guest image and simulated input |
| Design-specific | Quirks of one analysis platform or build | Case by case |

## Measures in CHIMERA

| Area | Measure | How |
|---|---|---|
| Firmware strings | Real-looking SMBIOS manufacturer, product and BIOS strings | `smbios=[…]` in the guest's xl configuration template |
| ACPI tables | The host's ACPI OEM IDs instead of "Xen" | An `hvmloader` built with a small libacpi patch (`scripts/chimera/arms/build-hvmloader-acpi.sh`), selected with `firmware_override`; takes effect on a cold boot of `vm-0` |
| Devices | No Xen platform PCI device, no emulated sound card, a real disk model string, a MAC address with a real vendor prefix | `xen_platform_pci=0`, no `soundhw`, `device_model_args_hvm` for the disk model, `vif … mac=` |
| Size | 4 vCPUs and more than 4 GiB of memory | Install parameters of the golden image |
| CPUID | Hypervisor-present bit cleared, Xen's `0x40000000`–`0x40000004` leaves hidden | DRAKVUF `cpuidmon` with `-s`, at run time |
| Human input | Mouse movement and occasional clicks | DRAKVUF `hidsim` (`--hid-random-clicks`) |
| Lived-in guest | Everyday applications, dated documents, browser and shell history; on Linux an XFCE desktop with an ordinary user | Prepared in a `modify-vm0` session (Windows) or by the Linux image build |
| Launch context | The sample starts from a normal Explorer session, not from a job object or an unusual parent | Checked before every snapshot commit |

The runtime measures are DRAKVUF options in `/etc/drakrun/config.toml`:

```toml
[drakrun]
plugins = ["apimon", "clipboardmon", "exmon", "filetracer", "memdump", "procmon", "regmon",
           "socketmon", "tlsmon", "cpuidmon", "hidsim"]
extra_drakvuf_args = { "-s" = true, "--hid-random-clicks" = true }
```

## Measuring it: experiment arms

Every hardening step was introduced as an **arm**: a snapshot plus VM profile that can be switched in and out
with `scripts/chimera/arms/chimera-arm use <ARM>`, so each measure is measured against the previous one rather
than assumed.

| Arm | Contents |
|---|---|
| A0 | Baseline: the guest with Xen defaults |
| H1 | SMBIOS strings, no Xen PCI device, no sound card, 4 vCPUs and more memory, real MAC prefix, disk model, first guest realism; measured without and with `cpuidmon -s`, `hidsim` and both, which then stayed on |
| H2 | H1 plus the host's ACPI OEM IDs, SMBIOS OEM strings and the remaining virtual devices removed |
| H3 | H2 plus a set of everyday applications installed in the guest |

Each arm is scanned several times with PERDEDOR, al-khaser and Pafish run as samples through the normal analysis
path, **with the DRAKVUF plugins attached**, because a guest that looks clean without instrumentation can still
give itself away under it. Results are reported per check (how often it fired), not as one number. On H3 the
PERDEDOR weighted score reached 100.0 while al-khaser still reported a set of residual detections, listed below.
See [Evasion verification](verification.md) for how to run such scans.

> Some techniques in third-party evasion-detection tools are excluded from CHIMERA's scans because running them
> destabilises the guest. Their results are not part of any reported score.

## What is still detectable

- **Timing.** `cpuidmon -s` traps every CPUID, which makes a CPUID-in-a-timing-loop check slower, not faster.
  RDTSC-based checks around VM exits remain a known residual of VMI on Xen.
- **Hardware sensors and tables.** WMI temperature and fan sensors, the number and shape of ACPI/SMBIOS tables,
  and the QEMU device set (network card, graphics) beyond their name strings.
- **EPT and altp2m side effects** specific to how DRAKVUF traps memory.
- **Teaching to the test.** PERDEDOR's thresholds are the project's own, so any "harder to detect" claim also
  needs the independent suites (al-khaser, Pafish).

Deeper anti-evasion work (sensors, CPUID exit timing, ACPI tables, launch parent) is in
[future scope](limitations.md).
