---
title: VMI, Xen and DRAKVUF
group: Concepts
---
# VMI, Xen and DRAKVUF

## Why introspection

Most sandboxes put a monitoring agent inside the guest: a driver or a DLL that hooks API calls and reports them.
Malware can look for that agent (its files, its driver, its hooks in memory) and simply stay quiet.
**Virtual-machine introspection (VMI)** moves the monitor out of the guest. The hypervisor already controls the
guest's CPU and memory, so a program in the privileged control domain can read guest memory, interpret it as
kernel data structures, and ask the hypervisor to stop the guest at chosen instructions or memory accesses.
Nothing is installed in the guest for the observation itself.

> CHIMERA still uses small guest-side helpers for orchestration: drakshell on Windows and a serial console
> helper on Linux start the sample and collect a few results. They are not the monitor; tracing is done from
> outside.

## Xen, dom0 and HVM guests

Xen is a type-1 hypervisor: it runs directly on the hardware and every operating system above it is a domain.

- **dom0** is the privileged control domain. In CHIMERA it is a Debian 12 system that runs the Xen toolstack
  (`xl`), the QEMU device model for the guests, DRAKVUF, and every CHIMERA service.
- **domU** guests are unprivileged. The analysis guests (`vm-1`, `vm-2`, …) are **HVM** guests: fully
  hardware-virtualised with Intel VT-x, so an unmodified Windows 10 or Linux kernel runs in them, with firmware
  from Xen's `hvmloader` and devices emulated by QEMU. The static-analysis VM is a lighter **PVH** guest with no
  emulated devices and no network interface.

Two hardware features matter for introspection:

- **EPT** (Extended Page Tables) translate guest-physical addresses to machine addresses in hardware. Each
  translation carries read/write/execute permissions that the hypervisor controls, so it can be told when a
  guest touches a particular page, without changing the guest's own page tables.
- **VM exits and vm_event.** Breakpoint instructions, EPT permission faults, CPUID, writes to CR3 (a new
  process address space) and single-steps can all exit to Xen, which forwards them as events to a listener in
  dom0. DRAKVUF is that listener.

## altp2m: hiding the breakpoints

DRAKVUF traces a function by writing a breakpoint (`0xCC`) at its first instruction. Malware that reads its own
code, or checks whether a system DLL has been patched, would see that byte. **altp2m** (alternate p2m) gives one
guest several EPT views of its memory:

1. DRAKVUF copies each page it wants to trap and writes the breakpoint into the copy (the shadow page).
2. In the execution view the guest-physical page maps to the shadow, so executing the function hits the
   breakpoint and exits to DRAKVUF.
3. The shadow page is execute-only. When the guest *reads* it, the EPT fault makes DRAKVUF switch that vCPU to
   the original view, single-step the read, and switch back. The guest only ever reads the original bytes.

That is why Xen is booted with `altp2m=1` and why breakpoint-integrity checks inside the guest do not see the
traps.

## LibVMI and profiles

DRAKVUF uses **LibVMI** to map guest memory and translate virtual addresses. To make sense of the bytes it needs
a profile of the guest kernel: structure layouts and symbol offsets.

- **Windows:** `drakrun make-profile` / `drakrun postinstall` read the kernel's GUID with `vmi-win-guid`, fetch the
  PDB symbols and write JSON profiles to `/var/lib/drakrun/profiles` (the kernel, and user-mode DLLs such as
  ntdll, kernel32, kernelbase, win32k, tcpip, for API tracing).
- **Linux:** the profile is built with `dwarf2json` from the debug package of the exact guest kernel
  (`drakrun make-profile --guest-os linux --debug-package …`). The kernel in the guest and the profile must match.

## DRAKVUF plugins

DRAKVUF is a set of plugins on top of that machinery. The default Windows set comes from
`drakrun/data/config.toml`; plugins can be added per analysis on the upload page.

| Plugin | What it records |
|---|---|
| `procmon` | Process creation and exit, command lines, parent/child relations: the basis of the process tree |
| `apimon` | User-mode API calls and arguments from a hook list (`apimon_hooks_path`) |
| `filetracer` | File operations at the NT syscall level (create, read, write, delete, rename) |
| `regmon` | Registry keys and values opened, set and deleted |
| `socketmon` | TCP/UDP connections and DNS queries made by guest processes |
| `tlsmon` | TLS session keys from the guest's crypto library, so the PCAP can be decrypted |
| `memdump` | Memory regions saved on heuristics: remote threads, written-then-executed memory, freed images |
| `exmon` | Exceptions raised in the guest |
| `clipboardmon` | Clipboard access |
| `cpuidmon` | CPUID executions; with `-s` it hides the hypervisor bit and Xen's CPUID leaves (see [hardening](concepts-hardening.md)) |
| `hidsim` | Simulated mouse movement and clicks, so the guest shows human input |

The Linux pipeline uses DRAKVUF's Linux plugins: `procmon`, `syscalls` (with a CHIMERA patch for socket
addresses), `filetracer`, `unixsocketmon`, `ptracemon` and `ebpfmon`, with `cpuidmon -s` always on.

## Starting the sample: the injector

To start the sample, DRAKVUF's **injector** hijacks a thread in a running guest process and makes it call a
function of the injector's choice: write a file into the guest, then start it. The upload page offers the start
methods `createproc`, `shellexec` and `runas`. On Linux the sample is written with injector `writefile` and the
serial helper starts it after a launch gate.

## Disposable guests

Each analysis VM is restored from a saved snapshot of a golden image (`vm-0`): disk changes go to a throwaway
overlay and the memory state is loaded from `snapshot.sav`, so a guest is ready in a few seconds (3.4–3.5 s
measured during the containment tests). The guest is destroyed when the analysis ends, whatever the sample did.
Before a restore, the worker waits for enough free Xen memory (`[worker] memory_admission_*`), so two analyses
never overcommit the host.
