#!/usr/bin/env python3
"""Linux anti-VM/analysis checklist. Standard library only; no network probes.

Each probe records its technique and evidence. Missing dependencies/permissions
are skipped, never inferred clean. This is a heuristic checklist, not attestation.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

VERSION = "1.0"
VM_WORDS = re.compile(
    r"xen|kvm|qemu|virtualbox|vbox|vmware|innotek|bochs|bhyve|parallels|virtual machine|hvm domu|microsoft corporation",
    re.I,
)
MAC_OUIS = {
    "00:16:3e": "Xen",
    "00:05:69": "VMware",
    "00:0c:29": "VMware",
    "00:1c:14": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5d": "Hyper-V",
}
PCI_VENDORS = {
    "0x5853": "Xen",
    "0x1af4": "virtio",
    "0x15ad": "VMware",
    "0x80ee": "VirtualBox",
    "0x1234": "QEMU",
}
SUSPICIOUS = re.compile(
    r"sandbox|malware|analysis|analyst|cuckoo|cape|drakrun|chimera|^test(?:user)?$",
    re.I,
)


class Checker:
    def __init__(self, root="/", command=None, environ=None, sleeper=time.sleep):
        self.root = Path(root)
        self.command = command or self._command
        self.environ = dict(os.environ if environ is None else environ)
        self.sleeper = sleeper

    def path(self, name):
        return self.root / name.lstrip("/")

    def read(self, name):
        # Bound evidence, including /proc/* files whose stat size is zero.
        with self.path(name).open("r", errors="replace") as handle:
            return handle.read(65536).strip()

    def glob(self, pattern):
        return sorted(self.root.glob(pattern.lstrip("/")))

    @staticmethod
    def _command(argv):
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "LC_ALL": "C"},
        )
        return (
            result.returncode,
            result.stdout[:65536].strip(),
            result.stderr[-2048:].strip(),
        )

    def check_cpu(self):
        text = self.read("/proc/cpuinfo")
        flags = re.findall(r"^(?:flags|Features)\s*:\s*(.*)$", text, re.M)
        yield "cpu.hypervisor_flag", "cpu", "CPUID hypervisor-present flag exposed by /proc/cpuinfo", any(
            "hypervisor" in f.split() for f in flags
        ), {
            "hypervisor_flag": any("hypervisor" in f.split() for f in flags)
        }

    def check_vendor(self):
        rc, out, err = self.command(["lscpu"])
        if rc:
            raise OSError(err or "lscpu failed")
        vendors = re.findall(r"^Hypervisor vendor:\s*(.+)$", out, re.M)
        yield "cpu.hypervisor_vendor", "cpu", "lscpu hypervisor vendor (CPUID/kernel virtualization information)", bool(
            vendors
        ), vendors

    def check_hypervisor(self):
        entries = self.glob("/sys/hypervisor/*")
        values = {}
        for entry in entries:
            if entry.is_file():
                values[entry.name] = self.read(str(entry.relative_to(self.root)))
        yield "hypervisor.sysfs", "virtualization", "/sys/hypervisor entries/type", bool(
            entries
        ), {
            "entries": [p.name for p in entries],
            "values": values,
        }
        xen = self.path("/proc/xen").exists()
        yield "hypervisor.proc_xen", "virtualization", "/proc/xen presence", xen, {
            "present": xen
        }

    def check_modules(self):
        modules = [
            line.split()[0]
            for line in self.read("/proc/modules").splitlines()
            if line.split()
        ]
        found = [
            name
            for name in modules
            if re.search(r"^(xen|kvm|vbox|vmw|vmware)", name, re.I)
        ]
        yield "kernel.vm_modules", "virtualization", "Loaded Xen/KVM/VirtualBox/VMware modules (KVM can also indicate a host)", bool(
            found
        ), found

    def check_dmi(self):
        for field in (
            "sys_vendor",
            "product_name",
            "bios_vendor",
            "board_vendor",
            "chassis_vendor",
            "product_serial",
        ):
            try:
                value = self.read("/sys/class/dmi/id/" + field)
                yield "dmi." + field, "firmware", "DMI vendor/product/serial string", bool(
                    VM_WORDS.search(value)
                ), value
            except OSError as exc:
                yield "dmi." + field, "firmware", "DMI vendor/product/serial string", None, str(
                    exc
                )

    def check_devices(self):
        interfaces = self.glob("/sys/class/net/*/address")
        macs = {
            p.parent.name: self.read(str(p.relative_to(self.root))) for p in interfaces
        }
        yield "devices.mac_oui", "devices", "Virtual NIC MAC OUI prefixes", any(
            v.lower()[:8] in MAC_OUIS for v in macs.values()
        ), macs
        disks = self.glob("/sys/block/*/device/model") + self.glob(
            "/sys/block/*/device/vendor"
        )
        strings = {
            str(p.relative_to(self.root)): self.read(str(p.relative_to(self.root)))
            for p in disks
        }
        yield "devices.disk_identity", "devices", "Block device model/vendor strings", (
            bool(any(VM_WORDS.search(v) for v in strings.values())) if strings else None
        ), strings
        pci = self.glob("/sys/bus/pci/devices/*/vendor")
        vendors = {
            p.parent.name: self.read(str(p.relative_to(self.root))).lower() for p in pci
        }
        yield "devices.pci_vendor", "devices", "Xen/virtio/VMware/VirtualBox/QEMU PCI vendor IDs", (
            any(v in PCI_VENDORS for v in vendors.values()) if vendors else None
        ), vendors

    def check_kernel_log(self):
        rc, out, err = self.command(["dmesg", "--color=never"])
        if rc:
            rc, out, err = self.command(
                ["journalctl", "-k", "-b", "--no-pager", "-n", "300"]
            )
        if rc or not out or out == "-- No entries --":
            raise OSError(err or "kernel log unavailable")
        lines = [
            line
            for line in out.splitlines()
            if re.search(r"hypervisor|xen|kvm|qemu|vmware|vbox", line, re.I)
        ]
        yield "kernel.hypervisor_log", "virtualization", "Readable dmesg or current-boot kernel journal hypervisor lines", bool(
            lines
        ), lines[
            :30
        ]

    def check_clocksource(self):
        source = self.read(
            "/sys/devices/system/clocksource/clocksource0/current_clocksource"
        )
        yield "kernel.clocksource", "virtualization", "Xen/KVM paravirtual clocksource", bool(
            re.search(r"xen|kvm", source, re.I)
        ), source

    def check_utilities(self):
        for tool, argv in (
            ("systemd_detect_virt", ["systemd-detect-virt", "--vm"]),
            ("virt_what", ["virt-what"]),
        ):
            try:
                rc, out, err = self.command(argv)
                # systemd uses 1 / 'none' for no VM; virt-what uses 0 / empty.
                if (tool == "systemd_detect_virt" and rc not in (0, 1)) or (
                    tool == "virt_what" and rc
                ):
                    raise OSError(err or "utility failed")
                if tool == "systemd_detect_virt" and rc == 1 and out != "none":
                    raise OSError(err or "utility could not determine virtualization")
                found = bool(out and out != "none")
                yield "utilities." + tool, "virtualization", "Public Linux VM detection utility", found, {
                    "rc": rc,
                    "stdout": out,
                    "stderr": err,
                }
            except (OSError, subprocess.SubprocessError) as exc:
                yield "utilities." + tool, "virtualization", "Public Linux VM detection utility", None, str(
                    exc
                )

    def check_resources(self):
        cpus = len(re.findall(r"^processor\s*:", self.read("/proc/cpuinfo"), re.M))
        yield "resources.cpu_count", "resources", "Fewer than 2 logical CPUs", (
            cpus < 2 if cpus else None
        ), {"cpus": cpus, "minimum": 2}
        mem = re.search(r"^MemTotal:\s*(\d+)", self.read("/proc/meminfo"), re.M)
        kb = int(mem.group(1)) if mem else None
        yield "resources.ram", "resources", "Less than 2 GiB RAM", (
            kb < 2 * 1024**2 if kb is not None else None
        ), {"ram_kib": kb, "minimum_kib": 2 * 1024**2}
        sizes = {
            p.parent.name: int(self.read(str(p.relative_to(self.root)))) * 512
            for p in self.glob("/sys/block/*/size")
            if not re.match(r"loop|ram|sr|fd", p.parent.name)
        }
        yield "resources.disk_size", "resources", "All non-loop/RAM/optical/floppy disks smaller than 60 GiB (512-byte sysfs sectors)", (
            max(sizes.values()) < 60 * 1024**3 if sizes else None
        ), sizes

    def processes(self):
        result = {}
        for p in self.glob("/proc/[0-9]*/cmdline"):
            try:
                # Evidence names only: never copy arbitrary argv/secrets.
                args = self.read(str(p.relative_to(self.root))).split("\0")
                result[p.parent.name] = [Path(arg).name for arg in args[:2]]
            except OSError:
                continue  # processes may exit during enumeration
        return result

    def check_activity(self):
        uptime = float(self.read("/proc/uptime").split()[0])
        yield "activity.uptime", "activity", "Uptime below 10 minutes", uptime < 600, {
            "seconds": uptime,
            "minimum": 600,
        }
        procs = self.processes()
        yield "activity.process_count", "activity", "Fewer than 50 readable process command lines", len(
            procs
        ) < 50, {
            "processes": len(procs),
            "minimum": 50,
        }
        rc, out, err = self.command(["who"])
        yield "activity.logged_in", "activity", "No users reported by who/utmp", (
            not bool(out) if rc == 0 else None
        ), {"sessions": len(out.splitlines()), "error": err}

    def check_desktop(self):
        homes = [self.path("/root")] + self.glob("/home/*")
        histories, recent = {}, {}
        for home in homes:
            for filename in (".bash_history", ".zsh_history"):
                p = home / filename
                if p.exists():
                    histories[str(p.relative_to(self.root))] = p.stat().st_size
            p = home / ".local/share/recently-used.xbel"
            if p.exists():
                recent[str(p.relative_to(self.root))] = len(
                    ET.fromstring(self.read(str(p.relative_to(self.root)))).findall(
                        "bookmark"
                    )
                )
        yield "activity.shell_history", "activity", "No nonempty bash/zsh history in root or user homes (content is not collected)", not any(
            histories.values()
        ), histories
        yield "activity.recent_files", "activity", "No recently-used.xbel bookmark entries in user homes", not any(
            recent.values()
        ), recent
        procs = self.processes()
        desktop = {
            pid: names
            for pid, names in procs.items()
            if any(
                re.search(
                    r"xfce4-session|gnome-session|plasmashell|Xorg|Xwayland|wayland",
                    n,
                    re.I,
                )
                for n in names
            )
        }
        yield "activity.desktop_session", "activity", "No XFCE/GNOME/KDE/X11/Wayland session process", not bool(
            desktop
        ), desktop

    def check_timing(self):
        requested = 0.25
        wall, mono = time.time(), time.monotonic()
        self.sleeper(requested)
        monotonic_elapsed, wall_elapsed = time.monotonic() - mono, time.time() - wall
        found = (
            monotonic_elapsed < requested * 0.8
            or abs(wall_elapsed - monotonic_elapsed) > 0.1
        )
        yield "timing.sleep_skew", "timing", "250 ms sleep vs monotonic and realtime clocks (20% undersleep / 100 ms divergence)", found, {
            "requested_s": requested,
            "monotonic_s": monotonic_elapsed,
            "wall_s": wall_elapsed,
        }

    def check_debug(self):
        status = self.read("/proc/self/status")
        tracer = re.search(r"^TracerPid:\s*(\d+)", status, re.M)
        yield "debug.tracer_pid", "debug", "/proc/self/status TracerPid", (
            int(tracer.group(1)) != 0 if tracer else None
        ), {"tracer_pid": int(tracer.group(1)) if tracer else None}
        preload = self.environ.get("LD_PRELOAD", "")
        yield "debug.ld_preload", "debug", "LD_PRELOAD instrumentation environment variable", bool(
            preload
        ), {
            "present": bool(preload)
        }

    def check_ptrace(self):
        # PTRACE_TRACEME is the conventional 'self-attach' anti-debug probe.
        # Isolate it in a short-lived child: the checker must not remain traced
        # or stop itself. EPERM is ambiguous (debugger, Yama or seccomp).
        code = "import ctypes,json,os; c=ctypes.CDLL(None,use_errno=True); r=c.ptrace(0,0,None,None); print(json.dumps({'rc':r,'errno':ctypes.get_errno()}),flush=True); os._exit(0)"
        rc, out, err = self.command(["python3", "-c", code])
        if rc:
            raise OSError(err or "ptrace child failed")
        value = json.loads(out)
        yield "debug.ptrace_traceme", "debug", "Child PTRACE_TRACEME refusal; may also mean Yama/seccomp policy", value[
            "rc"
        ] == -1, value

    def check_tools(self):
        # Avoid PATH/host dependencies in fixture runs: inspect guest paths.
        found = [
            name
            for name in ("strace", "gdb", "tcpdump", "wireshark")
            if any(
                self.path(prefix + "/" + name).is_file()
                for prefix in (
                    "/usr/bin",
                    "/bin",
                    "/usr/sbin",
                    "/sbin",
                    "/usr/local/bin",
                )
            )
        ]
        yield "tools.analysis_binaries", "tools", "strace/gdb/tcpdump/wireshark installed in standard executable paths", bool(
            found
        ), found

    def check_sandbox(self):
        hostname = self.read("/proc/sys/kernel/hostname")
        users = [
            line.split(":")[0] for line in self.read("/etc/passwd").splitlines() if line
        ]
        names = [name for name in [hostname] + users if SUSPICIOUS.search(name)]
        yield "sandbox.identity", "sandbox", "Analysis/sandbox/test host or account names (heuristic)", bool(
            names
        ), names
        procs = self.processes()
        agents = {
            pid: names
            for pid, names in procs.items()
            if any(
                re.search(
                    r"chimera-agent|drakshell|qemu-ga|VBoxService|vmtoolsd|cuckoo|sandbox-agent",
                    n,
                    re.I,
                )
                for n in names
            )
        }
        yield "sandbox.agent_processes", "sandbox", "Analysis/VM agent process names, including chimera-agent", bool(
            agents
        ), agents
        consoles = self.read("/proc/consoles")
        serial = [
            line
            for line in consoles.splitlines()
            if re.search(r"ttyS\d|hvc\d|xvc\d", line)
        ]
        yield "sandbox.serial_console", "sandbox", "Active serial/paravirtual consoles (also legitimate on physical servers)", bool(
            serial
        ), serial

    def report(self):
        checks = []
        for group in (
            "cpu",
            "vendor",
            "hypervisor",
            "modules",
            "dmi",
            "devices",
            "kernel_log",
            "clocksource",
            "utilities",
            "resources",
            "activity",
            "desktop",
            "timing",
            "debug",
            "ptrace",
            "tools",
            "sandbox",
        ):
            try:
                for ident, category, technique, detected, evidence in getattr(
                    self, "check_" + group
                )():
                    checks.append(
                        {
                            "id": ident,
                            "category": category,
                            "detected": bool(detected),
                            "evidence": evidence,
                            "technique": technique,
                            "status": "skipped" if detected is None else "ok",
                        }
                    )
            except (
                OSError,
                ValueError,
                ET.ParseError,
                subprocess.SubprocessError,
            ) as exc:
                checks.append(
                    {
                        "id": group + ".unavailable",
                        "category": {
                            "vendor": "cpu",
                            "modules": "virtualization",
                            "kernel_log": "virtualization",
                            "clocksource": "virtualization",
                            "hypervisor": "virtualization",
                            "dmi": "firmware",
                            "desktop": "activity",
                            "ptrace": "debug",
                        }.get(group, group),
                        "detected": False,
                        "evidence": str(exc),
                        "technique": "Probe group " + group,
                        "status": "skipped",
                    }
                )
        return {
            "tool": "chimera-vmcheck",
            "version": VERSION,
            "total": len(checks),
            "detected": sum(c["detected"] for c in checks),
            "checks": checks,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, help="Write the JSON report to this path"
    )
    args = parser.parse_args()
    Path(args.output).write_text(
        json.dumps(Checker().report(), indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
