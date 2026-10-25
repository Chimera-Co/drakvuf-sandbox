#!/usr/bin/env python3
"""
Compare identity.ps1 output (stdin) with an arm's cfg.template.

  ... gx.py vm-1 10 powershell.exe -File C:\\...\\identity.ps1 | check_identity.py H1/cfg.template --vcpus 4 --memory 5120

Exits non-zero if any check fails. SMBIOS expectations come from the cfg's
smbios list, so the template stays the single source of truth.
"""

import argparse
import re
import sys


def parse_report(text):
    report = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep:
            report[key] = value
    return report


def expected_from_cfg(cfg_text):
    expected = dict(re.findall(r'"((?:bios|system|baseboard|enclosure)_[a-z_]+)=([^"]*)"', cfg_text))
    model = re.search(r"ide-hd\.model=([^\"]+)\"", cfg_text)
    if model:
        expected["disk_model"] = model.group(1)
    mac = re.search(r"mac=([0-9a-f:]+?)(?:0\{\{|\{\{)", cfg_text, re.I)
    return expected, (mac.group(1).upper() if mac else None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cfg", type=argparse.FileType("r"))
    parser.add_argument("--vcpus", type=int, required=True)
    parser.add_argument("--memory", type=int, required=True, help="configured MiB")
    args = parser.parse_args()

    report = parse_report(sys.stdin.read())
    expected, mac_prefix = expected_from_cfg(args.cfg.read())
    checks = []
    for key, want in expected.items():
        if key in report:
            # Windows appends " ATA Device" to the model of IDE/SATA disks.
            ok = report[key].startswith(want) if key == "disk_model" else report[key] == want
            checks.append((key, ok, f"{report[key]!r} (want {want!r})"))
    if mac_prefix:
        mac = report.get("mac", "")
        checks.append(("mac", mac.upper().startswith(mac_prefix), f"{mac} (want {mac_prefix}*)"))
    checks += [
        ("logical_processors", report.get("logical_processors") == str(args.vcpus), report.get("logical_processors")),
        # Windows reports a little less than the configured RAM.
        ("memory_mb", args.memory * 0.9 <= int(report.get("memory_mb", 0)) <= args.memory, report.get("memory_mb")),
        ("xen_pci_devices", report.get("xen_pci_devices") == "0", report.get("xen_pci_devices")),
        ("defender_realtime", report.get("defender_realtime") == "False", report.get("defender_realtime")),
    ]
    # Reported by identity.ps1 since 2026-10-19 evening; older reports skip them.
    if "acpi_oem_version" in report:
        oem = report["acpi_oem_version"]
        checks.append(("acpi_oem_version", not oem.upper().startswith(("XEN", "BOCHS", "QEMU")), oem))
    if "phantom_vm_devices" in report:
        checks.append(("phantom_vm_devices", report["phantom_vm_devices"] == "0", report["phantom_vm_devices"]))
    failed = 0
    for name, ok, detail in checks:
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    missing = sorted(set(expected) - set(report))
    if missing:
        print(f"not reported by the guest (unchecked): {', '.join(missing)}")
    print(f"{len(checks) - failed}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
