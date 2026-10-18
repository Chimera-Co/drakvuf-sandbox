"""al-khaser adapter.

Ground truth for everything in this module was read directly from
al-khaser/Al-khaser.cpp (LordNoteworthy/al-khaser, master branch) - not from
its README, which does not document the CLI. Six behaviours verified there
drive this adapter's design; each is load-bearing, not incidental:

1. The ONLY real CLI surface is:
       al-khaser.exe [--check <TYPE>]... [--sleep SECONDS | --delay SECONDS] [-h|--help]
   There is no output-format flag, no log-path flag, no quiet flag. 18 valid
   --check values exist (ALKHASER_CHECK_TYPES below); EnableChecks() has no
   `else` branch, so an unrecognized value silently enables nothing while
   still counting as "some check was requested" - which suppresses
   EnableDefaultChecks() and leaves al-khaser running ZERO checks while still
   exiting 0. validate_options() below refuses unknown names outright so we
   never repeat that bug.

2. main() ends in `getchar(); return 0;`, which blocks forever reading from
   stdin under a pipe. The adapter's command MUST redirect stdin from NUL
   (build_argv() always wraps the real command in
   `cmd /c "<cmd> < NUL > stdout.txt 2>&1"`).

3. The exit code is unconditionally 0 (`return 0` is the only return in
   main()). It is never used to infer success or the presence of detections.

4. EnableDefaultChecks() enables 17 of the 18 types - every one except
   CODE_INJECTIONS. "Full" (no --check flags at all) is therefore genuinely
   17/18, not all of them; CODE_INJECTIONS is opt-in only.

5. TIMING_ATTACKS defaults --sleep to 600 seconds and performs NINE separate
   sleeps of that duration (nine distinct timing_* exec_check calls), so an
   unqualified full run sleeps for roughly 90 minutes. --sleep is therefore
   ALWAYS passed explicitly by this adapter; ALKHASER_DEFAULT_SLEEP_SECONDS
   is the fallback when the caller supplies none.

6. Per-check results reach the host through two surfaces, both format-
   verified against Shared/Common.cpp and Shared/log.cpp:
     - log.txt (LOG_PRINT, written to the process's CWD): each line is
       "[<asctime>] [*] <msg> -> <0|1>" - purely numeric, the primary source.
     - stdout: colour comes from SetConsoleTextAttribute (not ANSI escapes,
       so a redirected file is clean text); each line is
       "[*] <msg><padding to column 95>[ BAD  ]" (two spaces, detected) or
       "[ GOOD ]" (one space, clean) - kept only as a fallback.
   Crucially, NOT every --check type routes its checks through exec_check.
   VPC, ANALYSIS_TOOLS, ANTI_DISASSM, DUMPING_CHECK, and CODE_INJECTIONS call
   their detection functions directly with no exec_check wrapper at all, so
   they never appear in log.txt or as a [ GOOD ]/[ BAD ] line - there is no
   machine-readable verdict to parse for them, ever, in this al-khaser
   version (0.82). Several other categories (VBOX, VMWARE, QEMU, XEN, KVM,
   WINE, PARALLELS) mix exec_check-wrapped calls with bare, unwrapped ones
   (e.g. vbox_reg_keys(), vmware_files(), qemu_processes()) - only the
   exec_check-wrapped subset is parsed into NormalizedChecks; the bare calls'
   console output is preserved as raw text but is never turned into a
   fabricated per-check finding, because we have not verified those
   functions' own output format.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from drakrun.evasion.constants import Category, CheckStatus, Severity, ToolStatus
from drakrun.evasion.models import NormalizedCheck, ToolResult
from drakrun.evasion.verifiers.base import (
    GuestSession,
    VerifierAdapter,
    VerifierError,
    VerifierTimeout,
)

TOOL_ID = "alkhaser"

# The 18 values EnableChecks() recognizes (Al-khaser.cpp print_help()/EnableChecks()).
ALKHASER_CHECK_TYPES: Tuple[str, ...] = (
    "TLS",
    "DEBUG",
    "INJECTION",
    "GEN_SANDBOX",
    "VBOX",
    "VMWARE",
    "VPC",
    "QEMU",
    "KVM",
    "XEN",
    "WINE",
    "PARALLELS",
    "HYPERV",
    "CODE_INJECTIONS",
    "TIMING_ATTACKS",
    "DUMPING_CHECK",
    "ANALYSIS_TOOLS",
    "ANTI_DISASSM",
)

# EnableDefaultChecks() sets every ENABLE_*_CHECKS flag to TRUE except
# ENABLE_CODE_INJECTIONS, which stays FALSE. This is "no --check flags at
# all" behaviour, reproduced here (not just "all 18") for both argv building
# (full profile omits --check entirely, exactly like a bare invocation) and
# for the parser, which needs to know what actually ran without any --check
# flags on the command line.
DEFAULT_ENABLED_CHECK_TYPES: Tuple[str, ...] = tuple(
    t for t in ALKHASER_CHECK_TYPES if t != "CODE_INJECTIONS"
)

ALKHASER_DEFAULT_SLEEP_SECONDS = 30
# al-khaser's own default (Al-khaser.cpp: `UINT delayInSeconds = 600U;`),
# recorded here only so the adapter can warn about it - never used as our
# own default, since TIMING_ATTACKS performs nine sleeps of this duration.
ALKHASER_UPSTREAM_DEFAULT_SLEEP_SECONDS = 600

# main()'s fixed, unconditional execution order (verified: the only #ifdef in
# the entire file guards AntiDisassmSEHMisuse() inside ANTI_DISASSM, which
# produces no exec_check output regardless). This order is what a positional
# log-line parser must walk, independent of the order --check flags were
# passed on the command line.
MAIN_EXECUTION_ORDER: Tuple[str, ...] = (
    "TLS",
    "DEBUG",
    "INJECTION",
    "GEN_SANDBOX",
    "VBOX",
    "VMWARE",
    "VPC",
    "QEMU",
    "XEN",
    "KVM",
    "WINE",
    "PARALLELS",
    "HYPERV",
    "CODE_INJECTIONS",
    "TIMING_ATTACKS",
    "ANALYSIS_TOOLS",
    "ANTI_DISASSM",
    "DUMPING_CHECK",
)


class _CheckSpec:
    """One exec_check-wrapped call site, in the exact order it executes.

    ``message`` is copied verbatim (including trailing spaces where the
    source has them) from the TEXT(...) literal passed to exec_check, since
    that is the exact string LOG_PRINT and stdout both render. Matching
    strips trailing whitespace on both sides, so the literal spacing only
    needs to be present, not reproduced pixel-perfectly by callers.
    """

    __slots__ = ("slug", "message", "category", "description")

    def __init__(self, slug: str, message: str, category: Category, description: str):
        self.slug = slug
        self.message = message
        self.category = category
        self.description = description


# Per-check-type, ordered exactly as the exec_check(...) calls appear in
# Al-khaser.cpp. Category placement follows PERDEDOR's own stated bins
# (perdedor/agents/windows/README.md's per-category check table) wherever a
# clear parallel exists - e.g. PERDEDOR explicitly credits "mouse cursor
# movement (al-khaser Human Interface check)" under behavioural_interaction,
# and explicitly lists "NIC MAC OUI" and "hypervisor guest-tool window-class
# detection (FindWindow)" under design_specific, not environment_artifact.
# Where al-khaser has no PERDEDOR parallel, the placement is this adapter's
# own reasoned judgement (documented inline) - never al-khaser's own claim,
# since al-khaser does not categorize its checks at all.
_CHECK_TYPE_CHECKS: Dict[str, List[_CheckSpec]] = {
    "TLS": [
        _CheckSpec(
            "tls_process_attach_callback",
            "TLS process attach callback ",
            Category.design_specific,
            "Detects a debugger via a TLS callback registered for process attach.",
        ),
        _CheckSpec(
            "tls_thread_attach_callback",
            "TLS thread attach callback ",
            Category.design_specific,
            "Detects a debugger via a TLS callback registered for thread attach.",
        ),
    ],
    "DEBUG": [
        _CheckSpec(
            "is_debugger_present_api",
            "Checking IsDebuggerPresent API ",
            Category.design_specific,
            "IsDebuggerPresent() API check.",
        ),
        _CheckSpec(
            "is_debugger_present_peb",
            "Checking PEB.BeingDebugged ",
            Category.design_specific,
            "PEB.BeingDebugged flag check.",
        ),
        _CheckSpec(
            "check_remote_debugger_present_api",
            "Checking CheckRemoteDebuggerPresent API ",
            Category.design_specific,
            "CheckRemoteDebuggerPresent() API check.",
        ),
        _CheckSpec(
            "nt_global_flag",
            "Checking PEB.NtGlobalFlag ",
            Category.design_specific,
            "PEB.NtGlobalFlag heap-flag check.",
        ),
        _CheckSpec(
            "heap_flags",
            "Checking ProcessHeap.Flags ",
            Category.design_specific,
            "Process heap Flags field check.",
        ),
        _CheckSpec(
            "heap_force_flags",
            "Checking ProcessHeap.ForceFlags ",
            Category.design_specific,
            "Process heap ForceFlags field check.",
        ),
        _CheckSpec(
            "low_fragmentation_heap",
            "Checking Low Fragmentation Heap",
            Category.design_specific,
            "Low Fragmentation Heap indicator check.",
        ),
        _CheckSpec(
            "ntqip_debug_port",
            "Checking NtQueryInformationProcess with ProcessDebugPort ",
            Category.design_specific,
            "NtQueryInformationProcess(ProcessDebugPort) check.",
        ),
        _CheckSpec(
            "ntqip_debug_flags",
            "Checking NtQueryInformationProcess with ProcessDebugFlags ",
            Category.design_specific,
            "NtQueryInformationProcess(ProcessDebugFlags) check.",
        ),
        _CheckSpec(
            "ntqip_debug_object",
            "Checking NtQueryInformationProcess with ProcessDebugObject ",
            Category.design_specific,
            "NtQueryInformationProcess(ProcessDebugObject) check.",
        ),
        _CheckSpec(
            "wudf_is_any_debugger_present",
            "Checking WudfIsAnyDebuggerPresent API ",
            Category.design_specific,
            "WudfIsAnyDebuggerPresent() API check.",
        ),
        _CheckSpec(
            "wudf_is_kernel_debugger_present",
            "Checking WudfIsKernelDebuggerPresent API ",
            Category.design_specific,
            "WudfIsKernelDebuggerPresent() API check.",
        ),
        _CheckSpec(
            "wudf_is_user_debugger_present",
            "Checking WudfIsUserDebuggerPresent API ",
            Category.design_specific,
            "WudfIsUserDebuggerPresent() API check.",
        ),
        _CheckSpec(
            "thread_hide_from_debugger",
            "Checking NtSetInformationThread with ThreadHideFromDebugger ",
            Category.design_specific,
            "NtSetInformationThread(ThreadHideFromDebugger) check.",
        ),
        _CheckSpec(
            "close_handle_invalid_handle",
            "Checking CloseHandle with an invalide handle ",
            Category.design_specific,
            "CloseHandle-on-invalid-handle debugger trick.",
        ),
        _CheckSpec(
            "nt_system_debug_control",
            "Checking NtSystemDebugControl",
            Category.design_specific,
            "NtSystemDebugControl() check.",
        ),
        _CheckSpec(
            "unhandled_exception_filter",
            "Checking UnhandledExcepFilterTest ",
            Category.design_specific,
            "Unhandled exception filter debugger trick.",
        ),
        _CheckSpec(
            "output_debug_string",
            "Checking OutputDebugString ",
            Category.design_specific,
            "OutputDebugString() GetLastError debugger trick.",
        ),
        _CheckSpec(
            "hardware_breakpoints",
            "Checking Hardware Breakpoints ",
            Category.design_specific,
            "Hardware (Dr0-Dr7) breakpoint check.",
        ),
        _CheckSpec(
            "software_breakpoints",
            "Checking Software Breakpoints ",
            Category.design_specific,
            "Software (INT3) breakpoint check.",
        ),
        _CheckSpec(
            "interrupt_0x2d",
            "Checking Interupt 0x2d ",
            Category.design_specific,
            "INT 0x2D anti-debug trick.",
        ),
        _CheckSpec(
            "interrupt_3",
            "Checking Interupt 1 ",
            Category.design_specific,
            "INT 3 / INT 1 anti-debug trick.",
        ),
        _CheckSpec(
            "trap_flag",
            "Checking trap flag",
            Category.design_specific,
            "EFLAGS trap-flag single-stepping check.",
        ),
        _CheckSpec(
            "memory_breakpoints_page_guard",
            "Checking Memory Breakpoints PAGE GUARD ",
            Category.design_specific,
            "PAGE_GUARD memory-breakpoint check.",
        ),
        _CheckSpec(
            "parent_is_explorer",
            "Checking If Parent Process is explorer.exe ",
            Category.design_specific,
            "Parent-process-is-explorer.exe sanity check.",
        ),
        _CheckSpec(
            "se_debug_privilege",
            "Checking SeDebugPrivilege ",
            Category.design_specific,
            "SeDebugPrivilege / csrss.exe open check.",
        ),
        _CheckSpec(
            "ntqo_object_type_information",
            "Checking NtQueryObject with ObjectTypeInformation ",
            Category.design_specific,
            "NtQueryObject(ObjectTypeInformation) debug-object-count check.",
        ),
        _CheckSpec(
            "ntqo_object_all_types_information",
            "Checking NtQueryObject with ObjectAllTypesInformation ",
            Category.design_specific,
            "NtQueryObject(ObjectAllTypesInformation) debug-object-count check.",
        ),
        _CheckSpec(
            "nt_yield_execution",
            "Checking NtYieldExecution ",
            Category.design_specific,
            "NtYieldExecution() timing/debugger trick.",
        ),
        _CheckSpec(
            "close_handle_protected_handle",
            "Checking CloseHandle protected handle trick  ",
            Category.design_specific,
            "Protected-handle CloseHandle debugger trick.",
        ),
        _CheckSpec(
            "ntqsi_kernel_debugger_information",
            "Checking NtQuerySystemInformation with SystemKernelDebuggerInformation  ",
            Category.design_specific,
            "NtQuerySystemInformation(SystemKernelDebuggerInformation) check.",
        ),
        _CheckSpec(
            "shared_user_data_kd_debugger_enabled",
            "Checking SharedUserData->KdDebuggerEnabled  ",
            Category.design_specific,
            "KUSER_SHARED_DATA.KdDebuggerEnabled check.",
        ),
        _CheckSpec(
            "process_in_job",
            "Checking if process is in a job  ",
            Category.design_specific,
            "Process-in-a-Job-object sandbox/debugger indicator.",
        ),
        _CheckSpec(
            "valloc_write_watch_buffer_only",
            "Checking VirtualAlloc write watch (buffer only) ",
            Category.design_specific,
            "VirtualAlloc MEM_WRITE_WATCH buffer-only debugger trick.",
        ),
        _CheckSpec(
            "valloc_write_watch_api_calls",
            "Checking VirtualAlloc write watch (API calls) ",
            Category.design_specific,
            "VirtualAlloc MEM_WRITE_WATCH API-call debugger trick.",
        ),
        _CheckSpec(
            "valloc_write_watch_is_debugger_present",
            "Checking VirtualAlloc write watch (IsDebuggerPresent) ",
            Category.design_specific,
            "VirtualAlloc MEM_WRITE_WATCH combined with IsDebuggerPresent.",
        ),
        _CheckSpec(
            "valloc_write_watch_code_write",
            "Checking VirtualAlloc write watch (code write) ",
            Category.design_specific,
            "VirtualAlloc MEM_WRITE_WATCH code-write debugger trick.",
        ),
        _CheckSpec(
            "page_exception_breakpoint",
            "Checking for page exception breakpoints ",
            Category.design_specific,
            "Page-exception-based breakpoint check.",
        ),
        _CheckSpec(
            "module_bounds_hook_check",
            "Checking for API hooks outside module bounds ",
            Category.design_specific,
            "API hook detection via out-of-module-bounds trampolines.",
        ),
    ],
    "INJECTION": [
        _CheckSpec(
            "scan_modules_epme_32",
            "Enumerating modules with EnumProcessModulesEx [32-bit] ",
            Category.design_specific,
            "Module enumeration via EnumProcessModulesEx (32-bit).",
        ),
        _CheckSpec(
            "scan_modules_epme_64",
            "Enumerating modules with EnumProcessModulesEx [64-bit] ",
            Category.design_specific,
            "Module enumeration via EnumProcessModulesEx (64-bit).",
        ),
        _CheckSpec(
            "scan_modules_epme_all",
            "Enumerating modules with EnumProcessModulesEx [ALL] ",
            Category.design_specific,
            "Module enumeration via EnumProcessModulesEx (LIST_MODULES_ALL).",
        ),
        _CheckSpec(
            "scan_modules_toolhelp32",
            "Enumerating modules with ToolHelp32 ",
            Category.design_specific,
            "Module enumeration via CreateToolhelp32Snapshot.",
        ),
        _CheckSpec(
            "scan_modules_ldr_enumerate",
            "Enumerating the process LDR via LdrEnumerateLoadedModules ",
            Category.design_specific,
            "Module enumeration via LdrEnumerateLoadedModules.",
        ),
        _CheckSpec(
            "scan_modules_ldr_direct",
            "Enumerating the process LDR directly ",
            Category.design_specific,
            "Module enumeration via direct PEB LDR walk.",
        ),
        _CheckSpec(
            "scan_modules_memwalk_gmi",
            "Walking process memory with GetModuleInformation ",
            Category.design_specific,
            "Hidden-module detection via GetModuleInformation memory walk.",
        ),
        _CheckSpec(
            "scan_modules_memwalk_hidden",
            "Walking process memory for hidden modules ",
            Category.design_specific,
            "Hidden/unlinked module detection via raw memory walk.",
        ),
        _CheckSpec(
            "scan_modules_dotnet_structures",
            "Walking process memory for .NET module structures ",
            Category.design_specific,
            "Hidden .NET module detection via memory walk.",
        ),
    ],
    # Generic Sandboxe/VM Detection. Mostly hardware/WMI artifact checks
    # (environment_artifact), but two are genuinely human-interaction checks
    # PERDEDOR itself credits to al-khaser (mouse_movement, lack_user_input
    # -> behavioural_interaction) and one is a timing-manipulation check
    # (accelerated_sleep -> timing). idt/ldt/gdt/str "Red Pill"-style
    # descriptor-table location tricks are technique/instruction-based, not
    # static artifacts, so they are design_specific like the DEBUG checks.
    "GEN_SANDBOX": [
        _CheckSpec(
            "number_of_processors",
            "Checking Number of processors in machine ",
            Category.environment_artifact,
            "Low logical-processor count (GetSystemInfo).",
        ),
        _CheckSpec(
            "idt_trick",
            "Checking Interupt Descriptor Table location ",
            Category.design_specific,
            "IDT base-address 'Red Pill' virtualization trick.",
        ),
        _CheckSpec(
            "ldt_trick",
            "Checking Local Descriptor Table location ",
            Category.design_specific,
            "LDT base-address virtualization trick.",
        ),
        _CheckSpec(
            "gdt_trick",
            "Checking Global Descriptor Table location ",
            Category.design_specific,
            "GDT base-address virtualization trick.",
        ),
        _CheckSpec(
            "str_trick",
            "Checking Store Task Register ",
            Category.design_specific,
            "STR (Store Task Register) virtualization trick.",
        ),
        _CheckSpec(
            "number_cores_wmi",
            "Checking Number of cores in machine using WMI ",
            Category.environment_artifact,
            "Low core count via WMI (Win32_Processor).",
        ),
        _CheckSpec(
            "disk_size_wmi",
            "Checking hard disk size using WMI ",
            Category.environment_artifact,
            "Small disk size via WMI (Win32_DiskDrive).",
        ),
        _CheckSpec(
            "disk_size_deviceiocontrol",
            "Checking hard disk size using DeviceIoControl ",
            Category.environment_artifact,
            "Small disk size via IOCTL_DISK_GET_LENGTH_INFO.",
        ),
        _CheckSpec(
            "setupdi_diskdrive",
            "Checking SetupDi_diskdrive ",
            Category.environment_artifact,
            "Disk drive vendor/model string via SetupDi APIs.",
        ),
        _CheckSpec(
            "mouse_movement",
            "Checking mouse movement ",
            Category.behavioural_interaction,
            "Human Interface check: absence of mouse cursor movement.",
        ),
        _CheckSpec(
            "lack_user_input",
            "Checking lack of user input ",
            Category.behavioural_interaction,
            "Human Interface check: absence of keyboard/mouse input.",
        ),
        _CheckSpec(
            "memory_space",
            "Checking memory space using GlobalMemoryStatusEx ",
            Category.environment_artifact,
            "Low RAM via GlobalMemoryStatusEx.",
        ),
        _CheckSpec(
            "disk_size_getdiskfreespace",
            "Checking disk size using GetDiskFreeSpaceEx ",
            Category.environment_artifact,
            "Small disk size via GetDiskFreeSpaceEx.",
        ),
        _CheckSpec(
            "cpuid_is_hypervisor",
            "Checking if CPU hypervisor field is set using cpuid(0x1)",
            Category.environment_artifact,
            "CPUID leaf 0x1 hypervisor-present bit.",
        ),
        _CheckSpec(
            "cpuid_hypervisor_vendor",
            "Checking hypervisor vendor using cpuid(0x40000000)",
            Category.environment_artifact,
            "CPUID leaf 0x40000000 hypervisor vendor string.",
        ),
        _CheckSpec(
            "hosting_check",
            "Check if Machine is hosted on Cloud",
            Category.environment_artifact,
            "Cloud instance-metadata endpoint reachability.",
        ),
        _CheckSpec(
            "accelerated_sleep",
            "Check if time has been accelerated ",
            Category.timing,
            "Detects sandbox time acceleration around a sleep.",
        ),
        _CheckSpec(
            "vm_driver_services",
            "VM Driver Services  ",
            Category.environment_artifact,
            "Guest-integration driver services (VBoxService/VMware Tools/qemu-ga/etc.).",
        ),
        _CheckSpec(
            "serial_number_bios_wmi",
            "Checking SerialNumber from BIOS using WMI ",
            Category.environment_artifact,
            "Win32_BIOS.SerialNumber vendor string.",
        ),
        _CheckSpec(
            "model_computer_system_wmi",
            "Checking Model from ComputerSystem using WMI ",
            Category.environment_artifact,
            "Win32_ComputerSystem.Model vendor string.",
        ),
        _CheckSpec(
            "manufacturer_computer_system_wmi",
            "Checking Manufacturer from ComputerSystem using WMI ",
            Category.environment_artifact,
            "Win32_ComputerSystem.Manufacturer vendor string.",
        ),
        _CheckSpec(
            "current_temperature_wmi",
            "Checking Current Temperature using WMI ",
            Category.environment_artifact,
            "Missing thermal sensor data via WMI.",
        ),
        _CheckSpec(
            "process_id_processor_wmi",
            "Checking ProcessId using WMI ",
            Category.environment_artifact,
            "Win32_Processor.ProcessorId via WMI.",
        ),
        _CheckSpec(
            "power_capabilities",
            "Checking power capabilities ",
            Category.environment_artifact,
            "Missing/synthetic power capabilities (battery, AC line).",
        ),
        _CheckSpec(
            "cpu_fan_wmi",
            "Checking CPU fan using WMI ",
            Category.environment_artifact,
            "Missing CPU fan device via WMI.",
        ),
        _CheckSpec(
            "query_license_value",
            "Checking NtQueryLicenseValue with Kernel-VMDetection-Private ",
            Category.environment_artifact,
            "NtQueryLicenseValue(Kernel-VMDetection-Private) OS-level VM flag.",
        ),
        _CheckSpec(
            "cachememory_wmi",
            "Checking Win32_CacheMemory with WMI ",
            Category.environment_artifact,
            "Win32_CacheMemory hardware inventory via WMI.",
        ),
        _CheckSpec(
            "physicalmemory_wmi",
            "Checking Win32_PhysicalMemory with WMI ",
            Category.environment_artifact,
            "Win32_PhysicalMemory hardware inventory via WMI.",
        ),
        _CheckSpec(
            "memorydevice_wmi",
            "Checking Win32_MemoryDevice with WMI ",
            Category.environment_artifact,
            "Win32_MemoryDevice hardware inventory via WMI.",
        ),
        _CheckSpec(
            "memoryarray_wmi",
            "Checking Win32_MemoryArray with WMI ",
            Category.environment_artifact,
            "Win32_MemoryArray hardware inventory via WMI.",
        ),
        _CheckSpec(
            "voltageprobe_wmi",
            "Checking Win32_VoltageProbe with WMI ",
            Category.environment_artifact,
            "Missing Win32_VoltageProbe sensor via WMI.",
        ),
        _CheckSpec(
            "portconnector_wmi",
            "Checking Win32_PortConnector with WMI ",
            Category.environment_artifact,
            "Missing Win32_PortConnector hardware via WMI.",
        ),
        _CheckSpec(
            "smbiosmemory_wmi",
            "Checking Win32_SMBIOSMemory with WMI ",
            Category.environment_artifact,
            "Win32_SMBIOSMemory inventory via WMI.",
        ),
        _CheckSpec(
            "thermalzoneinfo_wmi",
            "Checking ThermalZoneInfo performance counters with WMI ",
            Category.environment_artifact,
            "Missing ThermalZoneInformation perf counters via WMI.",
        ),
        _CheckSpec(
            "cim_memory_wmi",
            "Checking CIM_Memory with WMI ",
            Category.environment_artifact,
            "CIM_Memory inventory via WMI.",
        ),
        _CheckSpec(
            "cim_sensor_wmi",
            "Checking CIM_Sensor with WMI ",
            Category.environment_artifact,
            "Missing CIM_Sensor devices via WMI.",
        ),
        _CheckSpec(
            "cim_numericsensor_wmi",
            "Checking CIM_NumericSensor with WMI ",
            Category.environment_artifact,
            "Missing CIM_NumericSensor devices via WMI.",
        ),
        _CheckSpec(
            "cim_temperaturesensor_wmi",
            "Checking CIM_TemperatureSensor with WMI ",
            Category.environment_artifact,
            "Missing CIM_TemperatureSensor devices via WMI.",
        ),
        _CheckSpec(
            "cim_voltagesensor_wmi",
            "Checking CIM_VoltageSensor with WMI ",
            Category.environment_artifact,
            "Missing CIM_VoltageSensor devices via WMI.",
        ),
        _CheckSpec(
            "cim_physicalconnector_wmi",
            "Checking CIM_PhysicalConnector with WMI ",
            Category.environment_artifact,
            "Missing CIM_PhysicalConnector devices via WMI.",
        ),
        _CheckSpec(
            "cim_slot_wmi",
            "Checking CIM_Slot with WMI ",
            Category.environment_artifact,
            "Missing CIM_Slot devices via WMI.",
        ),
        _CheckSpec(
            "pirated_windows",
            "Checking if Windows is Genuine ",
            Category.environment_artifact,
            "Windows activation/genuine-status artifact.",
        ),
        _CheckSpec(
            "registry_services_disk_enum",
            "Checking Services\\Disk\\Enum entries for VM strings ",
            Category.environment_artifact,
            "HKLM\\...\\Services\\Disk\\Enum VM vendor strings.",
        ),
        _CheckSpec(
            "registry_disk_enum",
            "Checking Enum\\IDE and Enum\\SCSI entries for VM strings ",
            Category.environment_artifact,
            "HKLM\\...\\Enum\\IDE and Enum\\SCSI VM vendor strings.",
        ),
        _CheckSpec(
            "number_smbios_tables",
            "Checking SMBIOS tables  ",
            Category.environment_artifact,
            "Raw SMBIOS firmware table scan.",
        ),
        _CheckSpec(
            "firmware_acpi",
            "Checking ACPI table strings ",
            Category.environment_artifact,
            "Raw ACPI firmware table string scan.",
        ),
    ],
    "VBOX": [
        _CheckSpec(
            "vbox_dir",
            "Checking VirtualBox Guest Additions directory ",
            Category.environment_artifact,
            "VirtualBox Guest Additions install directory.",
        ),
        _CheckSpec(
            "vbox_check_mac",
            "Checking Mac Address start with 08:00:27 ",
            Category.design_specific,
            "NIC MAC OUI matching VirtualBox's assigned range.",
        ),
        _CheckSpec(
            "hybridanalysismacdetect",
            "Checking MAC address (Hybrid Analysis) ",
            Category.design_specific,
            "NIC MAC OUI check (Hybrid Analysis sandbox range).",
        ),
        _CheckSpec(
            "vbox_window_class",
            "Checking VBoxTrayToolWndClass / VBoxTrayToolWnd ",
            Category.design_specific,
            "VBoxTray guest-tool window-class detection (FindWindow).",
        ),
        _CheckSpec(
            "vbox_network_share",
            "Checking VirtualBox Shared Folders network provider ",
            Category.environment_artifact,
            "VirtualBox Shared Folders network provider registration.",
        ),
        _CheckSpec(
            "vbox_pnpentity_pcideviceid_wmi",
            "Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device ",
            Category.environment_artifact,
            "Win32_PnPEntity vendor-ID scan for VBox PCI devices.",
        ),
        _CheckSpec(
            "vbox_pnpentity_controllers_wmi",
            "Checking Win32_PnPDevice Name from WMI for VBox controller hardware ",
            Category.environment_artifact,
            "Win32_PnPEntity name scan for VBox controller hardware.",
        ),
        _CheckSpec(
            "vbox_pnpentity_vboxname_wmi",
            "Checking Win32_PnPDevice Name from WMI for VBOX names ",
            Category.environment_artifact,
            "Win32_PnPEntity name scan for VBOX strings.",
        ),
        _CheckSpec(
            "vbox_bus_wmi",
            "Checking Win32_Bus from WMI ",
            Category.environment_artifact,
            "Win32_Bus VBox artifact scan via WMI.",
        ),
        _CheckSpec(
            "vbox_baseboard_wmi",
            "Checking Win32_BaseBoard from WMI ",
            Category.environment_artifact,
            "Win32_BaseBoard vendor string via WMI.",
        ),
        _CheckSpec(
            "vbox_mac_wmi",
            "Checking MAC address from WMI ",
            Category.design_specific,
            "NIC MAC OUI check via WMI (VBox range).",
        ),
        _CheckSpec(
            "vbox_eventlogfile_wmi",
            "Checking NTEventLog from WMI ",
            Category.environment_artifact,
            "Win32_NTEventlogFile VBox source scan via WMI.",
        ),
        _CheckSpec(
            "vbox_firmware_smbios",
            "Checking SMBIOS firmware  ",
            Category.environment_artifact,
            "Raw SMBIOS firmware table scan for VBox vendor strings.",
        ),
        _CheckSpec(
            "vbox_firmware_acpi",
            "Checking ACPI tables  ",
            Category.environment_artifact,
            "Raw ACPI firmware table scan for VBox vendor strings.",
        ),
    ],
    "VMWARE": [
        _CheckSpec(
            "vmware_adapter_name",
            "Checking VMWare network adapter name ",
            Category.environment_artifact,
            "Network adapter descriptive-name vendor string (VMware).",
        ),
        _CheckSpec(
            "vmware_dir",
            "Checking VMWare directory ",
            Category.environment_artifact,
            "VMware Tools install directory.",
        ),
        _CheckSpec(
            "vmware_firmware_smbios",
            "Checking SMBIOS firmware  ",
            Category.environment_artifact,
            "Raw SMBIOS firmware table scan for VMware vendor strings.",
        ),
        _CheckSpec(
            "vmware_firmware_acpi",
            "Checking ACPI tables  ",
            Category.environment_artifact,
            "Raw ACPI firmware table scan for VMware vendor strings.",
        ),
    ],
    # Virtual PC Detection calls virtual_pc_process()/virtual_pc_reg_keys()
    # directly with no exec_check wrapper at all - zero machine-readable
    # verdicts are ever produced for this category.
    "VPC": [],
    "QEMU": [
        _CheckSpec(
            "qemu_firmware_smbios",
            "Checking SMBIOS firmware  ",
            Category.environment_artifact,
            "Raw SMBIOS firmware table scan for QEMU vendor strings.",
        ),
        _CheckSpec(
            "qemu_firmware_acpi",
            "Checking ACPI tables  ",
            Category.environment_artifact,
            "Raw ACPI firmware table scan for QEMU vendor strings.",
        ),
    ],
    "XEN": [
        _CheckSpec(
            "xen_check_mac",
            "Checking Mac Address start with 08:16:3E ",
            Category.design_specific,
            "NIC MAC OUI matching Xen's assigned range.",
        ),
    ],
    "KVM": [
        _CheckSpec(
            "kvm_dir",
            "Checking KVM virio directory ",
            Category.environment_artifact,
            "KVM virtio driver install directory.",
        ),
    ],
    "WINE": [
        _CheckSpec(
            "wine_exports",
            "Checking Wine via dll exports ",
            Category.environment_artifact,
            "Wine-specific export symbols in system DLLs.",
        ),
    ],
    "PARALLELS": [
        _CheckSpec(
            "parallels_check_mac",
            "Checking Mac Address start with 00:1C:42 ",
            Category.design_specific,
            "NIC MAC OUI matching Parallels' assigned range.",
        ),
    ],
    "HYPERV": [
        _CheckSpec(
            "hyperv_driver_objects",
            "Checking for Hyper-V driver objects ",
            Category.environment_artifact,
            "Hyper-V integration driver objects.",
        ),
        _CheckSpec(
            "hyperv_global_objects",
            "Checking for Hyper-V global objects ",
            Category.environment_artifact,
            "Hyper-V integration global kernel objects.",
        ),
    ],
    # Direct calls to the raw injection primitives, no exec_check wrapper, no
    # print_category header either - zero machine-readable verdicts.
    "CODE_INJECTIONS": [],
    "TIMING_ATTACKS": [
        _CheckSpec(
            "timing_ntdelayexecution",
            "Performing a sleep using NtDelayExecution ...",
            Category.timing,
            "Detects time acceleration around NtDelayExecution.",
        ),
        _CheckSpec(
            "timing_sleep_loop",
            "Performing a sleep() in a loop ...",
            Category.timing,
            "Detects time acceleration around a sleep() loop.",
        ),
        _CheckSpec(
            "timing_settimer",
            "Delaying execution using SetTimer ...",
            Category.timing,
            "Detects time acceleration around SetTimer.",
        ),
        _CheckSpec(
            "timing_timesetevent",
            "Delaying execution using timeSetEvent ...",
            Category.timing,
            "Detects time acceleration around timeSetEvent.",
        ),
        _CheckSpec(
            "timing_waitforsingleobject",
            "Delaying execution using WaitForSingleObject ...",
            Category.timing,
            "Detects time acceleration around WaitForSingleObject.",
        ),
        _CheckSpec(
            "timing_waitformultipleobjects",
            "Delaying execution using WaitForMultipleObjects ...",
            Category.timing,
            "Detects time acceleration around WaitForMultipleObjects.",
        ),
        _CheckSpec(
            "timing_icmpsendecho",
            "Delaying execution using IcmpSendEcho ...",
            Category.timing,
            "Detects time acceleration around IcmpSendEcho.",
        ),
        _CheckSpec(
            "timing_createwaitabletimer",
            "Delaying execution using CreateWaitableTimer ...",
            Category.timing,
            "Detects time acceleration around CreateWaitableTimer.",
        ),
        _CheckSpec(
            "timing_createtimerqueuetimer",
            "Delaying execution using CreateTimerQueueTimer ...",
            Category.timing,
            "Detects time acceleration around CreateTimerQueueTimer.",
        ),
        _CheckSpec(
            "rdtsc_diff_locky",
            "Checking RDTSC Locky trick ",
            Category.timing,
            "RDTSC timing-difference check (Locky-style).",
        ),
        _CheckSpec(
            "rdtsc_diff_vmexit",
            "Checking RDTSC which force a VM Exit (cpuid) ",
            Category.timing,
            "RDTSC-around-CPUID VM-exit timing check.",
        ),
    ],
    # analysis_tools_process() is called directly, no exec_check wrapper -
    # zero machine-readable verdicts, despite PERDEDOR crediting an
    # equivalent check ("analysis tooling in the process list") to
    # design_specific; that placement cannot be reproduced here because
    # al-khaser's own version never emits one.
    "ANALYSIS_TOOLS": [],
    # Every AntiDisassm* function is called directly with plain _tprintf
    # banners, no exec_check wrapper - zero machine-readable verdicts.
    "ANTI_DISASSM": [],
    # ErasePEHeaderFromMemory()/SizeOfImage() are called directly, no
    # exec_check wrapper - zero machine-readable verdicts.
    "DUMPING_CHECK": [],
}

# Category headers actually emitted by print_category(), verified verbatim.
# Not required for parsing (log.txt carries no headers at all, and the
# positional walk below does not depend on stdout headers either) - kept
# only so a future stdout-only fallback parser has the real strings to
# anchor on rather than needing to guess them again.
CATEGORY_HEADERS: Dict[str, Optional[str]] = {
    "TLS": "TLS Callbacks",
    "DEBUG": "Debugger Detection",
    "INJECTION": "DLL Injection Detection",
    "GEN_SANDBOX": "Generic Sandboxe/VM Detection",
    "VBOX": "VirtualBox Detection",
    "VMWARE": "VMWare Detection",
    "VPC": "Virtual PC Detection",
    "QEMU": "QEMU Detection",
    "XEN": "Xen Detection",
    "KVM": "KVM Detection",
    "WINE": "Wine Detection",
    "PARALLELS": "Parallels Detection",
    "HYPERV": "Hyper-V Detection",
    "TIMING_ATTACKS": "Timing-attacks",
    "ANALYSIS_TOOLS": "Analysis-tools",
    "ANTI_DISASSM": None,  # no print_category call in this block
    "DUMPING_CHECK": "Anti Dumping",
    "CODE_INJECTIONS": None,  # no print_category call in this block either
}

_LOG_LINE_RE = re.compile(
    r"^\[[^\]]*\]\s*\[\*\]\s?(?P<msg>.*?)\s*->\s*(?P<result>\d+)\s*$"
)
_STDOUT_LINE_RE = re.compile(
    r"^\[\*\]\s?(?P<msg>.*?)\s*\[\s*(?P<verdict>BAD|GOOD)\s*\]\s*$"
)


def _severity_for(spec: "_CheckSpec") -> Severity:
    """al-khaser assigns no severity of its own (result is a plain 0/1). We
    assign a uniform, conservative default per category rather than invent
    per-check severity judgements al-khaser never made. timing/behavioural
    findings are typically weaker evidence than a static artifact or a
    debugger-detection API succeeding, so they are scored lower."""
    if spec.category in (Category.environment_artifact, Category.design_specific):
        return Severity.medium
    return Severity.low


def build_argv(
    checks: Optional[List[str]],
    sleep_seconds: int,
    guest_binary_path: str,
    guest_stdout_path: str,
) -> List[str]:
    """Build the real al-khaser command line, plus the cmd.exe wrapper that
    defeats its terminal `getchar()` call. ``checks`` is None/empty for the
    Full profile (no --check flags -> EnableDefaultChecks(), 17/18 types);
    a non-empty list emits one --check per entry for Custom. --sleep is
    always passed explicitly - never left at al-khaser's own 600s default.
    """
    inner = [guest_binary_path]
    for check in checks or []:
        inner += ["--check", check]
    inner += ["--sleep", str(int(sleep_seconds))]

    # Quoted for guest cmd.exe/CreateProcess argv parsing - NOT POSIX shlex.
    # shlex.quote() wraps unsafe strings (e.g. any path containing a
    # backslash) in single quotes, which cmd.exe has no concept of at all: a
    # real Xen run confirmed this sends the literal token
    # 'C:\Users\Public\alkhaser\al-khaser_x64.exe' (apostrophes included) to
    # cmd.exe, which cannot find that file and fails before al-khaser ever
    # launches. subprocess.list2cmdline() is the correct Windows command-line
    # quoting for this - the same primitive drakrun.evasion.guest_runner.
    # GuestSession._build_final_argv() already uses to wrap a cwd-qualified
    # guest command - and only adds quotes when a token actually needs them
    # (a space, an empty string, or an embedded quote), leaving the plain
    # backslash-only guest paths this adapter ever produces unquoted.
    inner_str = subprocess.list2cmdline(inner)
    redirect_target = subprocess.list2cmdline([guest_stdout_path])
    return ["cmd", "/c", f"{inner_str} < NUL > {redirect_target} 2>&1"]


_PROBE_EXISTS_MARKER = "CHIMERA_PROBE_EXISTS:"
_PROBE_SIZE_MARKER = "CHIMERA_PROBE_SIZE:"
_PROBE_ATTR_MARKER = "CHIMERA_PROBE_ATTR:"
# Fixed budget for the metadata probe, which is a cmd.exe builtin with no
# stdin and no I/O wait - it cannot legitimately take longer than this.
_METADATA_PROBE_TIMEOUT_SECONDS = 60.0


def _build_metadata_probe_argv(guest_path: str) -> List[str]:
    """Build the metadata-only existence/size probe for `guest_path`.

    This asks Windows itself - through the guest's own cmd.exe, over the
    drakshell channel GuestSession.run() already uses to launch al-khaser -
    whether the file is in the filesystem namespace and what size Windows
    reports for it. Deliberately metadata-only: `if exist` is a
    GetFileAttributes-class lookup and the `%~z`/`%~a` FOR modifiers are
    FindFirstFile-class lookups, so nothing here ever opens the file's data
    stream. That is precisely what makes it independent of
    Injector.read_file(), whose CreateFileW(GENERIC_READ, FILE_SHARE_READ,
    OPEN_EXISTING) DOES open the data stream and therefore cannot tell "the
    file is not there" apart from "the file is there but cannot be opened
    right now" - both surface as DRAKVUF's single "Couldn't open guest file"
    string, with the underlying GetLastError() captured into
    injector->error_code but never printed by the injector CLI.

    `if exist` is used rather than a bare `dir` because a plain `dir` does
    not list hidden/system-marked files at all, while `if exist` finds them;
    `%~aI` then reports the attributes a `dir /a` would have shown, without
    `dir`'s locale-dependent output ("File Not Found", date formats).

    The caller MUST pass cwd to GuestSession.run() for this argv. That takes
    _build_final_argv()'s "already a self-contained cmd /c script" splice
    branch, which forwards the script to drakshell as one plain str, left
    untouched on the wire. Without cwd the list would instead go through
    mslex.join(), which backslash-escapes the inner quotes into a form
    cmd.exe does not understand - the same class of quoting corruption a
    previous real-Xen scan already hit.
    """
    quoted = f'"{guest_path}"'
    # The previous formulation was
    #     if exist X (echo EXISTS:1) else (echo EXISTS:0) & for ... do (...)
    # which is silently wrong: cmd.exe binds a trailing `& <cmd>` to the ELSE
    # branch of an IF/ELSE, so the FOR only ran when the file was MISSING.
    # Real-Xen scan a1e7c574-cbe1-4dfc-8692-d8c0875c9b06 shows exactly that
    # symptom - stdout was precisely "CHIMERA_PROBE_EXISTS:1\r\n" and no size
    # or attribute line was ever emitted, because the file did exist.
    #
    # The replacement is built so it produces the same output under EITHER
    # of cmd.exe's two possible readings of `&`, rather than relying on
    # getting the precedence right:
    #
    #   * `IF ... (...) ELSE (...)` is LAST, with nothing after it. The
    #     ELSE-swallows-the-next-command bug needs a following `&` to
    #     happen, and there is none.
    #   * Both FOR statements come first and use DISTINCT variable letters
    #     (%I, %J). If cmd.exe extends a FOR's DO body across `&` (so the
    #     statements nest), distinct letters mean no shadowing; if it does
    #     not (so they stay siblings), they simply run in sequence. Either
    #     way each FOR iterates EXACTLY ONCE - the set is a single literal
    #     token with no `*`/`?`, so it is never filesystem-expanded - and
    #     each marker line is emitted exactly once.
    #   * `@echo off` up front suppresses cmd.exe's echoing of statements it
    #     would otherwise print under the nested reading, so stdout carries
    #     only marker lines.
    #
    # `%~zI`/`%~aI` expand to the empty string for a file that does not
    # exist, which _parse_metadata_probe_output() records as None - never
    # misread as a zero size.
    script = (
        f"@echo off"
        f" & for %I in ({quoted}) do echo {_PROBE_SIZE_MARKER}%~zI"
        f" & for %J in ({quoted}) do echo {_PROBE_ATTR_MARKER}%~aJ"
        f" & if exist {quoted} (echo {_PROBE_EXISTS_MARKER}1)"
        f" else (echo {_PROBE_EXISTS_MARKER}0)"
    )
    return ["cmd", "/c", script]


def _parse_metadata_probe_output(stdout_text: str) -> Dict[str, Any]:
    """Parse the probe's marker lines into structured fields.

    Every field stays None when its marker is absent or unparseable, so a
    garbled or empty probe is never silently reported as a definitive "file
    is missing" - that distinction is the whole point of the probe."""
    parsed: Dict[str, Any] = {
        "exists": None,
        "reported_size": None,
        "attributes": None,
    }
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if line.startswith(_PROBE_EXISTS_MARKER):
            value = line[len(_PROBE_EXISTS_MARKER) :].strip()
            if value in ("0", "1"):
                parsed["exists"] = value == "1"
        elif line.startswith(_PROBE_SIZE_MARKER):
            value = line[len(_PROBE_SIZE_MARKER) :].strip()
            # A missing file yields an empty %~zI expansion, not a zero.
            if value.isdigit():
                parsed["reported_size"] = int(value)
        elif line.startswith(_PROBE_ATTR_MARKER):
            value = line[len(_PROBE_ATTR_MARKER) :].strip()
            if value:
                parsed["attributes"] = value
    return parsed


def _probe_guest_file_metadata(
    session: GuestSession,
    guest_path: str,
    guest_dir: str,
    raw_dir: pathlib.Path,
    checkpoint: str,
) -> Dict[str, Any]:
    """Run the metadata probe at one checkpoint and persist the raw result.

    Never raises: a probe failure is recorded as `probe_error` and the
    verifier's own control flow continues untouched, so al-khaser can never
    fail merely because this diagnostic failed."""
    probe_argv = _build_metadata_probe_argv(guest_path)
    probe: Dict[str, Any] = {
        "checkpoint": checkpoint,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "guest_path": guest_path,
        "cwd": guest_dir,
        "command": " ".join(probe_argv),
        "mechanism": (
            "guest cmd.exe via GuestSession.run()/drakshell; metadata-only "
            "(if exist + FOR %~z/%~a), never opens the file's data stream"
        ),
        "exists": None,
        "reported_size": None,
        "attributes": None,
    }

    try:
        exit_code, stdout, stderr = session.run(
            probe_argv,
            timeout=_METADATA_PROBE_TIMEOUT_SECONDS,
            cwd=guest_dir,
        )
        stdout_text = stdout.decode("utf-8", errors="replace")
        probe["exit_code"] = exit_code
        probe["stdout"] = stdout_text
        probe["stderr"] = stderr.decode("utf-8", errors="replace")
        probe.update(_parse_metadata_probe_output(stdout_text))
    except Exception as exc:  # noqa: BLE001 - diagnostic-only, must not raise
        probe["probe_error"] = str(exc)

    try:
        probe_path = raw_dir / f"probe_{checkpoint}.json"
        probe_path.write_text(json.dumps(probe, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001 - diagnostic-only, must not raise
        pass

    return probe


_READ_TESTPATH_MARKER = "CHIMERA_READ_TESTPATH:"
_READ_LENGTH_MARKER = "CHIMERA_READ_LENGTH:"
_READ_ATTRS_MARKER = "CHIMERA_READ_ATTRS:"
_READ_LASTWRITE_MARKER = "CHIMERA_READ_LASTWRITE:"
_READ_STATERROR_MARKER = "CHIMERA_READ_STATERROR:"
_READ_OPEN_MARKER = "CHIMERA_READ_OPEN:"
_READ_BYTES_MARKER = "CHIMERA_READ_BYTES:"
_READ_SHA256_MARKER = "CHIMERA_READ_SHA256:"
_READ_EXCTYPE_MARKER = "CHIMERA_READ_EXCTYPE:"
_READ_HRESULT_MARKER = "CHIMERA_READ_HRESULT:"
_READ_EXCMSG_MARKER = "CHIMERA_READ_EXCMSG:"
_READ_EXPECTED_MARKER = "CHIMERA_READ_EXPECTED:"
_READ_HASHMATCH_MARKER = "CHIMERA_READ_HASHMATCH:"

# The four outcomes this probe exists to tell apart, plus the "file is not
# in the namespace at all" case and an explicit inconclusive value. These
# are recorded verbatim in read_probe_<checkpoint>.json so the artifact says
# what it proves rather than leaving that to be re-derived by eye.
READ_PROBE_CLASS_MISSING = "E_file_not_found"
READ_PROBE_CLASS_UNOPENABLE = "A_exists_but_cannot_be_opened"
READ_PROBE_CLASS_OPENED = "B_opened_and_read_but_host_hash_unknown"
READ_PROBE_CLASS_HASH_MATCHES = "C_opened_and_sha256_matches_host"
READ_PROBE_CLASS_HASH_DIFFERS = "D_opened_but_sha256_differs_from_host"
READ_PROBE_CLASS_INCONCLUSIVE = "inconclusive"

# PowerShell start-up dominates this probe's cost; hashing ~280 KB is
# instantaneous. Generous enough that a slow cold start is never mistaken
# for a hang, small enough to stay a rounding error against al-khaser's own
# multi-minute budget.
_READ_PROBE_TIMEOUT_SECONDS = 120.0


def _build_read_probe_script(
    guest_path: str, expected_sha256: Optional[str] = None
) -> str:
    """The Windows PowerShell 5.1 script body for the user-mode read probe.

    This is UPLOADED INTO THE GUEST as a .ps1 file and invoked by path - it
    is never passed on the command line. Real-Xen scan
    34ae2d08-dcf0-471b-88c8-5bead0cf40eb is why: as an inline
    `-EncodedCommand` payload this script produced a 7792-byte UTF-16LE
    command line against drakshell's 2048-byte ceiling, so it was rejected
    host-side and never executed at all. Shipping the body as a file removes
    the size constraint entirely instead of forcing the diagnostic to be
    shrunk until it fits.

    Every line it prints is a `MARKER:value` pair so the host-side parser
    never has to interpret locale-dependent prose. Design notes, all
    load-bearing:

    * `[System.IO.File]::Open(..., FileAccess::Read, FileShare::ReadWrite
      -bor FileShare::Delete)` rather than `Get-FileHash`/`OpenRead`. We
      choose the share mode deliberately: our request must be compatible
      with any handle another process already holds. Asking for the MOST
      permissive sharing maximises the chance of succeeding when some other
      opener merely holds the file, so an ERROR_SHARING_VIOLATION here means
      an existing handle denies read sharing outright - a much stronger
      statement than the default `OpenRead` (FileShare.Read) could make.
    * Read-only throughout. Nothing here creates, writes, moves, deletes or
      even touches the file's timestamps, and nothing here starts a process
      - in particular there is NO Process.Start()/CreateProcess of any kind,
      so this probe can never accidentally launch al-khaser itself.
    * The catch blocks walk `.InnerException` to the innermost exception.
      PowerShell wraps a throwing .NET method call in a
      MethodInvocationException, so the naive `$_.Exception.GetType()` would
      report the wrapper rather than the real UnauthorizedAccessException /
      IOException / FileNotFoundException we actually need.
    * `$_.Exception.HResult` is the numeric failure reason. For a Win32-
      facility HRESULT (0x8007xxxx) the low 16 bits ARE the Win32 error
      code, which is what makes this directly comparable with the
      ErrorCode DRAKVUF's own injector reports (see
      drakrun.evasion.guest_runner.parse_injector_error_json). The
      derivation itself is done host-side in _parse_read_probe_output().
    * Windows PowerShell 5.1 only - `[System.IO.File]`,
      `[System.Security.Cryptography.SHA256]` and `Exception.HResult` are
      all plain .NET Framework surface. Nothing here needs PowerShell 7 or
      `pwsh`, which matters because `powershell.exe -EncodedCommand` is
      already demonstrably working on this exact image (every put_file()
      runs one via GuestSession._ensure_remote_parent_dir()).
    """
    hex_digest = (
        "([System.BitConverter]::ToString($digest) -replace '-','')"
        ".ToLowerInvariant()"
    )
    open_call = (
        "[System.IO.File]::Open($p, [System.IO.FileMode]::Open, "
        "[System.IO.FileAccess]::Read, "
        "([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))"
    )
    flatten_msg = '(($e.Message -split "\\r?\\n") -join " ")'
    unwrap = "$e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }"
    lines = [
        "$ErrorActionPreference = 'Stop'",
        f"$p = '{guest_path}'",
        f"$expected = '{expected_sha256 or ''}'",
        f'Write-Output ("{_READ_TESTPATH_MARKER}" + '
        "(Test-Path -LiteralPath $p -PathType Leaf))",
        "try {",
        "  $i = Get-Item -LiteralPath $p -Force",
        f'  Write-Output ("{_READ_LENGTH_MARKER}" + $i.Length)',
        f'  Write-Output ("{_READ_ATTRS_MARKER}" + $i.Attributes)',
        f'  Write-Output ("{_READ_LASTWRITE_MARKER}" + '
        '$i.LastWriteTimeUtc.ToString("o"))',
        "} catch {",
        f"  {unwrap}",
        f'  Write-Output ("{_READ_STATERROR_MARKER}" + '
        f"$e.GetType().FullName + ' ' + {flatten_msg})",
        "}",
        "try {",
        f"  $fs = {open_call}",
        "  try {",
        "    $sha = [System.Security.Cryptography.SHA256]::Create()",
        "    $digest = $sha.ComputeHash($fs)",
        f"    $hex = {hex_digest}",
        f'    Write-Output ("{_READ_OPEN_MARKER}OK")',
        f'    Write-Output ("{_READ_BYTES_MARKER}" + $fs.Length)',
        f'    Write-Output ("{_READ_SHA256_MARKER}" + $hex)',
        # In-guest comparison against the host's own hash, so the artifact
        # states the verdict rather than leaving it to be recomputed. The
        # host-side classifier remains the authority (_classify_read_probe).
        "    if ($expected) {",
        f'      Write-Output ("{_READ_EXPECTED_MARKER}" + $expected)',
        f'      Write-Output ("{_READ_HASHMATCH_MARKER}" + ($hex -eq $expected))',
        "    }",
        "  } finally { $fs.Dispose() }",
        "} catch {",
        f"  {unwrap}",
        f'  Write-Output ("{_READ_OPEN_MARKER}FAIL")',
        f'  Write-Output ("{_READ_EXCTYPE_MARKER}" + $e.GetType().FullName)',
        f'  Write-Output ("{_READ_HRESULT_MARKER}" + $e.HResult)',
        f'  Write-Output ("{_READ_EXCMSG_MARKER}" + {flatten_msg})',
        "}",
        # Explicit, so a non-zero exit code means "the probe itself broke",
        # never "the file could not be opened" - that is reported in-band.
        "exit 0",
    ]
    # CRLF: .ps1 files are read by Windows PowerShell, not by this host.
    return "\r\n".join(lines) + "\r\n"


def _build_read_probe_argv(guest_script_path: str) -> List[str]:
    """`powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script>`.

    Short by construction - the payload lives in the uploaded .ps1, so this
    command line stays a few hundred bytes regardless of how much the
    diagnostic grows. That is the whole point of the file-based design; see
    _build_read_probe_script().

    `-ExecutionPolicy Bypass` is required, not decorative: Windows 10's
    default policy for a client SKU is Restricted, which refuses to run a
    .ps1 from disk at all. `-NoProfile` keeps a machine/user profile from
    injecting output ahead of our markers (the parser is marker-anchored, so
    stray output is tolerated, but not emitting it is better).

    Deliberately NOT prepare_ps_command(): -EncodedCommand is what made this
    probe too long to send in the first place. The four tokens here are
    plain, space-free ASCII, so mslex.join(for_cmd=False) passes them
    through unquoted, and the caller passes no cwd - the same path
    GuestSession._ensure_remote_parent_dir() already uses successfully on
    this image.
    """
    return [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        guest_script_path,
    ]


def read_probe_script_guest_path(guest_dir: str, checkpoint: str) -> str:
    """Where this checkpoint's probe script lives inside the guest.

    One path PER CHECKPOINT, not one shared path: the injector's writefile
    opens its destination with CREATE_NEW (confirmed in /opt/drakvuf's
    win_write_file.c), which fails outright if the file already exists - so
    re-uploading the same name for the second checkpoint would error. Per-
    checkpoint names also keep the two checkpoints independent of each
    other's ordering and failure state.

    The `__` prefix follows the existing convention for adapter-owned guest
    scratch files (GuestSession.put_tree_as_zip's __put_tree_as_zip.zip).
    """
    return f"{guest_dir.rstrip(chr(92))}\\__chimera_read_probe_{checkpoint}.ps1"


def _win32_error_from_hresult(hresult: Optional[int]) -> Optional[int]:
    """Low 16 bits of a FACILITY_WIN32 HRESULT (0x8007xxxx) - i.e. the
    original Win32 error code, directly comparable with the ErrorCode
    DRAKVUF's injector prints. Returns None for any other facility rather
    than inventing a code that does not mean what it appears to."""
    if hresult is None:
        return None
    unsigned = hresult & 0xFFFFFFFF
    if (unsigned >> 16) & 0xFFFF != 0x8007:
        return None
    return unsigned & 0xFFFF


def _parse_read_probe_output(stdout_text: str) -> Dict[str, Any]:
    """Parse the read probe's marker lines into structured fields.

    As with the metadata probe, a field whose marker is absent or
    unparseable stays None: a garbled probe must never be readable as a
    definitive negative result."""
    parsed: Dict[str, Any] = {
        "test_path": None,
        "length": None,
        "attributes": None,
        "last_write_utc": None,
        "stat_error": None,
        "open_result": None,
        "read_bytes": None,
        "guest_sha256": None,
        "exception_type": None,
        "hresult": None,
        "win32_error": None,
        "exception_message": None,
        "expected_sha256": None,
        "guest_hash_match": None,
    }

    def _tail(line: str, marker: str) -> str:
        return line[len(marker) :].strip()

    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if line.startswith(_READ_TESTPATH_MARKER):
            value = _tail(line, _READ_TESTPATH_MARKER).lower()
            if value in ("true", "false"):
                parsed["test_path"] = value == "true"
        elif line.startswith(_READ_LENGTH_MARKER):
            value = _tail(line, _READ_LENGTH_MARKER)
            if value.isdigit():
                parsed["length"] = int(value)
        elif line.startswith(_READ_ATTRS_MARKER):
            parsed["attributes"] = _tail(line, _READ_ATTRS_MARKER) or None
        elif line.startswith(_READ_LASTWRITE_MARKER):
            parsed["last_write_utc"] = _tail(line, _READ_LASTWRITE_MARKER) or None
        elif line.startswith(_READ_STATERROR_MARKER):
            parsed["stat_error"] = _tail(line, _READ_STATERROR_MARKER) or None
        elif line.startswith(_READ_OPEN_MARKER):
            value = _tail(line, _READ_OPEN_MARKER).upper()
            if value in ("OK", "FAIL"):
                parsed["open_result"] = value
        elif line.startswith(_READ_BYTES_MARKER):
            value = _tail(line, _READ_BYTES_MARKER)
            if value.isdigit():
                parsed["read_bytes"] = int(value)
        elif line.startswith(_READ_SHA256_MARKER):
            value = _tail(line, _READ_SHA256_MARKER).lower()
            if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                parsed["guest_sha256"] = value
        elif line.startswith(_READ_EXCTYPE_MARKER):
            parsed["exception_type"] = _tail(line, _READ_EXCTYPE_MARKER) or None
        elif line.startswith(_READ_HRESULT_MARKER):
            value = _tail(line, _READ_HRESULT_MARKER)
            try:
                parsed["hresult"] = int(value, 0)
            except ValueError:
                pass
        elif line.startswith(_READ_EXCMSG_MARKER):
            parsed["exception_message"] = _tail(line, _READ_EXCMSG_MARKER) or None
        elif line.startswith(_READ_EXPECTED_MARKER):
            value = _tail(line, _READ_EXPECTED_MARKER).lower()
            if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                parsed["expected_sha256"] = value
        elif line.startswith(_READ_HASHMATCH_MARKER):
            value = _tail(line, _READ_HASHMATCH_MARKER).lower()
            if value in ("true", "false"):
                parsed["guest_hash_match"] = value == "true"

    parsed["win32_error"] = _win32_error_from_hresult(parsed["hresult"])
    return parsed


def _classify_read_probe(parsed: Dict[str, Any], host_sha256: Optional[str]) -> str:
    """Map a parsed read probe onto the A/B/C/D outcomes this experiment was
    designed to separate. Anything the probe did not actually establish is
    'inconclusive' - never one of the substantive verdicts."""
    open_result = parsed.get("open_result")
    if open_result == "OK":
        guest_sha256 = parsed.get("guest_sha256")
        if not guest_sha256 or not host_sha256:
            return READ_PROBE_CLASS_OPENED
        if guest_sha256 == host_sha256:
            return READ_PROBE_CLASS_HASH_MATCHES
        return READ_PROBE_CLASS_HASH_DIFFERS
    if open_result == "FAIL":
        if parsed.get("test_path") is False:
            return READ_PROBE_CLASS_MISSING
        return READ_PROBE_CLASS_UNOPENABLE
    return READ_PROBE_CLASS_INCONCLUSIVE


def _upload_read_probe_script(
    session: GuestSession, script_text: str, guest_script_path: str
) -> None:
    """Write the probe script to a host temp file and put_file() it into the
    guest. UTF-8 with a BOM, because Windows PowerShell 5.1 falls back to the
    system ANSI codepage for a BOM-less .ps1 - the script is pure ASCII
    today, so this is belt-and-braces rather than a live problem."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        local_script = pathlib.Path(tmp_dir) / "read_probe.ps1"
        local_script.write_bytes(codecs.BOM_UTF8 + script_text.encode("utf-8"))
        session.put_file(local_script, guest_script_path)


def _probe_guest_file_read(
    session: GuestSession,
    host_binary_path: str,
    guest_path: str,
    guest_dir: str,
    raw_dir: pathlib.Path,
    checkpoint: str,
) -> Dict[str, Any]:
    """Ask an ORDINARY Windows user-mode process whether it can open and read
    the uploaded executable, and persist the raw result.

    This is the independent signal the injector-based diagnostic cannot
    give. Injector.read_file() opens the file from DRAKVUF's injected
    context with CreateFileW(GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    this probe opens it from a plain powershell.exe started by drakshell -
    the same mechanism that starts al-khaser itself. If the two disagree,
    the access condition is specific to the injector's context; if they
    agree, one condition explains both, and comparing this probe's
    Win32-facility HRESULT with the injector's own ErrorCode says which.

    Two guest round trips: upload the .ps1, then invoke it by path. The
    upload is what keeps the invocation command line small enough for
    drakshell to accept (see _build_read_probe_script). An upload failure is
    recorded as `upload_error` and the invocation is then skipped, so the
    artifact distinguishes "could not deliver the probe" from "the probe ran
    and reported something".

    Never raises: every failure becomes a field in the artifact and
    al-khaser's own control flow continues untouched."""
    guest_script_path = read_probe_script_guest_path(guest_dir, checkpoint)
    probe: Dict[str, Any] = {
        "checkpoint": checkpoint,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "guest_path": guest_path,
        "guest_script_path": guest_script_path,
        "mechanism": (
            "probe script uploaded via GuestSession.put_file(), then run as "
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script> "
            "via GuestSession.run()/drakshell; read-only "
            "[System.IO.File]::Open(FileAccess.Read, FileShare.ReadWrite|"
            "Delete) + SHA-256; never starts a process and never modifies "
            "the target file"
        ),
        "host_sha256": None,
    }
    # Every parsed field present as None up front, so the artifact's schema
    # is identical whether the probe ran, ran and was garbled, or could not
    # run at all - an absent key must never have to be read as a result.
    probe.update(_parse_read_probe_output(""))

    try:
        probe["host_sha256"] = hashlib.sha256(
            pathlib.Path(host_binary_path).read_bytes()
        ).hexdigest()
    except Exception as exc:  # noqa: BLE001 - diagnostic-only, must not raise
        probe["host_error"] = str(exc)

    script_text = _build_read_probe_script(guest_path, probe["host_sha256"])
    probe_argv = _build_read_probe_argv(guest_script_path)
    probe["script"] = script_text
    probe["command"] = " ".join(probe_argv)
    # Imported at function scope, not module scope: guest_runner imports
    # drakrun.evasion.verifiers.base, whose package __init__ registers this
    # very adapter, so a module-level import here closes an import cycle
    # whenever guest_runner happens to be imported first. This mirrors the
    # deferred-import convention drakrun.evasion.worker already follows.
    from drakrun.evasion.guest_runner import (
        DRAKSHELL_MAX_CMDLINE_BYTES,
        encoded_cmdline_size,
    )

    # Recorded so the artifact itself shows the invocation stayed inside
    # drakshell's ceiling - the exact thing that silently failed last time.
    probe["cmdline_bytes"] = encoded_cmdline_size(probe_argv)
    probe["cmdline_limit_bytes"] = DRAKSHELL_MAX_CMDLINE_BYTES

    parsed: Dict[str, Any] = {}
    try:
        _upload_read_probe_script(session, script_text, guest_script_path)
    except Exception as exc:  # noqa: BLE001 - diagnostic-only, must not raise
        probe["upload_error"] = str(exc)
    else:
        try:
            # No cwd on purpose - see _build_read_probe_argv().
            exit_code, stdout, stderr = session.run(
                probe_argv, timeout=_READ_PROBE_TIMEOUT_SECONDS
            )
            stdout_text = stdout.decode("utf-8", errors="replace")
            probe["exit_code"] = exit_code
            probe["stdout"] = stdout_text
            probe["stderr"] = stderr.decode("utf-8", errors="replace")
            parsed = _parse_read_probe_output(stdout_text)
            probe.update(parsed)
        except Exception as exc:  # noqa: BLE001 - diagnostic-only, must not raise
            probe["probe_error"] = str(exc)

    probe["classification"] = _classify_read_probe(parsed, probe.get("host_sha256"))

    try:
        probe_path = raw_dir / f"read_probe_{checkpoint}.json"
        probe_path.write_text(json.dumps(probe, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001 - diagnostic-only, must not raise
        pass

    return probe


def _diagnose_uploaded_binary(
    session: GuestSession,
    host_binary_path: str,
    guest_binary_path: str,
    raw_dir: pathlib.Path,
    label: str,
) -> Dict[str, Any]:
    """Best-effort, read-only diagnostic for the confirmed combined-scan
    al-khaser launch failure ("The system cannot execute the specified
    program.", scan d21be3bc-f39f-42d4-a34f-0642149fd6f4): retrieves the
    just-uploaded guest binary via GuestSession.get_file() (the same
    Injector.read_file() primitive get_file() already uses for stdout.txt/
    log.txt - this reads the actual guest-disk bytes directly, it does not
    depend on cmd.exe/pwsh or execute anything in the guest) and hashes it
    against the host original, so a future real-Xen run can show whether the
    uploaded bytes were ever wrong (upload/write corruption) or were correct
    immediately after upload but had changed by the time al-khaser was about
    to be launched (something else acting on the file in between). Called
    twice from AlKhaserAdapter.run() - once right after put_file(), once
    right before run() - so the two snapshots can be diffed against each
    other, not just against the host original.

    Deliberately never raises and never alters al-khaser's own control flow:
    every failure mode (host file unreadable, guest file missing/unreadable)
    is captured as a field in the returned/written diagnostic instead, so a
    diagnostic-retrieval problem cannot itself change ToolStatus or hide the
    launch failure being investigated."""
    diagnostic: Dict[str, Any] = {
        "label": label,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "guest_path": guest_binary_path,
    }

    try:
        host_bytes = pathlib.Path(host_binary_path).read_bytes()
        diagnostic["host_size"] = len(host_bytes)
        diagnostic["host_sha256"] = hashlib.sha256(host_bytes).hexdigest()
    except Exception as exc:  # noqa: BLE001 - diagnostic-only, must not raise
        diagnostic["host_error"] = str(exc)

    local_copy = raw_dir / f"_diag_readback_{label}.tmp"
    try:
        session.get_file(guest_binary_path, local_copy)
        guest_bytes = local_copy.read_bytes()
        diagnostic["guest_exists"] = True
        diagnostic["guest_size"] = len(guest_bytes)
        diagnostic["guest_sha256"] = hashlib.sha256(guest_bytes).hexdigest()
    except Exception as exc:  # noqa: BLE001 - diagnostic-only, must not raise
        diagnostic["guest_exists"] = False
        diagnostic["guest_error"] = str(exc)
        # GuestSession.get_file() raises InjectorReadError - a RuntimeError
        # SUBCLASS, so nothing about this except-clause or any other caller
        # changed - carrying the injector's raw stdout and DRAKVUF's own
        # {"Status": "Error", "ErrorCode": N, "Error": "<SYMBOLIC>"} record
        # (src/libinjector/injector_utils.c, printed on stdout under the
        # `-o json` drakrun already passes). That is the precise Win32
        # reason CreateFileW failed, which DRAKVUF's single opaque
        # "Couldn't open guest file" stderr string does not carry.
        #
        # Detected structurally via hasattr rather than by importing
        # guest_runner: the adapter must keep working against any
        # GuestSession Protocol implementation (the unit-test fakes raise
        # plain FileNotFoundError), and an import of guest_runner from a
        # verifier module would close an import cycle through
        # drakrun.evasion.verifiers.__init__.
        if hasattr(exc, "injector_json"):
            diagnostic["injector_returncode"] = getattr(exc, "returncode", None)
            diagnostic["injector_stdout"] = getattr(exc, "stdout", None)
            diagnostic["injector_stderr"] = getattr(exc, "stderr", None)
            diagnostic["injector_error_json"] = getattr(exc, "injector_json", None)
            diagnostic["injector_error_code"] = getattr(exc, "error_code", None)
            diagnostic["injector_error_name"] = getattr(exc, "error_name", None)
    finally:
        # Only the hash/size diagnostic is kept as an artifact, not the
        # binary itself - al-khaser is not redistributed by this project
        # (see the "No al-khaser binary configured" error message above).
        try:
            local_copy.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001 - best-effort cleanup only
            pass

    try:
        diag_path = raw_dir / f"diag_{label}.json"
        diag_path.write_text(json.dumps(diagnostic, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001 - diagnostic-only, must not raise
        pass

    return diagnostic


class AlKhaserAdapter(VerifierAdapter):
    id = TOOL_ID
    display_name = "al-khaser"
    # al-khaser is a Windows PE binary; it has no Linux/Android build.
    supported_platforms = frozenset({"windows"})

    def options_schema(self) -> Dict[str, Any]:
        return {
            "full_suite_only": False,
            "options": [
                {
                    "name": "checks",
                    "kind": "multiselect",
                    "label": "Check categories",
                    "choices": list(ALKHASER_CHECK_TYPES),
                    "default": list(DEFAULT_ENABLED_CHECK_TYPES),
                    "note": (
                        "CODE_INJECTIONS is not part of the default suite and "
                        "produces no machine-readable verdict in this al-khaser "
                        "version even when selected."
                    ),
                },
                {
                    "name": "sleep_seconds",
                    "kind": "integer",
                    "label": "Timing-attack sleep duration (seconds)",
                    "default": ALKHASER_DEFAULT_SLEEP_SECONDS,
                    "minimum": 1,
                    "note": (
                        "al-khaser's own default is 600s, and TIMING_ATTACKS "
                        "performs nine separate sleeps of this duration - an "
                        "unqualified full run would sleep for roughly 90 minutes."
                    ),
                },
            ],
        }

    def validate_options(self, tool_options: Dict[str, Any]) -> Dict[str, Any]:
        checks = tool_options.get("checks")
        if checks is not None:
            if not isinstance(checks, list) or not all(
                isinstance(c, str) for c in checks
            ):
                raise VerifierError("checks must be a list of strings", field="checks")
            unknown = [c for c in checks if c not in ALKHASER_CHECK_TYPES]
            if unknown:
                raise VerifierError(
                    f"Unknown al-khaser check type(s): {unknown!r}. "
                    f"Valid values are: {list(ALKHASER_CHECK_TYPES)}",
                    field="checks",
                )
            if len(checks) != len(set(checks)):
                raise VerifierError(
                    "checks must not contain duplicates", field="checks"
                )

        sleep_seconds = tool_options.get(
            "sleep_seconds", ALKHASER_DEFAULT_SLEEP_SECONDS
        )
        if not isinstance(sleep_seconds, int) or isinstance(sleep_seconds, bool):
            raise VerifierError(
                "sleep_seconds must be an integer", field="sleep_seconds"
            )
        if sleep_seconds < 1:
            raise VerifierError("sleep_seconds must be >= 1", field="sleep_seconds")

        return {
            "checks": list(checks) if checks else None,
            "sleep_seconds": sleep_seconds,
        }

    def _effective_check_types(self, checks: Optional[List[str]]) -> List[str]:
        """Which check types actually run, in main()'s fixed order - the
        default set if checks is None/empty (mirrors a bare invocation with
        no --check flags), else exactly what was requested."""
        selected = set(checks) if checks else set(DEFAULT_ENABLED_CHECK_TYPES)
        return [t for t in MAIN_EXECUTION_ORDER if t in selected]

    def _parse_log_lines(self, text: str) -> List[Tuple[str, bool]]:
        """Parse every '[*] <msg> -> <0|1>' line, in file order. Returns
        (message, detected) pairs; a line that doesn't match the format is
        simply not yielded (never guessed at)."""
        out = []
        for line in text.splitlines():
            m = _LOG_LINE_RE.match(line)
            if m:
                out.append((m.group("msg").rstrip(), m.group("result") != "0"))
        return out

    def _parse_stdout_lines(self, text: str) -> List[Tuple[str, bool]]:
        """Fallback parser for the padded stdout format, used only when
        log.txt could not be retrieved at all."""
        out = []
        for line in text.splitlines():
            m = _STDOUT_LINE_RE.match(line)
            if m:
                out.append((m.group("msg").rstrip(), m.group("verdict") == "BAD"))
        return out

    def _normalize(
        self, checks: Optional[List[str]], parsed_lines: List[Tuple[str, bool]]
    ) -> List[NormalizedCheck]:
        """Positionally pair parsed (message, detected) lines against the
        expected exec_check sequence for each selected check type, in
        main()'s fixed execution order. A check type with zero expected
        messages (VPC, CODE_INJECTIONS, ANALYSIS_TOOLS, ANTI_DISASSM,
        DUMPING_CHECK, or any category run entirely through bare/unwrapped
        calls) contributes a single explanatory `skipped` entry instead of
        being silently absent - so its console output being unparsed is
        visible in the normalized result, not just in the raw files."""
        results: List[NormalizedCheck] = []
        cursor = 0
        for check_type in self._effective_check_types(checks):
            specs = _CHECK_TYPE_CHECKS.get(check_type, [])
            if not specs:
                results.append(
                    NormalizedCheck(
                        id=f"alkhaser.skipped.{check_type.lower()}",
                        category=Category.design_specific,
                        name=f"{check_type} (no machine-readable output)",
                        description=(
                            f"al-khaser's {check_type} checks run directly "
                            "without going through its exec_check result "
                            "wrapper, so this version of al-khaser produces "
                            "no parseable per-check verdict for this "
                            "category. Its console output is preserved in "
                            "the raw artifacts for manual review."
                        ),
                        status=CheckStatus.skipped,
                        severity=Severity.info,
                        tool=TOOL_ID,
                    )
                )
                continue
            for spec in specs:
                if (
                    cursor < len(parsed_lines)
                    and parsed_lines[cursor][0] == spec.message.rstrip()
                ):
                    _, detected = parsed_lines[cursor]
                    cursor += 1
                    status = CheckStatus.detected if detected else CheckStatus.clean
                else:
                    status = CheckStatus.error
                results.append(
                    NormalizedCheck(
                        id=f"alkhaser.{spec.category.value}.{spec.slug}",
                        category=spec.category,
                        name=spec.message.strip(),
                        description=spec.description,
                        status=status,
                        severity=(
                            _severity_for(spec)
                            if status != CheckStatus.error
                            else Severity.info
                        ),
                        tool=TOOL_ID,
                        error_detail=(
                            None
                            if status != CheckStatus.error
                            else "Expected log line for this check was missing or out of order."
                        ),
                    )
                )
        return results

    def run(
        self,
        session: GuestSession,
        options: Dict[str, Any],
        scan_dir: pathlib.Path,
        deadline: float,
    ) -> ToolResult:
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        raw_dir = scan_dir / "raw" / TOOL_ID
        raw_dir.mkdir(parents=True, exist_ok=True)

        host_binary_path = options.get("host_binary_path")
        if not host_binary_path:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.unsupported,
                started_at=started_at,
                finished_at=started_at,
                error=(
                    "No al-khaser binary configured "
                    "([evasion.alkhaser].host_binary_path). The tool is not "
                    "redistributed by this project - place al-khaser_x64.exe "
                    "on the host and configure its path."
                ),
            )

        try:
            validated = self.validate_options(options)
        except VerifierError as exc:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=started_at,
                error=str(exc),
            )

        guest_binary_path = r"C:\Users\Public\alkhaser\al-khaser_x64.exe"
        guest_dir = r"C:\Users\Public\alkhaser"
        guest_stdout_path = guest_dir + r"\stdout.txt"
        guest_log_path = guest_dir + r"\log.txt"

        command_txt = build_argv(
            validated["checks"],
            validated["sleep_seconds"],
            guest_binary_path,
            guest_stdout_path,
        )
        (raw_dir / "command.txt").write_text(" ".join(command_txt), encoding="utf-8")

        try:
            session.put_file(pathlib.Path(host_binary_path), guest_binary_path)
            # ---- POST_UPLOAD checkpoint -------------------------------
            # The three diagnostics are ordered so that the cheapest and
            # least perturbing observation sits CLOSEST to the event being
            # observed, and the heaviest sits furthest from it. Mirrored
            # around the launch (see PRE_RUN below), this brackets the whole
            # window: a metadata probe immediately after put_file() and
            # another immediately before run(), with the two injector
            # read-backs adjacent in the middle where they can least distort
            # what they measure.
            #
            # 1. metadata only - GetFileAttributes/FindFirstFile class, never
            #    opens the data stream at all.
            # 2. ordinary user-mode open+read+SHA-256 from powershell.exe -
            #    opens the data stream, but from a normal guest process.
            # 3. DRAKVUF injector readfile - opens the data stream from the
            #    injected context, and now reports its own Win32 ErrorCode.
            _probe_guest_file_metadata(
                session, guest_binary_path, guest_dir, raw_dir, "post_upload"
            )
            _probe_guest_file_read(
                session,
                host_binary_path,
                guest_binary_path,
                guest_dir,
                raw_dir,
                "post_upload",
            )
            _diagnose_uploaded_binary(
                session, host_binary_path, guest_binary_path, raw_dir, "post_upload"
            )
            timeout = max(0.0, deadline - time.time())
            # ---- PRE_RUN checkpoint (reverse order) -------------------
            _diagnose_uploaded_binary(
                session, host_binary_path, guest_binary_path, raw_dir, "pre_run"
            )
            _probe_guest_file_read(
                session,
                host_binary_path,
                guest_binary_path,
                guest_dir,
                raw_dir,
                "pre_run",
            )
            # Last observation before launch, through the same guest-side
            # mechanism (drakshell -> cmd.exe) the launch itself uses.
            _probe_guest_file_metadata(
                session, guest_binary_path, guest_dir, raw_dir, "pre_run"
            )
            exit_code, _stdout, _stderr = session.run(
                command_txt, timeout=timeout, cwd=guest_dir
            )
        except VerifierTimeout:
            finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.timeout,
                started_at=started_at,
                finished_at=finished_at,
                command=" ".join(command_txt),
                error=f"al-khaser did not finish within its {validated['sleep_seconds']}s+ budget.",
            )
        except (
            Exception
        ) as exc:  # noqa: BLE001 - any guest/transport failure becomes ToolResult(error)
            finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=finished_at,
                command=" ".join(command_txt),
                error=f"Failed to launch al-khaser in the guest: {exc}",
            )

        # Exit code is unconditionally 0 in this al-khaser version and is
        # never treated as a verdict; it is recorded purely for audit.
        raw_artifacts: List[str] = []
        for checkpoint in ("post_upload", "pre_run"):
            for prefix in ("diag", "probe", "read_probe"):
                diag_path = raw_dir / f"{prefix}_{checkpoint}.json"
                if diag_path.exists():
                    raw_artifacts.append(str(diag_path.relative_to(scan_dir)))
        stdout_text = ""
        log_text: Optional[str] = None

        local_stdout = raw_dir / "stdout.txt"
        try:
            session.get_file(guest_stdout_path, local_stdout)
            stdout_text = local_stdout.read_text(encoding="utf-8", errors="replace")
            raw_artifacts.append(str(local_stdout.relative_to(scan_dir)))
        except Exception:  # noqa: BLE001 - retrieval failure is reported, not fatal
            pass

        local_log = raw_dir / "log.txt"
        try:
            session.get_file(guest_log_path, local_log)
            log_text = local_log.read_text(encoding="utf-8", errors="replace")
            raw_artifacts.append(str(local_log.relative_to(scan_dir)))
        except (
            Exception
        ):  # noqa: BLE001 - al-khaser may not have written a log.txt at all
            pass

        finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if log_text is not None:
            parsed = self._parse_log_lines(log_text)
        elif stdout_text:
            parsed = self._parse_stdout_lines(stdout_text)
        else:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=exit_code,
                command=" ".join(command_txt),
                raw_artifacts=raw_artifacts,
                error="Neither log.txt nor stdout could be retrieved from the guest.",
            )

        checks = self._normalize(validated["checks"], parsed)

        return ToolResult(
            tool=TOOL_ID,
            status=ToolStatus.ok,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=exit_code,
            command=" ".join(command_txt),
            checks=checks,
            raw_artifacts=raw_artifacts,
        )


__all__ = [
    "AlKhaserAdapter",
    "ALKHASER_CHECK_TYPES",
    "DEFAULT_ENABLED_CHECK_TYPES",
    "ALKHASER_DEFAULT_SLEEP_SECONDS",
    "MAIN_EXECUTION_ORDER",
    "build_argv",
]
