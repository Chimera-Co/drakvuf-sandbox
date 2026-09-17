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

import pathlib
import re
import shlex
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

    # quoted for guest cmd.exe, not POSIX shlex, but shlex.quote's
    # conservative double-quoting is compatible with cmd.exe's parsing for
    # the plain paths/tokens this adapter ever produces (no embedded quotes).
    inner_str = " ".join(shlex.quote(part) for part in inner)
    return ["cmd", "/c", f"{inner_str} < NUL > {shlex.quote(guest_stdout_path)} 2>&1"]


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
            timeout = max(0.0, deadline - time.time())
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
