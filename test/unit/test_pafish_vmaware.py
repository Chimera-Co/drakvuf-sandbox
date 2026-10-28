"""Pafish and VMAware adapters: output parsing and the guest put/run/get sequence."""

import json
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.constants import Category, CheckStatus, ToolStatus  # noqa: E402
from drakrun.evasion.verifiers import get_adapters_for_platform  # noqa: E402
from drakrun.evasion.verifiers.base import VerifierError, VerifierTimeout  # noqa: E402
from drakrun.evasion.verifiers.cpuid_timing import CpuidTimingAdapter  # noqa: E402
from drakrun.evasion.verifiers.pafish import PafishAdapter, parse_stdout  # noqa: E402
from drakrun.evasion.verifiers.vmaware import VMAwareAdapter, parse_report  # noqa: E402
from drakrun.lib.config import (  # noqa: E402
    EvasionConfigSection,
    SandboxDefinitionSection,
)

# Shaped like Pafish v0.6's console output (print_check_group / exec_check in common.c)
PAFISH_STDOUT = (
    "* Pafish (Paranoid fish) *\r\n\r\n"
    "[-] Windows version: 6.2 build 9200\r\n"
    "[-] Running in WoW64: False\r\n"
    "[-] CPU: GenuineIntel\r\n\r\n"
    "[-] Debuggers detection\r\n"
    "[*] Using IsDebuggerPresent() ... OK\r\n\r\n"
    "[-] CPU information based detections\r\n"
    "[*] Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit ... traced!\r\n"
    "[*] Checking hypervisor bit in cpuid feature bits ... OK\r\n\r\n"
    "[-] Generic reverse turing tests\r\n"
    "[*] Checking mouse movement ... OK\r\n\r\n"
    "[-] Generic sandbox detection\r\n"
    "[*] Checking operating system uptime using GetTickCount() ... \r\n"
    "[!] uptime warning printed by the check\r\n"
    "traced!\r\n\r\n"
    "[-] Pafish has finished analyzing the system, check the log file for more information\r\n"
)
VMAWARE_JSON = {
    "is_detected": True,
    "brand": "Xen HVM",
    "conclusion": "Running inside a Xen HVM VM",
    "percentage": 100,
    "detected_technique_count": 4,
    "vm_type": "Hypervisor (type 1)",
    "detected_techniques": ["HYPERVISOR_BIT", "TIMER"],
}


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / "tool.exe"
    path.write_bytes(b"MZ-fake")
    return path


def run(adapter, session, binary, tmp_path):
    options = {"host_binary_path": str(binary)} if binary else {}
    return adapter.run(session, options, tmp_path / "scan", time.time() + 60)


def test_pafish_parses_verdicts_groups_and_late_verdicts():
    checks = {c.name: c for c in parse_stdout(PAFISH_STDOUT)}
    assert len(checks) == 5
    assert checks["Using IsDebuggerPresent()"].status == CheckStatus.clean
    rdtsc = checks[
        "Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit"
    ]
    assert rdtsc.status == CheckStatus.detected and rdtsc.category == Category.timing
    assert (
        checks["Checking mouse movement"].category == Category.behavioural_interaction
    )
    uptime = checks["Checking operating system uptime using GetTickCount()"]
    assert (
        uptime.status == CheckStatus.detected
        and uptime.category == Category.environment_artifact
    )
    assert (
        uptime.id
        == "pafish.generic_sandbox_detection.checking_operating_system_uptime_using_gettickcount"
    )


def test_pafish_run_uploads_runs_with_stdin_from_nul_and_reads_back(binary, tmp_path):
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\pafish\stdout.txt": PAFISH_STDOUT.encode(),
            r"C:\Users\Public\pafish\pafish.log": b"[pafish] Start\n",
        }
    )
    result = run(PafishAdapter(), session, binary, tmp_path)
    assert result.status == ToolStatus.ok and len(result.checks) == 5
    assert session.put_file_calls == [(binary, r"C:\Users\Public\pafish\pafish64.exe")]
    argv, _, cwd = session.run_calls[0]
    assert argv == [
        "cmd",
        "/c",
        r"C:\Users\Public\pafish\pafish64.exe < NUL > C:\Users\Public\pafish\stdout.txt 2>&1",
    ]
    assert cwd == r"C:\Users\Public\pafish"
    assert result.raw_artifacts == ["raw/pafish/stdout.txt", "raw/pafish/pafish.log"]


def test_pafish_without_verdicts_is_an_error_not_a_clean_result(binary, tmp_path):
    session = FakeGuestSession(
        files={r"C:\Users\Public\pafish\stdout.txt": b"crashed\r\n"}
    )
    result = run(PafishAdapter(), session, binary, tmp_path)
    assert result.status == ToolStatus.error and not result.checks


def test_missing_binary_is_unsupported_and_runs_nothing(tmp_path):
    session = FakeGuestSession()
    for adapter in (PafishAdapter(), VMAwareAdapter()):
        assert run(adapter, session, None, tmp_path).status == ToolStatus.unsupported
    assert not session.put_file_calls and not session.run_calls


def test_guest_timeout_is_reported_as_timeout(binary, tmp_path):
    session = FakeGuestSession(raise_on_run=VerifierTimeout("slow"))
    assert run(VMAwareAdapter(), session, binary, tmp_path).status == ToolStatus.timeout


def test_vmaware_verdict_and_techniques():
    checks = parse_report(json.dumps(VMAWARE_JSON))
    verdict = checks[0]
    assert verdict.id == "vmaware.verdict" and verdict.status == CheckStatus.detected
    assert verdict.measured_value == 100 and verdict.evidence["brand"] == "Xen HVM"
    assert [c.id for c in checks[1:]] == [
        "vmaware.technique.HYPERVISOR_BIT",
        "vmaware.technique.TIMER",
    ]
    assert checks[2].category == Category.timing
    clean = parse_report(
        json.dumps({**VMAWARE_JSON, "is_detected": False, "detected_techniques": []})
    )
    assert [c.status for c in clean] == [CheckStatus.clean]


def test_vmaware_tolerates_an_unescaped_backslash_and_rejects_garbage():
    text = json.dumps({**VMAWARE_JSON, "brand": "BRAND"}).replace("BRAND", "Hyper-V\\x")
    assert parse_report(text)[0].evidence["brand"] == "Hyper-V\\x"
    with pytest.raises(ValueError):
        parse_report("{not json")
    with pytest.raises(ValueError):
        parse_report("{}")


def test_vmaware_run_writes_json_to_its_folder(binary, tmp_path):
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\vmaware\stdout.txt": b"",
            r"C:\Users\Public\vmaware\vmaware.json": json.dumps(VMAWARE_JSON).encode(),
        }
    )
    result = run(VMAwareAdapter(), session, binary, tmp_path)
    assert (
        result.status == ToolStatus.ok
        and result.checks[0].status == CheckStatus.detected
    )
    argv = session.run_calls[0][0]
    assert argv[2].startswith(
        r"C:\Users\Public\vmaware\vmaware.exe --json --output C:\Users\Public\vmaware\vmaware.json < NUL >"
    )
    missing = FakeGuestSession(
        files={r"C:\Users\Public\vmaware\stdout.txt": b"Failed to open/create file\n"}
    )
    assert run(VMAwareAdapter(), missing, binary, tmp_path).status == ToolStatus.error


def test_registered_for_windows_with_no_options():
    ids = {a.id for a in get_adapters_for_platform("windows")}
    assert {"pafish", "vmaware"} <= ids
    assert not {"pafish", "vmaware"} & {
        a.id for a in get_adapters_for_platform("linux")
    }
    for adapter in (PafishAdapter(), VMAwareAdapter()):
        assert adapter.validate_options({}) == {}
        with pytest.raises(VerifierError):
            adapter.validate_options({"checks": ["x"]})
    assert PafishAdapter().options_schema()["full_suite_only"]
    assert EvasionConfigSection().pafish.host_binary_path is None
    assert {"pafish", "vmaware"} <= set(SandboxDefinitionSection().verifiers)


def test_vmaware_disable_option_is_validated_and_passed_last(binary, tmp_path):
    adapter = VMAwareAdapter()
    assert adapter.validate_options({"disable": ["GPU_CAPABILITIES"]}) == {
        "disable": ["GPU_CAPABILITIES"]
    }
    for bad in ({"disable": ["eip; del"]}, {"disable": "GPU_CAPABILITIES"}, {"checks": []}):
        with pytest.raises(VerifierError):
            adapter.validate_options(bad)
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\vmaware\vmaware.json": json.dumps(VMAWARE_JSON).encode()
        }
    )
    options = {"host_binary_path": str(binary), "disable": ["GPU_CAPABILITIES", "TIMER"]}
    result = adapter.run(session, options, tmp_path / "scan", time.time() + 60)
    assert result.status == ToolStatus.ok
    assert "--disable GPU_CAPABILITIES,TIMER < NUL >" in session.run_calls[0][0][2]


def test_cpuid_timing_reads_its_statistics_back(binary, tmp_path):
    stat = {
        "n": 100000,
        "min": 1,
        "p5": 2,
        "p25": 3,
        "median": 4,
        "p75": 5,
        "p95": 6,
        "p99": 7,
        "max": 8,
        "mean": 4.0,
    }
    report = {
        "tool": "chimera-cpuid-timing 1",
        "iterations": 100000,
        "rdtsc_rdtsc": stat,
        "rdtsc_cpuid_rdtsc": stat,
        "alkhaser_style_avg10": stat,
        "alkhaser_style_detected": "997/1000",
    }
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\cpuid-timing\cpuid-timing.json": json.dumps(
                report
            ).encode(),
            r"C:\Users\Public\cpuid-timing\cpuid-timing.csv": b"20,1500\n",
        }
    )
    result = run(CpuidTimingAdapter(), session, binary, tmp_path)
    assert result.status == ToolStatus.ok
    check = result.checks[0]
    assert check.status == CheckStatus.detected and check.measured_value == "997/1000"
    assert check.evidence["rdtsc_cpuid_rdtsc"]["median"] == 4
    assert "raw/cpuid-timing/cpuid-timing.csv" in result.raw_artifacts
    assert session.run_calls[0][0][2].startswith(
        r"C:\Users\Public\cpuid-timing\cpuid_timing.exe 100000 C:\Users\Public\cpuid-timing\cpuid-timing.json "
    )
