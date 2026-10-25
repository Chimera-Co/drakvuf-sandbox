"""Output-driven parsing regressions, using a trimmed 0.82 H1 stdout run.

The fixture preserves original CRLF, padding, wording and repeated checks
from 19 Oct 2026. Only selected lines are included; it is not a full scan.
"""

from collections import Counter
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.constants import (
    Category,
    CheckStatus,
    Severity,
    ToolStatus,
)  # noqa: E402
from drakrun.evasion.verifiers.alkhaser import (
    AlKhaserAdapter,
    _decode_output,
)  # noqa: E402
from drakrun.evasion.verifiers.base import GuestCommandResult  # noqa: E402

EXCERPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "fixtures"
    / "alkhaser-0.82-H1-excerpt.txt"
)
GUEST_DIR = "C:\\Users\\Public\\alkhaser\\"


@pytest.fixture
def run_adapter(tmp_path):
    binary = tmp_path / "al-khaser.exe"
    binary.write_bytes(b"MZ-test")

    def run(files, checks=None, truncated=False):
        session = FakeGuestSession(
            files={GUEST_DIR + name: content for name, content in files.items()},
            run_result=GuestCommandResult(0, b"", b"", truncated=truncated),
        )
        return AlKhaserAdapter().run(
            session,
            {"host_binary_path": str(binary), "checks": checks},
            tmp_path,
            deadline=time.time() + 60,
        )

    return run


def test_real_excerpt_preserves_every_verdict_and_skips_unverdicted_sections(
    run_adapter,
):
    raw = EXCERPT.read_bytes()
    assert b"\r\n" in raw
    result = run_adapter({"stdout.txt": raw})

    assert result.status == ToolStatus.ok
    assert Counter(c.status for c in result.checks) == {
        CheckStatus.clean: 14,
        CheckStatus.detected: 8,
        CheckStatus.skipped: 2,
    }
    assert len({c.id for c in result.checks}) == len(result.checks)
    assert {c.id for c in result.checks if c.status == CheckStatus.skipped} == {
        "alkhaser.skipped.anti_disassm",
        "alkhaser.skipped.dumping_check",
    }
    assert all("Erasing PE header" not in c.name for c in result.checks)
    # Both sections use identical wording; each must keep its catalog id.
    by_id = {c.id: c for c in result.checks}
    assert (
        by_id["alkhaser.environment_artifact.vbox_firmware_smbios"].status
        == CheckStatus.clean
    )
    assert (
        by_id["alkhaser.environment_artifact.qemu_firmware_smbios"].status
        == CheckStatus.clean
    )
    # A known BAD late in the file must survive earlier extra catalog names.
    hyperv = by_id["alkhaser.environment_artifact.hyperv_driver_objects"]
    assert hyperv.status == CheckStatus.detected
    assert hyperv.severity == Severity.medium
    # Real direct-function output is represented, even for an empty catalog.
    tools = [c for c in result.checks if "ResourceHacker.exe" in c.name]
    assert len(tools) == 2
    assert all(c.category == Category.design_specific for c in tools)
    assert all(c.evidence == {"section": "Analysis-tools"} for c in tools)


@pytest.mark.parametrize("verdict", ["[ BAD ]", "[ BAD  ]", "[BAD]", "[  BAD   ]"])
def test_padding_and_unknown_names_do_not_block_later_catalog_checks(verdict):
    text = (
        "----[Debugger Detection]----\r\n"
        "[*] Checking PEB.BeingDebugged   [ GOOD ]\r\n"
        f"[*] Checking a new 0.82 probe   {verdict}\r\n"
        "[*] Checking an unfinished probe\r\n"
        "[ GOOD ]\r\n"  # An orphan verdict cannot finish the previous line.
        "[*] Checking IsDebuggerPresent API   [ GOOD ]\r\n"
    )
    adapter = AlKhaserAdapter()
    checks = adapter._normalize(["DEBUG"], adapter._parse_stdout_lines(text))
    assert [c.status for c in checks] == [
        CheckStatus.clean,
        CheckStatus.detected,
        CheckStatus.clean,
    ]
    assert checks[0].id == "alkhaser.design_specific.is_debugger_present_peb"
    assert checks[1].id.startswith("alkhaser.design_specific.generic_")
    assert checks[2].id == "alkhaser.design_specific.is_debugger_present_api"
    assert (
        checks[1].id
        == adapter._normalize(["DEBUG"], adapter._parse_stdout_lines(text))[1].id
    )


@pytest.mark.parametrize(
    "section, category",
    [
        ("QEMU Detection", Category.environment_artifact),
        ("Timing-attacks", Category.timing),
        ("Analysis-tools", Category.design_specific),
        ("New upstream section", Category.design_specific),
    ],
)
def test_generic_category_comes_from_section(section, category):
    adapter = AlKhaserAdapter()
    parsed = adapter._parse_stdout_lines(
        f"----[{section}]----\n[*] Checking new probe [ BAD ]\n"
    )
    check = adapter._normalize(["DEBUG"], parsed)[0]
    assert check.category == category
    assert check.evidence == {"section": section}
    assert check.status == CheckStatus.detected


def test_stdout_is_authoritative_when_numeric_log_omits_direct_checks(run_adapter):
    # An existing log.txt must not hide stdout-only BAD verdicts, nor double
    # count the checks present in both surfaces.
    result = run_adapter(
        {
            "stdout.txt": EXCERPT.read_bytes(),
            "log.txt": b"[Mon Oct 19 00:00:00 2026] [*] TLS process attach callback -> 0\r\n",
        }
    )
    assert Counter(c.status for c in result.checks)[CheckStatus.detected] == 8
    assert len(result.checks) == 24


@pytest.mark.parametrize("stdout", [None, b"", b"No parseable stdout verdicts\r\n"])
def test_numeric_log_fallback_keeps_unknown_checks_and_resynchronizes(
    run_adapter, stdout
):
    files = {
        "log.txt": (
            b"[Mon Oct 19 00:00:00 2026] [*] TLS thread attach callback -> 0\r\n"
            b"[Mon Oct 19 00:00:00 2026] [*] New upstream check -> 1\r\n"
            b"[Mon Oct 19 00:00:00 2026] [*] TLS process attach callback -> 1\r\n"
            b"[Mon Oct 19 00:00:00 2026] [*] No verdict -> \r\n"
        )
    }
    if stdout is not None:
        files["stdout.txt"] = stdout
    result = run_adapter(files, checks=["TLS"])
    assert result.status == ToolStatus.ok
    assert [c.status for c in result.checks] == [
        CheckStatus.clean,
        CheckStatus.detected,
        CheckStatus.detected,
    ]
    assert (
        result.checks[-1].id == "alkhaser.design_specific.tls_process_attach_callback"
    )


@pytest.mark.parametrize("log", [None, b"", b"garbled log"])
def test_empty_or_unparseable_log_cannot_mask_stdout(run_adapter, log):
    files = {"stdout.txt": EXCERPT.read_bytes()}
    if log is not None:
        files["log.txt"] = log
    assert len(run_adapter(files).checks) == 24


@pytest.mark.parametrize(
    "files",
    [
        {},
        {"stdout.txt": b"", "log.txt": b""},
        {"stdout.txt": b"[*] Checking an unfinished probe\r\n"},
    ],
)
def test_missing_or_unverdicted_output_is_error(run_adapter, files):
    result = run_adapter(files, checks=["DEBUG"])
    assert result.status == ToolStatus.error
    assert result.error
    assert result.checks == []


def test_sections_without_verdicts_remain_skipped(run_adapter):
    result = run_adapter(
        {
            "stdout.txt": b"Begin AntiDisassmConstantCondition\r\n"
            b"----[Anti Dumping]----\r\n[*] Erasing PE header from memory\r\n"
        },
        checks=["ANTI_DISASSM", "DUMPING_CHECK"],
    )
    assert result.status == ToolStatus.ok
    assert len(result.checks) == 2
    assert all(c.status == CheckStatus.skipped for c in result.checks)


def test_truncated_run_retains_observed_verdicts_and_incomplete_flag(run_adapter):
    result = run_adapter(
        {
            "stdout.txt": b"[*] Checking IsDebuggerPresent API [ BAD  ]\r\n"
            b"[*] Checking PEB.BeingDebugged"
        },
        checks=["DEBUG"],
        truncated=True,
    )
    assert result.to_dict()["truncated"] is True
    assert [c.status for c in result.checks] == [CheckStatus.detected]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-be"])
def test_bom_and_crlf_decoding(run_adapter, encoding):
    text = EXCERPT.read_bytes().decode("ascii")
    raw = text.encode(encoding)
    if encoding == "utf-16-be":
        raw = b"\xfe\xff" + raw
    assert _decode_output(raw) == text
    assert len(run_adapter({"stdout.txt": raw}).checks) == 24
