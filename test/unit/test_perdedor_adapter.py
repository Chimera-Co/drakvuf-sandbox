"""Tests for drakrun.evasion.verifiers.perdedor.PerdedorAdapter.run().

Same four-state coverage as al-khaser (unsupported / error / timeout / ok),
plus PERDEDOR-specific behaviour: it never calls perdedor test windows
(which would run on the wrong host), it requires PowerShell 7 in the guest,
and its findings map 1:1 onto NormalizedCheck via the real, importable
perdedor_common.validation.validate_report.
"""

import json
import pathlib
import sys
import time

import pytest

_THIS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.constants import CheckStatus, ToolStatus  # noqa: E402
from drakrun.evasion.verifiers.base import VerifierError, VerifierTimeout  # noqa: E402
from drakrun.evasion.verifiers.perdedor import PerdedorAdapter  # noqa: E402


def _valid_report(detected=False):
    return {
        "perdedor_version": "0.1.0",
        "platform": "windows",
        "hostname": "test-guest",
        "generated_at": "2024-01-01T00:00:00+00:00",
        "agent_metadata": {"os": "Windows", "os_release": "10"},
        "findings": [
            {
                "id": "windows.environment_artifact.smbios_vendor",
                "category": "environment_artifact",
                "platform": "windows",
                "name": "SMBIOS system vendor string",
                "description": "Raw SMBIOS firmware table scan for vendor strings.",
                "status": "detected" if detected else "clean",
                "severity": "high",
                "evidence": "QEMU" if detected else None,
                "remediation": (
                    "Spoof SMBIOS vendor strings in cfg.template." if detected else None
                ),
                "error_detail": None,
            }
        ],
        "summary": {
            "total": 1,
            "clean": 0 if detected else 1,
            "detected": 1 if detected else 0,
            "errored": 0,
            "skipped": 0,
            "raw_score": "0/1" if detected else "1/1",
            "weighted_score": 35.0 if detected else 100.0,
        },
    }


@pytest.fixture
def repo_path(tmp_path):
    # Only delivery is faked; validation uses installed perdedor_common.
    agent_dir = tmp_path / "agent-repo" / "agents" / "windows"
    agent_dir.mkdir(parents=True)
    (agent_dir / "Invoke-Perdedor.ps1").write_text("# test agent")
    return str(agent_dir.parent.parent)


def test_unsupported_when_no_repo_configured(tmp_path):
    adapter = PerdedorAdapter()
    session = FakeGuestSession()
    result = adapter.run(session, {}, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.unsupported
    assert "repo_path" in result.error
    assert session.run_calls == []


def test_unsupported_when_agent_tree_missing(tmp_path):
    adapter = PerdedorAdapter()
    session = FakeGuestSession()
    options = {"repo_path": str(tmp_path / "not-a-real-checkout")}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.unsupported
    assert "Invoke-Perdedor.ps1" in result.error


def test_unsupported_when_pwsh_missing_in_guest(tmp_path, repo_path):
    adapter = PerdedorAdapter()
    session = FakeGuestSession(probe_result=(False, "pwsh: command not found"))
    options = {"repo_path": repo_path}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.unsupported
    assert "PowerShell 7" in result.error
    assert "pwsh: command not found" in result.error
    assert session.put_tree_calls == []


def test_timeout_is_distinct_from_error(tmp_path, repo_path):
    adapter = PerdedorAdapter()
    session = FakeGuestSession(raise_on_run=VerifierTimeout())
    options = {"repo_path": repo_path}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.timeout
    assert result.status != ToolStatus.error


def test_error_on_guest_launch_failure(tmp_path, repo_path):
    adapter = PerdedorAdapter()
    session = FakeGuestSession(raise_on_run=RuntimeError("drakshell channel closed"))
    options = {"repo_path": repo_path}

    result = adapter.run(session, options, tmp_path, deadline=time.time() + 60)

    assert result.status == ToolStatus.error
    assert "drakshell channel closed" in result.error


def test_error_on_malformed_json(tmp_path, repo_path):
    session = FakeGuestSession(
        files={r"C:\Users\Public\perdedor\windows-report.json": b"{not valid json"},
    )
    adapter = PerdedorAdapter()
    result = adapter.run(
        session, {"repo_path": repo_path}, tmp_path, deadline=time.time() + 60
    )

    assert result.status == ToolStatus.error
    assert "JSON" in result.error
    assert result.raw_artifacts


def test_error_on_schema_validation_failure(tmp_path, repo_path):
    bad_report = {"perdedor_version": "0.1.0"}
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(
                bad_report
            ).encode(),
        },
    )
    adapter = PerdedorAdapter()
    result = adapter.run(
        session, {"repo_path": repo_path}, tmp_path, deadline=time.time() + 60
    )

    assert result.status == ToolStatus.error
    assert "schema" in result.error.lower()


def test_completed_run_with_findings(tmp_path, repo_path):
    report = _valid_report(detected=True)
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(
                report
            ).encode(),
        },
    )
    adapter = PerdedorAdapter()
    result = adapter.run(
        session, {"repo_path": repo_path}, tmp_path, deadline=time.time() + 60
    )

    assert result.status == ToolStatus.ok
    assert result.tool_version == "0.1.0"
    assert len(result.checks) == 1
    check = result.checks[0]
    assert check.id == "windows.environment_artifact.smbios_vendor"
    assert check.status == CheckStatus.detected
    assert check.evidence == "QEMU"
    assert check.remediation == "Spoof SMBIOS vendor strings in cfg.template."
    assert len(session.put_tree_calls) == 1
    launched_argv = session.run_calls[0][0]
    assert launched_argv[0] == "pwsh"
    assert "Invoke-Perdedor.ps1" in " ".join(launched_argv)
    assert "test" not in launched_argv


def test_validate_options_rejects_unknown_fields():
    adapter = PerdedorAdapter()

    with pytest.raises(VerifierError):
        adapter.validate_options({"checks": ["DEBUG"]})


def test_options_schema_declares_full_suite_only():
    adapter = PerdedorAdapter()
    schema = adapter.options_schema()
    assert schema["full_suite_only"] is True
    assert schema["options"] == []


@pytest.mark.parametrize("exit_code", [1, -1, 255])
def test_nonzero_exit_cannot_produce_ok(tmp_path, repo_path, exit_code):
    session = FakeGuestSession(
        run_result=(exit_code, b"partial output", b"agent failed"),
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(
                _valid_report()
            ).encode(),
        },
    )
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.error
    assert result.exit_code == exit_code
    assert "exit" in result.error.lower()
    assert result.checks  # Partial findings remain auditable, but cannot score.
    assert "raw/perdedor/windows-report.json" in result.raw_artifacts


@pytest.mark.parametrize(
    "weighted_score",
    [float("nan"), float("inf"), -float("inf"), True, "100", None],
)
def test_rejects_nonfinite_or_nonnumeric_summary(tmp_path, repo_path, weighted_score):
    report = _valid_report()
    report["summary"]["weighted_score"] = weighted_score
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(report).encode()
        }
    )
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.error
    assert result.checks == []


def test_rejects_duplicate_check_ids(tmp_path, repo_path):
    report = _valid_report()
    report["findings"].append(dict(report["findings"][0]))
    report["summary"].update(total=2, clean=2, raw_score="2/2")
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(report).encode()
        }
    )
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.error
    assert "duplicate" in result.error.lower()
    assert result.checks == []


@pytest.mark.parametrize("check_id", [[], {}, None])
def test_malformed_check_id_is_an_error_not_an_exception(tmp_path, repo_path, check_id):
    report = _valid_report()
    report["findings"][0]["id"] = check_id
    session = FakeGuestSession(
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(report).encode()
        }
    )
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.error
    assert result.checks == []


def test_report_too_large_is_rejected_before_read(tmp_path, repo_path, monkeypatch):
    monkeypatch.setattr(
        "drakrun.evasion.verifiers.base.MAX_REPORT_BYTES", 256, raising=False
    )
    session = FakeGuestSession(
        files={r"C:\Users\Public\perdedor\windows-report.json": b" " * 257}
    )
    original_open = pathlib.Path.open

    def guarded_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if path.name == "windows-report.json" and "r" in mode:
            pytest.fail("oversized report opened for reading")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", guarded_open)
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.error
    assert "report too large" in result.error.lower()
    assert "raw/perdedor/windows-report.json" in result.raw_artifacts


def test_truncation_flag_survives_adapter_and_serialization(tmp_path, repo_path):
    from drakrun.evasion.verifiers.base import GuestCommandResult

    session = FakeGuestSession(
        run_result=GuestCommandResult(0, b"[output truncated]", b"", truncated=True),
        files={
            r"C:\Users\Public\perdedor\windows-report.json": json.dumps(
                _valid_report()
            ).encode()
        },
    )
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.ok
    assert result.truncated is True
    assert result.to_dict()["truncated"] is True


def test_report_exactly_at_size_limit_is_accepted(tmp_path, repo_path, monkeypatch):
    data = json.dumps(_valid_report()).encode()
    monkeypatch.setattr("drakrun.evasion.verifiers.base.MAX_REPORT_BYTES", len(data))
    session = FakeGuestSession(
        files={r"C:\Users\Public\perdedor\windows-report.json": data}
    )
    result = PerdedorAdapter().run(
        session, {"repo_path": repo_path}, tmp_path, time.time() + 60
    )
    assert result.status == ToolStatus.ok


def test_report_growth_after_stat_still_has_a_bounded_read(tmp_path, monkeypatch):
    from io import BytesIO
    from types import SimpleNamespace

    from drakrun.evasion.verifiers.base import ReportTooLarge, read_report_bytes

    monkeypatch.setattr("drakrun.evasion.verifiers.base.MAX_REPORT_BYTES", 256)
    monkeypatch.setattr(pathlib.Path, "stat", lambda *args: SimpleNamespace(st_size=1))
    read_sizes = []

    class GrowingReport(BytesIO):
        def read(self, size=-1):
            read_sizes.append(size)
            return super().read(size)

    monkeypatch.setattr(pathlib.Path, "open", lambda *args: GrowingReport(b"x" * 4096))
    with pytest.raises(ReportTooLarge, match="Report too large"):
        read_report_bytes(tmp_path / "windows-report.json")
    assert read_sizes == [257]
