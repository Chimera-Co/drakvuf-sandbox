"""Offline Linux delivery and recorded-report coverage for PERDEDOR."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

import pytest

from fake_guest_session import FakeGuestSession
from perdedor_common.validation import validate_report

from drakrun.evasion.constants import ToolStatus
from drakrun.lib.linux_install import GUEST_AGENT_DIR
from drakrun.lib.linux_install import GUEST_WORK_DIR as WORK_DIR
from drakrun.evasion.scoring import compute_score
from drakrun.evasion.verifiers import get_adapters_for_platform
from drakrun.evasion.verifiers.base import GuestCommandResult, VerifierTimeout
from drakrun.evasion.verifiers.perdedor import PerdedorAdapter
from drakrun.evasion.verifiers.perdedor_linux import build_linux_zipapp

REPO = Path(__file__).resolve().parents[2] / "perdedor"
REPORT = Path(__file__).parent / "fixtures/perdedor-linux-report.json"
GUEST_REPORT = f"{GUEST_AGENT_DIR}/perdedor-linux-report.json"


def test_zipapp_runs_without_site_packages_or_checkout(tmp_path):
    app, output = tmp_path / "agent.pyz", tmp_path / "report.json"
    build_linux_zipapp(REPO, app)
    with zipfile.ZipFile(app) as archive:
        names = archive.namelist()
        assert all(name.endswith(".py") for name in names)
        assert "perdedor_linux/runner.py" in names
        assert "perdedor_common/models.py" in names
    run = subprocess.run(
        [sys.executable, "-I", "-S", str(app), "--output", str(output)],
        cwd=tmp_path,
        env={**os.environ, "HOME": str(tmp_path), "PATH": ""},
        capture_output=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr.decode()
    report = json.loads(output.read_text())
    validate_report(report)
    assert report["platform"] == "linux"
    assert report["summary"]["total"] >= 30
    # These probes explicitly skip when no native helper/compiler is shipped.
    by_id = {f["id"]: f for f in report["findings"]}
    assert by_id["linux.env.cpuid_hypervisor_bit"]["status"] == "skipped"
    assert by_id["linux.timing.rdtsc_cpuid_jitter"]["status"] == "skipped"


def test_linux_staging_execution_and_recorded_report(tmp_path):
    session = FakeGuestSession(files={GUEST_REPORT: REPORT.read_bytes()})
    session.probe_command = lambda *a, **kw: pytest.fail("Linux must not probe pwsh")
    adapter = PerdedorAdapter()
    state = adapter.stage(
        session,
        {"guest_os": "linux", "repo_path": str(REPO)},
        tmp_path,
        time.time() + 30,
    )
    assert len(session.put_file_calls) == 1
    assert session.put_tree_calls == session.run_calls == session.get_file_calls == []
    adapter.execute(state)
    argv, timeout, _ = session.run_calls[0]
    assert argv == [
        "python3",
        f"{WORK_DIR}/perdedor-linux.pyz",
        "--output",
        GUEST_REPORT,
    ]
    assert 0 < timeout <= 30
    assert session.get_file_calls == []
    result = adapter.collect(state)
    assert result.status == ToolStatus.ok
    report = json.loads(REPORT.read_text())
    assert len(result.checks) == len(report["findings"])
    for check, finding in zip(result.checks, report["findings"]):
        for field in (
            "id",
            "category",
            "status",
            "severity",
            "evidence",
            "remediation",
            "error_detail",
        ):
            assert getattr(check, field) == finding.get(field)
        assert check.tool == "perdedor"
    assert compute_score([result]).chimera_score == report["summary"]["weighted_score"]
    assert "raw/perdedor/linux-report.json" in result.raw_artifacts


@pytest.mark.parametrize(
    "mode",
    [
        "timeout",
        "transport",
        "missing",
        "json",
        "schema",
        "duplicate",
        "nan",
        "boolean",
        "platform",
        "finding-platform",
        "nonzero",
        "truncated",
    ],
)
def test_linux_errors_are_never_clean(tmp_path, mode):
    report = json.loads(REPORT.read_text())
    if mode == "schema":
        del report["summary"]
    elif mode == "duplicate":
        report["findings"][1]["id"] = report["findings"][0]["id"]
    elif mode in ("nan", "boolean"):
        report["summary"]["weighted_score"] = float("nan") if mode == "nan" else True
    elif mode == "platform":
        report["platform"] = "windows"
    elif mode == "finding-platform":
        report["findings"][0]["platform"] = "windows"
    data = b"{" if mode == "json" else json.dumps(report).encode()
    session = FakeGuestSession(
        files={} if mode == "missing" else {GUEST_REPORT: data},
        run_result=GuestCommandResult(
            1 if mode == "nonzero" else 0, b"out", b"err", mode == "truncated"
        ),
        raise_on_run=(
            VerifierTimeout("deadline")
            if mode == "timeout"
            else RuntimeError("connection lost") if mode == "transport" else None
        ),
    )
    result = PerdedorAdapter().run(
        session,
        {"guest_os": "linux", "repo_path": str(REPO)},
        tmp_path,
        time.time() + 30,
    )
    assert result.status == (
        ToolStatus.timeout if mode == "timeout" else ToolStatus.error
    )
    assert result.error
    assert compute_score([result]).chimera_score is None
    if mode not in ("timeout", "transport", "missing"):
        assert "raw/perdedor/linux-report.json" in result.raw_artifacts


@pytest.mark.parametrize("repo", [None, "missing"])
def test_missing_linux_source_is_unsupported(tmp_path, repo):
    session = FakeGuestSession()
    result = PerdedorAdapter().run(
        session,
        {"guest_os": "linux", "repo_path": repo},
        tmp_path,
        time.time() + 30,
    )
    assert result.status == ToolStatus.unsupported
    assert session.run_calls == session.put_file_calls == []


def test_linux_registry_offers_perdedor_first():
    assert [a.id for a in get_adapters_for_platform("linux")] == [
        "perdedor",
        "chimera-vmcheck",
    ]
