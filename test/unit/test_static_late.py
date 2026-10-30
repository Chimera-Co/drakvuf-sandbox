"""Ghidra failures say where Ghidra was; a static result that lands after the analysis still reaches the verdict."""

import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from drakrun.analyzer.static import sandbox, vm_backend, worker
from drakrun.lib.config import StaticConfigSection

AID = "8f14e45f-ceea-467a-9575-1c4b5d6e7f80"
LOG = "\n".join(
    [
        "INFO  REPORT: Import succeeded (HeadlessAnalyzer)",
        "INFO  ANALYZING all memory and code: /in/sample (HeadlessAnalyzer)",
        "",
    ]
)
RESULT = json.dumps({"functions": [{"name": "entry"}], "decompiled": 1})


def vm_ghidra(monkeypatch, tmp_path, step):
    settings = StaticConfigSection(backend="vm", ghidra_enabled=True)
    monkeypatch.setattr(
        vm_backend, "run_job", lambda *a, **k: {"job": "j", "steps": [step]}
    )
    return sandbox.run_ghidra(settings, AID, tmp_path, [])


def test_vm_timeout_keeps_a_result_the_script_already_wrote(tmp_path, monkeypatch):
    doc = vm_ghidra(
        monkeypatch,
        tmp_path,
        {
            "timed_out": True,
            "files": {
                "ghidra-out/ghidra.json": RESULT,
                "ghidra-out/headless.log": LOG,
            },
        },
    )
    assert doc["functions"] == [{"name": "entry"}] and doc["timed_out"] is True
    assert "error" not in doc


def test_vm_timeout_without_a_result_names_the_phase(tmp_path, monkeypatch):
    doc = vm_ghidra(
        monkeypatch,
        tmp_path,
        {
            "timed_out": True,
            "stderr": "Picked up JAVA_TOOL_OPTIONS\n",
            "files": {"ghidra-out/headless.log": LOG},
        },
    )
    wall = sandbox.ghidra_wall_s(StaticConfigSection())
    assert doc["error"] == f"decompiler timed out after {wall:.0f}s"
    assert doc["log"].endswith(
        "ANALYZING all memory and code: /in/sample (HeadlessAnalyzer)"
    )
    assert doc["stderr"] == "Picked up JAVA_TOOL_OPTIONS\n"


def test_vm_sigkill_is_not_called_a_timeout(tmp_path, monkeypatch):
    doc = vm_ghidra(
        monkeypatch,
        tmp_path,
        {
            "exit_code": 137,
            "stderr": "Picked up JAVA_TOOL_OPTIONS\n" * 100 + "last line\n",
            "files": {"ghidra-out/headless.log": LOG},
        },
    )
    assert doc["error"] == (
        "decompiler was killed (exit 137, SIGKILL before the time limit): last line"
    )
    assert doc["stderr"].endswith("last line\n") and len(doc["stderr"]) == 500
    assert "ANALYZING" in doc["log"]


def test_vm_success_is_unchanged(tmp_path, monkeypatch):
    doc = vm_ghidra(
        monkeypatch,
        tmp_path,
        {"exit_code": 0, "files": {"ghidra-out/ghidra.json": RESULT}},
    )
    assert doc == json.loads(RESULT)


def test_ghidra_step_collects_the_headless_log(tmp_path, monkeypatch):
    steps = []
    monkeypatch.setattr(
        vm_backend, "run_job", lambda s, st, *a, **k: steps.extend(st) or {}
    )
    sandbox.run_ghidra(
        StaticConfigSection(backend="vm", ghidra_enabled=True), AID, tmp_path, []
    )
    assert steps[0]["outputs"] == [
        "ghidra-out/ghidra.json",
        "ghidra-out/headless.log",
    ]


@pytest.mark.parametrize("wrote_result", [True, False])
def test_container_timeout(tmp_path, monkeypatch, wrote_result):
    settings = StaticConfigSection(ghidra_enabled=True)
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "sample").write_bytes(b"MZ")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv[1])
        if argv[1] == "run":
            out = tmp_path / "ghidra-out"
            (out / "headless.log").write_text(LOG)
            if wrote_result:
                (out / "ghidra.json").write_text(RESULT)
            raise subprocess.TimeoutExpired(argv, 5, stderr=b"partial stderr")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    doc = sandbox.run_ghidra(settings, AID, tmp_path, [])
    assert calls == ["run", "kill", "rm"]
    if wrote_result:
        assert doc["timed_out"] is True and doc["functions"]
    else:
        assert doc["error"].startswith("decompiler timed out")
        assert doc["stderr"] == "partial stderr" and "ANALYZING" in doc["log"]
    assert not (tmp_path / "ghidra-out").exists()


def test_deep_json_keeps_the_ghidra_diagnostics(tmp_path, monkeypatch):
    failure = sandbox.ghidra_failure(390, 137, "tail", LOG)
    monkeypatch.setattr(worker, "run_ghidra", lambda *a: failure)
    result = {"capa": {"rules": []}}
    assert worker._decompile(StaticConfigSection(), AID, tmp_path, result) is None
    [error] = result["errors"]
    assert error["stage"] == "ghidra"
    assert error["error"].startswith("decompiler was killed")
    assert error["stderr"] == "tail" and "ANALYZING" in error["log"]


# ---- a fast pass that lands after the analysis


@pytest.fixture
def late(tmp_path, monkeypatch):
    analyses, static = tmp_path / "analyses", tmp_path / "static"
    directory = analyses / AID
    directory.mkdir(parents=True)
    (static / AID).mkdir(parents=True)
    monkeypatch.setattr(worker, "STATIC_DIR", static)
    monkeypatch.setattr(worker, "ANALYSES_DIR", analyses)
    old_verdict = {"schema": "chimera-verdict/1", "label": "benign"}
    files = {
        "metadata.json": {
            "id": AID,
            "status": "finished",
            "options": {"mode": "full"},
            "classification": old_verdict,
        },
        "features.json": {"dynamic": {"x": 1}, "static": None},
        "classification.json": old_verdict,
        "chimera-report.json": {"schema": "chimera-report/1"},
    }
    for name, value in files.items():
        (directory / name).write_text(json.dumps(value))
    os.utime(directory / "chimera-report.json", (1000, 1000))
    (static / AID / "static.json").write_text(
        json.dumps({"schema": sandbox.SCHEMA, "score": 7})
    )
    classified = []

    def classify(features, analysis_dir, model_path, timeout_s):
        classified.append(features)
        return {"schema": "chimera-verdict/1", "label": "malicious"}

    monkeypatch.setattr("drakrun.analyzer.classifier.runner.run_classifier", classify)
    config = SimpleNamespace(
        classifier=SimpleNamespace(enabled=True, model_path=None, timeout_s=5)
    )
    monkeypatch.setattr(worker, "load_config", lambda: config)
    refreshed = []

    def refresh(analysis_id, directory=None):
        refreshed.append(analysis_id)
        (directory / "chimera-report.json").touch()

    monkeypatch.setattr(worker, "_refresh_report", refresh)
    return SimpleNamespace(dir=directory, classified=classified, refreshed=refreshed)


class FakeJob:
    def __init__(self):
        self.meta = {"extra_metadata": {"classification": {"label": "benign"}}}
        self.saved = 0

    def save_meta(self):
        self.saved += 1


def read(late, name):
    return json.loads((late.dir / name).read_text())


def test_late_static_reclassifies_and_refreshes(late):
    job = FakeJob()
    assert worker.reconcile_late_static(AID, job=job) == "verdict and report"
    assert late.classified[0]["static"]["score"] == 7
    assert late.classified[0]["dynamic"] == {"x": 1}
    assert read(late, "features.json")["static"]["score"] == 7
    assert read(late, "classification.json")["label"] == "malicious"
    assert read(late, "metadata.json")["classification"]["label"] == "malicious"
    assert read(late, "metadata.json")["status"] == "finished"
    assert job.meta["extra_metadata"]["classification"]["label"] == "malicious"
    assert job.saved == 1 and late.refreshed == [AID]
    # The second caller (the other worker) finds nothing left to do.
    assert worker.reconcile_late_static(AID, job=job) is None
    assert len(late.classified) == 1 and late.refreshed == [AID]


def test_nothing_while_the_analysis_runs(late):
    metadata = read(late, "metadata.json")
    (late.dir / "metadata.json").write_text(
        json.dumps({**metadata, "status": "started"})
    )
    assert worker.reconcile_late_static(AID) is None
    assert not late.classified and not late.refreshed


def test_dynamic_only_refreshes_the_report_but_keeps_the_verdict(late):
    metadata = read(late, "metadata.json")
    (late.dir / "metadata.json").write_text(
        json.dumps({**metadata, "options": {"mode": "dynamic-only"}})
    )
    assert worker.reconcile_late_static(AID) == "report"
    assert not late.classified
    assert read(late, "classification.json")["label"] == "benign"
    assert late.refreshed == [AID]


def test_static_in_time_redoes_nothing(late):
    features = read(late, "features.json")
    (late.dir / "features.json").write_text(
        json.dumps({**features, "static": {"score": 7}})
    )
    os.utime(late.dir / "chimera-report.json")  # built after static.json
    assert worker.reconcile_late_static(AID) is None
    assert not late.classified and not late.refreshed


def test_static_job_reconciles_and_never_fails_on_it(tmp_path, monkeypatch):
    settings = StaticConfigSection(enabled=True)
    monkeypatch.setattr(
        worker, "load_config", lambda: type("C", (), {"static": settings})()
    )
    monkeypatch.setattr(worker, "STATIC_DIR", tmp_path)
    monkeypatch.setattr(
        worker,
        "run_in_container",
        lambda *a, **k: {"schema": sandbox.SCHEMA, "type": {"format": "pdf"}},
    )
    calls = []

    def boom(analysis_id):
        calls.append(analysis_id)
        raise RuntimeError("classifier exploded")

    monkeypatch.setattr(worker, "reconcile_late_static", boom)
    (tmp_path / AID / "in").mkdir(parents=True)
    assert worker.run_static_job(AID, "x", str(tmp_path))["error"] is None
    assert calls == [AID]
    assert (tmp_path / AID / "static.json").is_file()


def test_analysis_worker_reconciles_after_writing_metadata(
    tmp_path, monkeypatch, base_config
):
    from datetime import datetime, timezone
    from unittest.mock import Mock

    from drakrun.analyzer import worker as analysis_worker
    from drakrun.analyzer.analysis_metadata import AnalysisMetadata
    from drakrun.analyzer.analysis_options import AnalysisOptions

    sample = tmp_path / "sample"
    sample.write_bytes(b"test")
    options = AnalysisOptions.with_config_defaults(
        base_config, guest_os="windows", host_sample_path=sample
    )
    job = SimpleNamespace(
        id=AID,
        started_at=datetime.now(timezone.utc),
        meta={"file": dict(name="sample", type="PE32", sha256="abc")},
        save_meta=Mock(),
    )
    monkeypatch.setattr(analysis_worker, "_WORKER_VM_ID", 2)
    monkeypatch.setattr(analysis_worker, "_WORKER_GUEST_OS", "any")
    monkeypatch.setattr(analysis_worker, "ANALYSES_DIR", tmp_path / "analyses")
    monkeypatch.setattr(analysis_worker, "load_config", lambda: base_config)
    monkeypatch.setattr(analysis_worker, "get_current_job", lambda: job)
    monkeypatch.setattr(analysis_worker, "analyze_file", Mock(return_value={}))
    seen = []

    def reconcile(analysis_id, job=None):
        path = tmp_path / "analyses" / analysis_id / "metadata.json"
        seen.append((analysis_id, AnalysisMetadata.load_from_file(path).status, job))
        raise RuntimeError("classifier exploded")

    monkeypatch.setattr(analysis_worker, "reconcile_late_static", reconcile)
    analysis_worker.worker_analyze(options)
    assert seen == [(AID, "finished", job)]
    assert not sample.exists()  # the job went on after the failure


def test_agent_keeps_stderr_and_outputs_of_a_timed_out_step(tmp_path, monkeypatch):
    from .test_static_vm import load_agent

    agent = load_agent()
    monkeypatch.setattr(agent, "WORK", str(tmp_path))
    monkeypatch.setattr(agent, "prepare", lambda step, spec: None)
    (tmp_path / "ghidra-out").mkdir()
    (tmp_path / "ghidra-out" / "headless.log").write_text(LOG)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv[:2])
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, 1, stderr=b"before the kill")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    step = {
        "name": "ghidra",
        "argv": ["podman", "run", "x"],
        "timeout_s": 1,
        "container": "c",
        "outputs": ["ghidra-out/ghidra.json", "ghidra-out/headless.log"],
    }
    rec = agent.run_step(step, {"uid": 0, "gid": 0})
    assert rec["timed_out"] is True and rec["stderr"] == "before the kill"
    assert rec["files"] == {"ghidra-out/headless.log": LOG}
    assert calls == [["podman", "run"], ["podman", "kill"], ["podman", "rm"]]
