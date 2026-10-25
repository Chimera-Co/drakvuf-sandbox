import importlib.util
import json
import pathlib
import struct
import types

import pytest

from drakrun.analyzer.static import sandbox, vm_backend
from drakrun.lib.config import StaticConfigSection

AGENT = pathlib.Path(__file__).parents[2] / "scripts/chimera/static-vm/guest/chimera-static-agent.py"


def load_agent():
    spec = importlib.util.spec_from_file_location("agent", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_job_disk_round_trip_through_guest_agent(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    sample.write_bytes(b"MZ" + bytes(5000))
    job_disk, result_disk = tmp_path / "job.img", tmp_path / "result.img"
    steps = [{"name": "static", "argv": ["podman", "run", "x"], "timeout_s": 5, "container": "c",
              "prepare": {"dirs": ["out"]}, "outputs": ["out/static.json"]}]
    spec = {"job": "j1", "sample_size": 5002, "sample_sha256": __import__("hashlib").sha256(
        sample.read_bytes()).hexdigest(), "uid": 0, "gid": 0, "steps": steps}
    vm_backend.write_job_disk(job_disk, spec, sample)
    result_disk.write_bytes(bytes(1 << 16))

    agent = load_agent()
    monkeypatch.setattr(agent, "JOB_DEV", str(job_disk))
    monkeypatch.setattr(agent, "RESULT_DEV", str(result_disk))
    monkeypatch.setattr(agent, "WORK", str(tmp_path / "work"))
    monkeypatch.setattr(agent.os, "chown", lambda *a: None)
    written = {}
    monkeypatch.setattr(agent, "xs_write", lambda k, v: written.__setitem__(k, v))

    def fake_run(argv, **kw):
        out = tmp_path / "work" / "out" / "static.json"
        assert (tmp_path / "work" / "in" / "sample").read_bytes() == sample.read_bytes()
        out.write_text(json.dumps({"schema": "chimera-static/1", "ok": True}))
        return types.SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    agent.handle("j1")
    assert written == {"done": "j1"}
    envelope = vm_backend.read_result_disk(result_disk, 1 << 16)
    step = envelope["steps"][0]
    assert step["exit_code"] == 0 and json.loads(step["files"]["out/static.json"])["ok"] is True


def test_agent_refuses_non_podman_steps(tmp_path):
    agent = load_agent()
    rec = agent.run_step({"name": "x", "argv": ["sh", "-c", "id"], "timeout_s": 1}, {"uid": 0, "gid": 0})
    assert rec["error"] == "only podman steps are allowed"


def test_agent_rejects_tampered_sample(tmp_path, monkeypatch):
    sample = tmp_path / "sample"
    sample.write_bytes(b"abc")
    job_disk = tmp_path / "job.img"
    vm_backend.write_job_disk(job_disk, {"job": "j", "sample_size": 3, "sample_sha256": "0" * 64, "uid": 0,
                                         "gid": 0, "steps": []}, sample)
    agent = load_agent()
    monkeypatch.setattr(agent, "JOB_DEV", str(job_disk))
    monkeypatch.setattr(agent, "WORK", str(tmp_path / "work"))
    with pytest.raises(ValueError, match="sha256"):
        agent.read_job()


@pytest.mark.parametrize("mutate,message", [
    (lambda b: b"XXXXXXXX" + b[8:], "no result"),
    (lambda b: b[:16] + bytes(32) + b[48:], "checksum"),
    (lambda b: b[:8] + struct.pack(">Q", 1 << 40) + b[16:], "too large"),
])
def test_result_disk_validation(tmp_path, mutate, message):
    data = json.dumps({"steps": []}).encode()
    raw = b"CHIMRES1" + struct.pack(">Q", len(data)) + __import__("hashlib").sha256(data).digest() + data
    path = tmp_path / "r.img"
    path.write_bytes(mutate(raw) + bytes(64))
    with pytest.raises(ValueError, match=message):
        vm_backend.read_result_disk(path, 1 << 20)


def test_vm_unavailable_falls_back_to_container(tmp_path, monkeypatch):
    settings = StaticConfigSection(backend="vm", vm_autostart=False)
    monkeypatch.setattr(vm_backend, "RUN_DIR", tmp_path / "run")
    monkeypatch.setattr(vm_backend, "ready", lambda s: None)
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", lambda *a, **k: calls.append(a[0]) or types.SimpleNamespace(
        returncode=1, stderr=b"boom"))
    job = tmp_path / "job"
    (job / "in").mkdir(parents=True)
    (job / "in" / "sample").write_bytes(b"x")
    result = sandbox.run_in_container(settings, "8f14e45f-ceea-467a-9575-1c4b5d6e7f80", job, "x")
    assert calls and calls[0][:2] == ["podman", "run"]  # dom0 container ran instead
    assert "error" in result


def test_vm_unavailable_without_fallback_reports_error(tmp_path, monkeypatch):
    settings = StaticConfigSection(backend="vm", vm_autostart=False, vm_fallback_container=False)
    monkeypatch.setattr(vm_backend, "RUN_DIR", tmp_path / "run")
    monkeypatch.setattr(vm_backend, "ready", lambda s: None)
    job = tmp_path / "job"
    (job / "in").mkdir(parents=True)
    (job / "in" / "sample").write_bytes(b"x")
    result = sandbox.run_in_container(settings, "8f14e45f-ceea-467a-9575-1c4b5d6e7f80", job, "x")
    assert "not ready" in result["error"]
    assert "not ready" in sandbox.run_ghidra(settings, "8f14e45f-ceea-467a-9575-1c4b5d6e7f80", job, [])["error"]


def test_job_timeout_restarts_vm(tmp_path, monkeypatch):
    settings = StaticConfigSection(backend="vm", timeout_s=1)
    monkeypatch.setattr(vm_backend, "VM_DIR", tmp_path / "vm")
    monkeypatch.setattr(vm_backend, "RUN_DIR", tmp_path / "run")
    monkeypatch.setattr(vm_backend, "ready", lambda s: 7)
    monkeypatch.setattr(vm_backend, "domid", lambda name: 7)
    monkeypatch.setattr(vm_backend, "_attach", lambda *a: None)
    monkeypatch.setattr(vm_backend, "_detach", lambda *a: True)
    monkeypatch.setattr(vm_backend, "_attached", lambda s: set())
    monkeypatch.setattr(vm_backend, "xs_write", lambda *a: None)
    monkeypatch.setattr(vm_backend, "xs_read", lambda *a: None)
    monkeypatch.setattr(vm_backend, "JOB_SLACK_S", 0)
    clock = iter(range(0, 10_000, 10))
    monkeypatch.setattr(vm_backend.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(vm_backend.time, "sleep", lambda s: None)
    restarts = []
    monkeypatch.setattr(vm_backend, "restart_vm", lambda s: restarts.append(1))
    sample = tmp_path / "s"
    sample.write_bytes(b"x")
    out = vm_backend.run_job(settings, [{"timeout_s": 5}], sample)
    assert "timed out" in out["error"] and restarts == [1]
    assert not list((tmp_path / "vm" / "jobs").iterdir())  # job disks removed
