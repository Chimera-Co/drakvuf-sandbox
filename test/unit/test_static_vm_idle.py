import os
import time
from types import SimpleNamespace

from drakrun.analyzer.static import vm_backend


def settings(idle=600):
    return SimpleNamespace(vm_idle_shutdown_s=idle, vm_name="chimera-static")


def setup(tmp_path, monkeypatch, running=True):
    monkeypatch.setattr(vm_backend, "RUN_DIR", tmp_path)
    monkeypatch.setattr(vm_backend, "domid", lambda name: 7 if running else None)
    calls = []
    monkeypatch.setattr(vm_backend.subprocess, "run", lambda argv, **kw: calls.append(argv))
    return calls


def test_stops_only_after_the_idle_time(tmp_path, monkeypatch):
    calls = setup(tmp_path, monkeypatch)
    vm_backend._mark_used()
    assert vm_backend.stop_if_idle(settings()).startswith("in use") and not calls
    old = time.time() - 700
    os.utime(tmp_path / vm_backend.LAST_JOB, (old, old))
    assert vm_backend.stop_if_idle(settings()) == "stopped"
    assert calls == [["systemctl", "stop", "chimera-static-vm.service"]]


def test_never_stops_while_a_job_holds_the_lock(tmp_path, monkeypatch):
    calls = setup(tmp_path, monkeypatch)
    old = time.time() - 7000
    vm_backend._mark_used()
    os.utime(tmp_path / vm_backend.LAST_JOB, (old, old))
    with vm_backend._vm_lock():
        pid = os.fork()
        if pid == 0:  # another process, like the idle timer, while this one runs a job
            os._exit(0 if vm_backend.stop_if_idle(settings()) == "busy" else 1)
        _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0 and not calls


def test_first_check_starts_the_clock_and_off_means_off(tmp_path, monkeypatch):
    calls = setup(tmp_path, monkeypatch)
    assert vm_backend.stop_if_idle(settings()) == "idle clock started" and not calls
    assert vm_backend.stop_if_idle(settings(idle=0)) == "idle shutdown off"
    setup(tmp_path, monkeypatch, running=False)
    assert vm_backend.stop_if_idle(settings()) == "not running"
