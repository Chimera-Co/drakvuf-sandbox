"""The static VM lock: a fast pass waiting for the VM is next, its wait is bounded, and RQ's timeout covers it."""

import fcntl
import threading
import time

import pytest

from drakrun.analyzer.static import sandbox, vm_backend, worker
from drakrun.lib.config import StaticConfigSection

AID = "8f14e45f-ceea-467a-9575-1c4b5d6e7f80"


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(vm_backend, "RUN_DIR", tmp_path)
    monkeypatch.setattr(vm_backend, "LOCK_POLL_S", 0.01)
    return tmp_path


def turnstile_taken(run_dir):
    with (run_dir / "static-vm.turnstile.lock").open("a") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fh, fcntl.LOCK_UN)
        return False


def test_a_waiting_job_goes_before_the_holders_next_step(run_dir):
    # flock gives its waiters no order, so a deep-queue job running step after step (capa then Ghidra, one dump
    # after another) could take the VM again the moment it let go; the turnstile makes the waiter next, which
    # is what bounds the fast pass's wait to one step (vm_backend.lock_wait_s).
    order = []

    def fast_pass():
        with vm_backend._vm_lock(wait_s=10):
            order.append("fast")
            time.sleep(0.05)

    holder = vm_backend._vm_lock()
    holder.__enter__()
    order.append("step 1")
    waiter = threading.Thread(target=fast_pass)
    waiter.start()
    deadline = time.monotonic() + 5
    while not turnstile_taken(
        run_dir
    ):  # the fast pass is queued behind the running step
        assert time.monotonic() < deadline
        time.sleep(0.01)
    holder.__exit__(None, None, None)
    with vm_backend._vm_lock():
        order.append("step 2")
    waiter.join(5)
    assert order == ["step 1", "fast", "step 2"]


def test_bounded_wait_raises_vm_busy_and_frees_the_turnstile(run_dir):
    with vm_backend._vm_lock():
        started = time.monotonic()
        with pytest.raises(vm_backend.VmBusy, match="busy"):
            with vm_backend._vm_lock(wait_s=0.1):
                pytest.fail("the VM lock is held")
        assert time.monotonic() - started < 2
        assert not turnstile_taken(run_dir)
    with vm_backend._vm_lock(wait_s=0.1) as locked:
        assert locked


def test_idle_check_does_not_queue(run_dir):
    with vm_backend._vm_lock():
        with vm_backend._vm_lock(blocking=False) as locked:
            assert locked is False
    assert not turnstile_taken(run_dir)


def test_busy_vm_is_an_error_not_a_dom0_fallback(tmp_path, monkeypatch):
    settings = StaticConfigSection(backend="vm", vm_fallback_container=True)
    waits = []

    def busy(*args, lock_wait_s=None, **kwargs):
        waits.append(lock_wait_s)
        raise vm_backend.VmBusy("static VM busy with another job for 9s")

    monkeypatch.setattr(vm_backend, "run_job", busy)
    monkeypatch.setattr(
        sandbox.subprocess, "run", lambda *a, **k: pytest.fail("ran in dom0")
    )
    job = tmp_path / "job"
    (job / "in").mkdir(parents=True)
    (job / "in" / "sample").write_bytes(b"x")
    result = sandbox.run_in_container(settings, AID, job, "x", lock_wait_s=9)
    assert result == {
        "schema": sandbox.SCHEMA,
        "error": "static VM busy with another job for 9s",
    }
    assert waits == [9]


def test_wait_bound_covers_the_longest_step():
    settings = StaticConfigSection(
        backend="vm", ghidra_enabled=True, mobsf_enabled=False
    )
    ghidra = sandbox.ghidra_wall_s(settings)
    assert ghidra > settings.deep_timeout_s + sandbox.GRACE_S
    assert vm_backend.lock_wait_s(settings) == vm_backend.step_hold_s(settings, ghidra)
    with_mobsf = settings.model_copy(update={"mobsf_enabled": True})
    assert vm_backend.lock_wait_s(with_mobsf) == vm_backend.step_hold_s(
        settings, settings.mobsf_timeout_s + 60
    )


class FakeQueue:
    jobs = []

    def __init__(self, name, connection):
        self.name = name

    def enqueue(self, *args, **kwargs):
        FakeQueue.jobs.append((self.name, kwargs))


@pytest.mark.parametrize("backend", ["vm", "container"])
def test_fast_pass_timeout_adds_the_vm_wait(tmp_path, monkeypatch, backend):
    settings = StaticConfigSection(enabled=True, backend=backend, timeout_s=90)
    FakeQueue.jobs = []
    monkeypatch.setattr(worker, "Queue", FakeQueue)
    monkeypatch.setattr(worker, "stage_sample", lambda *a: None)
    worker.stage_and_enqueue(AID, tmp_path / "x", "x", None, settings, base=tmp_path)
    [(queue, kwargs)] = FakeQueue.jobs
    wait = vm_backend.lock_wait_s(settings) if backend == "vm" else 0
    assert queue == worker.STATIC_QUEUE_NAME
    assert (
        kwargs["job_id"] == f"static-{AID}"
    )  # the pipeline view looks the job up by this id
    assert kwargs["job_timeout"] == int(90 + 120 + wait)


def test_fast_pass_waits_a_bounded_time_and_deep_steps_block(tmp_path, monkeypatch):
    settings = StaticConfigSection(
        enabled=True, backend="vm", deep_enabled=True, ghidra_enabled=True
    )
    monkeypatch.setattr(
        worker, "load_config", lambda: type("C", (), {"static": settings})()
    )
    calls = []

    def fake_run(
        settings, analysis_id, directory, file_name, deep=False, lock_wait_s=None
    ):
        calls.append((deep, lock_wait_s))
        return {"schema": sandbox.SCHEMA, "type": {"format": "pe"}}

    monkeypatch.setattr(worker, "run_in_container", fake_run)
    FakeQueue.jobs = []
    monkeypatch.setattr(worker, "Queue", FakeQueue)
    monkeypatch.setattr(
        "rq.get_current_job", lambda: type("J", (), {"connection": object()})()
    )
    (tmp_path / AID / "in").mkdir(parents=True)
    worker.run_static_job(AID, "x", str(tmp_path))
    assert calls == [(False, vm_backend.lock_wait_s(settings))]
    [(queue, kwargs)] = FakeQueue.jobs
    assert queue == worker.DEEP_QUEUE_NAME
    turn = vm_backend.step_hold_s(settings, settings.timeout_s + sandbox.GRACE_S)
    assert kwargs["job_timeout"] == int(
        settings.deep_timeout_s + sandbox.ghidra_wall_s(settings) + 120 + 2 * turn
    )
    worker.run_deep_job(AID, "x", str(tmp_path))
    assert calls[-1] == (True, None)
