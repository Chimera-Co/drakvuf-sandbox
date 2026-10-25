"""Memory admission uses a real flock, with injectable Xen and time sources."""

import fcntl
import multiprocessing
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from drakrun.analyzer import run_tools
from drakrun.lib import memory_admission as admission
from drakrun.lib.config import WorkerConfigSection


class Clock:
    now = 0.0

    def __init__(self):
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_xl_free_memory_parser(monkeypatch):
    read = Mock(return_value="total_memory : 16384\nfree_memory             : 5312\n")
    monkeypatch.setattr(admission.subprocess, "check_output", read)
    assert admission.xen_free_memory_mb() == 5312
    read.assert_called_once_with(["xl", "info"], text=True, timeout=10)


@pytest.mark.parametrize(
    "output", ["total_memory : 100", "free_memory : -1", "free_memory : bad"]
)
def test_xl_free_memory_fails_closed(monkeypatch, output):
    monkeypatch.setattr(admission.subprocess, "check_output", lambda *a, **kw: output)
    with pytest.raises((RuntimeError, ValueError)):
        admission.xen_free_memory_mb()


def test_enough_memory_holds_lock_until_restore_returns(tmp_path):
    clock = Clock()
    with admission.memory_admission(
        5120,
        WorkerConfigSection(),
        tmp_path,
        read_free_memory=lambda: 5312,
        clock=clock,
        sleep=clock.sleep,
    ) as waited:
        assert waited == 0
        with (tmp_path / "admission.lock").open("a") as other:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert clock.sleeps == []
    with (tmp_path / "admission.lock").open("a") as other:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_wait_then_admit_releases_lock_between_checks(tmp_path):
    clock = Clock()
    memory = iter([5311, 5312])

    def sleep(seconds):
        with (tmp_path / "admission.lock").open("a") as other:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        clock.sleep(seconds)

    with admission.memory_admission(
        5120,
        WorkerConfigSection(),
        tmp_path,
        read_free_memory=lambda: next(memory),
        clock=clock,
        sleep=sleep,
    ) as waited:
        assert waited == 5
    assert clock.sleeps == [5]


def test_timeout_is_bounded_and_releases_lock(tmp_path):
    clock = Clock()
    config = WorkerConfigSection(memory_admission_timeout=11)
    with pytest.raises(TimeoutError, match="free memory 100 MB, need 4288 MB"):
        with admission.memory_admission(
            4096,
            config,
            tmp_path,
            read_free_memory=lambda: 100,
            clock=clock,
            sleep=clock.sleep,
        ):
            pytest.fail("must not restore")
    assert clock.sleeps == [5, 5, 1]
    with admission.memory_admission(
        4096, config, tmp_path, read_free_memory=lambda: 9999
    ):
        pass


def test_wait_logs_once_per_minute(tmp_path, caplog):
    clock = Clock()
    with caplog.at_level("INFO"), pytest.raises(TimeoutError):
        with admission.memory_admission(
            4096,
            WorkerConfigSection(memory_admission_timeout=125),
            tmp_path,
            read_free_memory=lambda: 0,
            clock=clock,
            sleep=clock.sleep,
        ):
            pass
    assert sum("Waiting for memory admission" in r.message for r in caplog.records) == 3


def _try_admission(lock_dir, result):
    try:
        with admission.memory_admission(
            4096,
            WorkerConfigSection(memory_admission_timeout=0),
            lock_dir,
            read_free_memory=lambda: 9999,
        ):
            result.put("admitted")
    except TimeoutError:
        result.put("locked")


def test_admission_lock_excludes_other_processes(tmp_path):
    context = multiprocessing.get_context("fork")
    result = context.Queue()

    def probe():
        proc = context.Process(target=_try_admission, args=(tmp_path, result))
        proc.start()
        try:
            message = result.get(timeout=5)
            proc.join(timeout=5)
            assert proc.exitcode == 0
            return message
        finally:
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=5)

    with admission.memory_admission(
        4096, WorkerConfigSection(), tmp_path, read_free_memory=lambda: 9999
    ):
        assert probe() == "locked"
    assert probe() == "admitted"
    result.close()


def test_lock_wait_counts_towards_timeout(tmp_path):
    clock = Clock()
    with (tmp_path / "admission.lock").open("a") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX)
        read = Mock()
        with pytest.raises(TimeoutError, match="another worker"):
            with admission.memory_admission(
                4096,
                WorkerConfigSection(memory_admission_timeout=10),
                tmp_path,
                read_free_memory=read,
                clock=clock,
                sleep=clock.sleep,
            ):
                pass
        read.assert_not_called()
        assert clock.now == 10


def test_restore_exception_releases_admission_lock(tmp_path):
    with pytest.raises(RuntimeError, match="restore failed"):
        with admission.memory_admission(
            4096, WorkerConfigSection(), tmp_path, read_free_memory=lambda: 9999
        ):
            raise RuntimeError("restore failed")
    with admission.memory_admission(
        4096, WorkerConfigSection(), tmp_path, read_free_memory=lambda: 9999
    ):
        pass


@pytest.fixture
def fake_vm(monkeypatch, tmp_path, base_config):
    vm = SimpleNamespace(
        restore=Mock(), destroy=Mock(), is_running=False, vm_name="vm-1"
    )
    monkeypatch.setattr(run_tools, "VirtualMachine", lambda *args: vm)
    monkeypatch.setattr(run_tools, "RUN_DIR", tmp_path)
    monkeypatch.setattr(run_tools, "load_config", lambda: base_config)
    return vm


def test_run_vm_restores_under_admission_lock_and_releases_before_analysis(
    fake_vm, monkeypatch, tmp_path
):
    monkeypatch.setattr(admission, "xen_free_memory_mb", lambda: 5312)

    def restore():
        with (tmp_path / "admission.lock").open("a") as other:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)

    fake_vm.restore.side_effect = restore
    with run_tools.run_vm(1, SimpleNamespace(memory=5120), None):
        with admission.memory_admission(
            4096, WorkerConfigSection(), tmp_path, read_free_memory=lambda: 9999
        ):
            pass
    fake_vm.restore.assert_called_once()
    fake_vm.destroy.assert_called_once()


def test_run_vm_timeout_never_restores(fake_vm, monkeypatch, base_config):
    base_config.worker.memory_admission_timeout = 0
    monkeypatch.setattr(admission, "xen_free_memory_mb", lambda: 5311)
    with pytest.raises(TimeoutError):
        with run_tools.run_vm(1, SimpleNamespace(memory=5120), None):
            pass
    fake_vm.restore.assert_not_called()
    fake_vm.destroy.assert_called_once()


def test_no_restore_skips_memory_admission(fake_vm, monkeypatch):
    fake_vm.is_running = True
    read = Mock(side_effect=AssertionError("must not query Xen memory"))
    monkeypatch.setattr(admission, "xen_free_memory_mb", read)
    with run_tools.run_vm(1, None, None, no_restore=True):
        pass
    read.assert_not_called()
    fake_vm.restore.assert_not_called()
    fake_vm.destroy.assert_not_called()


def test_stale_domain_is_reclaimed_before_checking_memory(fake_vm, monkeypatch):
    fake_vm.is_running = True
    free = {"memory": 0}
    fake_vm.destroy.side_effect = lambda: free.update(memory=5312)
    monkeypatch.setattr(admission, "xen_free_memory_mb", lambda: free["memory"])
    with run_tools.run_vm(1, SimpleNamespace(memory=5120), None):
        pass
    fake_vm.restore.assert_called_once()
    assert fake_vm.destroy.call_count == 2


def test_run_vm_records_admission_wait_in_rq_meta(
    fake_vm, monkeypatch, tmp_path, base_config
):
    clock = Clock()
    memory = iter([0, 5312])
    monkeypatch.setattr(
        run_tools,
        "memory_admission",
        lambda *a, **kw: admission.memory_admission(
            *a,
            **kw,
            read_free_memory=lambda: next(memory),
            clock=clock,
            sleep=clock.sleep,
        ),
    )
    job = SimpleNamespace(meta={}, save_meta=Mock())
    monkeypatch.setattr(run_tools, "get_current_job", lambda: job)
    with run_tools.run_vm(1, SimpleNamespace(memory=5120), None):
        assert job.meta["memory_admission_wait_seconds"] == 5
    job.save_meta.assert_called_once()
