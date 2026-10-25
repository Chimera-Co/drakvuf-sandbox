"""Focused wiring tests for drakrun.evasion.worker.evasion_worker_main and
the drakrun.cli.evasion_worker Click command.

These do not touch Xen, Redis, or root privileges: rq.Worker and
load_config are stubbed out so only the wiring - which queue is listened
to, whether burst is forwarded, and which module's _WORKER_VM_ID global
gets set - is under test. worker_verify's own behavior is already covered
end-to-end by test_worker_verify.py and is not re-tested here.
"""

import types

import pytest


class FakeRedisConfig:
    host = "localhost"
    port = 6379
    username = None
    password = None


class FakeDrakrunSection:
    worker_hostname = "test-host"


class FakeConfig:
    redis = FakeRedisConfig()
    drakrun = FakeDrakrunSection()


class FakeWorker:
    """Stand-in for rq.Worker: records construction args and .work() calls
    instead of connecting to Redis or entering a dequeue loop."""

    instances = []

    def __init__(self, queues, name, connection):
        self.queues = queues
        self.name = name
        self.connection = connection
        self.work_calls = []
        FakeWorker.instances.append(self)

    def work(self, burst=False):
        self.work_calls.append(burst)


@pytest.fixture(autouse=True)
def reset_fake_worker():
    FakeWorker.instances = []
    yield
    FakeWorker.instances = []


@pytest.fixture
def worker_module(monkeypatch):
    import drakrun.evasion.worker as worker

    monkeypatch.setattr(worker, "_WORKER_VM_ID", None)
    monkeypatch.setattr(worker, "Worker", FakeWorker)
    monkeypatch.setattr(worker, "load_config", lambda: FakeConfig())
    monkeypatch.setattr(worker, "get_redis_connection", lambda config: "fake-conn")
    return worker


def test_evasion_worker_main_listens_on_evasion_queues_only(worker_module):
    worker_module.evasion_worker_main(vm_id=2, burst=True)

    assert len(FakeWorker.instances) == 1
    fake_worker = FakeWorker.instances[0]
    assert fake_worker.queues == ["drakrun-evasion", "drakrun-evasion-linux"]
    assert not {"drakrun-analysis", "drakrun-analysis-linux"} & set(fake_worker.queues)


@pytest.mark.parametrize(
    "guest_os,queue", [("windows", "drakrun-evasion"), ("linux", "drakrun-evasion-linux")]
)
def test_bound_evasion_worker_listens_to_its_os_queue(worker_module, guest_os, queue):
    # Two bound workers on two VM slots run a Windows and a Linux scan at the same time
    worker_module.evasion_worker_main(vm_id=2, burst=True, guest_os=guest_os)
    assert FakeWorker.instances[0].queues == [queue]
    assert worker_module._WORKER_GUEST_OS == guest_os


def test_evasion_worker_rejects_unknown_guest_os(worker_module):
    with pytest.raises(ValueError):
        worker_module.evasion_worker_main(vm_id=1, burst=True, guest_os="macos")


def test_scans_are_queued_by_sandbox_platform(worker_module, monkeypatch):
    queued = []

    class FakeQueue:
        def __init__(self, name, connection):
            self.name = name

        def enqueue(self, *args, **kwargs):
            queued.append(self.name)

    monkeypatch.setattr(worker_module, "Queue", FakeQueue)
    for platform in ("windows", "linux"):
        sandbox = types.SimpleNamespace(platform=platform, to_dict=lambda: {})
        options = types.SimpleNamespace(to_dict=lambda exclude_none=False: {})
        worker_module.enqueue_verification("id", sandbox, options, None, 60, 60)
    assert queued == ["drakrun-evasion", "drakrun-evasion-linux"]


def test_evasion_worker_main_forwards_burst_flag(worker_module):
    worker_module.evasion_worker_main(vm_id=1, burst=True)
    assert FakeWorker.instances[0].work_calls == [True]

    worker_module.evasion_worker_main(vm_id=1, burst=False)
    assert FakeWorker.instances[1].work_calls == [False]


def test_evasion_worker_main_sets_own_vm_id_global(worker_module):
    assert worker_module._WORKER_VM_ID is None
    worker_module.evasion_worker_main(vm_id=7, burst=True)
    assert worker_module._WORKER_VM_ID == 7


def test_evasion_worker_main_does_not_touch_analysis_worker_state(
    worker_module, monkeypatch
):
    """The two workers must stay fully isolated: running the evasion worker
    must never import or mutate drakrun.analyzer.worker's own globals."""
    fake_analyzer_worker = types.ModuleType("drakrun.analyzer.worker")
    fake_analyzer_worker._WORKER_VM_ID = None
    fake_analyzer_worker.ANALYSIS_QUEUE_NAME = "drakrun-analysis"
    monkeypatch.setitem(
        __import__("sys").modules, "drakrun.analyzer.worker", fake_analyzer_worker
    )

    worker_module.evasion_worker_main(vm_id=5, burst=True)

    assert fake_analyzer_worker._WORKER_VM_ID is None


def test_cli_evasion_worker_help(monkeypatch):
    from click.testing import CliRunner

    from drakrun.cli.evasion_worker import evasion_worker

    runner = CliRunner()
    result = runner.invoke(evasion_worker, ["--help"])

    assert result.exit_code == 0
    assert "--vm-id" in result.output
    assert "--burst" in result.output
    assert "--guest-os" in result.output


def test_cli_main_registers_evasion_worker():
    from click.testing import CliRunner

    from drakrun.cli.main import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "evasion-worker" in result.output
