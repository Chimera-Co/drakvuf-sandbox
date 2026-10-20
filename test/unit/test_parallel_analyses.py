"""Queue routing and OS binding without Redis or a running hypervisor."""

import importlib
import io
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import NAMESPACE_DNS, UUID, uuid5

import pytest
from click.testing import CliRunner
from rq.job import JobStatus

from drakrun.analyzer import worker
from drakrun.analyzer.analysis_metadata import FileMetadata
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.cli.worker import worker as worker_cli


def job_uid(name):
    return str(UUID(str(uuid5(NAMESPACE_DNS, name)), version=4))


@pytest.mark.parametrize(
    "guest_os,queue_name",
    [
        ("windows", "drakrun-analysis"),
        ("linux", "drakrun-analysis-linux"),
    ],
)
def test_enqueue_routes_os(monkeypatch, base_config, guest_os, queue_name):
    factory = Mock()
    monkeypatch.setattr(worker, "Queue", factory)
    monkeypatch.setattr(worker, "load_config", lambda: base_config)
    options = AnalysisOptions.with_config_defaults(
        base_config, guest_os=guest_os, timeout=60
    )
    file = FileMetadata(name="sample", type="test", sha256="abc")
    result = worker.enqueue_analysis("uid", file, options, "redis", 123)
    factory.assert_called_once_with(name=queue_name, connection="redis")
    call = factory.return_value.enqueue.call_args
    assert result is factory.return_value.enqueue.return_value
    assert call.args == (worker.worker_analyze, options)
    assert call.kwargs["job_id"] == "uid"
    assert call.kwargs["meta"] == {"options": options.to_dict(), "file": file.to_dict()}
    assert call.kwargs["result_ttl"] == 123
    assert (
        call.kwargs["job_timeout"]
        == options.timeout + options.job_timeout_leeway + 1800
    )


def test_queue_routing_rejects_unknown_os():
    with pytest.raises(ValueError, match="Invalid analysis guest OS"):
        worker.queue_for_guest_os("macos")


@pytest.mark.parametrize(
    "mapping,override,expected",
    [
        ({}, None, list(worker.ANALYSIS_QUEUE_NAMES)),
        ({1: "windows"}, None, [worker.ANALYSIS_QUEUE_NAME]),
        ({1: "linux"}, None, [worker.LINUX_ANALYSIS_QUEUE_NAME]),
        ({1: "windows"}, "linux", [worker.LINUX_ANALYSIS_QUEUE_NAME]),
        ({1: "windows"}, "any", list(worker.ANALYSIS_QUEUE_NAMES)),
    ],
)
def test_worker_queues_and_config(
    monkeypatch, base_config, mapping, override, expected
):
    base_config.worker.vm_guest_os = mapping
    factory = Mock()
    monkeypatch.setattr(worker, "Worker", factory)
    monkeypatch.setattr(worker, "load_config", lambda: base_config)
    monkeypatch.setattr(worker, "get_redis_connection", lambda _: "redis")
    # Restore globals after the test, including those assigned by worker_main.
    monkeypatch.setattr(worker, "_WORKER_VM_ID", None)
    monkeypatch.setattr(worker, "_WORKER_GUEST_OS", "any")
    worker.worker_main(1, guest_os=override)
    assert factory.call_args.kwargs["queues"] == expected
    assert worker._WORKER_GUEST_OS == (override or mapping.get(1, "any"))
    assert worker._WORKER_VM_ID == 1
    factory.return_value.work.assert_called_once()


@pytest.mark.parametrize(
    "binding,guest_os", [("windows", "linux"), ("linux", "windows")]
)
def test_worker_refuses_wrong_os_before_touching_sample(
    monkeypatch, tmp_path, base_config, binding, guest_os
):
    sample = tmp_path / "sample"
    sample.write_bytes(b"sample")
    monkeypatch.setattr(worker, "_WORKER_VM_ID", 2)
    monkeypatch.setattr(worker, "_WORKER_GUEST_OS", binding)
    monkeypatch.setattr(worker, "load_config", lambda: base_config)
    windows, linux = Mock(), Mock()
    monkeypatch.setattr(worker, "analyze_file", windows)
    monkeypatch.setattr(worker, "analyze_linux_file", linux)
    options = AnalysisOptions.with_config_defaults(
        base_config, guest_os=guest_os, host_sample_path=sample
    )
    with pytest.raises(RuntimeError, match=f"bound to {binding}; refusing {guest_os}"):
        worker.worker_analyze(options)
    windows.assert_not_called()
    linux.assert_not_called()
    assert sample.read_bytes() == b"sample"


@pytest.mark.parametrize("guest_os", [None, "windows", "linux", "any"])
def test_worker_cli_binding(monkeypatch, guest_os):
    main = Mock()
    monkeypatch.setattr(worker, "worker_main", main)
    monkeypatch.setattr("drakrun.cli.check_root.os.geteuid", lambda: 0)
    args = ["--vm-id", "2"]
    if guest_os is not None:
        args += ["--guest-os", guest_os]
    result = CliRunner().invoke(worker_cli, args)
    assert result.exit_code == 0, repr(result.exception)
    main.assert_called_once_with(2, guest_os=guest_os)


def test_worker_config_validation(config_factory):
    config = config_factory('[worker]\nvm_guest_os = {1 = "windows", 2 = "linux"}')
    assert config.worker.vm_guest_os == {1: "windows", 2: "linux"}
    for invalid in (
        'vm_guest_os = {1 = "macos"}',
        "memory_admission_poll_interval = 0",
        "memory_admission_timeout = -1",
        "memory_admission_margin_mb = -1",
    ):
        with pytest.raises(ValueError):
            config_factory("[worker]\n" + invalid)


@pytest.fixture
def queued_jobs(monkeypatch, base_config):
    now = datetime.now(timezone.utc)
    options = AnalysisOptions.with_config_defaults(base_config)
    file = FileMetadata(name="sample", type="test", sha256="abc")
    jobs = {}

    def job(uid, guest_os, age, status=JobStatus.QUEUED):
        meta = {
            "options": {**options.to_dict(), "guest_os": guest_os},
            "file": file.to_dict(),
        }
        item = SimpleNamespace(
            id=uid,
            meta=meta,
            enqueued_at=now - timedelta(seconds=age),
            created_at=now - timedelta(seconds=age),
            started_at=None,
            ended_at=None,
            get_status=lambda: status,
            get_meta=lambda: meta,
        )
        jobs[uid] = item
        return item

    win = job("windows", "windows", 10)
    linux = job("linux", "linux", 1)
    finished = job("finished", "linux", 20, JobStatus.FINISHED)
    failed = job("failed", "windows", 30, JobStatus.FAILED)
    started = job("started", "linux", 5, JobStatus.STARTED)
    deferred = job("deferred", "windows", 40, JobStatus.DEFERRED)
    scheduled = job("scheduled", "linux", 50, JobStatus.SCHEDULED)
    deferred.enqueued_at = None
    scheduled.enqueued_at = None
    canceled = job("canceled", "linux", 60, JobStatus.CANCELED)
    registry = lambda ids: SimpleNamespace(get_job_ids=lambda: ids)

    def queue(name, connection):
        windows = name == worker.ANALYSIS_QUEUE_NAME
        return SimpleNamespace(
            get_jobs=lambda: [win] if windows else [linux],
            started_job_registry=registry([] if windows else [started.id]),
            finished_job_registry=registry([] if windows else [finished.id, linux.id]),
            failed_job_registry=registry([failed.id, "deleted"] if windows else []),
            deferred_job_registry=registry([deferred.id] if windows else []),
            scheduled_job_registry=registry([] if windows else [scheduled.id]),
            canceled_job_registry=registry([] if windows else [canceled.id]),
        )

    monkeypatch.setattr(worker, "Queue", queue)
    monkeypatch.setattr(
        worker.Job, "fetch_many", lambda ids, connection: [jobs.get(uid) for uid in ids]
    )
    return jobs


def test_list_combines_queues_and_registries_newest_first(queued_jobs):
    assert [job.id for job in worker.get_analyses_list("redis")] == [
        "linux",
        "started",
        "windows",
        "finished",
        "failed",
        "deferred",
        "scheduled",
        "canceled",
    ]


@pytest.fixture
def api_client(monkeypatch, tmp_path, base_config, queued_jobs):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr(worker, "get_redis_connection", lambda _: "redis")
    sys.modules.pop("drakrun.web.api", None)
    api = importlib.import_module("drakrun.web.api")
    monkeypatch.setattr(api, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(api, "truncate_analysis_list", Mock())
    monkeypatch.setattr(
        "drakrun.analyzer.analysis_metadata.magic.from_file", lambda _: "test"
    )
    jobs_by_uid = {job_uid(key): job for key, job in queued_jobs.items()}
    monkeypatch.setattr(api.Job, "fetch", lambda uid, connection: jobs_by_uid[uid])
    monkeypatch.setattr(
        api,
        "read_analysis_json",
        lambda uid, *args: {
            "id": jobs_by_uid[uid].id,
            "status": "finished",
            **jobs_by_uid[uid].meta,
        },
    )
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="parallel", version="0"))
    app.register_api(api.api)
    yield app.test_client()
    sys.modules.pop("drakrun.web.api", None)


def test_list_api_shows_both_os(api_client):
    response = api_client.get("/api/list")
    assert response.status_code == 200
    assert [job["id"] for job in response.json][:3] == ["linux", "started", "windows"]
    assert response.json[0]["options"]["guest_os"] == "linux"
    assert response.json[2]["options"]["guest_os"] == "windows"


@pytest.mark.parametrize("uid", ["windows", "linux", "started", "finished"])
def test_status_api_finds_jobs_from_either_queue(api_client, uid, queued_jobs):
    response = api_client.get(f"/api/status/{job_uid(uid)}")
    assert response.status_code == 200, response.json
    assert response.json["id"] == uid
    assert (
        response.json["options"]["guest_os"]
        == queued_jobs[uid].meta["options"]["guest_os"]
    )


@pytest.mark.parametrize(
    "guest_os,queue_name",
    [
        ("windows", worker.ANALYSIS_QUEUE_NAME),
        ("linux", worker.LINUX_ANALYSIS_QUEUE_NAME),
    ],
)
def test_upload_uses_real_queue_routing(api_client, monkeypatch, guest_os, queue_name):
    factory = Mock()
    monkeypatch.setattr(worker, "Queue", factory)
    response = api_client.post(
        "/api/upload",
        data={
            "guest_os": guest_os,
            "file": (io.BytesIO(b"sample"), "sample"),
        },
    )
    assert response.status_code == 200, response.json
    factory.assert_called_once_with(name=queue_name, connection="redis")


def test_admission_wait_visible_in_job_metadata(queued_jobs):
    job = queued_jobs["linux"]
    job.meta["memory_admission_wait_seconds"] = 5.5
    metadata = worker.analysis_job_to_metadata(job)
    assert metadata.model_extra["memory_admission_wait_seconds"] == 5.5
