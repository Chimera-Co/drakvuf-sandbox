import importlib
import io
import json
import sys
import uuid
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask_openapi3 import Info, OpenAPI
from rq.job import JobStatus

from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.static import worker
from drakrun.analyzer.postprocessing.plugins.build_chimera_report import build_report


@pytest.fixture
def upload(tmp_path, monkeypatch, base_config):
    base_config.static.enabled = True
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    sys.modules.pop("drakrun.web.api", None)
    api = importlib.import_module("drakrun.web.api")
    monkeypatch.setattr(api, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(worker, "STATIC_DIR", tmp_path / "static")
    monkeypatch.setattr(api, "truncate_analysis_list", Mock())
    monkeypatch.setattr(
        "drakrun.analyzer.analysis_metadata.magic.from_file", lambda _: "data"
    )
    dynamic, static, queue = Mock(), Mock(), Mock()
    monkeypatch.setattr(api, "enqueue_analysis", dynamic)
    monkeypatch.setattr(api, "stage_and_enqueue", static)
    monkeypatch.setattr(worker, "Queue", queue)
    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(api.api)
    yield app.test_client(), api, dynamic, static, queue
    sys.modules.pop("drakrun.web.api", None)


@pytest.mark.parametrize("mode", ["combined", "dynamic-only", "static-only"])
def test_upload_modes(upload, mode):
    client, api, dynamic, static, queue = upload
    response = client.post(
        "/api/upload", data={"file": (io.BytesIO(b"fixture"), "x.bin"), "mode": mode}
    )
    assert response.status_code == 200, response.json
    assert dynamic.call_count == (mode != "static-only")
    assert static.call_count == (mode == "combined")
    if mode == "static-only":
        queue.assert_called_once_with(name="chimera-static-only", connection=api.redis)
        call = queue.return_value.enqueue.call_args
        assert call.args[0] is worker.run_static_only_analysis
        assert call.kwargs["job_id"] == response.json["task_uid"]
        assert call.kwargs["meta"]["options"]["mode"] == mode
    else:
        queue.assert_not_called()


@pytest.mark.parametrize(
    "field",
    ["extract_archive", "start_command", "file_path", "start_working_dir", "disabled"],
)
def test_reject_before_storage(upload, field):
    client, api, dynamic, static, queue = upload
    data = {"file": (io.BytesIO(b"fixture"), "x.bin"), "mode": "static-only"}
    if field == "disabled":
        api.config.static.enabled = False
    else:
        data[field] = "true" if field == "extract_archive" else "value"
    response = client.post("/api/upload", data=data)
    assert response.status_code == 400
    assert (
        "static analysis is disabled on this server" if field == "disabled" else field
    ) in response.json["error"]
    assert not api.UPLOADS_DIR.exists()
    dynamic.assert_not_called()
    static.assert_not_called()
    queue.assert_not_called()


@pytest.mark.parametrize("classifier_error", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_static_only_artifacts(
    tmp_path, monkeypatch, base_config, failure, classifier_error
):
    from drakrun.analyzer.classifier import runner

    aid = str(uuid.uuid4())
    monkeypatch.setattr(worker, "ANALYSES_DIR", tmp_path / "analyses")
    monkeypatch.setattr(worker, "STATIC_DIR", tmp_path / "static")
    monkeypatch.setattr(worker, "load_config", lambda: base_config)
    base_config.classifier.enabled = True
    worker.job_dir(aid).mkdir(parents=True)
    result = {
        "schema": "chimera-static/1",
        "coverage": {"complete": True},
        "error": "failed" if failure else None,
    }
    monkeypatch.setattr(worker, "run_in_container", Mock(return_value=result))
    verdict = {"label": "benign", "explanation": []}
    if classifier_error:
        verdict = runner.unknown_verdict("RuntimeError: classifier failed")
    classifier = (
        Mock(side_effect=RuntimeError("classifier failed"))
        if classifier_error
        else Mock(return_value=verdict)
    )
    monkeypatch.setattr(runner, "run_classifier", classifier)
    options = AnalysisOptions(
        mode="static-only", plugins=[], net_enable=False
    ).to_dict()
    file = {"name": "x.bin", "sha256": "a" * 64, "size_bytes": 7, "type": "data"}
    if failure:
        with pytest.raises(worker.StaticAnalysisFailed):
            worker.run_static_only_analysis(aid, file, options)
    else:
        worker.run_static_only_analysis(aid, file, options)
    directory = tmp_path / "analyses" / aid
    metadata = json.loads((directory / "metadata.json").read_text())
    assert metadata["status"] == ("failed" if failure else "finished")
    assert "vm_id" not in metadata
    assert metadata["classification"] == verdict
    assert metadata["chimera_report"] is True
    features = json.loads((directory / "features.json").read_text())
    assert features["run"] == {"mode": "static-only", "guest_os": None}
    assert "dynamic" not in features
    assert features["static"] == result
    assert json.loads((directory / "classification.json").read_text()) == verdict
    assert (directory / "chimera-report.html").is_file()
    classifier.assert_called_once()


@pytest.mark.parametrize(
    "mode,stage", [("static-only", "dynamic"), ("dynamic-only", "static")]
)
def test_report_modes(tmp_path, mode, stage):
    (tmp_path / "metadata.json").write_text(
        json.dumps({"options": {"mode": mode, "timeout": 60}})
    )
    report = build_report(tmp_path)
    assert report["mode"] == mode
    assert report["stages"][stage]["status"] == "not_requested"
    if mode == "static-only":
        assert not any(
            "INetSim" in s or "ran for" in s or "Monitors" in s
            for s in report["limitations"]
        )


def test_queue_isolation_and_old_options():
    from drakrun.analyzer.worker import ANALYSIS_QUEUE_NAMES, LISTED_QUEUE_NAMES

    assert worker.STATIC_ONLY_QUEUE_NAME not in ANALYSIS_QUEUE_NAMES
    assert worker.STATIC_ONLY_QUEUE_NAME in LISTED_QUEUE_NAMES
    assert AnalysisOptions(plugins=[], net_enable=False).mode == "combined"


def test_queued_and_finished_endpoints(upload, monkeypatch):
    client, api, *_ = upload
    aid = str(uuid.uuid4())
    metadata = {
        "id": aid,
        "options": {"mode": "static-only", "plugins": [], "net_enable": False},
        "file": {"name": "x", "type": "data", "sha256": "a" * 64},
    }
    job = SimpleNamespace(
        id=aid,
        meta=metadata,
        started_at=None,
        ended_at=None,
        get_status=lambda: JobStatus.QUEUED,
        get_meta=lambda: metadata,
    )
    monkeypatch.setattr(api, "get_analyses_list", lambda **kw: [job])
    monkeypatch.setattr(api.Job, "fetch", lambda *a, **kw: job)
    assert client.get("/api/list").json[0]["options"]["mode"] == "static-only"
    assert client.get(f"/api/status/{aid}").json["status"] == "queued"
    job.get_status = lambda: JobStatus.FINISHED
    monkeypatch.setattr(
        api,
        "read_analysis_json",
        lambda *a: {**metadata, "status": "finished", "chimera_report": True},
    )
    assert client.get(f"/api/status/{aid}").json["chimera_report"] is True


def test_dynamic_only_does_not_wait(tmp_path, monkeypatch, base_config):
    from drakrun.analyzer.analysis_metadata import AnalysisMetadata
    from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext

    module = importlib.import_module(
        "drakrun.analyzer.postprocessing.plugins.classify_sample"
    )
    base_config.classifier.enabled = base_config.static.enabled = True
    wait = Mock(side_effect=AssertionError("must not wait"))
    monkeypatch.setattr(module, "wait_for_static", wait)
    monkeypatch.setattr(
        module, "extract_features", lambda _: {"static": {"stale": True}}
    )
    monkeypatch.setattr(
        module, "run_classifier", Mock(return_value={"label": "unknown"})
    )
    context = PostprocessContext(
        tmp_path,
        base_config,
        AnalysisMetadata(
            id=str(uuid.uuid4()),
            options=AnalysisOptions(mode="dynamic-only", plugins=[], net_enable=False),
        ),
    )
    module.classify_sample(context)
    wait.assert_not_called()
    assert json.loads((tmp_path / "features.json").read_text())["static"] is None


def test_static_worker_listens_to_both_queues(monkeypatch, base_config, tmp_path):
    monkeypatch.setattr(worker, "load_config", lambda: base_config)
    monkeypatch.setattr(worker, "STATIC_DIR", tmp_path)
    mocked = Mock()
    monkeypatch.setattr(worker, "Worker", mocked)
    worker.static_worker_main(burst=True)
    assert mocked.call_args.kwargs["queues"] == [
        worker.STATIC_QUEUE_NAME,
        worker.STATIC_ONLY_QUEUE_NAME,
    ]


@pytest.mark.parametrize("mode", ["static-only", "dynamic-only"])
def test_unrequested_stage_does_not_make_report_partial(tmp_path, mode):
    files = {
        "metadata.json": {"options": {"mode": mode}, "telemetry": {"complete": True}},
        "features.json": {"static": {"coverage": {"complete": True}}},
        "classification.json": {"label": "benign", "explanation": []},
    }
    for name, data in files.items():
        (tmp_path / name).write_text(json.dumps(data))
    assert build_report(tmp_path)["status"] == "complete"
