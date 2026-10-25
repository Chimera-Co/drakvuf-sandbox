"""Pipeline status (/api/pipeline/<id>) and the full analyses list (/api/analyses)."""

import importlib
import json
import sys
import uuid
from types import SimpleNamespace

import pytest
from rq.exceptions import NoSuchJobError

MODULES = ("drakrun.web.api", "drakrun.web.pipeline_api")


@pytest.fixture
def pipeline(monkeypatch, base_config, tmp_path):
    analyses, static = tmp_path / "analyses", tmp_path / "static"
    analyses.mkdir()
    static.mkdir()
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr("drakrun.web.storage.ANALYSES_DIR", analyses)
    for name in MODULES:
        sys.modules.pop(name, None)
    module = importlib.import_module("drakrun.web.pipeline_api")
    monkeypatch.setattr(module, "ANALYSES_DIR", analyses)
    monkeypatch.setattr(module, "STATIC_DIR", static)
    monkeypatch.setattr(module, "_disk_cache", {})
    jobs = {}

    def fetch(job_id, connection=None):
        if job_id in jobs:
            return jobs[job_id]
        raise NoSuchJobError

    monkeypatch.setattr(module.Job, "fetch", fetch)
    monkeypatch.setattr(module, "get_analyses_list", lambda connection: [])
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(module.pipeline_api)
    yield SimpleNamespace(
        client=app.test_client(), analyses=analyses, static=static, jobs=jobs
    )
    for name in MODULES:
        sys.modules.pop(name, None)


def job(state, meta=None):
    return SimpleNamespace(get_status=lambda: state, meta=meta or {})


def write(directory, name, value):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(json.dumps(value))


def states(response):
    return {s["id"]: s["state"] for s in response.json["stages"]}


def test_unknown_or_invalid_id(pipeline):
    # the path schema rejects a malformed id, like every other analysis route
    assert pipeline.client.get("/api/pipeline/not-a-uuid").status_code == 422
    assert pipeline.client.get(f"/api/pipeline/{uuid.uuid4()}").status_code == 404


def test_finished_combined_analysis(pipeline):
    uid = str(uuid.uuid4())
    run, files = pipeline.analyses / uid, pipeline.static / uid
    write(run, "metadata.json", {"status": "finished", "options": {}})
    write(run, "report.json", {})
    write(run, "classification.json", {"label": "malicious"})
    write(
        run,
        "chimera-report.json",
        {"stages": {"intel": {"status": "ok", "reason": "offline"}}},
    )
    write(files, "static.json", {"type": {"format": "pe"}, "level": "full"})
    write(files, "deep.json", {})
    write(files, "memdumps.json", {"scanned": [{}, {}], "dumps_total": 3})
    response = pipeline.client.get(f"/api/pipeline/{uid}")
    assert response.status_code == 200
    assert states(response) == {
        "upload": "done",
        "static": "done",
        "dynamic": "done",
        "postprocess": "done",
        "classifier": "done",
        "deep": "done",
        "memdumps": "done",
        "intel": "done",
        "report": "done",
    }
    detail = {s["id"]: s["detail"] for s in response.json["stages"]}
    assert detail["memdumps"] == "2 of 3 dumps"
    assert detail["classifier"] == "malicious"
    assert response.json["active"] is False


def test_running_analysis_reads_job_states(pipeline):
    uid = str(uuid.uuid4())
    pipeline.jobs[uid] = job("started", {"substatus": "analyzing"})
    pipeline.jobs[f"static-{uid}"] = job("queued")
    write(pipeline.analyses / uid, "metadata.json", {"options": {}})
    response = pipeline.client.get(f"/api/pipeline/{uid}")
    got = states(response)
    assert got["static"] == "queued"
    assert got["dynamic"] == "running"
    assert got["postprocess"] == "pending"
    assert got["report"] == "pending"
    assert response.json["active"] is True


def test_postprocessing_and_online_intel_job(pipeline):
    uid = str(uuid.uuid4())
    pipeline.jobs[uid] = job("started", {"substatus": "postprocessing"})
    pipeline.jobs[f"intel-online-{uid}"] = job("queued")
    write(pipeline.analyses / uid, "metadata.json", {"options": {}})
    got = states(pipeline.client.get(f"/api/pipeline/{uid}"))
    assert got["dynamic"] == "done"
    assert got["postprocess"] == "running"
    assert got["intel"] == "queued"


def test_static_only_skips_the_vm_stages(pipeline):
    uid = str(uuid.uuid4())
    write(
        pipeline.analyses / uid,
        "metadata.json",
        {"status": "finished", "options": {"mode": "static-only"}},
    )
    write(pipeline.static / uid, "static.json", {"type": {"format": "zip"}})
    got = states(pipeline.client.get(f"/api/pipeline/{uid}"))
    assert got["dynamic"] == "skipped"
    assert got["postprocess"] == "skipped"
    assert got["memdumps"] == "skipped"
    assert got["deep"] == "skipped"  # capa/FLOSS only read PE and ELF


def test_failed_static_pass_is_reported(pipeline):
    uid = str(uuid.uuid4())
    write(pipeline.analyses / uid, "metadata.json", {"status": "finished"})
    write(pipeline.static / uid, "static.json", {"error": "container timed out"})
    response = pipeline.client.get(f"/api/pipeline/{uid}")
    static = next(s for s in response.json["stages"] if s["id"] == "static")
    assert static == {
        "id": "static",
        "label": "Static analysis",
        "state": "failed",
        "detail": "container timed out",
    }


def test_analyses_lists_disk_beyond_the_job_registry(pipeline):
    older, newer = str(uuid.uuid4()), str(uuid.uuid4())
    write(
        pipeline.analyses / older,
        "metadata.json",
        {"status": "finished", "time_started": "2026-10-01T10:00:00+00:00"},
    )
    write(
        pipeline.analyses / newer,
        "metadata.json",
        {"status": "finished", "time_started": "2026-10-20T10:00:00+00:00"},
    )
    (pipeline.analyses / "not-an-analysis").mkdir()
    response = pipeline.client.get("/api/analyses")
    assert response.status_code == 200
    assert [item["id"] for item in response.json] == [newer, older]
