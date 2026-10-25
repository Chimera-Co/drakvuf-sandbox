"""Log-statistics routes using offline analysis directories."""

import importlib
import json
import sys
import uuid

import pytest
from flask_openapi3 import Info, OpenAPI


@pytest.fixture
def stats_client(monkeypatch, base_config, tmp_path):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr("drakrun.web.storage.ANALYSES_DIR", tmp_path)
    sys.modules.pop("drakrun.web.api", None)
    module = importlib.import_module("drakrun.web.api")
    app = OpenAPI(__name__, info=Info(title="stats test", version="0"))
    app.register_api(module.api)
    yield app.test_client()
    sys.modules.pop("drakrun.web.api", None)


def test_stats_routes(stats_client, tmp_path):
    uid = str(uuid.uuid4())
    directory = tmp_path / uid
    directory.mkdir()
    (directory / "filetracer.log").write_text(
        json.dumps({"Method": "NtWriteFile", "TimeStamp": 2, "FileName": "a"})
        + "\nmalformed\n"
    )
    response = stats_client.get(f"/api/logs/{uid}/filetracer/stats")
    assert response.status_code == 200
    assert response.json["total"] == 1
    assert response.json["parse_errors"] == 1
    response = stats_client.get(f"/api/logs/{uid}/stats")
    assert response.status_code == 200
    assert response.json["logs"] == {"filetracer": 1}
    assert sum(response.json["histogram"]["counts"]) == 1
    assert stats_client.get(f"/api/logs/{uid}/missing/stats").status_code == 404
    assert stats_client.get(f"/api/logs/{uid}/..%5Cfiletracer/stats").status_code == 404
    assert stats_client.get("/api/logs/invalid/stats").status_code == 422


def test_missing_analysis(stats_client):
    uid = str(uuid.uuid4())
    assert stats_client.get(f"/api/logs/{uid}/stats").status_code == 404
    assert stats_client.get(f"/api/logs/{uid}/apimon/stats").status_code == 404
    assert stats_client.get(f"/api/logs/{uid}/stats/process/1").status_code == 404
