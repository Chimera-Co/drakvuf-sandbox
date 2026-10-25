"""Classifier artifacts and status through the real API with local storage."""

import importlib
import json
import sys
import uuid

import pytest
from rq.exceptions import NoSuchJobError

from drakrun.web.schema import AnalysisResponse


@pytest.fixture
def api_client(monkeypatch, base_config, tmp_path):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr("drakrun.web.storage.ANALYSES_DIR", tmp_path)
    sys.modules.pop("drakrun.web.api", None)
    module = importlib.import_module("drakrun.web.api")

    def missing_job(*args, **kwargs):
        raise NoSuchJobError

    monkeypatch.setattr(module.Job, "fetch", missing_job)
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(module.api)
    yield app.test_client()
    sys.modules.pop("drakrun.web.api", None)


@pytest.mark.parametrize("artifact", ["classification", "features"])
def test_classifier_artifacts_200_and_404(api_client, tmp_path, artifact):
    task_uid = str(uuid.uuid4())
    assert api_client.get(f"/api/{artifact}/{task_uid}").status_code == 404
    directory = tmp_path / task_uid
    directory.mkdir()
    value = {"schema": f"chimera-{artifact}/1", "test": True}
    (directory / f"{artifact}.json").write_text(json.dumps(value))
    response = api_client.get(f"/api/{artifact}/{task_uid}")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.json == value


def test_status_preserves_classification(api_client, tmp_path):
    task_uid = str(uuid.uuid4())
    directory = tmp_path / task_uid
    directory.mkdir()
    verdict = {
        "schema": "chimera-verdict/1",
        "label": "unknown",
        "error": "test failure",
    }
    (directory / "metadata.json").write_text(
        json.dumps(
            {
                "id": task_uid,
                "status": "finished",
                "options": {"plugins": [], "net_enable": False},
                "classification": verdict,
            }
        )
    )
    response = api_client.get(f"/api/status/{task_uid}")
    assert response.status_code == 200
    assert response.json["classification"] == verdict
    assert AnalysisResponse.model_validate(response.json).classification == verdict


@pytest.mark.parametrize("artifact", ["classification", "features"])
def test_classifier_routes_reject_invalid_uid(api_client, artifact):
    assert api_client.get(f"/api/{artifact}/not-a-uuid").status_code == 422


def test_chimera_report_is_served_with_a_locked_down_policy(api_client, tmp_path):
    task_uid = str(uuid.uuid4())
    assert api_client.get(f"/api/chimera_report/{task_uid}").status_code == 404
    assert api_client.get(f"/api/chimera_report/{task_uid}/html").status_code == 404
    directory = tmp_path / task_uid
    directory.mkdir()
    (directory / "chimera-report.json").write_text('{"schema": "chimera-report/1"}')
    (directory / "chimera-report.html").write_text("<!doctype html><p>x</p>")
    response = api_client.get(f"/api/chimera_report/{task_uid}")
    assert response.json == {"schema": "chimera-report/1"}
    response = api_client.get(f"/api/chimera_report/{task_uid}/html")
    assert response.status_code == 200 and response.mimetype == "text/html"
    assert "attachment" not in response.headers.get("Content-Disposition", "")
    policy = response.headers["Content-Security-Policy"]
    assert "default-src 'none'" in policy and "script-src" not in policy
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_ioc_exports_download_from_the_report(api_client, tmp_path):
    task_uid = str(uuid.uuid4())
    assert api_client.get(f"/api/chimera_report/{task_uid}/iocs.csv").status_code == 404
    directory = tmp_path / task_uid
    directory.mkdir()
    report = {
        "analysis_id": task_uid,
        "sample": {"sha256": "b" * 64},
        "iocs": [{"type": "domain", "value": "+x.example", "source": "dns"}],
        "evidence": [],
    }
    (directory / "chimera-report.json").write_text(json.dumps(report))
    response = api_client.get(f"/api/chimera_report/{task_uid}/iocs.csv")
    assert response.status_code == 200 and response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    assert '"\'+x.example"' in response.text
    response = api_client.get(f"/api/chimera_report/{task_uid}/iocs.json")
    assert response.json["iocs"][0]["value"] == "+x.example"
    assert "attachment" in response.headers["Content-Disposition"]
