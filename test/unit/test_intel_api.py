"""Offline intel route serves the saved report snapshot."""

import json
import uuid

from .test_classifier_api import api_client  # noqa: F401


def test_intel_route(api_client, tmp_path):
    uid = str(uuid.uuid4())
    assert api_client.get(f"/api/intel/{uid}").status_code == 404
    directory = tmp_path / uid
    directory.mkdir()
    stage = {"status": "ok", "payload": {"matches": []}}
    (directory / "chimera-report.json").write_text(
        json.dumps({"stages": {"intel": stage}})
    )
    assert api_client.get(f"/api/intel/{uid}").json == stage
    assert api_client.get("/api/intel/not-a-uuid").status_code == 422
