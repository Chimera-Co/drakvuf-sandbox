"""Online inventory, refresh and upload option API contracts."""

import io
import json
import uuid
from unittest.mock import Mock

import pytest

from .test_analysis_modes import upload  # noqa: F401
from .test_classifier_api import api_client  # noqa: F401


def test_inventory_no_secrets(api_client, base_config, tmp_path):
    base_config.intel.keys_dir = tmp_path / "keys"
    base_config.intel.keys_dir.mkdir()
    (base_config.intel.keys_dir / "virustotal").write_text("secret-never-exposed")
    response = api_client.get("/api/intel/providers")
    assert response.status_code == 200
    assert len(response.json["providers"]) == 10
    assert "secret-never-exposed" not in response.text
    assert response.json["providers"][0]["configured"] is True


def test_refresh(api_client, base_config, tmp_path, monkeypatch):
    uid = str(uuid.uuid4())
    assert api_client.post(f"/api/intel/{uid}/refresh").status_code == 409
    base_config.intel.online_enabled = True
    assert api_client.post(f"/api/intel/{uid}/refresh").status_code == 404
    directory = tmp_path / uid
    directory.mkdir()
    (directory / "chimera-report.json").write_text(json.dumps({"stages": {}}))
    queue = Mock()
    monkeypatch.setattr("drakrun.lib.intel.online.run.enqueue", queue)
    assert api_client.post(f"/api/intel/{uid}/refresh").status_code == 202
    assert queue.call_args.args[2] == {"intel_online": True}


@pytest.mark.parametrize("mode", ["combined", "static-only"])
@pytest.mark.parametrize("choice", [None, "true", "false"])
def test_upload_online_option(upload, mode, choice):
    client, api, dynamic, static, queue = upload
    api.config.intel.online_enabled = True
    data = {"file": (io.BytesIO(b"fixture"), "x.bin"), "mode": mode}
    if choice is not None:
        data["intel_online"] = choice
    response = client.post("/api/upload", data=data)
    assert response.status_code == 200, response.json
    expected = choice != "false"
    if mode == "static-only":
        options = queue.return_value.enqueue.call_args.kwargs["meta"]["options"]
    else:
        options = (
            dynamic.call_args.kwargs["options"].to_dict()
            if "options" in dynamic.call_args.kwargs
            else dynamic.call_args.args[0].to_dict()
        )
    assert options["intel_online"] is expected
    from drakrun.analyzer.static.worker import job_dir

    stored = json.loads(
        (job_dir(response.json["task_uid"]) / "online-options.json").read_text()
    )
    assert stored == {"intel_online": expected}
