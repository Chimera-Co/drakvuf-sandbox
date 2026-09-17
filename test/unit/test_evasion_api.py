"""Tests for drakrun.web.evasion_api.

Exercises the Sandbox Evasion HTTP API against Flask's test client. Two
things in this module are worth reading before the tests themselves:

1. drakrun.web.evasion_api, like the existing drakrun.web.api, calls
   load_config() at *module import time* - so it cannot be imported until a
   valid DrakrunConfig is available. _import_evasion_api() below monkeypatches
   drakrun.lib.config.load_config to return a temp-file-backed test config
   *before* (re-)importing the module, exactly the workaround
   test/unit/conftest.py's own docstring anticipates for exactly this
   problem.

2. RQ's real Job/Queue classes need a real Redis server to do anything
   useful, and this project intentionally takes on no new test dependency
   (no fakeredis) to get one. Instead, the handful of RQ-touching functions
   the blueprint imports by name (Job, enqueue_verification, get_scans_list)
   are monkeypatched on the freshly-imported module object with lightweight
   fakes - the plan's own "Redis faked/monkeypatched" testing note. This
   means these tests exercise the real route logic (validation, capability
   filtering, path traversal guarding, and - the whole point - that a score
   is never manufactured) without needing a live Redis or reimplementing
   one.

EVASION_DIR is also monkeypatched per-test to a tmp_path, since the real
constant is the absolute Linux path /var/lib/drakrun/evasion.
"""

import importlib
import io
import json
import sys
import zipfile

import pytest
from rq.exceptions import NoSuchJobError
from rq.job import JobStatus

from drakrun.evasion.constants import CheckStatus, Severity, ToolStatus
from drakrun.evasion.models import (
    EvasionScanMetadata,
    EvasionScanOptions,
    NormalizedCheck,
    ToolResult,
)
from drakrun.evasion.scoring import compute_score

_SANDBOX_TOML = """
[sandbox.win10]
display_name = "Windows 10 Test"
platform = "windows"
verifiers = ["perdedor", "alkhaser"]

[sandbox.linux-test]
display_name = "Linux Test"
platform = "linux"
verifiers = ["perdedor", "alkhaser"]
"""


@pytest.fixture
def app_config(config_factory):
    return config_factory(_SANDBOX_TOML)


@pytest.fixture
def evasion_api_module(monkeypatch, app_config):
    """Import (or re-import) drakrun.web.evasion_api with load_config()
    monkeypatched to return app_config, so its module-level `config =
    load_config()` / `redis = get_redis_connection(...)` succeed without a
    real /etc/drakrun/config.toml or a live Redis (Redis() itself is lazy -
    it never opens a socket until a command is actually issued)."""
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: app_config)
    sys.modules.pop("drakrun.web.evasion_api", None)
    module = importlib.import_module("drakrun.web.evasion_api")
    yield module
    sys.modules.pop("drakrun.web.evasion_api", None)


@pytest.fixture
def scan_dir(tmp_path, evasion_api_module, monkeypatch):
    monkeypatch.setattr(evasion_api_module, "EVASION_DIR", tmp_path)
    return tmp_path


@pytest.fixture
def client(evasion_api_module):
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(evasion_api_module.evasion_api)
    return app.test_client()


class FakeJob:
    """Stands in for rq.job.Job - only the surface evasion_api.py actually
    touches (id, get_status, get_meta, started_at, ended_at)."""

    def __init__(self, job_id, status, meta=None, started_at=None, ended_at=None):
        self.id = job_id
        self._status = status
        self.meta = meta or {}
        self.started_at = started_at
        self.ended_at = ended_at

    def get_status(self):
        return self._status

    def get_meta(self):
        return self.meta


class FakeJobRegistry:
    """Stands in for rq.job.Job's classmethods used by evasion_api.py -
    Job.fetch is monkeypatched onto this per-test."""

    def __init__(self, jobs_by_id=None):
        self._jobs_by_id = jobs_by_id or {}

    def fetch(self, job_id, connection=None):
        if job_id not in self._jobs_by_id:
            raise NoSuchJobError(job_id)
        return self._jobs_by_id[job_id]


def _write_metadata_json(scan_dir, scan_id, metadata: EvasionScanMetadata):
    scan_path = scan_dir / scan_id
    scan_path.mkdir(parents=True, exist_ok=True)
    metadata.store_to_file(scan_path / "metadata.json")


def _write_evasion_json(scan_dir, scan_id, metadata: EvasionScanMetadata):
    scan_path = scan_dir / scan_id
    scan_path.mkdir(parents=True, exist_ok=True)
    metadata.store_to_file(scan_path / "evasion.json")


def _finished_metadata(scan_id, tool_results, status="finished") -> EvasionScanMetadata:
    score = compute_score(tool_results)
    return EvasionScanMetadata(
        id=scan_id,
        status=status,
        sandbox={
            "id": "win10",
            "display_name": "Windows 10 Test",
            "platform": "windows",
        },
        options=EvasionScanOptions(
            sandbox_id="win10", tools=[tr.tool for tr in tool_results], profile="full"
        ),
        tool_results=tool_results,
        score=score,
        time_started="2024-01-01T00:00:00+00:00",
        time_finished="2024-01-01T00:10:00+00:00",
    )


# --- capability-driven sandbox/tool listing ---------------------------------


def test_list_sandboxes_is_capability_driven(client):
    resp = client.get("/api/evasion/sandboxes")
    assert resp.status_code == 200
    by_id = {s["id"]: s for s in resp.json}

    windows_tools = {t["id"] for t in by_id["win10"]["available_tools"]}
    assert windows_tools == {"perdedor", "alkhaser"}

    # Neither adapter currently declares linux support - the API must not
    # fabricate availability just because the sandbox opted in to both
    # verifier ids; capability comes from the adapter, not the config.
    assert by_id["linux-test"]["available_tools"] == []


def test_list_tools_exposes_real_option_schemas(client):
    resp = client.get("/api/evasion/tools")
    assert resp.status_code == 200
    by_id = {t["id"]: t for t in resp.json}
    assert by_id["perdedor"]["options_schema"]["full_suite_only"] is True
    assert by_id["perdedor"]["options_schema"]["options"] == []
    assert by_id["alkhaser"]["options_schema"]["full_suite_only"] is False
    option_names = {o["name"] for o in by_id["alkhaser"]["options_schema"]["options"]}
    assert "checks" in option_names
    assert "sleep_seconds" in option_names


# --- POST /scans -------------------------------------------------------------


def test_create_scan_success(client, evasion_api_module, monkeypatch):
    captured = {}

    def fake_enqueue(**kwargs):
        captured.update(kwargs)
        return FakeJob(kwargs["job_id"], JobStatus.QUEUED)

    monkeypatch.setattr(evasion_api_module, "enqueue_verification", fake_enqueue)

    resp = client.post(
        "/api/evasion/scans",
        json={"sandbox_id": "win10", "tools": ["perdedor"], "profile": "full"},
    )
    assert resp.status_code == 200
    scan_id = resp.json["scan_id"]
    assert captured["sandbox"].id == "win10"
    assert captured["options"].tools == ["perdedor"]
    assert (
        captured["options"].timeout == evasion_api_module.config.evasion.default_timeout
    )
    assert captured["job_id"] == scan_id


def test_create_scan_unknown_sandbox_is_404(client):
    resp = client.post(
        "/api/evasion/scans",
        json={
            "sandbox_id": "does-not-exist",
            "tools": ["perdedor"],
            "profile": "full",
        },
    )
    assert resp.status_code == 404
    assert "does-not-exist" in resp.json["error"]


def test_create_scan_unsupported_tool_is_400(client):
    resp = client.post(
        "/api/evasion/scans",
        json={
            "sandbox_id": "win10",
            "tools": ["not-a-real-tool"],
            "profile": "full",
        },
    )
    assert resp.status_code == 400
    assert "not-a-real-tool" in resp.json["error"]


def test_create_scan_invalid_custom_configuration_is_400(client):
    """Regression test for al-khaser's own --check TYPO bug: an unknown
    check name must be rejected by the API with a 400 naming the offending
    value, never silently accepted (which upstream would silently run zero
    checks while still exiting 0)."""
    resp = client.post(
        "/api/evasion/scans",
        json={
            "sandbox_id": "win10",
            "tools": ["alkhaser"],
            "profile": "custom",
            "tool_options": {"alkhaser": {"checks": ["TYPO"]}},
        },
    )
    assert resp.status_code == 400
    assert "TYPO" in resp.json["error"]


def test_create_scan_invalid_sleep_seconds_is_400(client):
    resp = client.post(
        "/api/evasion/scans",
        json={
            "sandbox_id": "win10",
            "tools": ["alkhaser"],
            "profile": "custom",
            "tool_options": {"alkhaser": {"sleep_seconds": -1}},
        },
    )
    assert resp.status_code == 400
    assert "sleep_seconds" in resp.json["error"]


# --- scan status --------------------------------------------------------------


def test_scan_status_while_running_reads_job_meta(
    client, evasion_api_module, monkeypatch
):
    scan_id = "11111111-1111-4111-8111-111111111111"
    job = FakeJob(
        scan_id,
        JobStatus.STARTED,
        meta={"substatus": "running", "vm_id": 3},
    )
    monkeypatch.setattr(evasion_api_module, "Job", FakeJobRegistry({scan_id: job}))

    resp = client.get(f"/api/evasion/scans/{scan_id}/status")
    assert resp.status_code == 200
    assert resp.json["status"] == "started"
    assert resp.json["substatus"] == "running"
    assert resp.json["vm_id"] == 3
    assert resp.json["time_finished"] is None


def test_scan_status_after_job_expiry_falls_back_to_metadata_json(
    client, evasion_api_module, monkeypatch, scan_dir
):
    scan_id = "22222222-2222-4222-8222-222222222222"
    monkeypatch.setattr(
        evasion_api_module, "Job", FakeJobRegistry({})
    )  # job expired from Redis
    metadata = _finished_metadata(scan_id, [])
    _write_metadata_json(scan_dir, scan_id, metadata)

    resp = client.get(f"/api/evasion/scans/{scan_id}/status")
    assert resp.status_code == 200
    assert resp.json["status"] == "finished"


def test_scan_status_unknown_scan_is_404(client, evasion_api_module, monkeypatch):
    monkeypatch.setattr(evasion_api_module, "Job", FakeJobRegistry({}))
    resp = client.get("/api/evasion/scans/33333333-3333-4333-8333-333333333333/status")
    assert resp.status_code == 404


# --- full scan record: successful vs incomplete, tool-native vs normalized ---


def test_get_scan_successful_scan_shows_real_score(
    client, evasion_api_module, monkeypatch, scan_dir
):
    scan_id = "44444444-4444-4444-8444-444444444444"
    monkeypatch.setattr(evasion_api_module, "Job", FakeJobRegistry({}))
    perdedor_result = ToolResult(
        tool="perdedor",
        status=ToolStatus.ok,
        checks=[
            NormalizedCheck(
                id="p1",
                category="timing",
                name="p1",
                description="d",
                status=CheckStatus.clean,
                severity=Severity.low,
                tool="perdedor",
            )
        ],
    )
    alkhaser_result = ToolResult(
        tool="alkhaser",
        status=ToolStatus.ok,
        checks=[
            NormalizedCheck(
                id="a1",
                category="design_specific",
                name="a1",
                description="d",
                status=CheckStatus.detected,
                severity=Severity.critical,
                tool="alkhaser",
            )
        ],
    )
    metadata = _finished_metadata(scan_id, [perdedor_result, alkhaser_result])
    _write_evasion_json(scan_dir, scan_id, metadata)

    resp = client.get(f"/api/evasion/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json
    # CHIMERA score is perdedor-only (100, clean) - unaffected by al-khaser's
    # detection, which is exactly the tool-native-vs-normalized separation.
    assert body["score"]["chimera_score"] == 100.0
    assert body["score"]["state"] == "pass"
    assert "weighted_score" not in body["score"]["tool_scores"]["alkhaser"]
    assert body["score"]["tool_scores"]["alkhaser"]["detected"] == 1


def test_get_scan_incomplete_scan_never_shows_a_manufactured_score(
    client, evasion_api_module, monkeypatch, scan_dir
):
    scan_id = "55555555-5555-4555-8555-555555555555"
    monkeypatch.setattr(evasion_api_module, "Job", FakeJobRegistry({}))
    unsupported_result = ToolResult(
        tool="perdedor", status=ToolStatus.unsupported, error="pwsh 7 not found"
    )
    metadata = _finished_metadata(scan_id, [unsupported_result], status="finished")
    _write_evasion_json(scan_dir, scan_id, metadata)

    resp = client.get(f"/api/evasion/scans/{scan_id}")
    assert resp.status_code == 200
    body = resp.json
    assert body["score"]["state"] == "incomplete"
    # exclude_none=True means an incomplete score's chimera_score key is
    # omitted entirely rather than ever being present as a number.
    assert "chimera_score" not in body["score"]
    assert any("pwsh 7 not found" in r for r in body["score"]["rationale"])


def test_get_scan_unknown_id_is_404(client, evasion_api_module, monkeypatch):
    monkeypatch.setattr(evasion_api_module, "Job", FakeJobRegistry({}))
    resp = client.get("/api/evasion/scans/66666666-6666-4666-8666-666666666666")
    assert resp.status_code == 404


# --- historical run listing ---------------------------------------------------


def test_list_scans_returns_finished_and_running_runs(
    client, evasion_api_module, monkeypatch, scan_dir
):
    finished_id = "77777777-7777-4777-8777-777777777777"
    running_id = "88888888-8888-4888-8888-888888888888"

    finished_metadata = _finished_metadata(
        finished_id,
        [
            ToolResult(
                tool="perdedor",
                status=ToolStatus.ok,
                checks=[
                    NormalizedCheck(
                        id="p1",
                        category="timing",
                        name="p1",
                        description="d",
                        status=CheckStatus.clean,
                        severity=Severity.low,
                        tool="perdedor",
                    )
                ],
            )
        ],
    )
    _write_evasion_json(scan_dir, finished_id, finished_metadata)

    finished_job = FakeJob(finished_id, JobStatus.FINISHED)
    running_job = FakeJob(
        running_id,
        JobStatus.STARTED,
        meta={
            "sandbox": {"id": "win10", "platform": "windows"},
            "options": {
                "sandbox_id": "win10",
                "tools": ["alkhaser"],
                "profile": "full",
            },
            "substatus": "running",
        },
    )

    monkeypatch.setattr(
        evasion_api_module,
        "get_scans_list",
        lambda connection: [running_job, finished_job],
    )

    resp = client.get("/api/evasion/scans")
    assert resp.status_code == 200
    by_id = {entry["id"]: entry for entry in resp.json}

    assert by_id[finished_id]["status"] == "finished"
    assert by_id[finished_id]["score"]["chimera_score"] == 100.0

    assert by_id[running_id]["status"] == "started"
    assert by_id[running_id]["score"] is None
    assert by_id[running_id]["tools"] == ["alkhaser"]


# --- artifact downloads --------------------------------------------------------


def test_scan_json_download(client, evasion_api_module, monkeypatch, scan_dir):
    scan_id = "99999999-9999-4999-8999-999999999999"
    monkeypatch.setattr(evasion_api_module, "Job", FakeJobRegistry({}))
    metadata = _finished_metadata(scan_id, [])
    _write_evasion_json(scan_dir, scan_id, metadata)

    resp = client.get(f"/api/evasion/scans/{scan_id}/json")
    assert resp.status_code == 200
    assert json.loads(resp.data)["id"] == scan_id


def test_scan_report_download_404_when_not_yet_generated(client, scan_dir):
    resp = client.get("/api/evasion/scans/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/report")
    assert resp.status_code == 404


def test_list_scan_files(client, scan_dir):
    scan_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    raw_dir = scan_dir / scan_id / "raw" / "alkhaser"
    raw_dir.mkdir(parents=True)
    (raw_dir / "log.txt").write_text("[*] check -> 1")

    resp = client.get(f"/api/evasion/scans/{scan_id}/files")
    assert resp.status_code == 200
    assert "raw/alkhaser/log.txt" in resp.json


def test_download_scan_file(client, scan_dir):
    scan_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    raw_dir = scan_dir / scan_id / "raw" / "alkhaser"
    raw_dir.mkdir(parents=True)
    (raw_dir / "log.txt").write_bytes(b"raw al-khaser output")

    resp = client.get(
        f"/api/evasion/scans/{scan_id}/files/download?filename=raw/alkhaser/log.txt"
    )
    assert resp.status_code == 200
    assert resp.data == b"raw al-khaser output"


def test_download_scan_file_path_traversal_is_rejected(client, scan_dir):
    scan_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    (scan_dir / scan_id).mkdir(parents=True)

    resp = client.get(
        f"/api/evasion/scans/{scan_id}/files/download?filename=../../../../etc/passwd"
    )
    assert resp.status_code == 400


def test_scan_artifacts_zip_download(client, scan_dir):
    scan_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    raw_dir = scan_dir / scan_id / "raw" / "perdedor"
    raw_dir.mkdir(parents=True)
    (raw_dir / "windows-report.json").write_text("{}")

    resp = client.get(f"/api/evasion/scans/{scan_id}/logs")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        assert any("windows-report.json" in n for n in zf.namelist())


def test_scan_artifacts_zip_unknown_scan_is_404(client, scan_dir):
    resp = client.get("/api/evasion/scans/ffffffff-ffff-4fff-8fff-ffffffffffff/logs")
    assert resp.status_code == 404
