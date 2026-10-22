"""Static analysis integration: container flags, staging, output validation, merge, API."""

import importlib
import json
import os
import stat
import sys
import textwrap
import uuid

import pytest
from rq.exceptions import NoSuchJobError

from drakrun.analyzer.static import sandbox
from drakrun.analyzer.static.worker import load_static, stage_and_enqueue, wait_for_static
from drakrun.lib.config import StaticConfigSection

AID = str(uuid.uuid4())

FAKE_ENGINE = textwrap.dedent("""\
    #!{python}
    import json, os, sys, time
    args = sys.argv[1:]
    if args[0] in ("kill", "rm"):
        sys.exit(0)
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    out = [m.split(":")[0] for m in mounts if m.split(":")[1] == "/out"][0]
    sample = [m.split(":")[0] for m in mounts if m.split(":")[1] == "/in/sample"][0]
    open(os.path.join(os.path.dirname(out), "argv.json"), "w").write(json.dumps(args))
    mode = os.environ.get("FAKE_MODE", "ok")
    if mode == "sleep":
        time.sleep(5)
    elif mode == "ok":
        data = open(sample, "rb").read()
        json.dump({{"schema": "chimera-static/1", "score": 12, "level": "clean", "size": len(data)}},
                  open(os.path.join(out, "static.json"), "w"))
    elif mode == "wrong":
        json.dump({{"schema": "other"}}, open(os.path.join(out, "static.json"), "w"))
    elif mode == "huge":
        open(os.path.join(out, "static.json"), "w").write('{{"schema": "chimera-static/1", "x": "' + "a" * 5000 + '"}}')
    elif mode == "symlink":
        os.symlink("/etc/passwd", os.path.join(out, "static.json"))
    sys.exit(0)
""")


@pytest.fixture
def engine(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "podman"
    script.write_text(FAKE_ENGINE.format(python=sys.executable))
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return script


@pytest.fixture
def settings():
    return StaticConfigSection(enabled=True, timeout_s=1, max_output_bytes=1000)


def staged(tmp_path, settings, data=b"MZ\x90\x00 sample bytes"):
    src = tmp_path / "upload.sample"
    src.write_bytes(data)
    job = tmp_path / "static" / AID
    sandbox.stage_sample(src, job, settings)
    return job


def test_command_has_every_isolation_flag(tmp_path, settings):
    cmd = sandbox.build_command(settings, AID, tmp_path / "s", tmp_path / "o", "invoice.exe")
    joined = " ".join(cmd)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--user 65534:65534", "--pids-limit 32", "--memory 2048m", "--memory-swap 2048m",
                 "--ulimit core=0", "/tmp:rw,noexec,nosuid,nodev", ":/in/sample:ro,noexec,nosuid,nodev",
                 ":/out:rw,noexec,nosuid,nodev"):
        assert flag in joined, flag
    assert "--privileged" not in joined and "--network host" not in joined
    assert cmd[cmd.index("--name") + 1] == f"chimera-static-{AID}"


def test_staged_copy_is_never_executable(tmp_path, settings):
    job = staged(tmp_path, settings)
    mode = (job / "in" / "sample").stat().st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert not mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)


def test_bad_analysis_id_is_rejected(tmp_path, settings):
    with pytest.raises(ValueError):
        stage_and_enqueue("../../etc", tmp_path / "x", "x", None, settings, base=tmp_path)


def test_disabled_does_nothing(tmp_path):
    assert stage_and_enqueue(AID, tmp_path / "x", "x", None, StaticConfigSection(enabled=False), base=tmp_path) is None
    assert not (tmp_path / AID).exists()


def test_run_ok(tmp_path, settings, engine, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "ok")
    job = staged(tmp_path, settings)
    result = sandbox.run_in_container(settings, AID, job, "invoice.exe")
    assert result["schema"] == "chimera-static/1" and result["size"] == len(b"MZ\x90\x00 sample bytes")
    assert result["container"]["exit_code"] == 0
    argv = json.loads((job / "argv.json").read_text())
    assert argv[argv.index("--network") + 1] == "none"


@pytest.mark.parametrize("mode,error", [("wrong", "wrong schema"), ("huge", "too large"),
                                        ("none", "no static.json"), ("symlink", "no static.json")])
def test_bad_output_rejected(tmp_path, settings, engine, monkeypatch, mode, error):
    monkeypatch.setenv("FAKE_MODE", mode)
    result = sandbox.run_in_container(settings, AID, staged(tmp_path, settings), "x")
    assert error in result["error"]


def test_timeout_kills_container(tmp_path, settings, engine, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "sleep")
    monkeypatch.setattr(sandbox, "GRACE_S", 0.5)
    result = sandbox.run_in_container(settings, AID, staged(tmp_path, settings), "x")
    assert "timed out" in result["error"]


def test_missing_engine(tmp_path, settings, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = sandbox.run_in_container(settings, AID, staged(tmp_path, settings), "x")
    assert "not installed" in result["error"]


def test_load_and_wait(tmp_path):
    assert load_static(AID, tmp_path) is None
    assert wait_for_static(AID, 0.2, tmp_path, poll_s=0.05) is None
    (tmp_path / AID).mkdir()
    (tmp_path / AID / "static.json").write_text(json.dumps({"schema": "chimera-static/1", "score": 3}))
    assert wait_for_static(AID, 0.2, tmp_path)["score"] == 3
    (tmp_path / AID / "static.json").write_text(json.dumps({"schema": "nope"}))
    assert load_static(AID, tmp_path) is None


def test_static_api_route(monkeypatch, base_config, tmp_path):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    sys.modules.pop("drakrun.web.api", None)
    module = importlib.import_module("drakrun.web.api")
    monkeypatch.setattr(module, "STATIC_DIR", tmp_path)
    monkeypatch.setattr(module.Job, "fetch", lambda *a, **k: (_ for _ in ()).throw(NoSuchJobError()))
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(module.api)
    client = app.test_client()
    assert client.get(f"/api/static/{AID}").status_code == 404
    (tmp_path / AID).mkdir()
    (tmp_path / AID / "static.json").write_text(json.dumps({"schema": "chimera-static/1"}))
    response = client.get(f"/api/static/{AID}")
    assert response.status_code == 200 and response.json == {"schema": "chimera-static/1"}
    assert client.get("/api/static/not-a-uuid").status_code in (400, 422)
    sys.modules.pop("drakrun.web.api", None)
