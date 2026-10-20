"""OS selection at worker/CLI entry points and the real multipart upload route."""

import importlib
import io
import json
import pathlib
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from drakrun.analyzer import worker
from drakrun.analyzer.analysis_metadata import AnalysisMetadata
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.analyzer import AnalysisSubstatus
from drakrun.cli.analyze import analyze


@pytest.mark.parametrize("guest_os", ["linux", "windows"])
@pytest.mark.parametrize("bound", [False, True])
def test_worker_dispatch_and_metadata(
    tmp_path, monkeypatch, base_config, guest_os, bound
):
    sample = tmp_path / "sample"
    sample.write_bytes(b"test")
    options = AnalysisOptions.with_config_defaults(
        base_config,
        guest_os=guest_os,
        host_sample_path=sample,
    )
    job = SimpleNamespace(
        id="test",
        started_at=datetime.now(timezone.utc),
        meta={"file": dict(name="sample", type="ELF", sha256="abc")},
        save_meta=Mock(),
    )
    monkeypatch.setattr(worker, "_WORKER_VM_ID", 2)
    monkeypatch.setattr(worker, "_WORKER_GUEST_OS", guest_os if bound else "any")
    if bound:
        job.meta["memory_admission_wait_seconds"] = 5.5
    monkeypatch.setattr(worker, "ANALYSES_DIR", tmp_path / "analyses")
    monkeypatch.setattr(worker, "load_config", lambda: base_config)
    monkeypatch.setattr(worker, "get_current_job", lambda: job)
    windows, linux = Mock(return_value={"selected": "windows"}), Mock(
        return_value={"selected": "linux"}
    )
    monkeypatch.setattr(worker, "analyze_file", windows)
    monkeypatch.setattr(worker, "analyze_linux_file", linux)
    worker.worker_analyze(options)
    selected, other = (linux, windows) if guest_os == "linux" else (windows, linux)
    selected.assert_called_once()
    other.assert_not_called()
    vm_id, directory, metadata = selected.call_args.args
    assert vm_id == 2
    assert metadata.options.guest_os == guest_os
    assert directory == tmp_path / "analyses" / "test"
    saved = AnalysisMetadata.load_from_file(directory / "metadata.json")
    assert saved.status == "finished"
    assert saved.model_extra["selected"] == guest_os
    assert job.meta["extra_metadata"] == {"selected": guest_os}
    if bound:
        assert saved.model_extra["memory_admission_wait_seconds"] == 5.5
    assert not sample.exists()


@pytest.mark.parametrize("guest_os", [None, "windows", "linux"])
def test_cli_dispatch(tmp_path, monkeypatch, base_config, guest_os):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    monkeypatch.setattr("drakrun.cli.check_root.os.geteuid", lambda: 0)
    windows, linux = Mock(return_value={}), Mock(return_value={})
    monkeypatch.setattr("drakrun.analyzer.analyzer.analyze_file", windows)
    monkeypatch.setattr("drakrun.analyzer.linux_analyzer.analyze_linux_file", linux)
    output = tmp_path / "output"
    args = [
        "--output-dir",
        str(output),
        "--vm-id",
        "3",
        "--start-method",
        "shellexec",
        "--target-filepath",
        r"C:\target",
        "--guest-working-directory",
        r"C:\work",
    ]
    if guest_os:
        args.extend(["--guest-os", guest_os])
    result = CliRunner().invoke(analyze, args)
    assert result.exit_code == 0, result.output or repr(result.exception)
    selected, other = (linux, windows) if guest_os == "linux" else (windows, linux)
    selected.assert_called_once()
    other.assert_not_called()
    kwargs = selected.call_args.kwargs
    assert kwargs["vm_id"] == 3
    assert kwargs["metadata"].options.guest_os == (guest_os or "windows")
    options = kwargs["metadata"].options
    if guest_os == "linux":
        assert options.start_method is None
        assert options.guest_target_directory is None
        assert options.guest_working_directory is None
    else:
        assert options.start_method == "shellexec"
        assert options.guest_target_directory == pathlib.PureWindowsPath(r"C:\target")
        assert options.guest_working_directory == pathlib.PureWindowsPath(r"C:\work")
    kwargs["substatus_callback"](AnalysisSubstatus.analyzing, updated_options=True)
    assert kwargs["metadata"].time_execution_started
    assert AnalysisMetadata.load_from_file(output / "metadata.json").time_finished


def test_cli_rejects_unknown_os(tmp_path):
    result = CliRunner().invoke(
        analyze, ["--guest-os", "macos", "--output-dir", str(tmp_path / "out")]
    )
    assert result.exit_code == 2
    assert "Invalid value for '--guest-os'" in result.output
    assert not (tmp_path / "out").exists()


@pytest.fixture
def upload_client(tmp_path, monkeypatch, base_config):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: base_config)
    sys.modules.pop("drakrun.web.api", None)
    module = importlib.import_module("drakrun.web.api")
    monkeypatch.setattr(module, "UPLOADS_DIR", tmp_path / "uploads")
    enqueued = Mock()
    monkeypatch.setattr(module, "enqueue_analysis", enqueued)
    monkeypatch.setattr(module, "truncate_analysis_list", Mock())
    monkeypatch.setattr(
        "drakrun.analyzer.analysis_metadata.magic.from_file", lambda _: "ELF"
    )
    from flask_openapi3 import Info, OpenAPI

    app = OpenAPI(__name__, info=Info(title="test", version="0"))
    app.register_api(module.api)
    yield app.test_client(), enqueued
    sys.modules.pop("drakrun.web.api", None)


@pytest.mark.parametrize("guest_os", [None, "windows", "linux"])
def test_upload_guest_os_and_windows_fields(upload_client, guest_os):
    client, enqueue = upload_client
    fields = dict(
        file=(io.BytesIO(b"sample"), "sample.elf"),
        timeout="123",
        file_path=r"C:\target",
        start_method="shellexec",
        start_working_dir=r"C:\work",
        start_command="echo sample",
        plugins=json.dumps(["procmon", "syscalls"]),
        no_internet="1",
    )
    if guest_os:
        fields["guest_os"] = guest_os
    response = client.post("/api/upload", data=fields)
    assert response.status_code == 200, response.json
    enqueue.assert_called_once()
    options = enqueue.call_args.kwargs["options"]
    assert options.guest_os == (guest_os or "windows")
    assert options.timeout == 123
    assert options.start_command == "echo sample"
    assert options.plugins == ["procmon", "syscalls"]
    assert options.net_enable is False
    assert options.sample_filename == "sample.elf"
    assert options.host_sample_path.read_bytes() == b"sample"
    if guest_os == "linux":
        assert options.start_method is None
        assert options.guest_target_directory is None
        assert options.guest_working_directory is None
        assert "guest_target_directory" not in options.to_dict()
    else:
        assert options.start_method == "shellexec"
        assert options.guest_target_directory == pathlib.PureWindowsPath(r"C:\target")
        assert options.guest_working_directory == pathlib.PureWindowsPath(r"C:\work")


@pytest.mark.parametrize("guest_os", ["linux", "windows"])
def test_upload_default_paths(upload_client, guest_os):
    client, enqueue = upload_client
    response = client.post(
        "/api/upload",
        data={"guest_os": guest_os, "file": (io.BytesIO(b"sample"), "sample")},
    )
    assert response.status_code == 200, response.json
    options = enqueue.call_args.kwargs["options"]
    if guest_os == "linux":
        assert options.guest_target_directory is None
    else:
        assert (
            options.guest_target_directory
            == AnalysisOptions.model_fields["guest_target_directory"].default
        )


@pytest.mark.parametrize("guest_os", ["macos", "Linux", ""])
def test_upload_rejects_invalid_os(upload_client, guest_os):
    client, enqueue = upload_client
    response = client.post(
        "/api/upload",
        data={"guest_os": guest_os, "file": (io.BytesIO(b"sample"), "sample")},
    )
    assert response.status_code == 422
    enqueue.assert_not_called()
