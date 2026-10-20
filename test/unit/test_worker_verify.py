"""End-to-end (Xen-free) tests for drakrun.evasion.worker.worker_verify.

worker_verify's real job is orchestration: resolve the sandbox, re-validate
each tool against its adapter's capability schema, drive the disposable
guest lifecycle, run the real (unmodified) verifier adapters against a
guest session, score, and persist evasion.json/report.html/metadata.json -
all before returning. Every one of those steps except the literal Xen guest
boot can be exercised without Xen:

- drakrun.analyzer.run_tools cannot be imported at all on this machine (its
  import chain reaches asyncvnc/perception/Xen bindings that are not
  installed and, for Xen, cannot be on a non-Linux host). A fake module is
  injected into sys.modules under its exact dotted name before calling
  worker_verify, so the function's own `from drakrun.analyzer.run_tools
  import run_vm` binds to a fake run_vm context manager instead - this is
  the same "fake one layer below the real dependency" approach
  test_guest_runner.py and fake_guest_session.py already use.
- drakrun.evasion.guest_runner.connect_guest_session is monkeypatched to
  return the existing FakeGuestSession test double (test/unit/
  fake_guest_session.py), so the REAL, unmodified PerdedorAdapter/
  AlKhaserAdapter run for real against scripted guest bytes.
- InstallInfo.load/VmiInfo.load are monkeypatched to avoid touching
  /etc/drakrun/install.json or a real VMI profile.

Real end-to-end guest execution against an actual restored Xen VM (a real
run_vm, a real Drakshell socket, a real al-khaser/PERDEDOR run) is a
Debian/Xen integration concern and is explicitly NOT covered here - see
docs/usage/... (Windows-development limitations) and the Phase F report.
"""

import contextlib
import datetime
import json
import pathlib
import subprocess
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.models import EvasionScanOptions  # noqa: E402
from drakrun.evasion.models import NormalizedCheck, ToolResult  # noqa: E402
from drakrun.evasion.verifiers.base import VerifierAdapter  # noqa: E402

_SANDBOX_TOML = """
[sandbox.win10]
display_name = "Windows 10 Test"
platform = "windows"
verifiers = ["perdedor", "alkhaser"]
"""

_ALKHASER_LOG = (
    "[2024-01-01 00:00:00] [*] TLS process attach callback  -> 0\n"
    "[2024-01-01 00:00:00] [*] TLS thread attach callback  -> 1\n"
)


class FakeJob:
    def __init__(self, job_id="11111111-1111-4111-8111-111111111111"):
        self.id = job_id
        self.meta = {}
        self.started_at = datetime.datetime.now(datetime.timezone.utc)
        self.substatus_history = []

    def save_meta(self):
        self.substatus_history.append(self.meta.get("substatus"))


class FakeVm:
    vm_name = "vm-1"


@pytest.fixture
def worker_module(monkeypatch, tmp_path):
    """Import drakrun.evasion.worker with every Xen-only dependency it
    would otherwise need faked out, and EVASION_DIR pointed at tmp_path."""
    import drakrun.evasion.worker as worker

    monkeypatch.setattr(worker, "_WORKER_VM_ID", 1)
    monkeypatch.setattr("drakrun.lib.paths.EVASION_DIR", tmp_path)

    fake_run_tools = types.ModuleType("drakrun.analyzer.run_tools")

    @contextlib.contextmanager
    def fake_run_vm(vm_id, install_info, network_conf, no_restore=False):
        yield FakeVm()

    fake_run_tools.run_vm = fake_run_vm

    class FakeStallMonitor:
        def __init__(self, vm_name):
            self.vm_name = vm_name
            self.stalled = False
            self.max_stall_s = 0.0

    fake_run_tools.StallMonitor = FakeStallMonitor
    monkeypatch.setitem(sys.modules, "drakrun.analyzer.run_tools", fake_run_tools)

    monkeypatch.setattr(
        "drakrun.lib.install_info.InstallInfo.load",
        staticmethod(lambda path: object()),
    )
    monkeypatch.setattr(
        "drakrun.lib.libvmi.VmiInfo.load", staticmethod(lambda path: object())
    )

    return worker


@pytest.fixture
def app_config(config_factory):
    config = config_factory(_SANDBOX_TOML)
    config.drakrun.no_post_restore = True
    return config


def _patch_load_config(monkeypatch, config):
    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: config)


def test_worker_verify_runs_real_adapters_against_a_fake_guest_session(
    worker_module, app_config, monkeypatch, tmp_path
):
    """The core happy-path integration: al-khaser (host_binary_path
    configured) actually executes against a scripted guest session and
    produces real, parsed checks; PERDEDOR (no repo_path configured)
    correctly reports itself unsupported. The overall CHIMERA score must
    still be 'incomplete', because PERDEDOR - the primary tool - never
    produced a usable result, regardless of al-khaser's own findings."""
    host_binary = tmp_path / "al-khaser_x64.exe"
    host_binary.write_bytes(b"fake-pe-binary")
    app_config.evasion.alkhaser.host_binary_path = host_binary

    _patch_load_config(monkeypatch, app_config)

    fake_session = FakeGuestSession(
        run_result=(0, b"", b""),
        files={r"C:\Users\Public\alkhaser\log.txt": _ALKHASER_LOG.encode()},
    )
    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda vm_name, injector: fake_session,
    )

    job = FakeJob()
    monkeypatch.setattr("rq.get_current_job", lambda: job)

    options = EvasionScanOptions(
        sandbox_id="win10",
        tools=["perdedor", "alkhaser"],
        profile="custom",
        tool_options={"alkhaser": {"checks": ["TLS"], "sleep_seconds": 1}},
        timeout=60,
    )

    worker_module.worker_verify(options)

    scan_dir = tmp_path / job.id
    evasion_json = json.loads((scan_dir / "evasion.json").read_text())

    tool_status = {tr["tool"]: tr["status"] for tr in evasion_json["tool_results"]}
    assert tool_status["alkhaser"] == "ok"
    assert tool_status["perdedor"] == "unsupported"

    alkhaser_checks = next(
        tr["checks"] for tr in evasion_json["tool_results"] if tr["tool"] == "alkhaser"
    )
    assert {c["status"] for c in alkhaser_checks} == {"clean", "detected"}

    # The whole point of Phase C's scoring guarantee, now proven through a
    # real worker run: al-khaser produced real findings, but the primary
    # tool (perdedor) never did, so the scan is "incomplete" - never a
    # fabricated pass, and never influenced by al-khaser's own findings.
    assert evasion_json["score"]["state"] == "incomplete"
    assert "chimera_score" not in evasion_json["score"]

    assert (scan_dir / "report.html").exists()
    assert (scan_dir / "metadata.json").exists()

    # The al-khaser binary is uploaded exactly once. The user-mode read/hash
    # diagnostic also uses put_file() to deliver its .ps1 probe script (once
    # per checkpoint), so select the binary rather than asserting a bare
    # call count.
    binary_uploads = [
        c
        for c in fake_session.put_file_calls
        if c[1] == r"C:\Users\Public\alkhaser\al-khaser_x64.exe"
    ]
    assert len(binary_uploads) == 1
    # Exactly one real al-khaser launch. The upload/pre-run metadata probe
    # diagnostics also go through run(), so filter to the launch itself
    # rather than asserting it is the only guest command in the scan.
    launches = [
        argv for (argv, _t, _c) in fake_session.run_calls if "--sleep" in " ".join(argv)
    ]
    assert len(launches) == 1

    assert "preparing" in job.substatus_history
    assert "booting" in job.substatus_history
    assert "probing" in job.substatus_history
    assert "running_perdedor" in job.substatus_history
    assert "running_alkhaser" in job.substatus_history
    assert "collecting" in job.substatus_history
    assert "reporting" in job.substatus_history
    assert "cleanup" in job.substatus_history


def test_worker_verify_skips_guest_boot_when_nothing_is_runnable(
    worker_module, app_config, monkeypatch, tmp_path
):
    """Every requested tool fails the capability pre-check itself (not
    configured in the sandbox's verifier list at all) - the VM must never
    be booted for a scan with nothing capability-valid left to run. (A tool
    that IS capability-valid but merely lacks admin config, e.g. no
    host_binary_path, is a different, legitimate case: the adapter itself
    decides "unsupported" - see the happy-path test above, where PERDEDOR
    takes exactly that path after a real guest session was already
    created.)"""
    _patch_load_config(monkeypatch, app_config)

    run_vm_called = []
    fake_run_tools = sys.modules["drakrun.analyzer.run_tools"]
    original_run_vm = fake_run_tools.run_vm

    def tracking_run_vm(*args, **kwargs):
        run_vm_called.append(True)
        return original_run_vm(*args, **kwargs)

    monkeypatch.setattr(fake_run_tools, "run_vm", tracking_run_vm)

    job = FakeJob(job_id="22222222-2222-4222-8222-222222222222")
    monkeypatch.setattr("rq.get_current_job", lambda: job)

    # Not declared in [sandbox.win10].verifiers at all - a genuine
    # capability mismatch, resolved before ever touching a guest.
    options = EvasionScanOptions(
        sandbox_id="win10", tools=["not-a-real-tool"], profile="full"
    )

    worker_module.worker_verify(options)

    assert run_vm_called == []
    scan_dir = tmp_path / job.id
    evasion_json = json.loads((scan_dir / "evasion.json").read_text())
    (result,) = evasion_json["tool_results"]
    assert result["tool"] == "not-a-real-tool"
    assert result["status"] == "unsupported"
    assert evasion_json["score"]["state"] == "incomplete"


def test_worker_verify_converts_unexpected_adapter_exception_to_error_result(
    worker_module, app_config, monkeypatch, tmp_path
):
    """An adapter is documented to never raise, but if one does anyway
    (a genuine bug, or a guest-session surprise), the scan must still
    finish with that tool marked 'error' - never crash the whole scan or
    skip cleanup."""
    host_binary = tmp_path / "al-khaser_x64.exe"
    host_binary.write_bytes(b"fake-pe-binary")
    app_config.evasion.alkhaser.host_binary_path = host_binary
    _patch_load_config(monkeypatch, app_config)

    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda vm_name, injector: FakeGuestSession(),
    )

    def broken_run(self, session, options, scan_dir, deadline):
        raise ValueError("adapter bug")

    monkeypatch.setattr(
        "drakrun.evasion.verifiers.alkhaser.AlKhaserAdapter.run", broken_run
    )

    job = FakeJob(job_id="33333333-3333-4333-8333-333333333333")
    monkeypatch.setattr("rq.get_current_job", lambda: job)

    options = EvasionScanOptions(sandbox_id="win10", tools=["alkhaser"], profile="full")

    worker_module.worker_verify(options)

    scan_dir = tmp_path / job.id
    evasion_json = json.loads((scan_dir / "evasion.json").read_text())
    (alkhaser_result,) = evasion_json["tool_results"]
    assert alkhaser_result["status"] == "error"
    assert "adapter bug" in alkhaser_result["error"]
    assert "cleanup" in job.substatus_history


def test_worker_verify_marks_job_failed_and_still_writes_metadata_on_report_failure(
    worker_module, app_config, monkeypatch, tmp_path
):
    """If report generation itself raises (a genuine infrastructure
    failure), the scan must not be silently reported as finished - the
    exception must propagate (so RQ marks the job FAILED), and
    metadata.json must still reflect status=failed."""
    _patch_load_config(monkeypatch, app_config)

    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda vm_name, injector: FakeGuestSession(),
    )
    monkeypatch.setattr(
        "drakrun.evasion.report.write_evasion_json",
        lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
    )

    job = FakeJob(job_id="44444444-4444-4444-8444-444444444444")
    monkeypatch.setattr("rq.get_current_job", lambda: job)

    options = EvasionScanOptions(sandbox_id="win10", tools=["perdedor"], profile="full")

    with pytest.raises(OSError, match="disk full"):
        worker_module.worker_verify(options)

    scan_dir = tmp_path / job.id
    metadata = json.loads((scan_dir / "metadata.json").read_text())
    assert metadata["status"] == "failed"
    assert "disk full" in metadata["error"]


@pytest.mark.parametrize("failure_stage", [None, "booting", "reporting", "cleanup"])
def test_terminal_artifacts_agree(
    worker_module, app_config, monkeypatch, tmp_path, failure_stage
):
    _patch_load_config(monkeypatch, app_config)
    job = FakeJob()
    monkeypatch.setattr("rq.get_current_job", lambda: job)
    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda *args: FakeGuestSession(),
    )
    if failure_stage == "reporting":

        def fail_report(*args):
            raise RuntimeError("report failed")

        monkeypatch.setattr("drakrun.evasion.report.write_html_report", fail_report)
    elif failure_stage:

        @contextlib.contextmanager
        def fail_vm(*args):
            if failure_stage == "booting":
                raise RuntimeError("boot failed")
            yield FakeVm()
            raise RuntimeError("cleanup failed")

        monkeypatch.setattr(
            sys.modules["drakrun.analyzer.run_tools"], "run_vm", fail_vm
        )

    options = EvasionScanOptions(sandbox_id="win10", tools=["perdedor"])
    if failure_stage:
        with pytest.raises(RuntimeError, match="failed"):
            worker_module.worker_verify(options)
    else:
        worker_module.worker_verify(options)

    metadata = json.loads((tmp_path / job.id / "metadata.json").read_text())
    result = json.loads((tmp_path / job.id / "evasion.json").read_text())
    assert result == metadata
    assert metadata["status"] == ("failed" if failure_stage else "finished")
    assert metadata["substatus"] == (failure_stage or "done")
    assert metadata["time_finished"] == job.meta["time_finished"]


def test_result_is_only_published_after_vm_cleanup(
    worker_module, app_config, monkeypatch, tmp_path
):
    _patch_load_config(monkeypatch, app_config)
    job = FakeJob()
    monkeypatch.setattr("rq.get_current_job", lambda: job)
    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda *args: FakeGuestSession(),
    )

    @contextlib.contextmanager
    def checked_run_vm(*args):
        yield FakeVm()
        assert not (tmp_path / job.id / "evasion.json").exists()

    monkeypatch.setattr(
        sys.modules["drakrun.analyzer.run_tools"], "run_vm", checked_run_vm
    )
    worker_module.worker_verify(
        EvasionScanOptions(sandbox_id="win10", tools=["perdedor"])
    )
    result = json.loads((tmp_path / job.id / "evasion.json").read_text())
    assert result["status"] == "finished"


@pytest.fixture
def instrumented_scan(worker_module, app_config, monkeypatch, tmp_path):
    """Fake the instrumentation boundary and track both guest/process lifetimes."""
    _patch_load_config(monkeypatch, app_config)
    job = FakeJob()
    monkeypatch.setattr("rq.get_current_job", lambda: job)
    events = []
    captured = {}

    class Process:
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            if self.returncode is None:
                raise subprocess.TimeoutExpired("drakvuf", timeout)
            return self.returncode

    process = Process()

    @contextlib.contextmanager
    def run_vm(*args):
        events.append("restore")
        try:
            yield FakeVm()
        finally:
            events.append("destroy")

    def check_call(command):
        events.append(command)

    def finish():
        pytest.fail("drakshell must remain alive during verification")

    session = types.SimpleNamespace(
        drakshell=types.SimpleNamespace(check_call=check_call, finish=finish)
    )

    def connect(*args):
        events.append("connect")
        return session

    monkeypatch.setattr("drakrun.evasion.guest_runner.connect_guest_session", connect)
    app_config.drakrun.no_post_restore = False
    monkeypatch.setattr(
        "drakrun.analyzer.post_restore.get_post_restore_command",
        lambda net_enable: "post-restore",
    )
    fake_run_tools = sys.modules["drakrun.analyzer.run_tools"]
    monkeypatch.setattr(fake_run_tools, "run_vm", run_vm)

    @contextlib.contextmanager
    def run_drakvuf(**kwargs):
        assert session.drakvuf_attached is True
        captured.update(kwargs)
        events.append("drakvuf-start")
        kwargs["output_file"].write_bytes(captured.get("log_bytes", b"{}\n"))
        kwargs["output_err_file"].write_text("")
        if captured.get("start_error"):
            raise OSError("cannot execute drakvuf")
        try:
            yield process
        finally:
            assert session.drakvuf_attached is True
            events.append("drakvuf-stop")
            if process.returncode is None:
                process.returncode = -15
            if captured.get("teardown_error"):
                raise OSError("DRAKVUF teardown failed")

    monkeypatch.setattr(fake_run_tools, "run_drakvuf", run_drakvuf, raising=False)
    fake_analyzer = types.ModuleType("drakrun.analyzer.analyzer")

    def prepare_args(output_dir, options):
        captured["prepared_dir"] = output_dir
        captured["prepared_options"] = options
        return ["-a", "procmon"]

    fake_analyzer.prepare_drakvuf_args = prepare_args
    monkeypatch.setitem(sys.modules, "drakrun.analyzer.analyzer", fake_analyzer)
    version = object()
    monkeypatch.setattr(
        "drakrun.lib.version_detection.get_drakvuf_version", lambda: version
    )

    def adapter(tool_id):
        def phases(self, guest, options, scan_dir, deadline, *, instrumented=False):
            assert guest is session
            assert not getattr(guest, "drakvuf_attached", False)
            events.append(f"stage-{tool_id}")
            if captured.get("stage_error") == tool_id:
                raise ValueError("stage bug")
            if tool_id == "alkhaser" and "clock" in captured:
                captured["clock"]["now"] += 10000
            yield
            assert getattr(guest, "drakvuf_attached", False) is instrumented
            assert process.returncode is None
            guest.drakshell.check_call(f"run-{tool_id}")
            if captured.get("exit_during_tool"):
                process.returncode = 2
            if captured.get("stall_during_tool"):
                captured["stall_monitor"].stalled = True
                captured["stall_monitor"].max_stall_s = 45.0
                process.returncode = -15
            if captured.get("adapter_error"):
                raise ValueError("adapter bug")
            yield
            assert not getattr(guest, "drakvuf_attached", False)
            events.append(f"collect-{tool_id}")
            if captured.get("collect_error") == tool_id:
                raise ValueError("collect bug")
            return ToolResult(
                tool=tool_id,
                status="ok",
                raw_artifacts=[f"raw/{tool_id}/report.json"],
                checks=[
                    NormalizedCheck(
                        id="clean",
                        category="timing",
                        name="clean",
                        description="d",
                        status="clean",
                        severity="low",
                        tool=tool_id,
                    )
                ],
            )

        class Adapter(VerifierAdapter):
            id = tool_id
            options_schema = lambda self: {}
            validate_options = lambda self, opts: {}
            _run_phases = phases

        return Adapter()

    monkeypatch.setattr(
        "drakrun.evasion.verifiers.get_adapters_for_platform",
        lambda platform: [adapter("perdedor"), adapter("alkhaser")],
    )

    def execute(**kwargs):
        worker_module.worker_verify(
            EvasionScanOptions(
                sandbox_id="win10", tools=["perdedor", "alkhaser"], **kwargs
            )
        )
        scan_dir = tmp_path / job.id
        metadata = json.loads((scan_dir / "metadata.json").read_text())
        assert metadata == json.loads((scan_dir / "evasion.json").read_text())
        return metadata

    return types.SimpleNamespace(
        execute=execute,
        events=events,
        captured=captured,
        process=process,
        scan_dir=tmp_path / job.id,
        config=app_config,
        version=version,
        session=session,
    )


@pytest.mark.parametrize("log_bytes", [b"{}\n", b""])
def test_drakvuf_wraps_tool_runs_after_post_restore(instrumented_scan, log_bytes):
    scan = instrumented_scan
    scan.captured["log_bytes"] = log_bytes
    scan.config.drakrun.plugins = ["procmon", "memdump"]
    metadata = scan.execute(with_drakvuf=True)
    assert scan.events == [
        "restore",
        "connect",
        "post-restore",
        "stage-perdedor",
        "stage-alkhaser",
        "drakvuf-start",
        "run-perdedor",
        "run-alkhaser",
        "drakvuf-stop",
        "collect-perdedor",
        "collect-alkhaser",
        "destroy",
    ]
    assert metadata["drakvuf_attached"] is True
    assert metadata["drakvuf_returncode"] == -15
    assert metadata["drakmon_log_nonempty"] is bool(log_bytes)
    assert "drakvuf_error" not in metadata
    assert metadata["score"]["state"] == "pass"
    args = scan.captured
    assert args["vm_name"] == "vm-1"
    assert args["exec_parameters"] is None
    assert args["drakvuf_version_info"] is scan.version
    assert args["output_file"] == scan.scan_dir / "drakvuf" / "drakmon.log"
    assert args["output_err_file"] == scan.scan_dir / "drakvuf" / "drakvuf_stderr.log"
    assert args["drakvuf_cwd"] == args["prepared_dir"] == scan.scan_dir / "drakvuf"
    assert args["drakvuf_args"] == ["-a", "procmon"]
    options = args["prepared_options"]
    assert options.plugins == scan.config.drakrun.plugins
    assert options.host_sample_path is None
    assert options.start_command is None
    assert options.timeout is None
    assert (scan.scan_dir / "drakvuf" / "dumps").is_dir()


@pytest.mark.parametrize("options", [{}, {"with_drakvuf": False}])
def test_drakvuf_disabled_preserves_default_scan(instrumented_scan, options):
    scan = instrumented_scan
    metadata = scan.execute(**options)
    assert scan.events == [
        "restore",
        "connect",
        "post-restore",
        "stage-perdedor",
        "run-perdedor",
        "collect-perdedor",
        "stage-alkhaser",
        "run-alkhaser",
        "collect-alkhaser",
        "destroy",
    ]
    assert scan.captured == {}
    assert not (scan.scan_dir / "drakvuf").exists()
    assert "with_drakvuf" not in metadata["options"]
    assert not any(key.startswith("drakvuf_") for key in metadata)
    assert "drakmon_log_nonempty" not in metadata
    assert metadata["score"]["state"] == "pass"


@pytest.mark.parametrize("startup_failure", ["spawn", "exit", "clean-exit"])
def test_drakvuf_start_failure_prevents_uninstrumented_results(
    instrumented_scan, startup_failure
):
    scan = instrumented_scan
    if startup_failure == "spawn":
        scan.captured["start_error"] = True
    else:
        scan.process.returncode = 0 if startup_failure == "clean-exit" else 1
    metadata = scan.execute(with_drakvuf=True)
    assert metadata["drakvuf_attached"] is False
    assert "failed to start" in metadata["drakvuf_error"]
    assert all(result["status"] == "error" for result in metadata["tool_results"])
    assert all("DRAKVUF" in result["error"] for result in metadata["tool_results"])
    assert metadata["score"]["state"] == "incomplete"
    assert "chimera_score" not in metadata["score"]
    assert not any(event.startswith("run-") for event in scan.events)
    assert scan.events[-1] == "destroy"
    if startup_failure != "spawn":
        assert metadata["drakvuf_returncode"] == scan.process.returncode
        assert scan.events[-2] == "drakvuf-stop"


def test_drakvuf_early_exit_invalidates_results_and_stops_further_tools(
    instrumented_scan,
):
    scan = instrumented_scan
    scan.captured["exit_during_tool"] = True
    metadata = scan.execute(with_drakvuf=True)
    assert metadata["drakvuf_attached"] is False
    assert metadata["drakvuf_returncode"] == 2
    assert "exited before" in metadata["drakvuf_error"]
    assert all(result["status"] == "error" for result in metadata["tool_results"])
    assert metadata["tool_results"][0]["raw_artifacts"] == ["raw/perdedor/report.json"]
    assert metadata["score"]["state"] == "incomplete"
    assert "run-alkhaser" not in scan.events
    assert scan.events[-3:] == ["drakvuf-stop", "collect-perdedor", "destroy"]


def test_guest_stall_under_drakvuf_invalidates_results(instrumented_scan):
    scan = instrumented_scan
    scan.captured["stall_during_tool"] = True
    metadata = scan.execute(with_drakvuf=True)
    assert scan.captured["stall_monitor"].vm_name == "vm-1"
    assert metadata["drakvuf_attached"] is False
    assert "stalled under DRAKVUF for 45 s" in metadata["drakvuf_error"]
    assert all(result["status"] == "error" for result in metadata["tool_results"])
    assert metadata["score"]["state"] == "incomplete"


def test_drakvuf_stops_even_when_adapters_raise(instrumented_scan):
    scan = instrumented_scan
    scan.captured["adapter_error"] = True
    metadata = scan.execute(with_drakvuf=True)
    assert metadata["drakvuf_attached"] is True
    assert metadata["drakvuf_returncode"] == -15
    assert all("adapter bug" in result["error"] for result in metadata["tool_results"])
    assert scan.events[-2:] == ["drakvuf-stop", "destroy"]


@pytest.mark.parametrize("phase", ["stage", "collect"])
def test_drakvuf_isolates_phase_failures(instrumented_scan, phase):
    scan = instrumented_scan
    scan.captured[f"{phase}_error"] = "perdedor"
    metadata = scan.execute(with_drakvuf=True)
    first, second = metadata["tool_results"]
    assert first["status"] == "error"
    assert f"{phase} bug" in first["error"]
    assert second["status"] == "ok"
    assert metadata["score"]["state"] == "incomplete"
    assert scan.events.index("drakvuf-stop") < scan.events.index("collect-alkhaser")
    assert scan.events[-1] == "destroy"


def test_drakvuf_does_not_reset_tool_deadlines(instrumented_scan, monkeypatch):
    scan = instrumented_scan
    clock = {"now": 100.0}
    scan.captured["clock"] = clock
    monkeypatch.setattr("time.time", lambda: clock["now"])
    metadata = scan.execute(with_drakvuf=True)
    assert metadata["drakvuf_attached"] is True
    assert all(result["status"] == "timeout" for result in metadata["tool_results"])
    assert not any(event.startswith("run-") for event in scan.events)
    assert metadata["score"]["state"] == "incomplete"
    assert scan.events[-2:] == ["drakvuf-stop", "destroy"]


def test_drakvuf_teardown_failure_never_collects(instrumented_scan):
    scan = instrumented_scan
    scan.captured["teardown_error"] = True
    with pytest.raises(OSError, match="teardown failed"):
        scan.execute(with_drakvuf=True)
    assert scan.session.drakvuf_attached is True
    assert not any(event.startswith("collect-") for event in scan.events)
    assert scan.events[-1] == "destroy"
    metadata = json.loads((scan.scan_dir / "metadata.json").read_text())
    assert metadata["status"] == "failed"
    assert "teardown failed" in metadata["error"]


@pytest.mark.parametrize("fail_run", [False, True])
@pytest.mark.parametrize("with_perdedor", [False, True])
def test_linux_worker_restores_linux_golden_and_closes_agent(
    worker_module, config_factory, monkeypatch, tmp_path, fail_run, with_perdedor
):
    from types import SimpleNamespace

    from test_linux_evasion import raw_report
    from test_perdedor_linux import REPO, REPORT, GUEST_REPORT

    tools = ["perdedor", "chimera-vmcheck"] if with_perdedor else ["chimera-vmcheck"]

    config = config_factory("""
[sandbox.linux-test]
platform = "linux"
verifiers = ["chimera-vmcheck"]
""")
    config.sandbox["linux-test"].verifiers = tools
    config.evasion.perdedor.repo_path = REPO
    config.drakrun.no_post_restore = True
    _patch_load_config(monkeypatch, config)
    install_paths, closed, calls = [], [], []
    install = SimpleNamespace(snapshot_dir=tmp_path / "golden")

    def load_install(path):
        install_paths.append(path)
        return install

    monkeypatch.setattr("drakrun.lib.install_info.InstallInfo.load", load_install)
    monkeypatch.setattr(
        "drakrun.lib.libvmi.VmiInfo.load",
        lambda *a: pytest.fail("Windows VMI must not be loaded"),
    )
    session = FakeGuestSession(
        files={
            "/var/lib/console-helper/linux-report.json": json.dumps(raw_report()).encode()
        },
        raise_on_run=RuntimeError("agent failed") if fail_run else None,
    )
    session.files[GUEST_REPORT] = REPORT.read_bytes()
    session.agent = SimpleNamespace(call=lambda *a, **kw: calls.append((a, kw)))
    session.close = lambda: closed.append(True)
    monkeypatch.setattr(
        "drakrun.evasion.linux_guest_runner.connect_linux_guest_session",
        lambda vm, kernel: session,
    )
    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda *a: pytest.fail("Windows session must not be opened"),
    )
    job = FakeJob()
    monkeypatch.setattr("rq.get_current_job", lambda: job)
    worker_module.worker_verify(
        EvasionScanOptions(sandbox_id="linux-test", guest_os="linux", tools=tools)
    )
    report = json.loads((tmp_path / job.id / "evasion.json").read_text())
    assert str(install_paths[0]) == "/var/lib/drakrun/linux/golden/install.json"
    assert closed == [True]
    assert calls[0][0][0] == "net"
    assert report["options"]["guest_os"] == "linux"
    assert report["tool_results"][0]["status"] == ("error" if fail_run else "ok")
    assert report["score"]["state"] == (
        "incomplete" if fail_run else "pass" if with_perdedor else "fail"
    )
    assert report["score"]["primary_tool"] == tools[0]
    assert [r["tool"] for r in report["tool_results"]] == tools
    assert "chimera-vmcheck" in (tmp_path / job.id / "report.html").read_text()


def test_worker_accepts_pre_guest_os_pickled_options(
    worker_module, app_config, monkeypatch, tmp_path
):
    _patch_load_config(monkeypatch, app_config)
    session = FakeGuestSession()
    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session", lambda *a: session
    )
    job = FakeJob()
    monkeypatch.setattr("rq.get_current_job", lambda: job)
    options = EvasionScanOptions(sandbox_id="win10", tools=["perdedor"])
    del options.__dict__["guest_os"]  # Shape of an old RQ-pickled instance.
    worker_module.worker_verify(options)
    report = json.loads((tmp_path / job.id / "evasion.json").read_text())
    assert report["sandbox"]["platform"] == "windows"
    assert "guest_os" not in report["options"]
