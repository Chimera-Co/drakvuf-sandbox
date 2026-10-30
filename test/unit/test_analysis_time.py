import io
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from drakrun.analyzer import run_tools
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.analyzer import prepare_drakvuf_args
from drakrun.lib import analysis_time
from drakrun.lib import memory_admission as admission
from drakrun.lib.config import AnalysisTimeConfigSection

from .test_analysis_modes import upload  # noqa: F401  (fixture)

SETTINGS = AnalysisTimeConfigSection(clock_scale_enabled=True)


@pytest.fixture(autouse=True)
def plenty_of_disk(monkeypatch):
    # Upload tests check the host's analyses directory; never depend on this machine's disk.
    monkeypatch.setattr(
        analysis_time.shutil, "disk_usage", lambda _: SimpleNamespace(free=10**15)
    )


@pytest.mark.parametrize(
    "timeout, scale, ok",
    [
        (300, 1, True),
        (86400, 1, True),
        (86401, 1, False),
        (0, 1, False),
        (600, 60, True),
        (600, 61, False),
        (600, 0, False),
    ],
)
def test_validate_time_options(timeout, scale, ok):
    assert (analysis_time.validate_time_options(timeout, scale, SETTINGS) is None) is ok


def test_clock_scale_is_refused_unless_enabled():
    settings = AnalysisTimeConfigSection()
    assert settings.clock_scale_enabled is False
    assert "not available" in analysis_time.validate_time_options(600, 12, settings)
    assert analysis_time.validate_time_options(600, 1, settings) is None


def test_free_disk_needs_base_plus_rate(monkeypatch, tmp_path):
    gib = 1024**3
    monkeypatch.setattr(
        analysis_time.shutil, "disk_usage", lambda _: SimpleNamespace(free=100 * gib)
    )
    # 20 GB + 8 GB/h: 10 h needs 100 GB, 10 h and a bit more does not fit
    assert analysis_time.check_free_disk(tmp_path, 36000, SETTINGS) is None
    problem = analysis_time.check_free_disk(tmp_path, 36000 + 3600, SETTINGS)
    assert "100.0 GB free, 108.0 GB needed" in problem


def test_free_disk_of_a_directory_not_created_yet(tmp_path):
    assert analysis_time.check_free_disk(tmp_path / "a" / "b", 60, SETTINGS) is None


def test_summarize_delay_shortening(tmp_path):
    lines = [
        {
            "Plugin": "delaymon",
            "ProcessName": "a.exe",
            "DelayIntervalMs": -3600000.0,
            "Shortened": "yes",
            "ShortenedToMs": 1000,
            "SkippedTotalMs": 3599000,
        },
        {"Plugin": "delaymon", "ProcessName": "a.exe", "DelayIntervalMs": -500.0},
        {
            "Plugin": "delaymon",
            "ProcessName": "b.exe",
            "DelayIntervalMs": -60000.0,
            "Shortened": "failed",
            "ShortenedToMs": 1000,
            "SkippedTotalMs": 3599000,
        },
    ]
    (tmp_path / "delaymon.log").write_text(
        "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"
    )
    assert analysis_time.summarize_delay_shortening(tmp_path) == {
        "delays_shortened": 1,
        "delays_not_shortened": 1,
        "delay_skipped_ms": 3599000,
        "delay_shortened_processes": ["a.exe"],
    }


def test_summarize_without_delaymon_log(tmp_path):
    assert analysis_time.summarize_delay_shortening(tmp_path)["delays_shortened"] == 0


def test_apply_clock_scale_runs_helper_with_domid(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "xl":
            return SimpleNamespace(returncode=0, stdout="7\n", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout='{"domid": 7, "factor": 12, "gtsc_khz_before": 2304000, '
            '"gtsc_khz_after": 27648000, "tsc_mode": 0}\n',
            stderr="",
        )

    monkeypatch.setattr(analysis_time.subprocess, "run", run)
    report = analysis_time.apply_clock_scale("vm-1", 12, SETTINGS)
    assert calls == [
        ["xl", "domid", "vm-1"],
        ["/usr/local/sbin/chimera-clock-scale", "7", "12"],
    ]
    assert report["gtsc_khz_after"] == 27648000


def test_apply_clock_scale_failure_raises(monkeypatch):
    def run(argv, **kwargs):
        if argv[0] == "xl":
            return SimpleNamespace(returncode=0, stdout="7\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="domain 7 is not paused")

    monkeypatch.setattr(analysis_time.subprocess, "run", run)
    with pytest.raises(analysis_time.ClockScaleError, match="not paused"):
        analysis_time.apply_clock_scale("vm-1", 12, SETTINGS)


def test_apply_clock_scale_without_domain(monkeypatch):
    def run(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(analysis_time.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        analysis_time.apply_clock_scale("vm-1", 12, SETTINGS)


def _options(**kwargs):
    return AnalysisOptions(plugins=["procmon"], net_enable=False, timeout=60, **kwargs)


def test_sleep_skip_adds_delaymon_and_its_arguments(tmp_path, monkeypatch, base_config):
    monkeypatch.setattr("drakrun.analyzer.analyzer.load_config", lambda: base_config)
    options = _options(sleep_skip=True)
    args = prepare_drakvuf_args(tmp_path, options)
    assert args[args.index("--delaymon-skip-above") + 1] == "10000"
    assert args[args.index("--delaymon-skip-to") + 1] == "1000"
    assert ["-a", "procmon", "-a", "delaymon"] == args[:4]
    # the analysis' own plugin list (telemetry expects its logs) is unchanged
    assert options.plugins == ["procmon"]


def test_no_sleep_skip_leaves_arguments_alone(tmp_path):
    args = prepare_drakvuf_args(tmp_path, _options())
    assert "delaymon" not in args
    assert "--delaymon-skip-above" not in args


def test_options_default_to_no_acceleration():
    options = _options()
    assert options.clock_scale == 1 and options.sleep_skip is False


@pytest.fixture
def fake_vm(monkeypatch, tmp_path, base_config):
    order = []
    vm = SimpleNamespace(
        restore=Mock(side_effect=lambda **kw: order.append(("restore", kw))),
        destroy=Mock(side_effect=lambda: order.append(("destroy", {}))),
        is_running=False,
        vm_name="vm-1",
    )
    monkeypatch.setattr(run_tools, "VirtualMachine", lambda *args: vm)
    monkeypatch.setattr(run_tools, "RUN_DIR", tmp_path)
    monkeypatch.setattr(run_tools, "load_config", lambda: base_config)
    monkeypatch.setattr(admission, "xen_free_memory_mb", lambda: 99999)
    monkeypatch.setattr(
        run_tools, "xen_unpause_vm", lambda name: order.append(("unpause", name))
    )
    return vm, order


def test_run_vm_calls_while_paused_between_restore_and_unpause(fake_vm):
    vm, order = fake_vm
    with run_tools.run_vm(
        1,
        SimpleNamespace(memory=5120),
        None,
        while_paused=lambda v: order.append(("scale", v.vm_name)),
    ):
        order.append(("analysis", None))
    assert order == [
        ("restore", {"pause": True}),
        ("scale", "vm-1"),
        ("unpause", "vm-1"),
        ("analysis", None),
        ("destroy", {}),
    ]


def test_run_vm_while_paused_failure_destroys_vm(fake_vm):
    vm, order = fake_vm

    def fail(_):
        raise analysis_time.ClockScaleError("no")

    with pytest.raises(analysis_time.ClockScaleError):
        with run_tools.run_vm(1, SimpleNamespace(memory=5120), None, while_paused=fail):
            pytest.fail("must not run the analysis")
    assert ("unpause", "vm-1") not in order
    assert order[-1] == ("destroy", {})


def test_run_vm_without_while_paused_restores_running(fake_vm):
    vm, order = fake_vm
    with run_tools.run_vm(1, SimpleNamespace(memory=5120), None):
        pass
    assert order == [("restore", {}), ("destroy", {})]


def _post(client, **data):
    return client.post(
        "/api/upload",
        data={
            "file": (io.BytesIO(b"fixture"), "x.exe"),
            "mode": "dynamic-only",
            **data,
        },
    )


def test_upload_passes_time_options(upload):  # noqa: F811
    client, api, dynamic, static, queue = upload
    api.config.analysis_time.clock_scale_enabled = True
    response = _post(client, timeout="36000", clock_scale="12", sleep_skip="true")
    assert response.status_code == 200, response.json
    options = dynamic.call_args.kwargs["options"]
    assert (options.timeout, options.clock_scale, options.sleep_skip) == (
        36000,
        12,
        True,
    )
    # 600 s leeway plus 10 minutes per hour of run time for postprocessing
    assert options.job_timeout_leeway == 600 + 6000


def test_upload_without_time_options_is_unaccelerated(upload):  # noqa: F811
    client, api, dynamic, static, queue = upload
    response = _post(client, timeout="600")
    assert response.status_code == 200, response.json
    options = dynamic.call_args.kwargs["options"]
    assert (options.clock_scale, options.sleep_skip) == (1, False)


def test_upload_refuses_clock_scale_when_disabled(upload):  # noqa: F811
    client, api, dynamic, static, queue = upload
    response = _post(client, timeout="300", clock_scale="12")
    assert response.status_code == 400
    assert "not available" in response.json["error"]
    dynamic.assert_not_called()


def test_analysis_time_settings_endpoint(upload):  # noqa: F811
    client, api, dynamic, static, queue = upload
    response = client.get("/api/analysis-time")
    assert response.status_code == 200
    assert response.json == {
        "max_timeout_s": 86400,
        "clock_scale_enabled": False,
        "clock_scale_max": 60,
        "sleep_skip_above_ms": 10000,
        "sleep_skip_to_ms": 1000,
    }


@pytest.mark.parametrize(
    "data, error",
    [
        ({"timeout": "86401"}, "timeout must be between"),
        ({"timeout": "600", "clock_scale": "61"}, "clock_scale must be between"),
        (
            {"timeout": "600", "clock_scale": "12", "guest_os": "linux"},
            "Windows only",
        ),
        ({"timeout": "600", "sleep_skip": "true", "guest_os": "linux"}, "Windows only"),
    ],
)
def test_upload_rejects_bad_time_options(upload, data, error):  # noqa: F811
    client, api, dynamic, static, queue = upload
    api.config.analysis_time.clock_scale_enabled = True
    response = _post(client, **data)
    assert response.status_code == 400
    assert error in response.json["error"]
    dynamic.assert_not_called()
    assert not api.UPLOADS_DIR.exists()


def test_upload_rejects_when_disk_is_short(upload, monkeypatch):  # noqa: F811
    client, api, dynamic, static, queue = upload
    monkeypatch.setattr(
        analysis_time.shutil, "disk_usage", lambda _: SimpleNamespace(free=10 * 1024**3)
    )
    response = _post(client, timeout="600")
    assert response.status_code == 400
    assert "not enough free disk" in response.json["error"]
    dynamic.assert_not_called()


class _FakeProc:
    """Popen stand-in: runs for run_s seconds of fake time unless terminated."""

    args = ["drakvuf"]

    def __init__(self, clock, run_s):
        self.clock, self.end, self.terminated = clock, clock[0] + run_s, False

    def wait(self, timeout=None):
        if self.terminated:
            return 0
        if self.clock[0] + (timeout or 0) >= self.end:
            self.clock[0] = min(self.end, self.clock[0] + (timeout or 0))
            return 0
        self.clock[0] += timeout
        raise subprocess.TimeoutExpired(self.args, timeout)

    def terminate(self):
        self.terminated = True


@pytest.fixture
def fake_clock(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(analysis_time.time, "monotonic", lambda: clock[0])
    return clock


def test_wait_returns_when_drakvuf_ends(fake_clock, tmp_path):
    proc = _FakeProc(fake_clock, 95)
    assert analysis_time.wait_watching_disk(proc, 3630, tmp_path, SETTINGS) is False
    assert not proc.terminated


def test_wait_times_out_like_popen(fake_clock, tmp_path):
    proc = _FakeProc(fake_clock, 10**6)
    with pytest.raises(subprocess.TimeoutExpired):
        analysis_time.wait_watching_disk(proc, 100, tmp_path, SETTINGS)


def test_low_disk_stops_drakvuf(fake_clock, tmp_path, monkeypatch):
    (tmp_path / "drakmon.log").write_bytes(b"x")
    free = iter([100, 100, 19])
    monkeypatch.setattr(analysis_time, "_free_gb", lambda _: next(free))
    proc = _FakeProc(fake_clock, 10**6)
    assert analysis_time.wait_watching_disk(proc, 3630, tmp_path, SETTINGS) is True
    assert proc.terminated
    assert fake_clock[0] == 90  # three 30 s polls


@pytest.mark.parametrize("log_mb, analysed", [(1, True), (3, False)])
def test_capa_skips_dynamic_logs_above_the_limit(tmp_path, monkeypatch, log_mb, analysed):
    from drakrun.analyzer.postprocessing.plugins.capa_plugin import capa_processor
    from drakrun.lib.config import CapaConfigSection

    (tmp_path / "apimon.log").write_bytes(b"x" * (log_mb * 1024 * 1024))
    (tmp_path / "syscall.log").write_bytes(b"")
    monkeypatch.setattr(capa_processor, "check_rules_directory_exist", lambda _: True)
    monkeypatch.setattr(capa_processor, "get_rules", lambda _: [])
    monkeypatch.setattr(capa_processor, "filter_rules", lambda rules, **_: rules)
    monkeypatch.setattr(capa_processor, "construct_ttp_blocks", lambda *_, **__: [])
    dynamic = Mock(return_value={})
    monkeypatch.setattr(capa_processor, "dynamic_capa_analysis", dynamic)
    context = SimpleNamespace(
        analysis_dir=tmp_path,
        config=SimpleNamespace(capa=CapaConfigSection(max_dynamic_log_mb=2)),
    )

    capa_processor.capa_analysis(context)

    assert dynamic.called is analysed
    assert (tmp_path / "ttps.json").exists() is analysed
