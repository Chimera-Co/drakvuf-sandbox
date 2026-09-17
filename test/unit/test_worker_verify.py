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
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402

from drakrun.evasion.models import EvasionScanOptions  # noqa: E402

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

    assert len(fake_session.put_file_calls) == 1
    assert len(fake_session.run_calls) == 1

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
