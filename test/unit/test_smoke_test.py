"""Xen-free tests for drakrun.evasion.smoke_test.run_guest_smoke_test and
the drakrun.cli.evasion_smoke_test CLI command.

Mirrors test_worker_verify.py's approach exactly: drakrun.analyzer.run_tools
is faked via sys.modules injection (its real import chain reaches Xen
bindings not installed here), connect_guest_session is monkeypatched to
return the existing FakeGuestSession test double, and InstallInfo/VmiInfo
loading is stubbed out. This proves the smoke test's own wiring - not a
real guest, which is a Debian/Xen concern covered by Phase G's manual
execution, not by this suite.
"""

import contextlib
import sys
import types

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from fake_guest_session import FakeGuestSession  # noqa: E402


class FakeVm:
    vm_name = "vm-2"


class FakeRedisConfig:
    host = "localhost"
    port = 6379
    username = None
    password = None


class FakeNetworkSection:
    out_interface = "default"
    dns_server = "use-gateway-address"
    net_enable = True


class FakeConfig:
    redis = FakeRedisConfig()
    network = FakeNetworkSection()


@pytest.fixture
def smoke_test_module(monkeypatch):
    """Import drakrun.evasion.smoke_test with every Xen-only dependency it
    would otherwise need faked out - same pattern test_worker_verify.py
    already uses for drakrun.evasion.worker."""
    import drakrun.evasion.smoke_test as smoke_test

    fake_run_tools = types.ModuleType("drakrun.analyzer.run_tools")

    @contextlib.contextmanager
    def fake_run_vm(vm_id, install_info, network_conf, no_restore=False):
        yield FakeVm()

    fake_run_tools.run_vm = fake_run_vm
    monkeypatch.setitem(sys.modules, "drakrun.analyzer.run_tools", fake_run_tools)

    monkeypatch.setattr("drakrun.lib.config.load_config", lambda: FakeConfig())
    monkeypatch.setattr(
        "drakrun.lib.install_info.InstallInfo.load",
        staticmethod(lambda path: object()),
    )
    monkeypatch.setattr(
        "drakrun.lib.libvmi.VmiInfo.load", staticmethod(lambda path: object())
    )

    return smoke_test


def _patch_guest_session(monkeypatch, fake_session):
    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session",
        lambda vm_name, injector: fake_session,
    )


def test_smoke_test_rejects_vm_id_zero(smoke_test_module):
    with pytest.raises(ValueError):
        smoke_test_module.run_guest_smoke_test(0)


def test_smoke_test_success_flow(smoke_test_module, monkeypatch):
    fake_session = FakeGuestSession(probe_result=(True, "MS-DOS 6.22"))
    _patch_guest_session(monkeypatch, fake_session)

    result = smoke_test_module.run_guest_smoke_test(2)

    assert result.vm_id == 2
    assert result.probe_ok is True
    assert result.probe_detail == "MS-DOS 6.22"
    assert result.upload_ok is True
    assert result.retrieval_ok is True
    assert result.bytes_match is True
    assert result.success is True

    # The exact harmless operations were actually performed against the
    # fake session, in the documented order.
    assert fake_session.put_file_calls[0][1] == smoke_test_module.GUEST_REMOTE_PATH
    assert fake_session.get_file_calls[0][0] == smoke_test_module.GUEST_REMOTE_PATH


def test_smoke_test_command_probe_failure(smoke_test_module, monkeypatch):
    fake_session = FakeGuestSession(probe_result=(False, "probe timed out after 30.0s"))
    _patch_guest_session(monkeypatch, fake_session)

    result = smoke_test_module.run_guest_smoke_test(2)

    assert result.probe_ok is False
    assert result.probe_detail == "probe timed out after 30.0s"
    # Upload/retrieval still proceed independently of the probe result.
    assert result.upload_ok is True
    assert result.retrieval_ok is True
    assert result.bytes_match is True
    assert result.success is False


def test_smoke_test_upload_failure(smoke_test_module, monkeypatch):
    fake_session = FakeGuestSession()

    def failing_put_file(local_path, remote_path):
        raise RuntimeError("injector writefile failed (exit 1)")

    fake_session.put_file = failing_put_file
    _patch_guest_session(monkeypatch, fake_session)

    result = smoke_test_module.run_guest_smoke_test(2)

    assert result.upload_ok is False
    assert "injector writefile failed" in result.upload_error
    assert result.retrieval_ok is False
    assert result.bytes_match is False
    assert result.success is False


def test_smoke_test_retrieval_failure(smoke_test_module, monkeypatch):
    fake_session = FakeGuestSession()

    def failing_get_file(remote_path, local_path):
        raise RuntimeError("injector readfile failed (exit 1)")

    fake_session.get_file = failing_get_file
    _patch_guest_session(monkeypatch, fake_session)

    result = smoke_test_module.run_guest_smoke_test(2)

    assert result.upload_ok is True
    assert result.retrieval_ok is False
    assert "injector readfile failed" in result.retrieval_error
    assert result.bytes_match is False
    assert result.success is False


def test_smoke_test_byte_mismatch(smoke_test_module, monkeypatch):
    fake_session = FakeGuestSession()
    real_put_file = fake_session.put_file

    def corrupting_put_file(local_path, remote_path):
        # Simulate the guest returning different bytes than were uploaded.
        real_put_file(local_path, remote_path)
        fake_session.files[remote_path] = b"CORRUPTED-BYTES"

    fake_session.put_file = corrupting_put_file
    _patch_guest_session(monkeypatch, fake_session)

    result = smoke_test_module.run_guest_smoke_test(2)

    assert result.upload_ok is True
    assert result.retrieval_ok is True
    assert result.bytes_match is False
    assert result.success is False


def test_smoke_test_exception_propagates_through_run_vm_cleanup(
    smoke_test_module, monkeypatch
):
    """If something unexpected inside the run_vm block raises (here:
    connect_guest_session itself), run_vm's own context manager must still
    run its cleanup, and the exception must still propagate out of
    run_guest_smoke_test rather than being swallowed as a diagnostic
    result."""
    destroyed = []

    @contextlib.contextmanager
    def fake_run_vm_with_cleanup_tracking(
        vm_id, install_info, network_conf, no_restore=False
    ):
        try:
            yield FakeVm()
        finally:
            destroyed.append(vm_id)

    fake_run_tools = types.ModuleType("drakrun.analyzer.run_tools")
    fake_run_tools.run_vm = fake_run_vm_with_cleanup_tracking
    monkeypatch.setitem(sys.modules, "drakrun.analyzer.run_tools", fake_run_tools)

    def raising_connect(vm_name, injector):
        raise RuntimeError("drakshell connection refused")

    monkeypatch.setattr(
        "drakrun.evasion.guest_runner.connect_guest_session", raising_connect
    )

    with pytest.raises(RuntimeError, match="drakshell connection refused"):
        smoke_test_module.run_guest_smoke_test(2)

    assert destroyed == [2]


def test_cli_evasion_smoke_test_help():
    from click.testing import CliRunner

    from drakrun.cli.evasion_smoke_test import evasion_smoke_test

    runner = CliRunner()
    result = runner.invoke(evasion_smoke_test, ["--help"])

    assert result.exit_code == 0
    assert "--vm-id" in result.output


def test_cli_main_registers_evasion_smoke_test():
    from click.testing import CliRunner

    from drakrun.cli.main import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "evasion-smoke-test" in result.output
