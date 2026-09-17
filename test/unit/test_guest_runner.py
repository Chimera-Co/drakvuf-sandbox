"""Tests for drakrun.evasion.guest_runner.GuestSession.

These exercise the real GuestSession class against hand-built fake
Drakshell/Injector doubles - NOT drakrun.lib.drakshell.Drakshell or
drakrun.lib.injector.Injector themselves, since GuestSession only ever calls
a handful of documented methods on each (run_interactive/check_call on
Drakshell; write_file/read_file on Injector) and driving the real classes
would require an actual Xen guest. This is exactly the same duck-typing
approach test/unit/fake_guest_session.py already uses one layer up (faking
the whole GuestSession Protocol for adapter tests) - here we fake one layer
lower, the two primitives GuestSession itself is built on.

None of this requires Xen: it validates GuestSession's own logic (the
watchdog-based timeout - Drakshell.join() has no built-in timeout - the cwd
wrapping, and the Injector.read_file/write_file return-code hardening this
phase specifically calls for). Real end-to-end guest execution against an
actual restored VM is a Debian/Xen integration concern, out of scope here -
see docs/usage/... (Windows-development limitations).
"""

import pathlib
import subprocess
import threading

import pytest

from drakrun.evasion.guest_runner import GuestSession
from drakrun.evasion.verifiers.base import VerifierTimeout


class FakeProcess:
    """Stands in for drakrun.lib.drakshell.DrakshellInteractiveProcess -
    only join()/terminate(), which is all GuestSession touches."""

    def __init__(self, exit_code=0, hang=False, terminable=True):
        self.exit_code = exit_code
        self.hang = hang
        self.terminable = terminable
        self.terminate_called = False
        self._release = threading.Event()

    def join(self):
        if self.hang:
            released = self._release.wait(timeout=2)
            if not released or not self.terminable:
                # A process that ignores terminate() - bounded here (not a
                # real infinite hang) so the test itself cannot hang.
                self._release.wait(timeout=2)
        return self.exit_code

    def terminate(self):
        self.terminate_called = True
        if self.terminable:
            self._release.set()


class FakeDrakshell:
    """Stands in for drakrun.lib.drakshell.Drakshell - only
    run_interactive()/check_call(), which is all GuestSession touches."""

    def __init__(self, processes, stdout_bytes=b"", stderr_bytes=b""):
        self._processes = list(processes)
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.run_interactive_calls = []

    def run_interactive(self, args, stdin=None, stdout=None, stderr=None):
        self.run_interactive_calls.append(args)
        if stdout is not None:
            stdout.buffer.write(self.stdout_bytes)
        if stderr is not None:
            stderr.buffer.write(self.stderr_bytes)
        return self._processes.pop(0)

    def check_call(self, args):
        process = self.run_interactive(args)
        if process.join() != 0:
            raise RuntimeError("check_call failed")


class FakeInjector:
    """Stands in for drakrun.lib.injector.Injector - only write_file()/
    read_file(), which is all GuestSession touches."""

    def __init__(self):
        self.write_calls = []
        self.read_calls = []
        self.write_returncode = 0
        self.read_returncode = 0
        self.read_stderr = b""
        self.read_content = b"fake guest file content"

    def write_file(self, local_path, remote_path):
        self.write_calls.append((local_path, remote_path))
        return subprocess.CompletedProcess([], self.write_returncode)

    def read_file(self, remote_path, local_path):
        self.read_calls.append((remote_path, local_path))
        if self.read_returncode == 0:
            pathlib.Path(local_path).write_bytes(self.read_content)
        return subprocess.CompletedProcess(
            [], self.read_returncode, stderr=self.read_stderr
        )


def _fast_grace_period(monkeypatch):
    import drakrun.evasion.guest_runner as guest_runner_module

    monkeypatch.setattr(guest_runner_module, "_TERMINATE_GRACE_SECONDS", 0.3)


def test_run_returns_exit_code_and_captured_output():
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0)], stdout_bytes=b"ok", stderr_bytes=b""
    )
    session = GuestSession(FakeInjector(), drakshell)

    exit_code, stdout, stderr = session.run(["whoami"], timeout=5)

    assert exit_code == 0
    assert stdout == b"ok"
    assert stderr == b""


def test_run_wraps_argv_with_cwd():
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    session = GuestSession(FakeInjector(), drakshell)

    session.run(["cmd", "/c", "dir"], timeout=5, cwd=r"C:\Users\Public\tool")

    (called_argv,) = drakshell.run_interactive_calls
    assert called_argv[0] == "cmd"
    assert called_argv[1] == "/c"
    assert r'cd /d "C:\Users\Public\tool"' in called_argv[2]
    assert "dir" in called_argv[2]


def test_run_times_out_and_terminates_cleanly_leaves_session_usable(monkeypatch):
    _fast_grace_period(monkeypatch)
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0, hang=True, terminable=True), FakeProcess(exit_code=0)]
    )
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(VerifierTimeout):
        session.run(["cmd", "/c", "sleep-forever"], timeout=0.1)

    # A clean termination does not poison the session - the next command
    # must still be usable.
    exit_code, _stdout, _stderr = session.run(["cmd", "/c", "echo ok"], timeout=5)
    assert exit_code == 0


def test_run_times_out_and_cannot_terminate_breaks_the_session(monkeypatch):
    _fast_grace_period(monkeypatch)
    drakshell = FakeDrakshell([FakeProcess(exit_code=0, hang=True, terminable=False)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(VerifierTimeout):
        session.run(["cmd", "/c", "sleep-forever"], timeout=0.1)

    # The channel could be desynced by the still-running command - every
    # subsequent call must fail fast and clearly, never silently proceed.
    with pytest.raises(RuntimeError, match="no longer usable"):
        session.run(["cmd", "/c", "echo ok"], timeout=5)
    with pytest.raises(RuntimeError, match="no longer usable"):
        session.put_file(pathlib.Path(__file__), r"C:\x")
    available, detail = session.probe_command(["pwsh"], timeout=1)
    assert available is False
    assert "unavailable" in detail


def test_probe_command_never_raises_on_nonzero_exit():
    drakshell = FakeDrakshell([FakeProcess(exit_code=1)], stderr_bytes=b"not found")
    session = GuestSession(FakeInjector(), drakshell)

    available, detail = session.probe_command(["pwsh"], timeout=5)

    assert available is False
    assert "not found" in detail


def test_probe_command_reports_available_on_success():
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)], stdout_bytes=b"7.4.1")
    session = GuestSession(FakeInjector(), drakshell)

    available, detail = session.probe_command(["pwsh"], timeout=5)

    assert available is True
    assert "7.4.1" in detail


def test_put_file_raises_on_nonzero_returncode():
    injector = FakeInjector()
    injector.write_returncode = 1
    session = GuestSession(injector, FakeDrakshell([]))

    with pytest.raises(RuntimeError, match="injector writefile failed"):
        session.put_file(pathlib.Path(__file__), r"C:\x\file.exe")


def test_get_file_raises_on_nonzero_returncode_instead_of_silently_succeeding(
    tmp_path,
):
    """Regression test for Injector.read_file's own gap: it does not pass
    check=True, so a failed guest-side read otherwise returns silently.
    GuestSession.get_file must not let that surface as a clean success."""
    injector = FakeInjector()
    injector.read_returncode = 1
    injector.read_stderr = b"file not found on guest"
    session = GuestSession(injector, FakeDrakshell([]))

    local_path = tmp_path / "out.txt"
    with pytest.raises(RuntimeError, match="injector readfile failed"):
        session.get_file(r"C:\missing.txt", local_path)


def test_get_file_writes_local_content_on_success(tmp_path):
    injector = FakeInjector()
    injector.read_content = b"real content"
    session = GuestSession(injector, FakeDrakshell([]))

    local_path = tmp_path / "nested" / "out.txt"
    session.get_file(r"C:\report.json", local_path)

    assert local_path.read_bytes() == b"real content"
