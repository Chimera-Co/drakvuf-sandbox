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

import base64
import pathlib
import subprocess
import threading

import mslex
import pytest

from drakrun.evasion.guest_runner import (
    DRAKSHELL_MAX_CMDLINE_BYTES,
    GuestCommandTooLong,
    GuestSession,
    InjectorReadError,
    encoded_cmdline_size,
    parse_injector_error_json,
)
from drakrun.evasion.verifiers.base import VerifierTimeout
from drakrun.lib.drakshell import ProcessStartError


def _decode_ps_command(argv):
    """Undo drakrun.analyzer.post_restore.prepare_ps_command's -EncodedCommand
    base64/UTF-16LE encoding, so tests can assert on the plaintext script."""
    assert argv[0] == "powershell.exe"
    assert argv[1] == "-EncodedCommand"
    return base64.b64decode(argv[2]).decode("utf-16le")


class FakeProcess:
    """Stands in for drakrun.lib.drakshell.DrakshellInteractiveProcess.

    GuestSession._run_with_timeout no longer calls this class's join() -
    doing so from a watchdog thread is exactly the bug being regression-
    tested here (join() calls signal.signal(), which is main-thread-only).
    Instead it joins ._thread directly and reads ._exit_code/._fatal_error,
    the same private attributes the real class exposes, so this fake models
    those instead of a callable join(). join() itself is kept but rigged to
    raise the real bug's exact error, proving GuestSession never calls it
    (see test_run_never_calls_process_join_directly)."""

    def __init__(self, exit_code=0, hang=False, terminable=True, fatal_error=None):
        self.exit_code = exit_code
        self.hang = hang
        self.terminable = terminable
        self.fatal_error = fatal_error
        self.terminate_called = False
        self._release = threading.Event()
        self._exit_code = None
        self._fatal_error = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        if self.hang:
            released = self._release.wait(timeout=2)
            if not released or not self.terminable:
                # A process that ignores terminate() - bounded here (not a
                # real infinite hang) so the test itself cannot hang.
                return
        if self.fatal_error is not None:
            self._fatal_error = self.fatal_error
        else:
            self._exit_code = self.exit_code

    def join(self):
        # The real DrakshellInteractiveProcess.join() calls signal.signal(),
        # which raises this exact error when called off the main thread.
        # GuestSession must never call this method at all any more.
        raise ValueError("signal only works in main thread of the main interpreter")

    def terminate(self):
        self.terminate_called = True
        if self.terminable:
            self._release.set()


class FakeDrakshell:
    """Stands in for drakrun.lib.drakshell.Drakshell - only
    run_interactive()/check_call(), which is all GuestSession touches."""

    def __init__(
        self,
        processes,
        stdout_bytes=b"",
        stderr_bytes=b"",
        raise_on_run_interactive=None,
    ):
        self._processes = list(processes)
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        # A queue of exceptions (or None) to raise instead of starting a
        # process, consumed one entry per run_interactive() call, in lock
        # step with _processes below - models Drakshell._start_process()
        # raising before any DrakshellInteractiveProcess is ever created
        # (e.g. a RESP_PROCESS_ERROR reply for a missing executable).
        self._raise_on_run_interactive = list(raise_on_run_interactive or [])
        self.run_interactive_calls = []

    def run_interactive(self, args, stdin=None, stdout=None, stderr=None):
        self.run_interactive_calls.append(args)
        if self._raise_on_run_interactive:
            exc = self._raise_on_run_interactive.pop(0)
            if exc is not None:
                raise exc
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
        self.read_stdout = b""
        self.read_content = b"fake guest file content"

    def write_file(self, local_path, remote_path):
        self.write_calls.append((local_path, remote_path))
        return subprocess.CompletedProcess([], self.write_returncode)

    def read_file(self, remote_path, local_path):
        self.read_calls.append((remote_path, local_path))
        if self.read_returncode == 0:
            pathlib.Path(local_path).write_bytes(self.read_content)
        return subprocess.CompletedProcess(
            [], self.read_returncode, stdout=self.read_stdout, stderr=self.read_stderr
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
    """When cwd is supplied, the final command sent to Drakshell must be a
    plain str (not a List[str]) - Drakshell._start_process() only applies
    mslex.join(for_cmd=False) to a list/tuple, and forwards a str straight
    to the wire untouched. Re-serializing an already cmd/c-wrapped or
    plain-argv command through mslex a second time is exactly the confirmed
    double-quoting bug this fix removes."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    session = GuestSession(FakeInjector(), drakshell)

    session.run(["cmd", "/c", "dir"], timeout=5, cwd=r"C:\Users\Public\tool")

    (called_command,) = drakshell.run_interactive_calls
    assert isinstance(called_command, str)
    assert called_command == r'cmd /c cd /d "C:\Users\Public\tool" && dir'


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
    # One queued process for put_file's own mkdir step (succeeds), so the
    # injector failure below is what actually raises.
    session = GuestSession(injector, FakeDrakshell([FakeProcess(exit_code=0)]))

    with pytest.raises(RuntimeError, match="injector writefile failed"):
        session.put_file(pathlib.Path(__file__), r"C:\x\file.exe")


def test_put_file_creates_missing_parent_dir_via_new_item(tmp_path):
    """Regression test for the confirmed injector writefile gap: CreateFileW
    with CREATE_NEW never creates missing parent directories (verified
    against /opt/drakvuf's real win_write_file.c/win_functions.c), so
    put_file() must run a guest-side mkdir equivalent before invoking
    injector writefile - covers a destination whose immediate parent does
    not yet exist."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_path = tmp_path / "al-khaser_x64.exe"
    local_path.write_bytes(b"fake-binary")

    session.put_file(local_path, r"C:\Users\Public\alkhaser\al-khaser_x64.exe")

    (mkdir_argv,) = drakshell.run_interactive_calls
    script = _decode_ps_command(mkdir_argv)
    assert "New-Item" in script
    assert r"C:\Users\Public\alkhaser" in script
    assert injector.write_calls == [
        (str(local_path), r"C:\Users\Public\alkhaser\al-khaser_x64.exe")
    ]


def test_put_file_succeeds_when_parent_dir_already_exists(tmp_path):
    """New-Item -Force is idempotent by design - a destination whose parent
    already exists on the guest (e.g. C:\\Windows\\Temp, used by the smoke
    test) must still succeed via the same single mkdir-then-write path, not
    take a different branch that could skip or mishandle an existing dir."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_path = tmp_path / "chimera_smoke_test.txt"
    local_path.write_bytes(b"CHIMERA-PHASE-G-SMOKE-TEST\n")

    session.put_file(local_path, r"C:\Windows\Temp\chimera_smoke_test.txt")

    (mkdir_argv,) = drakshell.run_interactive_calls
    assert r"C:\Windows\Temp" in _decode_ps_command(mkdir_argv)
    assert injector.write_calls == [
        (str(local_path), r"C:\Windows\Temp\chimera_smoke_test.txt")
    ]


def test_put_file_creates_missing_nested_parent_dir(tmp_path):
    """Same guarantee for a multi-level missing path (not just one missing
    directory) - New-Item -Force creates every missing intermediate level in
    a single guest round trip, so exactly one mkdir command is issued."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_path = tmp_path / "payload.bin"
    local_path.write_bytes(b"fake-binary")

    session.put_file(local_path, r"C:\Users\Public\tool\nested\deep\payload.bin")

    assert len(drakshell.run_interactive_calls) == 1
    (mkdir_argv,) = drakshell.run_interactive_calls
    script = _decode_ps_command(mkdir_argv)
    assert "New-Item" in script
    assert r"C:\Users\Public\tool\nested\deep" in script
    assert injector.write_calls == [
        (str(local_path), r"C:\Users\Public\tool\nested\deep\payload.bin")
    ]


def test_put_file_skips_mkdir_for_bare_drive_root(tmp_path):
    """A destination directly at a drive root has no directory to create -
    put_file() must not issue a pointless guest round trip for it."""
    drakshell = FakeDrakshell([])
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_path = tmp_path / "file.txt"
    local_path.write_bytes(b"x")

    session.put_file(local_path, r"C:\file.txt")

    assert drakshell.run_interactive_calls == []
    assert injector.write_calls == [(str(local_path), r"C:\file.txt")]


def test_put_file_mkdir_failure_raises_and_skips_write():
    """If the guest-side mkdir itself fails, put_file() must raise before
    ever attempting injector writefile - never write into a directory that
    was not actually created."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=1)], stderr_bytes=b"Access is denied"
    )
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)

    with pytest.raises(RuntimeError, match="failed to create guest directory"):
        session.put_file(pathlib.Path(__file__), r"C:\Users\Public\alkhaser\a.exe")

    assert injector.write_calls == []


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


# --------------------------------------------------------------------------
# Surfacing DRAKVUF's own injection error code.
#
# print_injection_info() in /opt/drakvuf/src/libinjector/injector_utils.c
# (case INJECT_RESULT_ERROR_CODE, OUTPUT_JSON) prints the Win32 failure
# reason for a failed CreateFileW as a single JSON line on STDOUT, and
# drakrun.lib.drakvuf_cmdline already passes `-o json` on every injector
# invocation - so this record has been produced on every failed guest read
# all along. get_file() used to build its error from stderr ONLY, discarding
# it. These tests pin the recovery of that record, and pin that recovering
# it changed nothing for existing callers.
# --------------------------------------------------------------------------

_INJECTOR_ERROR_LINE = (
    '{"Plugin": "inject", "TimeStamp": "1758134613.123456", '
    '"Method": "readfile", "Status": "Error", "ErrorCode": 5, '
    '"Error": "ERROR_ACCESS_DENIED"}'
)


def test_parse_injector_error_json_extracts_error_code_and_name():
    parsed = parse_injector_error_json(_INJECTOR_ERROR_LINE.encode())

    assert parsed is not None
    assert parsed["ErrorCode"] == 5
    assert parsed["Error"] == "ERROR_ACCESS_DENIED"
    assert parsed["Method"] == "readfile"


def test_parse_injector_error_json_ignores_interleaved_non_json_lines():
    """The injector interleaves plain-text lines with its JSON output, so
    every line has to be tried independently rather than assuming the whole
    stream parses."""
    stdout = (
        b"Received VMI event\n"
        b"Couldn't open guest file\n"
        + _INJECTOR_ERROR_LINE.encode()
        + b"\nnot json at all {oops\n"
    )

    parsed = parse_injector_error_json(stdout)

    assert parsed is not None and parsed["ErrorCode"] == 5


def test_parse_injector_error_json_returns_none_for_empty_or_unstructured_output():
    for stdout in (None, b"", b"Couldn't open guest file\n", b'{"Plugin": "inject"}\n'):
        assert parse_injector_error_json(stdout) is None


def test_parse_injector_error_json_takes_the_last_record_when_several_present():
    """More than one injection attempt may be reported; the final one is the
    outcome that actually stands."""
    second = _INJECTOR_ERROR_LINE.replace('"ErrorCode": 5', '"ErrorCode": 32').replace(
        "ERROR_ACCESS_DENIED", "ERROR_SHARING_VIOLATION"
    )
    parsed = parse_injector_error_json(
        (_INJECTOR_ERROR_LINE + "\n" + second + "\n").encode()
    )

    assert parsed["ErrorCode"] == 32
    assert parsed["Error"] == "ERROR_SHARING_VIOLATION"


def test_get_file_error_carries_injector_error_code_from_stdout_json(tmp_path):
    injector = FakeInjector()
    injector.read_returncode = 1
    injector.read_stderr = b"Couldn't open guest file"
    injector.read_stdout = _INJECTOR_ERROR_LINE.encode()
    session = GuestSession(injector, FakeDrakshell([]))

    with pytest.raises(InjectorReadError) as excinfo:
        session.get_file(r"C:\Users\Public\alkhaser\al-khaser_x64.exe", tmp_path / "o")

    exc = excinfo.value
    assert exc.error_code == 5
    assert exc.error_name == "ERROR_ACCESS_DENIED"
    assert exc.injector_json["Method"] == "readfile"
    assert exc.returncode == 1
    # Raw evidence is preserved on the exception, not just the parsed view.
    assert _INJECTOR_ERROR_LINE in exc.stdout
    assert "Couldn't open guest file" in exc.stderr
    # ...and the code is visible in the message a caller would log.
    assert "ErrorCode=5" in str(exc)
    assert "ERROR_ACCESS_DENIED" in str(exc)


def test_get_file_error_with_stderr_only_keeps_its_original_message_shape(tmp_path):
    """No JSON on stdout (older injector output, or a failure raised before
    print_injection_info ran): the error must still be raised, still say
    exactly what it always said, and simply carry no code."""
    injector = FakeInjector()
    injector.read_returncode = 1
    injector.read_stderr = b"file not found on guest"
    injector.read_stdout = b""
    session = GuestSession(injector, FakeDrakshell([]))

    with pytest.raises(InjectorReadError) as excinfo:
        session.get_file(r"C:\missing.txt", tmp_path / "out.txt")

    exc = excinfo.value
    assert exc.error_code is None
    assert exc.error_name is None
    assert exc.injector_json is None
    assert str(exc) == (
        "injector readfile failed (exit 1) for C:\\missing.txt: "
        "file not found on guest"
    )
    assert "ErrorCode" not in str(exc)


def test_get_file_error_tolerates_malformed_non_json_stdout(tmp_path):
    """Garbage on stdout must never make the diagnostic itself throw - the
    underlying read failure is what has to reach the caller."""
    injector = FakeInjector()
    injector.read_returncode = 1
    injector.read_stderr = b"Couldn't open guest file"
    injector.read_stdout = b'{"Plugin": "inject", "ErrorCode": \n\x00\xff garbage {'
    session = GuestSession(injector, FakeDrakshell([]))

    with pytest.raises(InjectorReadError) as excinfo:
        session.get_file(r"C:\x.exe", tmp_path / "out.txt")

    assert excinfo.value.error_code is None
    assert "injector readfile failed" in str(excinfo.value)


def test_injector_read_error_is_a_runtimeerror_for_existing_callers(tmp_path):
    """Backwards compatibility is the whole reason this is a subclass: both
    adapter callers catch broad RuntimeError/Exception around get_file(), and
    test_get_file_raises_on_nonzero_returncode_instead_of_silently_succeeding
    above still matches on the unchanged message prefix."""
    injector = FakeInjector()
    injector.read_returncode = 1
    session = GuestSession(injector, FakeDrakshell([]))

    assert issubclass(InjectorReadError, RuntimeError)
    with pytest.raises(RuntimeError, match="injector readfile failed"):
        session.get_file(r"C:\missing.txt", tmp_path / "out.txt")


def test_get_file_success_path_is_unchanged_by_the_error_plumbing(tmp_path):
    """A successful read must not touch stdout parsing at all."""
    injector = FakeInjector()
    injector.read_content = b"real content"
    injector.read_stdout = _INJECTOR_ERROR_LINE.encode()  # ignored on success
    session = GuestSession(injector, FakeDrakshell([]))

    local_path = tmp_path / "out.txt"
    session.get_file(r"C:\report.json", local_path)

    assert local_path.read_bytes() == b"real content"


def test_get_file_writes_local_content_on_success(tmp_path):
    injector = FakeInjector()
    injector.read_content = b"real content"
    session = GuestSession(injector, FakeDrakshell([]))

    local_path = tmp_path / "nested" / "out.txt"
    session.get_file(r"C:\report.json", local_path)

    assert local_path.read_bytes() == b"real content"


# Regression tests for the "signal only works in main thread of the main
# interpreter" bug (Phase G real-Xen smoke test): GuestSession._run_with_timeout
# used to wrap DrakshellInteractiveProcess.join() in its own watchdog thread,
# and join() calls signal.signal(), which CPython only allows on the main
# thread of the main interpreter. The fix joins the process's own worker
# thread directly instead of ever calling join().


def test_run_never_calls_process_join_directly():
    """FakeProcess.join() is rigged to raise the exact bug being regression-
    tested; a normal, successful command must not trigger it."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0)], stdout_bytes=b"ok", stderr_bytes=b""
    )
    session = GuestSession(FakeInjector(), drakshell)

    exit_code, stdout, stderr = session.run(["cmd", "/c", "ver"], timeout=5)

    assert exit_code == 0
    assert stdout == b"ok"
    assert stderr == b""


def test_run_never_calls_process_join_directly_on_timeout(monkeypatch):
    """The same guarantee must hold on the timeout path too - terminating a
    hung command must not call process.join() either."""
    _fast_grace_period(monkeypatch)
    drakshell = FakeDrakshell([FakeProcess(exit_code=0, hang=True, terminable=True)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(VerifierTimeout):
        session.run(["cmd", "/c", "sleep-forever"], timeout=0.1)


def test_probe_command_success_preserves_stdout_exit_code():
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)], stdout_bytes=b"MS-DOS 6.22")
    session = GuestSession(FakeInjector(), drakshell)

    available, detail = session.probe_command(["cmd", "/c", "ver"], timeout=5)

    assert available is True
    assert detail == "MS-DOS 6.22"


def test_run_preserves_nonzero_exit_code_and_stderr():
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=3)], stdout_bytes=b"", stderr_bytes=b"access denied"
    )
    session = GuestSession(FakeInjector(), drakshell)

    exit_code, stdout, stderr = session.run(["cmd", "/c", "whoami"], timeout=5)

    assert exit_code == 3
    assert stdout == b""
    assert stderr == b"access denied"


def test_run_raises_fatal_error_from_process_and_breaks_session():
    fatal = RuntimeError("Drakshell is out of sync: got 176 during process execution")
    drakshell = FakeDrakshell([FakeProcess(fatal_error=fatal)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(RuntimeError, match="out of sync"):
        session.run(["cmd", "/c", "ver"], timeout=5)

    with pytest.raises(RuntimeError, match="no longer usable"):
        session.run(["cmd", "/c", "ver"], timeout=5)


def test_timeout_marks_session_broken_when_termination_fails_and_rejects_next_call(
    monkeypatch,
):
    _fast_grace_period(monkeypatch)
    drakshell = FakeDrakshell([FakeProcess(hang=True, terminable=False)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(VerifierTimeout):
        session.run(["cmd", "/c", "sleep-forever"], timeout=0.1)

    with pytest.raises(RuntimeError, match="no longer usable"):
        session.run(["cmd", "/c", "ver"], timeout=5)
    # probe_command never raises per its documented contract - it must
    # report the broken session as an unavailable result instead.
    available, detail = session.probe_command(["cmd", "/c", "ver"], timeout=5)
    assert available is False
    assert "unavailable" in detail


# Regression tests for the confirmed _build_final_argv() double-quoting bug:
# a real Xen al-khaser run (05833a28-7c8f-44b6-94b3-4637cb420ac5, then
# 5ed417f7-b22a-46a3-a610-e31533529e2f after the build_argv() POSIX-quoting
# fix) failed because _build_final_argv used to re-serialize an
# already-complete cmd/c script (or a plain argv) through
# subprocess.list2cmdline() and return a List[str], which
# Drakshell._start_process() then re-quoted a SECOND time via
# mslex.join(for_cmd=False). That doubled the outer quote layer, made the
# guest's /c tail start with a quote character, and tripped cmd.exe's blunt
# "strip first-and-last-quote" fallback parsing - confirmed against the real
# installed mslex library and cmd.exe's own documented /c quote-preservation
# rule, not assumed. The fix: when cwd is set, _build_final_argv now returns
# a plain str, which Drakshell._start_process() forwards to the wire
# completely untouched (mslex.join is only ever applied to a list/tuple),
# so there is exactly one quote layer - the one this method deliberately
# writes for the cd/d target - and it never starts with a quote character.


def test_build_final_argv_normal_argv_with_cwd_is_a_raw_string():
    """A plain executable+flags argv (PERDEDOR's shape) combined with cwd
    must produce a single str, quoted via subprocess.list2cmdline() for the
    inner argv only - not re-handed to Drakshell as a List[str] that would
    be re-quoted by mslex a second time."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    argv = [
        "pwsh",
        "-NoProfile",
        "-File",
        r"C:\Users\Public\perdedor\Invoke-Perdedor.ps1",
        "-OutputPath",
        r"C:\Users\Public\perdedor\windows-report.json",
    ]

    final = session._build_final_argv(argv, r"C:\Users\Public\perdedor")

    assert isinstance(final, str)
    assert final == (
        r'cmd /c cd /d "C:\Users\Public\perdedor" && pwsh -NoProfile -File '
        r"C:\Users\Public\perdedor\Invoke-Perdedor.ps1 -OutputPath "
        r"C:\Users\Public\perdedor\windows-report.json"
    )


def test_build_final_argv_existing_cmd_c_script_with_cwd_is_spliced_verbatim():
    """When argv is already a complete ['cmd', '/c', '<script>'] invocation
    (AlKhaserAdapter's build_argv() shape), the script must be spliced into
    the cd/d wrapper byte-for-byte, never re-serialized through
    list2cmdline/mslex - that re-serialization is exactly what corrupted the
    real command against real Xen."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    script = r"C:\Users\Public\alkhaser\al-khaser_x64.exe --sleep 30 < NUL > C:\Users\Public\alkhaser\stdout.txt 2>&1"
    argv = ["cmd", "/c", script]

    final = session._build_final_argv(argv, r"C:\Users\Public\alkhaser")

    assert isinstance(final, str)
    assert final == f'cmd /c cd /d "C:\\Users\\Public\\alkhaser" && {script}'
    # The script's own text appears completely unmodified - no re-quoting.
    assert script in final


def test_run_produces_exact_alkhaser_command_with_live_redirection_operators():
    """End-to-end through GuestSession.run(): the exact real al-khaser
    Full-scan command (as built by AlKhaserAdapter.build_argv()) combined
    with cwd must reach Drakshell as one string, with <, >, and 2>&1 intact
    as literal text ready to be interpreted as live cmd.exe operators (this
    module does not re-parse cmd.exe grammar - that correctness was
    verified separately against the real mslex library and cmd.exe's
    documented /c behavior; here we assert the string GuestSession actually
    hands to Drakshell)."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    session = GuestSession(FakeInjector(), drakshell)
    argv = [
        "cmd",
        "/c",
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe --sleep 30 < NUL > "
        r"C:\Users\Public\alkhaser\stdout.txt 2>&1",
    ]

    session.run(argv, timeout=60, cwd=r"C:\Users\Public\alkhaser")

    (command,) = drakshell.run_interactive_calls
    assert command == (
        r'cmd /c cd /d "C:\Users\Public\alkhaser" && '
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe --sleep 30 < NUL > "
        r"C:\Users\Public\alkhaser\stdout.txt 2>&1"
    )
    assert "< NUL" in command
    assert "> C:\\Users\\Public\\alkhaser\\stdout.txt" in command
    assert command.endswith("2>&1")


def test_build_final_argv_cwd_with_spaces():
    """A cwd containing a space (e.g. under Program Files) must still be
    wrapped in exactly one pair of quotes - not double-quoted, and not left
    unquoted (which would let cmd.exe misparse it as two tokens)."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    argv = ["cmd", "/c", "dir"]

    final = session._build_final_argv(argv, r"C:\Program Files\alkhaser")

    assert final == r'cmd /c cd /d "C:\Program Files\alkhaser" && dir'
    assert final.count('"') == 2


def test_build_final_argv_executable_path_with_spaces_stays_quoted_by_build_argv():
    """A guest binary/stdout path containing a space must arrive already
    quoted by the caller's own build_argv()-style quoting (list2cmdline),
    and _build_final_argv must preserve those quotes exactly, adding only
    its own cd/d quote pair - never touching or re-quoting the script."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    script = subprocess.list2cmdline(
        [r"C:\Program Files\alkhaser\al-khaser_x64.exe", "--sleep", "30"]
    )
    argv = ["cmd", "/c", f"{script} < NUL"]

    final = session._build_final_argv(argv, r"C:\Program Files\alkhaser")

    assert final == (
        r'cmd /c cd /d "C:\Program Files\alkhaser" && '
        r'"C:\Program Files\alkhaser\al-khaser_x64.exe" --sleep 30 < NUL'
    )
    # cd/d's own pair, plus the executable path's own pair - 4 total, never
    # more (no spurious extra outer wrapping).
    assert final.count('"') == 4


def test_build_final_argv_no_cwd_plain_argv_is_unchanged_list():
    """With no cwd, _build_final_argv must return argv completely
    untouched - the pre-existing List[str] -> Drakshell ->
    mslex.join(for_cmd=False) path (verified here against the real,
    installed mslex library, not a reimplementation) must not regress."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    argv = ["pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"]

    final = session._build_final_argv(argv, None)

    assert final is argv
    assert isinstance(final, list)
    # Sanity check against the real project dependency: this is exactly
    # what Drakshell._start_process() will do with it on the wire.
    assert mslex.join(final, for_cmd=False) == (
        "pwsh -NoProfile -Command $PSVersionTable.PSVersion.Major"
    )


def test_run_no_cwd_sends_plain_list_to_drakshell():
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    session = GuestSession(FakeInjector(), drakshell)

    session.run(["pwsh", "-NoProfile", "-Command", "whoami"], timeout=5)

    (called,) = drakshell.run_interactive_calls
    assert isinstance(called, list)
    assert called == ["pwsh", "-NoProfile", "-Command", "whoami"]


def test_build_final_argv_never_produces_nested_cmd_c():
    """The confirmed double-nesting bug: an already-complete cmd/c script
    combined with cwd must never produce a second 'cmd /c' anywhere in the
    result - exactly one, at the very start."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    argv = [
        "cmd",
        "/c",
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe --sleep 30 < NUL > "
        r"C:\Users\Public\alkhaser\stdout.txt 2>&1",
    ]

    final = session._build_final_argv(argv, r"C:\Users\Public\alkhaser")

    assert final.lower().count("cmd /c") == 1


def test_build_final_argv_no_backslash_quote_corruption():
    """The confirmed corruption mechanism: re-serializing the cwd-wrapped
    command through mslex a second time left literal backslash-quote (\\")
    sequences in the final command, which cmd.exe's grammar (no backslash
    escaping) turns into a stray leading backslash on the cd/d target. The
    fixed, single-string result must contain no such sequence anywhere, and
    must not begin with a quote character (which is what triggers cmd.exe's
    blunt fallback quote-stripping in the first place)."""
    session = GuestSession(FakeInjector(), FakeDrakshell([FakeProcess(exit_code=0)]))
    argv = [
        "cmd",
        "/c",
        r"C:\Users\Public\alkhaser\al-khaser_x64.exe --sleep 30 < NUL > "
        r"C:\Users\Public\alkhaser\stdout.txt 2>&1",
    ]

    final = session._build_final_argv(argv, r"C:\Users\Public\alkhaser")
    tail = final[len("cmd /c ") :]

    assert '\\"' not in final
    assert not tail.startswith('"')


# Regression tests for the confirmed session-poisoning bug: a real combined
# perdedor + alkhaser scan (d91d894f-9079-4e1c-897b-8fdcfe02b2e5) failed both
# tools even though only PERDEDOR's own prerequisite (pwsh) was actually
# missing. PERDEDOR's PWSH_PROBE_ARGV probe_command() call triggered
# Drakshell._start_process()'s RESP_PROCESS_ERROR branch (a well-formed
# "the OS could not start this process" reply, not a protocol desync), which
# _run_with_timeout()'s blanket "any exception marks the session broken"
# handling then applied indiscriminately - poisoning the one shared
# GuestSession for al-khaser, which ran next and inherited a stale "session
# unusable" error that had nothing to do with its own, perfectly runnable
# command. The fix: Drakshell._start_process() now raises a dedicated
# ProcessStartError for RESP_PROCESS_ERROR, and GuestSession._run_with_timeout
# re-raises it without touching _broken_reason - every other exception
# (protocol desync, fatal errors, unterminated timeouts) still marks the
# session broken exactly as before.


def test_run_raises_process_start_error_for_missing_executable():
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0)],
        raise_on_run_interactive=[ProcessStartError("Process startup failed: 2")],
    )
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(ProcessStartError, match="Process startup failed: 2"):
        session.run(["pwsh", "-NoProfile", "-Command", "exit 0"], timeout=5)


def test_probe_command_returns_false_on_process_start_error():
    drakshell = FakeDrakshell(
        [], raise_on_run_interactive=[ProcessStartError("Process startup failed: 2")]
    )
    session = GuestSession(FakeInjector(), drakshell)

    available, detail = session.probe_command(["pwsh", "-NoProfile"], timeout=5)

    assert available is False
    assert "Process startup failed: 2" in detail


def test_process_start_error_does_not_set_broken_reason():
    drakshell = FakeDrakshell(
        [], raise_on_run_interactive=[ProcessStartError("Process startup failed: 2")]
    )
    session = GuestSession(FakeInjector(), drakshell)

    session.probe_command(["pwsh", "-NoProfile"], timeout=5)

    assert session._broken_reason is None


def test_process_start_error_leaves_session_usable_for_a_later_command():
    """The exact combined-tool scenario: PERDEDOR's pwsh probe fails with
    ProcessStartError (missing executable), then a completely unrelated
    later command on the SAME GuestSession (al-khaser's own, valid launch)
    must still execute normally - not fail with a stale 'session unusable'
    error inherited from PERDEDOR's own, unrelated probe."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0)],
        stdout_bytes=b"[al-khaser version 0.82]",
        raise_on_run_interactive=[ProcessStartError("Process startup failed: 2")],
    )
    session = GuestSession(FakeInjector(), drakshell)

    available, detail = session.probe_command(["pwsh", "-NoProfile"], timeout=5)
    assert available is False
    assert "Process startup failed: 2" in detail

    exit_code, stdout, _stderr = session.run(
        ["cmd", "/c", r"C:\Users\Public\alkhaser\al-khaser_x64.exe --sleep 30"],
        timeout=60,
    )

    assert exit_code == 0
    assert stdout == b"[al-khaser version 0.82]"
    assert len(drakshell.run_interactive_calls) == 2


def test_run_raises_generic_drakshell_exception_and_still_breaks_session():
    """A genuine, non-startup Drakshell failure (protocol desync, a fatal
    communication error) must still mark the session broken exactly as
    before - only ProcessStartError is exempted, nothing else."""
    drakshell = FakeDrakshell(
        [],
        raise_on_run_interactive=[
            RuntimeError("Drakshell is out of sync: got 176 instead of 162")
        ],
    )
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(RuntimeError, match="out of sync"):
        session.run(["cmd", "/c", "ver"], timeout=5)

    with pytest.raises(RuntimeError, match="no longer usable"):
        session.run(["cmd", "/c", "ver"], timeout=5)
    available, detail = session.probe_command(["cmd", "/c", "ver"], timeout=5)
    assert available is False
    assert "unavailable" in detail


def test_timeout_and_fatal_error_broken_session_behavior_unaffected(monkeypatch):
    """Sanity check that the ProcessStartError carve-out did not loosen the
    two pre-existing broken-session paths: an unterminated timeout, and a
    fatal error surfaced mid-command (process._fatal_error). Both must still
    mark the session broken, exactly as the pre-existing test coverage above
    (test_timeout_marks_session_broken_when_termination_fails_and_rejects_next_call,
    test_run_raises_fatal_error_from_process_and_breaks_session) already
    proves - this test drives both through the same FakeDrakshell used by
    the new ProcessStartError coverage above, confirming they were not
    disturbed by FakeDrakshell's new raise_on_run_interactive parameter."""
    _fast_grace_period(monkeypatch)
    drakshell = FakeDrakshell([FakeProcess(hang=True, terminable=False)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(VerifierTimeout):
        session.run(["cmd", "/c", "sleep-forever"], timeout=0.1)
    with pytest.raises(RuntimeError, match="no longer usable"):
        session.run(["cmd", "/c", "ver"], timeout=5)

    fatal = RuntimeError("Drakshell is out of sync: got 176 during process execution")
    drakshell2 = FakeDrakshell([FakeProcess(fatal_error=fatal)])
    session2 = GuestSession(FakeInjector(), drakshell2)

    with pytest.raises(RuntimeError, match="out of sync"):
        session2.run(["cmd", "/c", "ver"], timeout=5)
    with pytest.raises(RuntimeError, match="no longer usable"):
        session2.run(["cmd", "/c", "ver"], timeout=5)


# Regression tests for the confirmed PERDEDOR upload failure: put_file()
# already called _ensure_remote_parent_dir() before writing, but
# put_tree_as_zip() did not - so a not-yet-existing remote_dir (e.g.
# PERDEDOR's C:\Users\Public\perdedor, which nothing creates ahead of time)
# made injector.write_file() fail with ERROR_PATH_NOT_FOUND while writing
# the intermediate __put_tree_as_zip.zip. The fix mirrors put_file() exactly:
# ensure the remote directory exists (derived from the guest zip path, so the
# directory actually created is remote_dir itself) before the zip is ever
# written.


def test_put_tree_as_zip_creates_remote_dir_before_writing_zip(tmp_path):
    """Proves the exact ordering the confirmed bug got wrong: the guest-side
    mkdir must happen before injector.write_file() is ever called for the
    intermediate zip, not after."""
    order = []

    class OrderTrackingInjector(FakeInjector):
        def write_file(self, local_path, remote_path):
            order.append(("write_file", remote_path))
            return super().write_file(local_path, remote_path)

    class OrderTrackingDrakshell(FakeDrakshell):
        def run_interactive(self, args, stdin=None, stdout=None, stderr=None):
            order.append(("run_interactive", args))
            return super().run_interactive(
                args, stdin=stdin, stdout=stdout, stderr=stderr
            )

    drakshell = OrderTrackingDrakshell(
        [FakeProcess(exit_code=0), FakeProcess(exit_code=0)]
    )
    injector = OrderTrackingInjector()
    session = GuestSession(injector, drakshell)
    local_dir = tmp_path / "perdedor"
    local_dir.mkdir()
    (local_dir / "Invoke-Perdedor.ps1").write_bytes(b"# fake agent")

    session.put_tree_as_zip(local_dir, r"C:\Users\Public\perdedor")

    assert order[0][0] == "run_interactive"
    assert "New-Item" in _decode_ps_command(order[0][1])
    assert r"C:\Users\Public\perdedor" in _decode_ps_command(order[0][1])
    assert order[1] == (
        "write_file",
        r"C:\Users\Public\perdedor\__put_tree_as_zip.zip",
    )
    assert order[2][0] == "run_interactive"
    assert "Expand-Archive" in _decode_ps_command(order[2][1])


def test_put_tree_as_zip_succeeds_when_remote_dir_already_exists(tmp_path):
    """New-Item -Force is idempotent, same guarantee as put_file() - a
    remote_dir that already exists must still go through the same
    mkdir-then-write-then-expand path without error."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0), FakeProcess(exit_code=0)])
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_dir = tmp_path / "alkhaser-provisioning"
    local_dir.mkdir()
    (local_dir / "al-khaser_x64.exe").write_bytes(b"fake-binary")

    session.put_tree_as_zip(local_dir, r"C:\Users\Public\alkhaser")

    assert len(drakshell.run_interactive_calls) == 2
    assert injector.write_calls == [
        (
            injector.write_calls[0][0],
            r"C:\Users\Public\alkhaser\__put_tree_as_zip.zip",
        )
    ]


def test_put_tree_as_zip_mkdir_failure_raises_and_skips_write(tmp_path):
    """If the guest-side mkdir fails, put_tree_as_zip() must raise before
    ever attempting injector.write_file() for the zip - never write into a
    directory that was not actually created."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=1)], stderr_bytes=b"Access is denied"
    )
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_dir = tmp_path / "perdedor"
    local_dir.mkdir()
    (local_dir / "Invoke-Perdedor.ps1").write_bytes(b"# fake agent")

    with pytest.raises(RuntimeError, match="failed to create guest directory"):
        session.put_tree_as_zip(local_dir, r"C:\Users\Public\perdedor")

    assert injector.write_calls == []


def test_put_tree_as_zip_skips_mkdir_for_bare_drive_root(tmp_path):
    """A remote_dir directly at a drive root has no directory to create -
    put_tree_as_zip() must not issue a pointless guest round trip for it,
    mirroring put_file()'s identical bare-drive-root carve-out."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    injector = FakeInjector()
    session = GuestSession(injector, drakshell)
    local_dir = tmp_path / "tool"
    local_dir.mkdir()
    (local_dir / "payload.bin").write_bytes(b"fake-binary")

    session.put_tree_as_zip(local_dir, "C:\\")

    # Only the Expand-Archive call should have gone through - no mkdir.
    assert len(drakshell.run_interactive_calls) == 1
    assert "Expand-Archive" in _decode_ps_command(drakshell.run_interactive_calls[0])
    assert injector.write_calls == [
        (injector.write_calls[0][0], "C:\\__put_tree_as_zip.zip")
    ]


# ==========================================================================
# Pre-send command-length validation.
#
# Real-Xen scan 34ae2d08-dcf0-471b-88c8-5bead0cf40eb: a diagnostic command
# exceeded drakshell's 2048-byte UTF-16LE ceiling. drakshell performs that
# check as the FIRST thing in _start_process(), before its first
# channel.send_control() - so nothing was transmitted and the channel was
# never desynced. GuestSession nevertheless marked itself permanently
# broken, which skipped every remaining diagnostic AND the real al-khaser
# launch. These tests pin the distinction: host-side pre-send validation
# must propagate WITHOUT poisoning, while genuine post-send failures must
# still poison exactly as before.
# ==========================================================================


def _oversized_argv():
    """An argv whose encoded form is guaranteed to exceed the limit."""
    return ["powershell.exe", "-EncodedCommand", "A" * DRAKSHELL_MAX_CMDLINE_BYTES]


def test_encoded_cmdline_size_matches_drakshells_own_computation():
    """Not an approximation: the same mslex-join -> UTF-16LE -> +2 NUL
    computation Drakshell._start_process() performs."""
    argv = ["powershell.exe", "-NoProfile", "-File", r"C:\Users\Public\a.ps1"]

    joined = mslex.join(argv, for_cmd=False)
    assert encoded_cmdline_size(argv) == len(joined.encode("utf-16le")) + 2
    # A plain str (the cwd-wrapped form) is passed through, not re-joined.
    assert (
        encoded_cmdline_size("cmd /c dir") == len("cmd /c dir".encode("utf-16le")) + 2
    )


def test_drakshell_rejects_at_exactly_our_mirrored_limit():
    """Pins DRAKSHELL_MAX_CMDLINE_BYTES against the REAL
    Drakshell._start_process(). If drakshell's own ceiling ever changes,
    this fails rather than letting the two silently drift apart.

    Needs no Xen and no socket: the length check runs before any channel
    use, so a channel that records whether it was touched is enough."""
    from drakrun.lib.drakshell import Drakshell, ReqCode

    class RecordingChannel:
        def __init__(self):
            self.touched = False

        def send_control(self, req):
            self.touched = True
            raise _StopHere()

    class _StopHere(Exception):
        pass

    # Exactly at the limit: must get PAST the length check and reach the
    # channel. (limit - 2 bytes of NUL) / 2 bytes per UTF-16LE char.
    at_limit = "a" * ((DRAKSHELL_MAX_CMDLINE_BYTES - 2) // 2)
    assert encoded_cmdline_size(at_limit) == DRAKSHELL_MAX_CMDLINE_BYTES

    shell = Drakshell("vm-test")
    shell.channel = RecordingChannel()
    with pytest.raises(_StopHere):
        shell._start_process(at_limit, ReqCode.REQ_INTERACTIVE_EXECUTE)
    assert shell.channel.touched is True

    # One character over: must be rejected BEFORE the channel is touched.
    over_limit = at_limit + "a"
    assert encoded_cmdline_size(over_limit) > DRAKSHELL_MAX_CMDLINE_BYTES

    shell = Drakshell("vm-test")
    shell.channel = RecordingChannel()
    with pytest.raises(RuntimeError, match="Command line too long"):
        shell._start_process(over_limit, ReqCode.REQ_INTERACTIVE_EXECUTE)
    assert shell.channel.touched is False


def test_command_below_the_limit_is_accepted():
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)], stdout_bytes=b"ok")
    session = GuestSession(FakeInjector(), drakshell)

    argv = ["powershell.exe", "-NoProfile", "-File", r"C:\Users\Public\probe.ps1"]
    assert encoded_cmdline_size(argv) < DRAKSHELL_MAX_CMDLINE_BYTES

    exit_code, stdout, _stderr = session.run(argv, timeout=5)

    assert exit_code == 0
    assert stdout == b"ok"


def test_oversized_command_is_rejected_before_reaching_drakshell():
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(GuestCommandTooLong) as excinfo:
        session.run(_oversized_argv(), timeout=5)

    # Rejected host-side: drakshell was never called at all.
    assert drakshell.run_interactive_calls == []
    assert "was not sent to the guest" in str(excinfo.value)
    assert str(DRAKSHELL_MAX_CMDLINE_BYTES) in str(excinfo.value)


def test_oversized_command_does_not_poison_the_session():
    """The regression that cost scan 34ae2d08 its entire result."""
    drakshell = FakeDrakshell([FakeProcess(exit_code=0)])
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(GuestCommandTooLong):
        session.run(_oversized_argv(), timeout=5)

    assert session._broken_reason is None


def test_subsequent_commands_still_work_after_an_oversized_command(tmp_path):
    """The whole point of not poisoning: the next diagnostic, and the real
    verifier launch, must still be attempted."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0), FakeProcess(exit_code=0)], stdout_bytes=b"still here"
    )
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(GuestCommandTooLong):
        session.run(_oversized_argv(), timeout=5)

    exit_code, stdout, _stderr = session.run(["whoami"], timeout=5)
    assert exit_code == 0
    assert stdout == b"still here"

    # ...and file transfer over the same session is unaffected too.
    local_path = tmp_path / "out.txt"
    session.get_file(r"C:\report.json", local_path)
    assert local_path.read_bytes() == b"fake guest file content"


def test_oversized_command_is_a_runtimeerror_for_existing_callers():
    """Subclass, so adapters catching broad RuntimeError/Exception keep
    behaving exactly as they did."""
    assert issubclass(GuestCommandTooLong, RuntimeError)

    session = GuestSession(FakeInjector(), FakeDrakshell([]))
    with pytest.raises(RuntimeError):
        session.run(_oversized_argv(), timeout=5)


def test_genuine_start_failure_still_poisons_the_session():
    """The narrow fix must NOT make every RuntimeError harmless: a failure
    raised from drakshell once communication has begun still means the
    channel cannot be trusted."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0)],
        raise_on_run_interactive=[RuntimeError("Drakshell is out of sync: got 5")],
    )
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(RuntimeError, match="out of sync"):
        session.run(["whoami"], timeout=5)

    assert session._broken_reason is not None
    assert "failed to start guest command" in session._broken_reason

    # ...and the session is now genuinely unusable, as before.
    with pytest.raises(RuntimeError, match="no longer usable"):
        session.run(["whoami"], timeout=5)


def test_process_start_error_behaviour_is_unchanged():
    """ProcessStartError (a well-formed RESP_PROCESS_ERROR reply) must still
    propagate without poisoning - this fix must not disturb it."""
    drakshell = FakeDrakshell(
        [FakeProcess(exit_code=0)],
        raise_on_run_interactive=[ProcessStartError("Process startup failed: 2")],
    )
    session = GuestSession(FakeInjector(), drakshell)

    with pytest.raises(ProcessStartError):
        session.run(["missing.exe"], timeout=5)

    assert session._broken_reason is None
