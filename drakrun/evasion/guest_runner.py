"""Real (Xen/DRAKVUF-backed) implementation of the GuestSession Protocol
(drakrun.evasion.verifiers.base.GuestSession).

This module composes primitives that already exist and are already used by
drakrun.analyzer.analyzer for real analyses - Injector for file transfer,
Drakshell for command execution - into the five-method surface the Phase B
verifier adapters were written against. Nothing here talks to Xen directly,
creates a VM, or manages snapshots: that lifecycle (VirtualMachine.restore/
destroy via run_vm) belongs to drakrun.evasion.worker, exactly mirroring how
drakrun.analyzer.worker.worker_analyze uses it. This module's only job is
"given an already-booted guest's Injector and Drakshell, run commands and
move files in and out of it."

Two known gaps in the underlying primitives are deliberately hardened here,
not worked around silently:

1. Drakshell.join() has no built-in timeout - the plan's own risk list flags
   this. _run_with_timeout() below enforces one by joining the guest
   command's own worker thread (DrakshellInteractiveProcess._thread) with a
   timeout, and calling DrakshellInteractiveProcess.terminate() at the
   caller's deadline, raising VerifierTimeout if the process still hasn't
   exited after a short grace period. This deliberately does not call
   DrakshellInteractiveProcess.join() itself: that method calls
   signal.signal(), which CPython only permits on the main thread of the
   main interpreter, so join() must only ever be invoked directly from
   whatever thread the caller is running GuestSession on - never from a
   watchdog thread spawned to enforce the timeout. Joining the process's own
   worker thread directly gives the identical happens-before guarantee
   join() itself relies on (the worker thread has fully finished, so
   _exit_code/_fatal_error are safe to read) without ever touching signal
   handling, and without spawning any thread of GuestSession's own.

2. Injector.read_file() has no caller anywhere outside its own CLI (per the
   implementation plan's reconnaissance) and does not pass check=True, so a
   failed guest-side read silently returns a non-zero-exit CompletedProcess
   rather than raising. get_file() below checks the return code itself and
   raises, so a verifier adapter's own try/except around get_file behaves
   the way its (adapter-side) code already assumes it does.

3. Injector writefile (confirmed against /opt/drakvuf's real source -
   win_write_file.c/win_functions.c - not assumed) opens the destination
   with CreateFileW(..., CREATE_NEW, ...), which never creates missing
   parent directories: writing into a not-yet-existing guest directory fails
   the injection with ERROR_PATH_NOT_FOUND. put_file() below runs an
   idempotent New-Item -Force through the same _run_with_timeout() path
   first, so any caller's destination directory is created on demand - no
   tool-specific path is hardcoded here, and a destination whose parent
   already exists costs one harmless extra guest round trip.

If a guest command's watchdog has to force-terminate it and the process
still does not exit, the session is marked permanently broken: nothing about
a half-desynced drakshell channel can be trusted for any later command in
the same scan (the protocol is a single request/response stream, not
multiplexed), so every subsequent call on this session fails fast with a
clear error instead of risking silent cross-talk between two guest
commands. The scan's overall cleanup is unaffected either way, since VM
teardown happens in drakrun.evasion.worker's run_vm block, not here.
"""

from __future__ import annotations

import json
import logging
import pathlib
import subprocess
import tempfile
import zipfile
from typing import Any, Dict, List, Optional, Tuple, Union

import mslex

from drakrun.analyzer.post_restore import prepare_ps_command
from drakrun.evasion.verifiers.base import VerifierTimeout
from drakrun.lib.drakshell import Drakshell, ProcessStartError
from drakrun.lib.injector import Injector

logger = logging.getLogger(__name__)

# Grace period after terminate() before giving up on a hung command and
# marking the whole session broken.
_TERMINATE_GRACE_SECONDS = 15.0
# Fixed budget for setup commands (Expand-Archive) that are not part of a
# verifier's own timeout budget.
_SETUP_COMMAND_TIMEOUT_SECONDS = 60.0

# Mirrors the hard ceiling in drakrun.lib.drakshell.Drakshell._start_process():
#
#     cmdline = args.encode("utf-16le") + b"\0\0"
#     if len(cmdline) > 2048:
#         raise RuntimeError("Command line too long")
#
# Duplicated here ON PURPOSE so GuestSession can reject an oversized command
# as its own precondition, BEFORE calling into drakshell at all - see
# GuestCommandTooLong below for why that distinction matters. The duplication
# is pinned by test_drakshell_rejects_at_exactly_our_mirrored_limit(), which
# drives the real Drakshell._start_process() at the boundary, so the two can
# never silently drift apart.
DRAKSHELL_MAX_CMDLINE_BYTES = 2048


class GuestCommandTooLong(RuntimeError):
    """A command was rejected by host-side validation, before any byte of it
    reached the guest.

    This is emphatically NOT a session failure. Drakshell performs its length
    check as the very first thing in _start_process(), well before its first
    channel.send_control() - so when it trips, the request/response stream has
    not been touched, nothing is half-written, and the session is exactly as
    usable as it was a moment earlier. Real-Xen scan
    34ae2d08-dcf0-471b-88c8-5bead0cf40eb is the cautionary case: an oversized
    diagnostic command tripped this check, GuestSession marked itself
    permanently broken anyway, and every remaining diagnostic AND the actual
    al-khaser launch were skipped for a channel that was never damaged.

    A RuntimeError subclass so existing callers that catch RuntimeError keep
    working unchanged.
    """


def encoded_cmdline_size(argv: Union[List[str], str]) -> int:
    """Bytes drakshell will put on the wire for this command.

    Computed through the SAME path Drakshell._start_process() uses - mslex
    joining for a list/tuple, UTF-16LE encoding, plus the two-byte NUL
    terminator - rather than an approximation of it, so a caller checking
    this value is checking the number that is actually going to be compared
    against the limit.
    """
    # drakshell tests the concrete type rather than isinstance; mirrored so
    # an exotic sequence type cannot take a different branch here than there.
    if type(argv) is list or type(argv) is tuple:
        args = mslex.join(argv, for_cmd=False)
    else:
        args = argv
    return len(args.encode("utf-16le")) + 2


def parse_injector_error_json(stdout: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """Extract DRAKVUF's own structured injection-error record from the
    injector's STDOUT, if it emitted one.

    Verified against /opt/drakvuf's real source, not assumed:
    print_injection_info() in src/libinjector/injector_utils.c, case
    INJECT_RESULT_ERROR_CODE under OUTPUT_JSON, prints exactly one line of
    the form

        {"Plugin": "inject", "TimeStamp": "...", "Method": "<method>",
         "Status": "Error", "ErrorCode": <int>, "Error": "<SYMBOLIC_NAME>"}

    to stdout (NOT stderr). "Error" is the symbolic Win32 name resolved
    through src/libdrakvuf/win-error-codes.h (ERROR_FILE_NOT_FOUND,
    ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_BAD_EXE_FORMAT, ...).
    src/libinjector/win/win_injector.c routes a failed readfile CreateFileW
    into precisely that branch, and drakrun.lib.drakvuf_cmdline already
    passes `-o json` on every injector invocation, so this record is being
    produced on every failed guest read today - it was simply never read,
    because get_file() below only ever looked at stderr.

    Tolerant by design: the injector interleaves other, non-JSON lines on
    stdout, so every line is tried independently and anything unparseable is
    skipped. The LAST matching record wins (it reflects the final outcome if
    more than one injection attempt was reported). Returns None when stdout
    is empty/absent or carries no such record - never raises.
    """
    if not stdout:
        return None
    if isinstance(stdout, bytes):
        text = stdout.decode("utf-8", errors="replace")
    else:
        text = str(stdout)

    found: Optional[Dict[str, Any]] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("{") or "ErrorCode" not in line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and "ErrorCode" in obj:
            found = obj
    return found


class InjectorReadError(RuntimeError):
    """Raised by GuestSession.get_file() when the injector's readfile fails.

    Deliberately a RuntimeError SUBCLASS, not a new exception hierarchy:
    get_file() has always raised RuntimeError on a non-zero injector exit,
    and both adapter callers (alkhaser.py, perdedor.py) catch broad
    Exception/RuntimeError around it. Subclassing therefore keeps every
    existing caller's behaviour byte-for-byte identical while making the
    structured DRAKVUF error record reachable by a caller that wants it.

    The str() message keeps its existing "injector readfile failed (exit N)
    for <path>: <stderr>" shape - the tests matching on that prefix still
    pass - and merely appends the Win32 error code when one was recovered.
    """

    def __init__(
        self,
        remote_path: str,
        returncode: int,
        stdout: Optional[bytes],
        stderr: Optional[bytes],
    ):
        self.remote_path = remote_path
        self.returncode = returncode
        self.stdout = (stdout or b"").decode("utf-8", errors="replace")
        self.stderr = (stderr or b"").decode("utf-8", errors="replace")
        self.injector_json = parse_injector_error_json(stdout)
        self.error_code: Optional[int] = None
        self.error_name: Optional[str] = None
        if self.injector_json is not None:
            code = self.injector_json.get("ErrorCode")
            if isinstance(code, int) and not isinstance(code, bool):
                self.error_code = code
            name = self.injector_json.get("Error")
            if isinstance(name, str) and name:
                self.error_name = name

        message = (
            f"injector readfile failed (exit {returncode}) for "
            f"{remote_path}: {self.stderr.strip()}"
        )
        if self.error_code is not None or self.error_name is not None:
            message += (
                f" [injector ErrorCode={self.error_code} " f"Error={self.error_name}]"
            )
        super().__init__(message)


class _BufferWriter:
    """Minimal stand-in for a file-like object with the two attributes
    DrakshellInteractiveProcess actually uses on a non-socket stdout/stderr:
    ``.buffer.write(bytes)`` and ``.flush()``. A bare io.BytesIO has neither
    a ``.buffer`` attribute nor is treated as socket-like, so passing one
    directly raises AttributeError inside drakshell - this wrapper is the
    fix, not a workaround."""

    def __init__(self) -> None:
        self._chunks: List[bytes] = []
        self.buffer = self

    def write(self, data: bytes) -> int:
        self._chunks.append(data)
        return len(data)

    def flush(self) -> None:
        pass

    def getvalue(self) -> bytes:
        return b"".join(self._chunks)


class GuestSession:
    """Real GuestSession over an already-connected Drakshell/Injector pair
    for one already-booted, already-restored guest. Constructed fresh per
    scan by drakrun.evasion.worker.worker_verify, inside its own run_vm
    block - this class never restores, destroys, or otherwise manages VM
    lifecycle itself."""

    def __init__(self, injector: Injector, drakshell: Drakshell):
        self.injector = injector
        self.drakshell = drakshell
        self._broken_reason: Optional[str] = None

    def _check_not_broken(self) -> None:
        if self._broken_reason is not None:
            raise RuntimeError(
                f"Guest session is no longer usable: {self._broken_reason}"
            )

    def _build_final_argv(
        self, argv: List[str], cwd: Optional[str]
    ) -> Union[List[str], str]:
        if not cwd:
            return argv
        # Drakshell has no native concept of a working directory - wrap the
        # command in a cmd.exe "cd /d <cwd> && <command>" so callers that
        # pass cwd (as the adapters do) get exactly the semantics they ask
        # for.
        #
        # This must be built as a single, final STRING, not a List[str]:
        # Drakshell._start_process() only applies mslex.join(for_cmd=False)
        # to a list/tuple, and leaves a plain str completely untouched
        # before sending it to the guest. mslex's quoting (either
        # for_cmd=False or for_cmd=True - both were checked against the
        # real installed library) is designed to escort a single opaque
        # argument value through one more layer of parsing; it is not
        # designed to carry already-correct, live cmd.exe shell syntax
        # (&&, <, >) verbatim, and re-quoting this f-string through it (the
        # previous, broken design) adds a spurious outer quote layer that
        # makes the /c tail start with a quote character - which triggers
        # cmd.exe's blunt "strip first-and-last-quote" fallback parsing and
        # corrupts the cd/d target with a stray leading backslash (verified
        # against the real mslex/cmd.exe grammar, not assumed). Building the
        # final command as one string that never starts with a quote
        # character avoids that fallback path entirely.
        if len(argv) == 3 and argv[0].lower() == "cmd" and argv[1].lower() == "/c":
            # argv is already a self-contained cmd.exe script (e.g. one
            # built with its own shell redirection, like AlKhaserAdapter's
            # build_argv()) - splice cd/d into it verbatim rather than
            # re-serializing/requoting the script, which would corrupt its
            # own internal quoting.
            script = argv[2]
        else:
            script = subprocess.list2cmdline(argv)
        return f'cmd /c cd /d "{cwd}" && {script}'

    def _run_with_timeout(
        self, argv: List[str], timeout: float, cwd: Optional[str] = None
    ) -> Tuple[int, bytes, bytes]:
        # final_argv is a List[str] when cwd is not supplied (passed through
        # unchanged to Drakshell, which quotes it via mslex.join(for_cmd=False)
        # exactly as before) or a plain str when cwd is supplied (see
        # _build_final_argv - Drakshell forwards a str to the wire untouched,
        # bypassing mslex entirely). Both are valid Drakshell.run_interactive()
        # inputs; only the type annotation below needs to reflect this.
        self._check_not_broken()
        final_argv: Union[List[str], str] = self._build_final_argv(argv, cwd)

        # PRE-SEND VALIDATION. Everything from here to the drakshell call
        # below is pure host-side computation on a command that has not been
        # transmitted, so a failure here cannot possibly have desynced the
        # channel and must not poison the session. Checking it ourselves -
        # rather than letting drakshell's identical check fire inside the
        # try/except that DOES poison - is what makes that distinction
        # structural rather than a guess about which RuntimeError we caught.
        cmdline_size = encoded_cmdline_size(final_argv)
        if cmdline_size > DRAKSHELL_MAX_CMDLINE_BYTES:
            raise GuestCommandTooLong(
                f"guest command line is {cmdline_size} bytes of UTF-16LE, over "
                f"drakshell's {DRAKSHELL_MAX_CMDLINE_BYTES}-byte limit; the "
                f"command was not sent to the guest and this session remains "
                f"usable"
            )

        stdout_writer = _BufferWriter()
        stderr_writer = _BufferWriter()

        try:
            process = self.drakshell.run_interactive(
                final_argv, stdin=None, stdout=stdout_writer, stderr=stderr_writer
            )
        except GuestCommandTooLong:
            # Defence in depth: only reachable if drakshell's own limit ever
            # drops BELOW our mirrored constant. Still a pre-send rejection,
            # so it must still not poison the session.
            raise
        except ProcessStartError:
            # A well-formed RESP_PROCESS_ERROR reply - the drakshell channel
            # answered correctly, it's just reporting that the OS couldn't
            # start this particular process (e.g. a missing executable like
            # a probe for an absent guest dependency). The channel's
            # request/response framing is intact and safe to reuse, so this
            # must NOT poison the session for whatever runs next - unlike a
            # genuine desync or an unterminated hung command below, nothing
            # here is actually broken.
            raise
        except Exception as exc:
            self._broken_reason = f"failed to start guest command: {exc}"
            raise

        # Do not call process.join() here - it calls signal.signal(), which
        # is only legal on the main thread of the main interpreter, and this
        # method may be called from any thread the caller happens to be on.
        # Wait on the process's own worker thread directly instead (a plain
        # Thread.join(), which has no such restriction and is safe from any
        # thread) so the timeout below can be enforced without ever spawning
        # a watchdog thread of our own.
        process._thread.join(timeout=max(0.0, timeout))

        if process._thread.is_alive():
            logger.warning(
                "Guest command exceeded its %.1fs budget, terminating: %s",
                timeout,
                final_argv,
            )
            try:
                process.terminate()
            except Exception as exc:  # noqa: BLE001 - best-effort termination
                logger.warning("Failed to terminate timed-out guest command: %s", exc)
            process._thread.join(timeout=_TERMINATE_GRACE_SECONDS)
            if process._thread.is_alive():
                # The channel is a single request/response stream, not
                # multiplexed - a command we could not even terminate means
                # we can no longer trust its state for anything run after
                # it. Mark the session broken rather than risk a later
                # command's response being read by this stale thread.
                self._broken_reason = (
                    "a previous guest command timed out and could not be "
                    "terminated cleanly"
                )
            raise VerifierTimeout(
                f"guest command did not finish within {timeout:.1f}s: {final_argv}"
            )

        if process._fatal_error is not None:
            self._broken_reason = f"guest command failed: {process._fatal_error}"
            raise process._fatal_error

        return (
            process._exit_code,
            stdout_writer.getvalue(),
            stderr_writer.getvalue(),
        )

    def probe_command(self, argv: List[str], timeout: float) -> Tuple[bool, str]:
        """Never raises - always returns (available, detail), per the
        GuestSession Protocol's contract, since PerdedorAdapter.run() calls
        this outside any try/except of its own."""
        if self._broken_reason is not None:
            return False, f"guest session unavailable: {self._broken_reason}"
        try:
            exit_code, stdout, stderr = self._run_with_timeout(argv, timeout)
        except VerifierTimeout:
            return False, f"probe timed out after {timeout:.1f}s"
        except Exception as exc:  # noqa: BLE001 - probe failures are diagnostic only
            return False, str(exc)
        if exit_code == 0:
            detail = stdout.decode("utf-8", errors="replace").strip()
            return True, detail or "ok"
        detail = stderr.decode("utf-8", errors="replace").strip()
        return False, f"exit code {exit_code}" + (f": {detail}" if detail else "")

    def _ensure_remote_parent_dir(self, remote_path: str) -> None:
        """Injector writefile's own CreateFile(..., CREATE_NEW, ...) call
        never creates missing directories (confirmed against /opt/drakvuf's
        real win_write_file.c/win_functions.c: a missing parent fails the
        injection with ERROR_PATH_NOT_FOUND rather than creating anything) -
        so any caller writing into a not-yet-existing guest directory (e.g. a
        verifier's own per-tool subfolder under C:\\Users\\Public) needs this
        done first. New-Item -Force is idempotent - safe to run unconditionally
        even when the directory already exists, and creates every missing
        intermediate level in one guest round trip. Skipped only for a bare
        drive root (e.g. "C:\\"), which always exists."""
        parent = pathlib.PureWindowsPath(remote_path).parent
        if parent == pathlib.PureWindowsPath(f"{parent.drive}\\"):
            return
        mkdir_cmd = prepare_ps_command(
            f"New-Item -ItemType Directory -Force -Path '{parent}' | Out-Null"
        )
        exit_code, _stdout, stderr = self._run_with_timeout(
            mkdir_cmd, timeout=_SETUP_COMMAND_TIMEOUT_SECONDS
        )
        if exit_code != 0:
            raise RuntimeError(
                f"failed to create guest directory {parent} (exit {exit_code}): "
                f"{stderr.decode('utf-8', errors='replace').strip()}"
            )

    def put_file(self, local_path: pathlib.Path, remote_path: str) -> None:
        self._check_not_broken()
        self._ensure_remote_parent_dir(remote_path)
        result = self.injector.write_file(str(local_path), remote_path)
        if result.returncode:
            raise RuntimeError(
                f"injector writefile failed (exit {result.returncode}) for "
                f"{remote_path}"
            )

    def put_tree_as_zip(self, local_dir: pathlib.Path, remote_dir: str) -> None:
        self._check_not_broken()
        guest_zip_path = remote_dir.rstrip("\\") + "\\__put_tree_as_zip.zip"
        self._ensure_remote_parent_dir(guest_zip_path)
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = pathlib.Path(tmp_dir) / "tree.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in sorted(local_dir.rglob("*")):
                    if path.is_file():
                        zf.write(path, path.relative_to(local_dir))

            result = self.injector.write_file(str(zip_path), guest_zip_path)
            if result.returncode:
                raise RuntimeError(
                    f"injector writefile failed (exit {result.returncode}) "
                    f"transferring tree archive to {guest_zip_path}"
                )

        expand_cmd = prepare_ps_command(
            f"Expand-Archive -Force -LiteralPath '{guest_zip_path}' "
            f"-DestinationPath '{remote_dir}'"
        )
        exit_code, _stdout, stderr = self._run_with_timeout(
            expand_cmd, timeout=_SETUP_COMMAND_TIMEOUT_SECONDS
        )
        if exit_code != 0:
            raise RuntimeError(
                f"Expand-Archive failed (exit {exit_code}) for {remote_dir}: "
                f"{stderr.decode('utf-8', errors='replace').strip()}"
            )

    def run(
        self, argv: List[str], timeout: float, cwd: Optional[str] = None
    ) -> Tuple[int, bytes, bytes]:
        return self._run_with_timeout(argv, timeout, cwd=cwd)

    def get_file(self, remote_path: str, local_path: pathlib.Path) -> None:
        self._check_not_broken()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        result = self.injector.read_file(remote_path, str(local_path))
        if result.returncode:
            # Injector.read_file() does not pass check=True (a latent gap
            # documented in the implementation plan), so a failed guest-side
            # read otherwise returns silently with a stale/empty local file.
            #
            # InjectorReadError is a RuntimeError subclass carrying the raw
            # injector stdout and DRAKVUF's own {"ErrorCode", "Error"} JSON
            # record (see parse_injector_error_json above). Raising the
            # subclass rather than a bare RuntimeError is backwards
            # compatible for every existing caller, while letting a caller
            # that cares - currently only al-khaser's read-only upload
            # diagnostic - recover the precise Win32 failure reason instead
            # of DRAKVUF's single opaque "Couldn't open guest file" string.
            raise InjectorReadError(
                remote_path,
                result.returncode,
                getattr(result, "stdout", None),
                getattr(result, "stderr", None),
            )


def connect_guest_session(vm_name: str, injector: Injector) -> GuestSession:
    """Connect Drakshell on an already-restored, already-booted VM and wrap
    it in a GuestSession. Mirrors drakrun.analyzer.analyzer.analyze_file's
    own connection sequence exactly (plain connect(), no shellcode
    injection) rather than drakshell.get_drakshell()'s inject-if-missing
    fallback: every golden image this project boots already runs drakshell
    as part of its normal startup (analyze_file relies on the same plain
    connect()), and get_drakshell()'s injection path is for the
    pre-provisioning/profiling flow in drakrun.lib.vmi_profile, not for a
    disposable overlay restored from that same golden image."""
    drakshell = Drakshell(vm_name)
    drakshell.connect(timeout=10)
    return GuestSession(injector, drakshell)


__all__ = [
    "DRAKSHELL_MAX_CMDLINE_BYTES",
    "GuestCommandTooLong",
    "GuestSession",
    "InjectorReadError",
    "connect_guest_session",
    "encoded_cmdline_size",
    "parse_injector_error_json",
]
