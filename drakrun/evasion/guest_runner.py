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
   this. _run_with_timeout() below supervises every guest command with a
   watchdog thread that calls DrakshellInteractiveProcess.terminate() at the
   caller's deadline, and raises VerifierTimeout if the process still hasn't
   exited after a short grace period.

2. Injector.read_file() has no caller anywhere outside its own CLI (per the
   implementation plan's reconnaissance) and does not pass check=True, so a
   failed guest-side read silently returns a non-zero-exit CompletedProcess
   rather than raising. get_file() below checks the return code itself and
   raises, so a verifier adapter's own try/except around get_file behaves
   the way its (adapter-side) code already assumes it does.

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

import logging
import pathlib
import subprocess
import tempfile
import threading
import zipfile
from typing import List, Optional, Tuple

from drakrun.analyzer.post_restore import prepare_ps_command
from drakrun.evasion.verifiers.base import VerifierTimeout
from drakrun.lib.drakshell import Drakshell
from drakrun.lib.injector import Injector

logger = logging.getLogger(__name__)

# Grace period after terminate() before giving up on a hung command and
# marking the whole session broken.
_TERMINATE_GRACE_SECONDS = 15.0
# Fixed budget for setup commands (Expand-Archive) that are not part of a
# verifier's own timeout budget.
_SETUP_COMMAND_TIMEOUT_SECONDS = 60.0


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

    def _build_final_argv(self, argv: List[str], cwd: Optional[str]) -> List[str]:
        if not cwd:
            return argv
        # Drakshell has no native concept of a working directory - wrap the
        # command in a cmd.exe "cd /d <cwd> && <command>" so callers that
        # pass cwd (as the adapters do) get exactly the semantics they ask
        # for. subprocess.list2cmdline is used purely as a Windows-style
        # quoting helper here; it does not execute anything itself.
        inner = subprocess.list2cmdline(argv)
        return ["cmd", "/c", f'cd /d "{cwd}" && {inner}']

    def _run_with_timeout(
        self, argv: List[str], timeout: float, cwd: Optional[str] = None
    ) -> Tuple[int, bytes, bytes]:
        self._check_not_broken()
        final_argv = self._build_final_argv(argv, cwd)
        stdout_writer = _BufferWriter()
        stderr_writer = _BufferWriter()

        try:
            process = self.drakshell.run_interactive(
                final_argv, stdin=None, stdout=stdout_writer, stderr=stderr_writer
            )
        except Exception as exc:
            self._broken_reason = f"failed to start guest command: {exc}"
            raise

        outcome: dict = {}

        def _wait() -> None:
            try:
                outcome["exit_code"] = process.join()
            except Exception as exc:  # noqa: BLE001 - surfaced to the caller below
                outcome["error"] = exc

        waiter = threading.Thread(
            target=_wait, name="guest-command-waiter", daemon=True
        )
        waiter.start()
        waiter.join(timeout=max(0.0, timeout))

        if waiter.is_alive():
            logger.warning(
                "Guest command exceeded its %.1fs budget, terminating: %s",
                timeout,
                final_argv,
            )
            try:
                process.terminate()
            except Exception as exc:  # noqa: BLE001 - best-effort termination
                logger.warning("Failed to terminate timed-out guest command: %s", exc)
            waiter.join(timeout=_TERMINATE_GRACE_SECONDS)
            if waiter.is_alive():
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

        if "error" in outcome:
            self._broken_reason = f"guest command failed: {outcome['error']}"
            raise outcome["error"]

        return outcome["exit_code"], stdout_writer.getvalue(), stderr_writer.getvalue()

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

    def put_file(self, local_path: pathlib.Path, remote_path: str) -> None:
        self._check_not_broken()
        result = self.injector.write_file(str(local_path), remote_path)
        if result.returncode:
            raise RuntimeError(
                f"injector writefile failed (exit {result.returncode}) for "
                f"{remote_path}"
            )

    def put_tree_as_zip(self, local_dir: pathlib.Path, remote_dir: str) -> None:
        self._check_not_broken()
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = pathlib.Path(tmp_dir) / "tree.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in sorted(local_dir.rglob("*")):
                    if path.is_file():
                        zf.write(path, path.relative_to(local_dir))

            guest_zip_path = remote_dir.rstrip("\\") + "\\__put_tree_as_zip.zip"
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
            raise RuntimeError(
                f"injector readfile failed (exit {result.returncode}) for "
                f"{remote_path}: "
                f"{(result.stderr or b'').decode('utf-8', errors='replace').strip()}"
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


__all__ = ["GuestSession", "connect_guest_session"]
