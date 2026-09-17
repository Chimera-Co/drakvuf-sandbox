"""FakeGuestSession: a scriptable stand-in for drakrun.evasion.guest_runner's
real (Xen/DRAKVUF-backed) GuestSession, conforming to the same Protocol
defined in drakrun.evasion.verifiers.base.GuestSession.

This lets every verifier adapter be exercised fully - including the guest
put/run/get_file call sequence a real scan performs - without Xen, root, or
a provisioned drakrun install, matching the Windows-development limitations
in the implementation plan (adapters are tested against fixture bytes;
guest_runner.GuestSession itself is validated later, on Debian/Xen).
"""

from __future__ import annotations

import pathlib
from typing import Dict, List, Optional, Tuple

from drakrun.evasion.verifiers.base import VerifierTimeout


class FakeGuestSession:
    def __init__(
        self,
        run_result: Tuple[int, bytes, bytes] = (0, b"", b""),
        files: Optional[Dict[str, bytes]] = None,
        probe_result: Tuple[bool, str] = (True, "pwsh 7.4.1"),
        raise_on_run: Optional[Exception] = None,
    ):
        """
        run_result: (exit_code, stdout, stderr) returned by every run() call.
        files: guest_path -> bytes, consulted by get_file(); a put_file/
               put_tree_as_zip call registers files into this same dict so a
               later get_file for output that a real script would produce
               can be pre-seeded by the test instead.
        probe_result: (available, detail) returned by every probe_command() call.
        raise_on_run: if set, run() raises this instead of returning run_result
               (used to simulate VerifierTimeout or a transport failure).
        """
        self.files: Dict[str, bytes] = dict(files or {})
        self.run_result = run_result
        self.probe_result = probe_result
        self.raise_on_run = raise_on_run
        self.put_file_calls: List[Tuple[pathlib.Path, str]] = []
        self.put_tree_calls: List[Tuple[pathlib.Path, str]] = []
        self.run_calls: List[Tuple[List[str], float, Optional[str]]] = []
        self.get_file_calls: List[Tuple[str, pathlib.Path]] = []

    def probe_command(self, argv: List[str], timeout: float) -> Tuple[bool, str]:
        return self.probe_result

    def put_file(self, local_path: pathlib.Path, remote_path: str) -> None:
        self.put_file_calls.append((local_path, remote_path))
        self.files[remote_path] = pathlib.Path(local_path).read_bytes()

    def put_tree_as_zip(self, local_dir: pathlib.Path, remote_dir: str) -> None:
        self.put_tree_calls.append((local_dir, remote_dir))
        for p in pathlib.Path(local_dir).rglob("*"):
            if p.is_file():
                rel = p.relative_to(local_dir).as_posix()
                self.files[f"{remote_dir}\\{rel}".replace("/", "\\")] = p.read_bytes()

    def run(
        self, argv: List[str], timeout: float, cwd: Optional[str] = None
    ) -> Tuple[int, bytes, bytes]:
        self.run_calls.append((argv, timeout, cwd))
        if self.raise_on_run is not None:
            raise self.raise_on_run
        return self.run_result

    def get_file(self, remote_path: str, local_path: pathlib.Path) -> None:
        self.get_file_calls.append((remote_path, local_path))
        if remote_path not in self.files:
            raise FileNotFoundError(remote_path)
        pathlib.Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(local_path).write_bytes(self.files[remote_path])


__all__ = ["FakeGuestSession", "VerifierTimeout"]
