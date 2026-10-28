"""Shared adapter for checkers that are one Windows PE with no per-check options.

Pafish and VMAware are both a single console executable: upload it, run it
once through cmd.exe (stdin from NUL, so a closing getchar() cannot block),
read its output files back after DRAKVUF has stopped, and parse them. Like
al-khaser, the binary is not redistributed by this project: the administrator
downloads the release, records its SHA-256 and sets host_binary_path.
"""

from __future__ import annotations

import abc
import pathlib
import subprocess
import time
from typing import Any, Dict, Generator, List, Tuple

from drakrun.evasion.constants import ToolStatus
from drakrun.evasion.models import NormalizedCheck, ToolResult
from drakrun.evasion.verifiers.base import (
    GuestSession,
    ReportTooLarge,
    VerifierAdapter,
    VerifierError,
    VerifierTimeout,
    read_report_bytes,
)

STDOUT_NAME = "stdout.txt"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_argv(
    guest_binary_path: str, args: List[str], guest_stdout_path: str
) -> List[str]:
    """cmd.exe wrapper with Windows quoting (list2cmdline, never shlex; see alkhaser.build_argv)."""
    inner = subprocess.list2cmdline([guest_binary_path, *args])
    return [
        "cmd",
        "/c",
        f"{inner} < NUL > {subprocess.list2cmdline([guest_stdout_path])} 2>&1",
    ]


class SingleBinaryAdapter(VerifierAdapter):
    supported_platforms = frozenset({"windows"})
    guest_dir: str
    binary_name: str
    # Guest files (relative to guest_dir) read back after the run; stdout.txt is always first
    output_files: Tuple[str, ...] = ()

    def options_schema(self) -> Dict[str, Any]:
        return {
            "full_suite_only": True,
            "options": [],
            "note": f"{self.display_name} has no per-check selection; it always runs its full suite.",
        }

    def validate_options(self, tool_options: Dict[str, Any]) -> Dict[str, Any]:
        if tool_options:
            field = next(iter(tool_options))
            raise VerifierError(
                f"{self.display_name} accepts no options (got '{field}').", field=field
            )
        return {}

    def args(self) -> List[str]:
        """Command-line arguments after the binary path."""
        return []

    @abc.abstractmethod
    def parse(self, outputs: Dict[str, str]) -> List[NormalizedCheck]:
        """Checks from the retrieved output files (name -> text). Raises ValueError if unusable."""

    def _run_phases(
        self,
        session: GuestSession,
        options: Dict[str, Any],
        scan_dir: pathlib.Path,
        deadline: float,
        *,
        instrumented: bool = False,
    ) -> Generator[None, None, ToolResult]:
        started_at = _now()
        raw_dir = scan_dir / "raw" / self.id
        raw_dir.mkdir(parents=True, exist_ok=True)
        host_binary_path = options.get("host_binary_path")
        if not host_binary_path:
            return ToolResult(
                tool=self.id,
                status=ToolStatus.unsupported,
                started_at=started_at,
                finished_at=started_at,
                error=f"No {self.display_name} binary configured ([evasion.{self.id}].host_binary_path).",
            )

        guest_binary_path = f"{self.guest_dir}\\{self.binary_name}"
        argv = build_argv(
            guest_binary_path, self.args(), f"{self.guest_dir}\\{STDOUT_NAME}"
        )
        command = " ".join(argv)
        (raw_dir / "command.txt").write_text(command, encoding="utf-8")
        try:
            session.put_file(pathlib.Path(host_binary_path), guest_binary_path)
            yield  # staged; DRAKVUF attaches here on an instrumented scan
            result = session.run(
                argv, timeout=max(0.0, deadline - time.time()), cwd=self.guest_dir
            )
            exit_code, _stdout, _stderr = result
        except VerifierTimeout:
            return ToolResult(
                tool=self.id,
                status=ToolStatus.timeout,
                started_at=started_at,
                finished_at=_now(),
                command=command,
                error=f"{self.display_name} did not finish within its time budget.",
            )
        except (
            Exception
        ) as exc:  # noqa: BLE001 - any guest/transport failure becomes ToolResult(error)
            return ToolResult(
                tool=self.id,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=_now(),
                command=command,
                error=f"Failed to run {self.display_name} in the guest: {exc}",
            )
        yield  # executed; files are read back only after DRAKVUF has stopped

        outputs: Dict[str, str] = {}
        raw_artifacts: List[str] = []
        error = None
        for name in (STDOUT_NAME, *self.output_files):
            local = raw_dir / name
            try:
                session.get_file(f"{self.guest_dir}\\{name}", local)
                raw_artifacts.append(str(local.relative_to(scan_dir)))
                outputs[name] = read_report_bytes(local).decode(
                    "utf-8", errors="replace"
                )
            except ReportTooLarge as exc:
                error = str(exc)
            except Exception:  # noqa: BLE001 - a missing file is judged by parse()
                pass
        if error is None:
            try:
                checks = self.parse(outputs)
            except ValueError as exc:
                error = str(exc)
        status = ToolStatus.error if error else ToolStatus.ok
        return ToolResult(
            tool=self.id,
            status=status,
            started_at=started_at,
            finished_at=_now(),
            exit_code=exit_code,
            command=command,
            checks=[] if error else checks,
            raw_artifacts=raw_artifacts,
            truncated=getattr(result, "truncated", False),
            error=error,
        )


__all__ = ["SingleBinaryAdapter", "build_argv", "STDOUT_NAME"]
