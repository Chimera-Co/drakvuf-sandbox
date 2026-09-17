"""Verifier adapter contract for Sandbox Evasion.

An adapter's job is narrow and disciplined: turn validated options into the
verifier's REAL, source-verified command line (nothing invented), execute it
via a GuestSession, and turn whatever the tool actually produced into a
ToolResult - preserving raw stdout/stderr/files alongside whatever it could
normalize. Everything the adapter does not understand about the tool's own
quirks (exit codes, working-directory tricks, output file naming, which
checks even have a machine-readable verdict) stays inside that one adapter
module; core code only ever sees ToolResult/NormalizedCheck.

Four run outcomes are always kept distinct (never collapsed into a single
pass/fail):
  - ToolStatus.unsupported - the tool cannot run here for a known, reportable
    reason (e.g. PowerShell 7 missing from the guest), discovered *before*
    anything was launched.
  - ToolStatus.error - the tool was launched but failed in a way that
    prevents a usable result (crash, unparseable output, missing binary).
  - ToolStatus.timeout - the tool was launched and exceeded its deadline.
  - ToolStatus.ok - the tool ran to completion and produced (at least
    partially) parseable findings. "ok" describes the RUN, not the verdict -
    a clean sandbox and a heavily-detected one are both status=ok.
"""

from __future__ import annotations

import abc
import pathlib
from typing import Any, Dict, List, Optional, Protocol, Tuple

from drakrun.evasion.models import ToolResult


class VerifierError(Exception):
    """Raised for a request the adapter can prove is invalid before running
    anything - e.g. an unknown al-khaser --check name, or an out-of-range
    --sleep value. Distinct from ToolResult(status=error), which represents a
    tool that WAS launched and then failed or produced unparseable output.
    Carries the exact offending field/value so the API layer can return an
    actionable 400 rather than a generic one."""

    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(message)
        self.field = field


class VerifierTimeout(Exception):
    """Raised internally when a guest-side run exceeds its deadline. Adapters
    catch this themselves and translate it into ToolResult(status=timeout);
    it should never escape run()."""


class GuestSession(Protocol):
    """The subset of guest interaction an adapter needs.

    Implemented for real by drakrun.evasion.guest_runner.GuestSession
    (Xen/DRAKVUF-backed, built in a later phase) and by a FakeGuestSession in
    tests. Protocol makes this a structural contract: adapters never import
    the real implementation, so they are fully exercisable on Windows against
    fixture bytes with no Xen dependency.
    """

    def probe_command(self, argv: List[str], timeout: float) -> Tuple[bool, str]:
        """Best-effort check that a command is runnable in the guest, e.g.
        `pwsh -NoProfile -Command $PSVersionTable.PSVersion.Major`. Returns
        (available, detail) - detail carries a diagnostic string either way,
        used verbatim in the ToolResult.error message when unavailable."""
        ...

    def put_file(self, local_path: pathlib.Path, remote_path: str) -> None:
        """Copy one local file into the guest at remote_path."""
        ...

    def put_tree_as_zip(self, local_dir: pathlib.Path, remote_dir: str) -> None:
        """Zip local_dir, transfer it once, and expand it guest-side at
        remote_dir. Avoids one injector round-trip per file for a multi-file
        agent tree (mirrors the pattern already used by
        drakrun.analyzer.analyzer.extract_archive_on_vm)."""
        ...

    def run(
        self,
        argv: List[str],
        timeout: float,
        cwd: Optional[str] = None,
    ) -> Tuple[int, bytes, bytes]:
        """Execute argv in the guest and return (exit_code, stdout, stderr).
        Raises VerifierTimeout if the run exceeds timeout."""
        ...

    def get_file(self, remote_path: str, local_path: pathlib.Path) -> None:
        """Copy one file back from the guest to local_path."""
        ...


class VerifierAdapter(abc.ABC):
    id: str
    display_name: str
    # Platform strings this tool genuinely supports, verified against its
    # actual source/CLI - never "all platforms" by default.
    supported_platforms: frozenset

    @abc.abstractmethod
    def options_schema(self) -> Dict[str, Any]:
        """Describe the REAL, currently-supported options for this tool, so
        the frontend Custom panel can render itself with no tool-specific
        logic in React. A tool with no per-check selection (PERDEDOR) returns
        a schema that says so explicitly (full_suite_only=True, options=[]),
        rather than an empty list the UI might mistake for 'not loaded yet'."""

    @abc.abstractmethod
    def validate_options(self, tool_options: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a request against options_schema()-shaped constraints and
        return a normalized options dict. Raises VerifierError naming the
        exact offending field/value - never silently drops or ignores an
        unknown option. (This is the deliberate fix for al-khaser's own
        --check TYPO bug, where EnableChecks() silently no-ops an unrecognized
        name while still suppressing the default set: we refuse instead.)"""

    @abc.abstractmethod
    def run(
        self,
        session: GuestSession,
        options: Dict[str, Any],
        scan_dir: pathlib.Path,
        deadline: float,
    ) -> ToolResult:
        """Execute the tool against an already-prepared, already-booted guest
        session and return a normalized ToolResult. Must never raise - every
        failure mode becomes ToolResult(status=error/timeout/unsupported)
        with raw artifacts preserved under scan_dir wherever any were
        captured before the failure."""


__all__ = [
    "VerifierError",
    "VerifierTimeout",
    "GuestSession",
    "VerifierAdapter",
]
