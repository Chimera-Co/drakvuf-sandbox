"""PERDEDOR adapter.

Ground truth for this module comes from the perdedor submodule itself
(github.com/clustercoder/perdedor), read directly - the schema at
schema/perdedor-report.schema.json, the CLI at cli/perdedor_cli/__main__.py,
and the Windows agent at agents/windows/. Three facts drive this adapter's
design; each is load-bearing:

1. PERDEDOR's real CLI is `perdedor test {windows|linux|android}
   [-s SERIAL] [-o OUTPUT] [--json] [--verbose] [--no-color]` and
   `perdedor report REPORT... [-o OUT.html] [--json OUT.json]`. There is NO
   per-check selection anywhere in this CLI - `test` always runs a
   platform's entire fixed check suite. options_schema() below reflects
   that honestly (full_suite_only=True, options=[]) instead of inventing
   controls PERDEDOR does not have.

2. `perdedor test windows` is the wrong integration point for this project:
   it shells out to agents/windows/Invoke-Perdedor.ps1 and runs it on
   whatever host executes the `perdedor` CLI. On a Debian dom0 that would
   fingerprint dom0, not the disposable guest under test. This adapter
   therefore never calls the `perdedor` CLI's `test` subcommand at all -
   it injects the agent tree into the guest and invokes
   Invoke-Perdedor.ps1 there directly, then validates and normalizes the
   resulting JSON host-side using the importable perdedor_common library
   (which is dependency-free and safe to run on the host regardless of
   what's installed in the guest).

3. The Windows agent's own README states it requires PowerShell 7, because
   it reads CPUID via the .NET `System.Runtime.Intrinsics.X86.X86Base`
   intrinsic - Windows PowerShell 5.1 (`powershell.exe`, the only PS this
   codebase's existing guest automation already uses) cannot run it. This
   adapter probes for pwsh before doing anything else and reports
   ToolStatus.unsupported with an actionable message if it's absent, rather
   than launching a script guaranteed to fail partway through.

The schema (schema/perdedor-report.schema.json) already matches this
subsystem's NormalizedCheck shape almost field-for-field (same four
categories, same four statuses, same five severities), so findings are
mapped over verbatim rather than re-derived - including each finding's own
``id``, which is preserved exactly as PERDEDOR assigned it for traceability
back to the upstream report.
"""

from __future__ import annotations

import json
import pathlib
import time
from typing import Any, Dict, List

from drakrun.evasion.constants import Category, CheckStatus, Severity, ToolStatus
from drakrun.evasion.models import NormalizedCheck, ToolResult
from drakrun.evasion.verifiers.base import (
    GuestSession,
    VerifierAdapter,
    VerifierError,
    VerifierTimeout,
)

TOOL_ID = "perdedor"

# Probe command for PowerShell 7+: exits 0 when available, non-zero
# otherwise. Run with -NoProfile so a guest's PS profile script can't
# interfere with the check.
PWSH_PROBE_ARGV = [
    "pwsh",
    "-NoProfile",
    "-Command",
    "if ($PSVersionTable.PSVersion.Major -ge 7) { exit 0 } else { exit 1 }",
]

# Relative to the perdedor submodule checkout (options["repo_path"]).
_AGENT_SUBDIR = "agents/windows"


def _load_perdedor_common():
    """Deferred import: perdedor_common only exists once the perdedor
    submodule is installed (see requirements.txt: -e ./perdedor). Importing
    it lazily lets this module (and the adapter registry that imports it)
    load even before that install step has happened, failing only when a
    scan actually tries to use PERDEDOR."""
    from perdedor_common.validation import ValidationError, validate_report

    return validate_report, ValidationError


class PerdedorAdapter(VerifierAdapter):
    id = TOOL_ID
    display_name = "PERDEDOR"
    # PERDEDOR genuinely supports linux/android/windows platforms in its own
    # CLI, but this adapter only implements the Windows integration so far -
    # Linux/Android sandboxes are future work (a Linux/Android GuestSession
    # would run `perdedor test linux`/`... android -s <serial>` directly
    # in-guest, which needs no PowerShell-probe equivalent).
    supported_platforms = frozenset({"windows"})

    def options_schema(self) -> Dict[str, Any]:
        return {
            "full_suite_only": True,
            "options": [],
            "note": (
                "PERDEDOR's CLI (`perdedor test <platform>`) has no per-check "
                "selection - it always runs its full, fixed check suite for "
                "the target platform."
            ),
        }

    def validate_options(self, tool_options: Dict[str, Any]) -> Dict[str, Any]:
        # There is nothing user-configurable to validate - reject any
        # unexpected keys outright rather than silently ignoring them, for
        # the same reason al-khaser's adapter refuses unknown --check names.
        unknown = set(tool_options.keys()) - {"repo_path"}
        if unknown:
            raise VerifierError(
                f"PERDEDOR takes no configurable options; got unexpected field(s): {sorted(unknown)}",
                field=next(iter(unknown)),
            )
        return {}

    def run(
        self,
        session: GuestSession,
        options: Dict[str, Any],
        scan_dir: pathlib.Path,
        deadline: float,
    ) -> ToolResult:
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        raw_dir = scan_dir / "raw" / TOOL_ID
        raw_dir.mkdir(parents=True, exist_ok=True)

        repo_path = options.get("repo_path")
        if not repo_path:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.unsupported,
                started_at=started_at,
                finished_at=started_at,
                error=(
                    "No perdedor checkout configured "
                    "([evasion.perdedor].repo_path). Add the perdedor git "
                    "submodule and point this setting at it."
                ),
            )

        agent_dir = pathlib.Path(repo_path) / _AGENT_SUBDIR
        if not (agent_dir / "Invoke-Perdedor.ps1").exists():
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.unsupported,
                started_at=started_at,
                finished_at=started_at,
                error=(
                    f"agents/windows/Invoke-Perdedor.ps1 not found under {repo_path}. "
                    "Is the perdedor submodule checked out?"
                ),
            )

        timeout = max(0.0, deadline - time.time())
        available, detail = session.probe_command(
            PWSH_PROBE_ARGV, timeout=min(30.0, timeout)
        )
        if not available:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.unsupported,
                started_at=started_at,
                finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                error=(
                    "PowerShell 7 (pwsh) is not available in the guest. "
                    "PERDEDOR's Windows agent requires it to read CPUID via "
                    "the .NET X86Base intrinsic, which Windows PowerShell "
                    f"5.1 cannot do. Probe detail: {detail}"
                ),
            )

        guest_dir = r"C:\Users\Public\perdedor"
        guest_output_path = guest_dir + r"\windows-report.json"
        command_txt = [
            "pwsh",
            "-NoProfile",
            "-File",
            guest_dir + r"\Invoke-Perdedor.ps1",
            "-OutputPath",
            guest_output_path,
        ]
        (raw_dir / "command.txt").write_text(" ".join(command_txt), encoding="utf-8")

        try:
            session.put_tree_as_zip(agent_dir, guest_dir)
            timeout = max(0.0, deadline - time.time())
            exit_code, stdout, stderr = session.run(
                command_txt, timeout=timeout, cwd=guest_dir
            )
        except VerifierTimeout:
            finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.timeout,
                started_at=started_at,
                finished_at=finished_at,
                command=" ".join(command_txt),
                error="PERDEDOR's Windows agent did not finish within its time budget.",
            )
        except (
            Exception
        ) as exc:  # noqa: BLE001 - any guest/transport failure becomes ToolResult(error)
            finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=finished_at,
                command=" ".join(command_txt),
                error=f"Failed to launch the PERDEDOR Windows agent in the guest: {exc}",
            )

        raw_artifacts: List[str] = []
        if stderr:
            stderr_path = raw_dir / "agent-stderr.txt"
            stderr_path.write_bytes(stderr)
            raw_artifacts.append(str(stderr_path.relative_to(scan_dir)))
        if stdout:
            stdout_path = raw_dir / "agent-stdout.txt"
            stdout_path.write_bytes(stdout)
            raw_artifacts.append(str(stdout_path.relative_to(scan_dir)))

        finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        local_report = raw_dir / "windows-report.json"
        try:
            session.get_file(guest_output_path, local_report)
        except (
            Exception
        ) as exc:  # noqa: BLE001 - retrieval failure -> error, not silently empty
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=exit_code,
                command=" ".join(command_txt),
                raw_artifacts=raw_artifacts,
                error=f"Could not retrieve the report the agent wrote in-guest: {exc}",
            )
        raw_artifacts.append(str(local_report.relative_to(scan_dir)))

        try:
            report_text = local_report.read_text(encoding="utf-8")
            report = json.loads(report_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=exit_code,
                command=" ".join(command_txt),
                raw_artifacts=raw_artifacts,
                error=f"PERDEDOR report was not valid JSON: {exc}",
            )

        validate_report, ValidationError = _load_perdedor_common()
        try:
            validate_report(report, source="perdedor-guest-report")
        except ValidationError as exc:
            return ToolResult(
                tool=TOOL_ID,
                status=ToolStatus.error,
                started_at=started_at,
                finished_at=finished_at,
                exit_code=exit_code,
                command=" ".join(command_txt),
                raw_artifacts=raw_artifacts,
                error=f"PERDEDOR report failed schema validation: {exc}",
            )

        checks = self._normalize(report)

        return ToolResult(
            tool=TOOL_ID,
            tool_version=report.get("perdedor_version"),
            status=ToolStatus.ok,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=exit_code,
            command=" ".join(command_txt),
            checks=checks,
            raw_artifacts=raw_artifacts,
        )

    def _normalize(self, report: Dict[str, Any]) -> List[NormalizedCheck]:
        """Map every PERDEDOR finding onto NormalizedCheck 1:1. Field names
        and enum values are identical by construction (this subsystem's
        Category/CheckStatus/Severity enums were defined to match PERDEDOR's
        schema exactly), so this is a direct copy, not a reinterpretation -
        including keeping each finding's own ``id`` verbatim rather than
        renaming it, so a normalized check can always be traced back to the
        exact line in the upstream report."""
        checks: List[NormalizedCheck] = []
        for finding in report.get("findings", []):
            checks.append(
                NormalizedCheck(
                    id=finding["id"],
                    category=Category(finding["category"]),
                    name=finding["name"],
                    description=finding["description"],
                    status=CheckStatus(finding["status"]),
                    severity=Severity(finding["severity"]),
                    tool=TOOL_ID,
                    tool_version=report.get("perdedor_version"),
                    evidence=finding.get("evidence"),
                    remediation=finding.get("remediation"),
                    error_detail=finding.get("error_detail"),
                )
            )
        return checks


__all__ = ["PerdedorAdapter", "PWSH_PROBE_ARGV"]
