"""CHIMERA's standard-library Linux VM checklist adapter."""

from __future__ import annotations

import json
import shlex
import time

from drakrun.evasion.constants import Category, CheckStatus, Severity, ToolStatus
from drakrun.evasion.models import NormalizedCheck, ToolResult
from drakrun.evasion.verifiers.base import (
    VerifierAdapter,
    VerifierError,
    VerifierTimeout,
    read_report_bytes,
)
from drakrun.lib.linux_install import GUEST_AGENT_DIR, GUEST_WORK_DIR
from drakrun.lib.paths import PACKAGE_DATA_PATH

TOOL_ID = "chimera-vmcheck"
# Shipped with the other Linux guest assets (drakrun/data/linux)
VMCHECK_SCRIPT = PACKAGE_DATA_PATH / "linux" / "chimera-vmcheck.py"
CATEGORY_MAP = {
    "cpu": Category.environment_artifact,
    "firmware": Category.environment_artifact,
    "devices": Category.environment_artifact,
    "virtualization": Category.environment_artifact,
    "resources": Category.environment_artifact,
    "activity": Category.behavioural_interaction,
    "timing": Category.timing,
    "debug": Category.design_specific,
    "tools": Category.environment_artifact,
    "sandbox": Category.environment_artifact,
}


class LinuxVmcheckAdapter(VerifierAdapter):
    id = TOOL_ID
    display_name = "CHIMERA Linux VM check"
    supported_platforms = frozenset({"linux"})

    def options_schema(self):
        return {"full_suite_only": True, "options": []}

    def validate_options(self, tool_options):
        if tool_options:
            raise VerifierError(
                "chimera-vmcheck runs its full suite and takes no configurable options"
            )
        return {}

    def _normalize(self, report):
        if (
            not isinstance(report, dict)
            or report.get("tool") != TOOL_ID
            or not isinstance(report.get("version"), str)
        ):
            raise ValueError("Unexpected tool/version")
        checks = report.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or type(report.get("total")) is not int
            or report["total"] != len(checks)
        ):
            raise ValueError("Invalid total/checks")
        if type(report.get("detected")) is not int:
            raise ValueError("Invalid detected count")
        normalized, ids = [], set()
        for check in checks:
            if not isinstance(check, dict) or type(check.get("detected")) is not bool:
                raise ValueError("Each check needs a boolean detected value")
            ident = check.get("id")
            category = check.get("category")
            technique = check.get("technique")
            status = check.get("status", "ok")
            if (
                not isinstance(ident, str)
                or not ident
                or ident in ids
                or category not in CATEGORY_MAP
                or not isinstance(technique, str)
                or not technique
                or "evidence" not in check
                or status not in ("ok", "skipped", "error")
            ):
                raise ValueError(
                    "Invalid/duplicate check id, category, technique, evidence or status"
                )
            if status != "ok" and check["detected"]:
                raise ValueError("Unavailable checks cannot be detected")
            ids.add(ident)
            severity = (
                Severity.low
                if category in ("resources", "activity", "tools", "timing")
                else Severity.high
            )
            normalized.append(
                NormalizedCheck(
                    id=ident,
                    category=CATEGORY_MAP[category],
                    name=ident,
                    description=technique,
                    status=(
                        CheckStatus(status)
                        if status != "ok"
                        else (
                            CheckStatus.detected
                            if check["detected"]
                            else CheckStatus.clean
                        )
                    ),
                    severity=severity,
                    tool=TOOL_ID,
                    tool_version=report["version"],
                    evidence={"group": category, "detail": check["evidence"]},
                )
            )
        if report["detected"] != sum(c["detected"] for c in checks):
            raise ValueError("Detected count disagrees with checks")
        return normalized

    def _run_phases(self, session, options, scan_dir, deadline, *, instrumented=False):
        start = time.time()
        raw = scan_dir / "raw" / TOOL_ID
        raw.mkdir(parents=True, exist_ok=True)
        # The checker is the "sample": it runs from where samples run; its report goes to the agent's directory
        script = f"{GUEST_WORK_DIR}/vmcheck.py"
        output = f"{GUEST_AGENT_DIR}/linux-report.json"
        argv = ["python3", script, "--output", output]
        result = ToolResult(
            tool=TOOL_ID,
            status=ToolStatus.error,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            command=shlex.join(argv),
        )
        (raw / "command.txt").write_text(result.command, encoding="utf-8")
        result.raw_artifacts.append(str((raw / "command.txt").relative_to(scan_dir)))
        try:
            source = VMCHECK_SCRIPT
            if not source.is_file():
                result.status = ToolStatus.unsupported
                result.error = (
                    "chimera-vmcheck.py is missing from the host installation"
                )
                return result
            session.put_file(source, script)
            yield
            command = session.run(argv, timeout=max(0, deadline - time.time()))
            result.exit_code, stdout, stderr = command
            result.truncated = getattr(command, "truncated", False)
            yield
            for name, data in (("stdout.txt", stdout), ("stderr.txt", stderr)):
                (raw / name).write_bytes(data)
                result.raw_artifacts.append(str((raw / name).relative_to(scan_dir)))
            local_report = raw / "linux-report.json"
            session.get_file(output, local_report)
            result.raw_artifacts.append(str(local_report.relative_to(scan_dir)))
            report = json.loads(read_report_bytes(local_report))
            result.checks = self._normalize(report)
            result.tool_version = report["version"]
            if result.exit_code != 0:
                result.error = f"chimera-vmcheck exited with code {result.exit_code}"
            elif result.truncated:
                result.error = "chimera-vmcheck command output was truncated"
            else:
                result.status = ToolStatus.ok
        except VerifierTimeout as exc:
            result.status, result.error = ToolStatus.timeout, str(exc)
        except Exception as exc:
            result.error = f"Linux verifier failed: {exc}"
        finally:
            result.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            result.duration_s = round(time.time() - start, 3)
        return result
