"""VMAware adapter.

Verified against the VMAware v2.8.2 CLI source (NotRequiem/VMAware, formerly
kernelwernel/VMAware; cli/main.cpp and cli/output.cpp): ``--json --output
<file>`` runs the default VM::MULTIPLE detection and writes is_detected,
brand, conclusion, percentage, detected_technique_count, vm_type and the
detected technique names, then exits without any TUI or prompt. The JSON
lists only detected techniques, so there are no per-technique clean results:
the verdict check carries the overall result and the percentage.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from drakrun.evasion.constants import Category, CheckStatus, Severity
from drakrun.evasion.models import NormalizedCheck
from drakrun.evasion.verifiers.base import VerifierError
from drakrun.evasion.verifiers.single_binary import SingleBinaryAdapter

TOOL_ID = "vmaware"
REPORT_NAME = "vmaware.json"
_TIMING_WORDS = ("TIMER", "RDTSC", "TIMING", "CLOCK")
_TECHNIQUE_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


def _load(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except ValueError:
        # The CLI writes brand/conclusion without JSON escaping; a backslash in them is the likely breakage
        return json.loads(text.replace("\\", "\\\\"))


def parse_report(text: str) -> List[NormalizedCheck]:
    try:
        report = _load(text)
        detected = bool(report["is_detected"])
        techniques = list(report.get("detected_techniques") or [])
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"Unreadable VMAware JSON report: {exc}") from exc
    checks = [
        NormalizedCheck(
            id=f"{TOOL_ID}.verdict",
            category=Category.environment_artifact,
            name="VMAware overall verdict",
            description="VM::MULTIPLE detection at the default threshold",
            status=CheckStatus.detected if detected else CheckStatus.clean,
            severity=Severity.high,
            tool=TOOL_ID,
            measured_value=report.get("percentage"),
            evidence={
                k: report.get(k)
                for k in ("brand", "conclusion", "vm_type", "detected_technique_count")
            },
        )
    ]
    for name in techniques:
        checks.append(
            NormalizedCheck(
                id=f"{TOOL_ID}.technique.{name}",
                category=(
                    Category.timing
                    if any(w in str(name).upper() for w in _TIMING_WORDS)
                    else Category.environment_artifact
                ),
                name=str(name),
                description="VMAware technique that fired",
                status=CheckStatus.detected,
                severity=Severity.medium,
                tool=TOOL_ID,
            )
        )
    return checks


class VMAwareAdapter(SingleBinaryAdapter):
    id = TOOL_ID
    display_name = "VMAware"
    guest_dir = r"C:\Users\Public\vmaware"
    binary_name = "vmaware.exe"
    output_files = (REPORT_NAME,)

    def options_schema(self) -> Dict[str, Any]:
        return {
            "full_suite_only": False,
            "options": [
                {
                    "name": "disable",
                    "type": "list[str]",
                    "description": "Technique names passed to --disable (e.g. TIMER).",
                }
            ],
        }

    def validate_options(self, tool_options: Dict[str, Any]) -> Dict[str, Any]:
        unknown = set(tool_options) - {"disable"}
        if unknown:
            field = sorted(unknown)[0]
            raise VerifierError(
                f"VMAware accepts only 'disable' (got '{field}').", field=field
            )
        disable = tool_options.get("disable") or []
        if not isinstance(disable, list) or len(disable) > 32:
            raise VerifierError(
                "disable must be a list of at most 32 technique names.", field="disable"
            )
        for name in disable:
            if not isinstance(name, str) or not _TECHNIQUE_NAME.match(name):
                raise VerifierError(
                    f"Not a VMAware technique name: {name!r}", field="disable"
                )
        return {"disable": disable} if disable else {}

    def args(self, options: Dict[str, Any]) -> List[str]:
        args = ["--json", "--output", f"{self.guest_dir}\\{REPORT_NAME}"]
        if options.get("disable"):
            # --disable takes the following tokens until the next option, so it goes last
            args += ["--disable", ",".join(options["disable"])]
        return args

    def parse(self, outputs: Dict[str, str]) -> List[NormalizedCheck]:
        if REPORT_NAME not in outputs:
            raise ValueError(f"VMAware wrote no {REPORT_NAME}.")
        return parse_report(outputs[REPORT_NAME])


__all__ = ["VMAwareAdapter", "parse_report"]
