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
from typing import Any, Dict, List

from drakrun.evasion.constants import Category, CheckStatus, Severity
from drakrun.evasion.models import NormalizedCheck
from drakrun.evasion.verifiers.single_binary import SingleBinaryAdapter

TOOL_ID = "vmaware"
REPORT_NAME = "vmaware.json"
_TIMING_WORDS = ("TIMER", "RDTSC", "TIMING", "CLOCK")


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

    def args(self) -> List[str]:
        return ["--json", "--output", f"{self.guest_dir}\\{REPORT_NAME}"]

    def parse(self, outputs: Dict[str, str]) -> List[NormalizedCheck]:
        if REPORT_NAME not in outputs:
            raise ValueError(f"VMAware wrote no {REPORT_NAME}.")
        return parse_report(outputs[REPORT_NAME])


__all__ = ["VMAwareAdapter", "parse_report"]
