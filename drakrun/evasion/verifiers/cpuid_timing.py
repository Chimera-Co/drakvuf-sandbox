"""CPUID round-trip timing harness (scripts/chimera/bench/cpuid-timing/cpuid_timing.c).

Not a detector: it measures RDTSC;CPUID;RDTSC and RDTSC;RDTSC in TSC cycles and
an al-khaser-style 10-round average (rdtsc_diff_vmexit in al-khaser v1.1.0
flags an average >= 1000 cycles or 0). One check carries those statistics as
evidence; it is "detected" when any al-khaser-style trial crossed the threshold.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from drakrun.evasion.constants import Category, CheckStatus, Severity
from drakrun.evasion.models import NormalizedCheck
from drakrun.evasion.verifiers.single_binary import SingleBinaryAdapter

TOOL_ID = "cpuid-timing"
ITERATIONS = 100000
REPORT_NAME = "cpuid-timing.json"
RAW_NAME = "cpuid-timing.csv"
_STATS = ("rdtsc_rdtsc", "rdtsc_cpuid_rdtsc", "alkhaser_style_avg10")


def parse_report(text: str) -> List[NormalizedCheck]:
    try:
        report = json.loads(text)
        detected, trials = (
            int(x) for x in report["alkhaser_style_detected"].split("/")
        )
        evidence = {name: report[name] for name in _STATS}
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"Unreadable cpuid-timing report: {exc}") from exc
    evidence["iterations"] = report.get("iterations")
    return [
        NormalizedCheck(
            id=f"{TOOL_ID}.rdtsc_cpuid",
            category=Category.timing,
            name="RDTSC;CPUID;RDTSC round trip",
            description="al-khaser-style 10-round average >= 1000 cycles (or 0) in any of the trials",
            status=CheckStatus.detected if detected else CheckStatus.clean,
            severity=Severity.info,
            tool=TOOL_ID,
            measured_value=f"{detected}/{trials}",
            evidence=evidence,
        )
    ]


class CpuidTimingAdapter(SingleBinaryAdapter):
    id = TOOL_ID
    display_name = "CPUID timing"
    guest_dir = r"C:\Users\Public\cpuid-timing"
    binary_name = "cpuid_timing.exe"
    output_files = (REPORT_NAME, RAW_NAME)

    def args(self, options: Dict[str, Any]) -> List[str]:
        return [
            str(ITERATIONS),
            f"{self.guest_dir}\\{REPORT_NAME}",
            f"{self.guest_dir}\\{RAW_NAME}",
        ]

    def parse(self, outputs: Dict[str, str]) -> List[NormalizedCheck]:
        if REPORT_NAME not in outputs:
            raise ValueError(f"cpuid-timing wrote no {REPORT_NAME}.")
        return parse_report(outputs[REPORT_NAME])


__all__ = ["CpuidTimingAdapter", "parse_report"]
