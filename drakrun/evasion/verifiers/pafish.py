"""Pafish (Paranoid Fish) adapter.

Verified against Pafish v0.6 (a0rtega/pafish, pafish/main.c and common.c):
the console prints each check as ``[*] <name> ... `` followed by
``traced!`` or ``OK``, under ``[-] <group>`` headings, and ends in a
getchar() (stdin is NUL here). It has no options. Its reverse-Turing checks
wait at most 3 s each. Traced checks are also appended to pafish.log and, in
the release build, looked up as ``<id>.pafish`` in DNS (answered by INetSim).
"""

from __future__ import annotations

import re
from typing import Dict, List

from drakrun.evasion.constants import Category, CheckStatus, Severity
from drakrun.evasion.models import NormalizedCheck
from drakrun.evasion.verifiers.single_binary import STDOUT_NAME, SingleBinaryAdapter

TOOL_ID = "pafish"
_CHECK_LINE = re.compile(r"^\[\*\] (?P<name>.+?) \.\.\.(?: (?P<rest>.*))?$")
_GROUP_LINE = re.compile(r"^\[-\] (?P<group>[^:]+)$")
_GROUP_CATEGORIES = {
    "Debuggers detection": Category.design_specific,
    "Generic reverse turing tests": Category.behavioural_interaction,
    "Hooks detection": Category.design_specific,
}


def _category(group: str, name: str) -> Category:
    if "rdtsc" in name.lower() or "Sleep()" in name:
        return Category.timing
    return _GROUP_CATEGORIES.get(group, Category.environment_artifact)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def parse_stdout(text: str) -> List[NormalizedCheck]:
    checks: List[NormalizedCheck] = []
    group = ""
    seen: Dict[str, int] = {}
    pending = None  # a check whose verdict is on a later line (a check printed a warning first)
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.rstrip()
        group_match = _GROUP_LINE.match(line)
        if group_match:
            group, pending = group_match.group("group"), None
            continue
        check_match = _CHECK_LINE.match(line)
        if check_match:
            pending, rest = check_match.group("name"), check_match.group("rest") or ""
        elif pending is not None:
            rest = line
        else:
            continue
        if rest.endswith("traced!"):
            status = CheckStatus.detected
        elif rest.endswith("OK"):
            status = CheckStatus.clean
        else:
            continue
        check_id = f"{TOOL_ID}.{_slug(group)}.{_slug(pending)}"
        seen[check_id] = seen.get(check_id, 0) + 1
        if seen[check_id] > 1:
            check_id += f".{seen[check_id]}"
        checks.append(
            NormalizedCheck(
                id=check_id,
                category=_category(group, pending),
                name=pending,
                description=f"Pafish: {group}",
                status=status,
                severity=Severity.medium,
                tool=TOOL_ID,
            )
        )
        pending = None
    return checks


class PafishAdapter(SingleBinaryAdapter):
    id = TOOL_ID
    display_name = "Pafish"
    guest_dir = r"C:\Users\Public\pafish"
    binary_name = "pafish64.exe"
    output_files = ("pafish.log",)

    def parse(self, outputs: Dict[str, str]) -> List[NormalizedCheck]:
        checks = parse_stdout(outputs.get(STDOUT_NAME, ""))
        if not checks:
            raise ValueError(
                "No Pafish check verdicts (traced!/OK) found in its output."
            )
        return checks


__all__ = ["PafishAdapter", "parse_stdout"]
