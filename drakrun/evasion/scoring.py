"""CHIMERA evasion scoring.

Windows keeps PERDEDOR as the primary; al-khaser remains corroborating only.
Linux uses chimera-vmcheck with the same documented severity-weighted formula.
Missing, failed or insufficiently covered primaries produce an incomplete score.
Scores describe their own checklist; they are not calibrated across OSes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from drakrun.evasion.constants import (
    SEVERITY_WEIGHT,
    Category,
    CheckStatus,
    ScoreState,
    ToolStatus,
)
from drakrun.evasion.models import EvasionScore, NormalizedCheck, ToolResult

# Historical Windows primary; retained for stored reports and native rendering.
PRIMARY_TOOL_ID = "perdedor"

DEFAULT_PASS_THRESHOLD = 90.0
DEFAULT_WARN_THRESHOLD = 70.0
MIN_APPLICABLE_FRACTION = 0.5


def _tool_native_summary(result: ToolResult) -> Dict[str, Any]:
    """Plain counts for one tool's checks - no weighting, no invented score.
    This is the "tool-native result" half of the required distinction: every
    tool gets one of these, regardless of whether it has its own scoring
    concept."""
    checks = result.checks
    total = len(checks)
    clean = sum(1 for c in checks if c.status == CheckStatus.clean)
    detected = sum(1 for c in checks if c.status == CheckStatus.detected)
    errored = sum(1 for c in checks if c.status == CheckStatus.error)
    skipped = sum(1 for c in checks if c.status == CheckStatus.skipped)
    applicable = clean + detected

    return {
        "tool": result.tool,
        "tool_version": result.tool_version,
        "status": result.status.value,
        "total": total,
        "clean": clean,
        "detected": detected,
        "errored": errored,
        "skipped": skipped,
        "applicable": applicable,
        # "clean/applicable" - the same headline shape PERDEDOR itself uses,
        # kept identical for every tool so the report can show one
        # consistent counting convention even for tools with no scoring
        # concept of their own.
        "raw_score": f"{clean}/{applicable}" if applicable else "0/0",
        "error": result.error,
    }


def _weighted_score(checks: List[NormalizedCheck]) -> Optional[float]:
    """PERDEDOR's own formula (perdedor_common/scoring.py:score_report),
    replicated exactly: 100 * (1 - sum(severity_weight of each DETECTED
    applicable check) / applicable_count), where applicable = clean +
    detected. errored/skipped checks are excluded from both the numerator
    and denominator - they were never "clean", so they must not silently
    inflate the score, and they were never "detected" either, so they must
    not silently deflate it.

    Returns None - not 0.0 and not PERDEDOR's own 100.0 default - when there
    are zero applicable checks, i.e. nothing at all could be scored. This is
    the one deliberate deviation from perdedor_common's own formula: that
    library defines "no applicable checks" as a clean 100.0 (nothing was
    detected because nothing was checked), which is correct for its own
    "did any of my findings detect something" semantics, but would read as a
    perfect, fully-verified sandbox in CHIMERA's report if adopted verbatim -
    exactly the misleading-100 outcome this subsystem must not produce.
    """
    applicable_checks = [
        c for c in checks if c.status in (CheckStatus.clean, CheckStatus.detected)
    ]
    if not applicable_checks:
        return None

    penalty = sum(
        SEVERITY_WEIGHT[c.severity]
        for c in applicable_checks
        if c.status == CheckStatus.detected
    )
    return round(max(0.0, 100.0 * (1.0 - penalty / len(applicable_checks))), 2)


def _per_category_scores(checks: List[NormalizedCheck]) -> Dict[str, float]:
    """Primary-tool weighted-score-per-category (feeds the four-category
    evasion profile visualization). A category with zero applicable checks
    is omitted entirely - not scored as 0 or 100 - for the same reason
    _weighted_score returns None rather than guessing."""
    by_category: Dict[Category, List[NormalizedCheck]] = {}
    for check in checks:
        by_category.setdefault(check.category, []).append(check)

    result: Dict[str, float] = {}
    for category, category_checks in by_category.items():
        score = _weighted_score(category_checks)
        if score is not None:
            result[category.value] = score
    return result


def compute_score(
    tool_results: List[ToolResult],
    pass_threshold: float = DEFAULT_PASS_THRESHOLD,
    warn_threshold: float = DEFAULT_WARN_THRESHOLD,
) -> EvasionScore:
    """Score the primary's applicable checks and retain every tool's counts.

    PERDEDOR remains the Windows primary. Linux selects chimera-vmcheck when
    PERDEDOR is absent, reusing the same formula and coverage requirements.
    Other tools remain corroborating and never change the primary's score.
    """
    rationale: List[str] = []
    if any(tr.tool == "chimera-vmcheck" for tr in tool_results):
        rationale.append(
            "Linux checklist scoring uses the CHIMERA severity-weighted formula: "
            "100 * (1 - detected severity weights / applicable checks). "
            "Low-resource/activity/tool/timing heuristics weigh 0.15; other checks weigh 0.65. "
            "This heuristic score is not a probability or a cross-OS benchmark."
        )
    tool_scores: Dict[str, Any] = {
        tr.tool: _tool_native_summary(tr) for tr in tool_results
    }

    primary_tool_id = (
        "chimera-vmcheck"
        if any(tr.tool == "chimera-vmcheck" for tr in tool_results)
        and not any(tr.tool == PRIMARY_TOOL_ID for tr in tool_results)
        else PRIMARY_TOOL_ID
    )
    primary_result = next(
        (tr for tr in tool_results if tr.tool == primary_tool_id), None
    )
    chimera_score: Optional[float] = None
    per_category: Dict[str, float] = {}

    if primary_result is None:
        rationale.append(
            f"{primary_tool_id} was not part of this scan; no primary CHIMERA score is available."
        )
    elif primary_result.status != ToolStatus.ok:
        detail = f" Detail: {primary_result.error}" if primary_result.error else ""
        rationale.append(
            f"{primary_tool_id} did not complete successfully "
            f"(status={primary_result.status.value}); no primary CHIMERA score "
            f"is available.{detail}"
        )
    else:
        summary = tool_scores[primary_tool_id]
        if not summary["applicable"]:
            rationale.append(
                f"{primary_tool_id} completed, but every one of its checks was "
                "errored or skipped, so there is nothing applicable to score."
            )
        elif summary["applicable"] < MIN_APPLICABLE_FRACTION * summary["total"]:
            rationale.append(
                f"{primary_tool_id} coverage is insufficient: "
                f"{summary['applicable']}/{summary['total']} checks applicable; "
                f"at least {MIN_APPLICABLE_FRACTION:.0%} is required for a score."
            )
        else:
            chimera_score = _weighted_score(primary_result.checks)
            summary["weighted_score"] = chimera_score
            rationale.append(
                f"CHIMERA score is {primary_tool_id}'s own severity-weighted "
                f"score over {summary['applicable']} applicable check(s) "
                f"({summary['raw_score']} clean)."
            )
            if summary["errored"] or summary["skipped"]:
                rationale.append(
                    f"{summary['errored']} check(s) errored and {summary['skipped']} "
                    "were skipped/unparseable, and were excluded from scoring "
                    "rather than counted as clean."
                )
            per_category = _per_category_scores(primary_result.checks)

    # Every other tool is corroborating evidence only - reported, never
    # averaged in, per the explicit requirement not to combine incompatible
    # tool scores.
    for result in tool_results:
        if result.tool == primary_tool_id:
            continue
        summary = tool_scores[result.tool]
        if result.status == ToolStatus.ok:
            rationale.append(
                f"{result.tool} ran as corroborating evidence: "
                f"{summary['detected']} detected / {summary['clean']} clean of "
                f"{summary['applicable']} applicable check(s) "
                "(not incorporated into the CHIMERA score)."
            )
        else:
            detail = f" Detail: {result.error}" if result.error else ""
            rationale.append(
                f"{result.tool} did not complete successfully "
                f"(status={result.status.value}) and contributes no "
                f"corroborating evidence.{detail}"
            )

    if chimera_score is None:
        state = ScoreState.incomplete
    elif chimera_score >= pass_threshold:
        state = ScoreState.passed
    elif chimera_score >= warn_threshold:
        state = ScoreState.warn
    else:
        state = ScoreState.fail

    return EvasionScore(
        chimera_score=chimera_score,
        state=state,
        primary_tool=primary_tool_id if primary_result is not None else None,
        per_category=per_category,
        tool_scores=tool_scores,
        rationale=rationale,
    )


__all__ = [
    "PRIMARY_TOOL_ID",
    "DEFAULT_PASS_THRESHOLD",
    "DEFAULT_WARN_THRESHOLD",
    "compute_score",
]
