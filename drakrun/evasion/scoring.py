"""CHIMERA evasion scoring.

This module computes exactly one number - ``chimera_score`` - and it always
comes from PERDEDOR's own severity-weighted scoring formula (verified from
``perdedor_common/scoring.py`` in the perdedor submodule and replicated here
over our own ``NormalizedCheck`` list, which is a verbatim 1:1 copy of
PERDEDOR's findings). PERDEDOR is the only verifier with a documented,
tool-native scoring methodology; nothing here invents a weighting scheme for
a tool that doesn't have one.

al-khaser (and any future non-primary adapter) is never averaged into
``chimera_score`` and never produces its own weighted score - al-khaser
itself has no scoring concept at all (it is a checklist tool with a plain
0/1 result per check and no aggregate verdict). Its results are surfaced
purely as corroborating counts (clean/detected/errored/skipped) alongside
the CHIMERA score, with an explicit note that they are not incorporated
into it. This keeps "tool-native result" and "CHIMERA normalized score"
visibly distinct, per the subsystem's design requirement.

Three situations must never be silently reported as a passing (or any)
numeric score:
  - the primary tool (PERDEDOR) did not run at all for this scan,
  - it ran but did not complete successfully (unsupported/error/timeout),
  - it completed, but every one of its checks ended up errored or skipped,
    leaving nothing applicable to score (PERDEDOR's own formula would call
    this 100.0 - "nothing detected because nothing was checked" - which
    reads exactly like a clean, fully-verified sandbox; this module refuses
    to make that conflation).
In all three cases ``chimera_score`` is ``None`` and ``state`` is
``ScoreState.incomplete`` - never a number, and never coerced to "pass".
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

# The only tool this subsystem currently trusts for an aggregate score.
# Deliberately a single constant, not a pluggable "primary tool" concept per
# adapter, because PERDEDOR is presently the only verifier with a documented
# native scoring methodology to reuse - inventing an equivalent for a tool
# that has none would be exactly the kind of fabricated weighting this
# module is required not to do.
PRIMARY_TOOL_ID = "perdedor"

DEFAULT_PASS_THRESHOLD = 90.0
DEFAULT_WARN_THRESHOLD = 70.0


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
    """PERDEDOR-only, weighted-score-per-category (feeds the four-category
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
    """Combine every tool's result for one scan into a single EvasionScore.

    ``tool_scores`` carries every tool's plain, unweighted counts (the
    tool-native view). Only ``tool_scores[PRIMARY_TOOL_ID]`` additionally
    gets a ``weighted_score`` key - the exact number PERDEDOR's own
    severity-weighted formula produces, and the same number ``chimera_score``
    is set to when available. No other tool's entry ever gets a
    ``weighted_score`` key, because no other tool has one to report.
    """
    rationale: List[str] = []
    tool_scores: Dict[str, Any] = {
        tr.tool: _tool_native_summary(tr) for tr in tool_results
    }

    primary_result = next(
        (tr for tr in tool_results if tr.tool == PRIMARY_TOOL_ID), None
    )
    chimera_score: Optional[float] = None
    per_category: Dict[str, float] = {}

    if primary_result is None:
        rationale.append(
            f"{PRIMARY_TOOL_ID} was not part of this scan; no primary CHIMERA score is available."
        )
    elif primary_result.status != ToolStatus.ok:
        detail = f" Detail: {primary_result.error}" if primary_result.error else ""
        rationale.append(
            f"{PRIMARY_TOOL_ID} did not complete successfully "
            f"(status={primary_result.status.value}); no primary CHIMERA score "
            f"is available.{detail}"
        )
    else:
        chimera_score = _weighted_score(primary_result.checks)
        summary = tool_scores[PRIMARY_TOOL_ID]
        if chimera_score is None:
            rationale.append(
                f"{PRIMARY_TOOL_ID} completed, but every one of its checks was "
                "errored or skipped, so there is nothing applicable to score."
            )
        else:
            summary["weighted_score"] = chimera_score
            rationale.append(
                f"CHIMERA score is {PRIMARY_TOOL_ID}'s own severity-weighted "
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
        if result.tool == PRIMARY_TOOL_ID:
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
        primary_tool=PRIMARY_TOOL_ID if primary_result is not None else None,
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
