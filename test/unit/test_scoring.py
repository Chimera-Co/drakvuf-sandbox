"""Tests for drakrun.evasion.scoring.compute_score.

Every scenario here maps directly to an explicit correctness requirement for
the scoring subsystem:
  - PERDEDOR's own severity-weighted formula is reproduced exactly (cross-
    checked against the real, importable perdedor_common.scoring.score_report
    on an equivalent input, not just against our own re-derivation of it).
  - al-khaser (or any non-primary tool) never changes chimera_score and
    never receives an invented weighted_score of its own.
  - unsupported / error / timeout / "ran but nothing applicable" all collapse
    to the same ScoreState.incomplete with chimera_score=None - none of them
    can produce a numeric score, let alone a misleading 100.
  - skipped/errored checks are excluded from scoring, never counted as clean.
"""

import pytest

from drakrun.evasion.constants import CheckStatus, ScoreState, Severity, ToolStatus
from drakrun.evasion.models import NormalizedCheck, ToolResult
from drakrun.evasion.scoring import PRIMARY_TOOL_ID, compute_score


def _check(
    id_,
    status,
    severity=Severity.medium,
    category="environment_artifact",
    tool="perdedor",
):
    return NormalizedCheck(
        id=id_,
        category=category,
        name=id_,
        description="d",
        status=status,
        severity=severity,
        tool=tool,
    )


def test_no_tools_ran_is_incomplete():
    score = compute_score([])
    assert score.chimera_score is None
    assert score.state == ScoreState.incomplete
    assert score.primary_tool is None
    assert score.rationale


@pytest.mark.parametrize(
    "status,error",
    [
        (ToolStatus.unsupported, "pwsh missing"),
        (ToolStatus.error, "schema validation failed"),
        (ToolStatus.timeout, "agent did not finish"),
    ],
)
def test_primary_tool_incomplete_states_never_produce_a_score(status, error):
    result = ToolResult(tool=PRIMARY_TOOL_ID, status=status, error=error)
    score = compute_score([result])

    assert score.chimera_score is None
    assert score.state == ScoreState.incomplete
    assert any(error in r for r in score.rationale)


def test_primary_tool_ok_but_nothing_applicable_is_incomplete_not_100():
    """The core misleading-100 trap: PERDEDOR completed (status=ok) but every
    check was errored/skipped, so there is nothing to score. PERDEDOR's own
    formula would call this 100.0; this subsystem must not."""
    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[_check("a", CheckStatus.error), _check("b", CheckStatus.skipped)],
    )
    score = compute_score([result])

    assert score.chimera_score is None
    assert score.state == ScoreState.incomplete
    assert score.tool_scores[PRIMARY_TOOL_ID]["applicable"] == 0


def test_all_clean_scores_100_and_passes():
    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[_check("a", CheckStatus.clean), _check("b", CheckStatus.clean)],
    )
    score = compute_score([result])

    assert score.chimera_score == 100.0
    assert score.state == ScoreState.passed


def test_critical_detection_drops_score_and_fails():
    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[
            _check("a", CheckStatus.clean),
            _check("b", CheckStatus.detected, Severity.critical),
        ],
    )
    score = compute_score([result])

    # 100 * (1 - 1.0/2) = 50.0
    assert score.chimera_score == 50.0
    assert score.state == ScoreState.fail


def test_errored_and_skipped_checks_excluded_from_scoring_not_counted_as_clean():
    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[
            _check("a", CheckStatus.clean),
            _check("b", CheckStatus.error),
            _check("c", CheckStatus.skipped),
        ],
    )
    score = compute_score([result])

    # Only "a" is applicable -> a clean-only score of 100, not diluted or
    # penalized by the errored/skipped entries.
    assert score.chimera_score == 100.0
    summary = score.tool_scores[PRIMARY_TOOL_ID]
    assert summary["applicable"] == 1
    assert summary["errored"] == 1
    assert summary["skipped"] == 1


def test_weighted_formula_matches_real_perdedor_common_exactly():
    """Cross-check against the actual perdedor_common library (not a
    reimplementation we trust blindly) on an equivalent input."""
    from perdedor_common.models import Category as PCategory
    from perdedor_common.models import Finding, Platform
    from perdedor_common.models import Severity as PSeverity
    from perdedor_common.models import Status as PStatus
    from perdedor_common.scoring import score_report

    findings = [
        Finding(
            id="a1",
            category=PCategory.ENVIRONMENT_ARTIFACT,
            platform=Platform.WINDOWS,
            name="a",
            description="d",
            status=PStatus.CLEAN,
            severity=PSeverity.HIGH,
        ),
        Finding(
            id="a2",
            category=PCategory.ENVIRONMENT_ARTIFACT,
            platform=Platform.WINDOWS,
            name="b",
            description="d",
            status=PStatus.DETECTED,
            severity=PSeverity.HIGH,
        ),
    ]
    native = score_report(findings)

    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[
            _check("a1", CheckStatus.clean, Severity.high),
            _check("a2", CheckStatus.detected, Severity.high),
        ],
    )
    score = compute_score([result])

    assert score.chimera_score == native["weighted_score"]


def test_alkhaser_never_alters_chimera_score_even_with_detections():
    perdedor_clean = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[_check("a", CheckStatus.clean), _check("b", CheckStatus.clean)],
    )
    alkhaser_bad = ToolResult(
        tool="alkhaser",
        status=ToolStatus.ok,
        checks=[
            _check("x", CheckStatus.detected, Severity.critical, tool="alkhaser"),
            _check("y", CheckStatus.detected, Severity.critical, tool="alkhaser"),
        ],
    )
    score = compute_score([perdedor_clean, alkhaser_bad])

    assert score.chimera_score == 100.0
    assert score.state == ScoreState.passed
    assert "alkhaser" in score.tool_scores
    assert score.tool_scores["alkhaser"]["detected"] == 2


def test_alkhaser_never_gets_an_invented_weighted_score():
    result = ToolResult(
        tool="alkhaser",
        status=ToolStatus.ok,
        checks=[_check("x", CheckStatus.detected, Severity.critical, tool="alkhaser")],
    )
    score = compute_score([result])

    assert "weighted_score" not in score.tool_scores["alkhaser"]


def test_alkhaser_only_scan_is_incomplete_never_falls_back_to_alkhaser_scoring():
    result = ToolResult(
        tool="alkhaser",
        status=ToolStatus.ok,
        checks=[_check("x", CheckStatus.clean, tool="alkhaser")],
    )
    score = compute_score([result])

    assert score.chimera_score is None
    assert score.state == ScoreState.incomplete
    assert score.primary_tool is None


def test_per_category_scores_are_perdedor_only_and_omit_unscoreable_categories():
    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[
            _check(
                "a", CheckStatus.clean, Severity.high, category="environment_artifact"
            ),
            _check(
                "b",
                CheckStatus.detected,
                Severity.high,
                category="environment_artifact",
            ),
            _check("c", CheckStatus.clean, Severity.low, category="timing"),
            _check(
                "d", CheckStatus.skipped, Severity.critical, category="design_specific"
            ),
        ],
    )
    score = compute_score([result])

    assert score.per_category["environment_artifact"] == 67.5
    assert score.per_category["timing"] == 100.0
    # A category where every check is skipped is omitted, not fabricated as
    # 0 or 100.
    assert "design_specific" not in score.per_category


def test_thresholds_are_configurable():
    result = ToolResult(
        tool=PRIMARY_TOOL_ID,
        status=ToolStatus.ok,
        checks=[
            _check("a", CheckStatus.clean),
            _check("b", CheckStatus.detected, Severity.medium),
        ],
    )
    # 100 * (1 - 0.35/2) = 82.5
    score_default = compute_score([result])
    assert (
        score_default.state == ScoreState.warn
    )  # 82.5 is between 70 and 90 by default

    score_strict = compute_score([result], pass_threshold=80.0, warn_threshold=50.0)
    assert score_strict.state == ScoreState.passed  # 82.5 >= 80

    score_lenient = compute_score([result], pass_threshold=95.0, warn_threshold=90.0)
    assert score_lenient.state == ScoreState.fail  # 82.5 < 90
