"""Constants shared across the evasion subsystem.

This module deliberately imports nothing from drakrun. ``analyzer/worker.py``
needs ``EVASION_QUEUE_NAME`` to register the second queue, while
``evasion/worker.py`` needs ``get_redis_connection`` from ``analyzer/worker.py``
- keeping the constants here breaks what would otherwise be an import cycle.
"""

import enum

EVASION_QUEUE_NAME = "drakrun-evasion"

# Directory layout inside a scan directory. Raw tool output is preserved
# verbatim under RAW_SUBDIR even when parsing fails, because independently
# verifiable raw output is a hard requirement for this subsystem.
RAW_SUBDIR = "raw"
METADATA_FILENAME = "metadata.json"
RESULT_FILENAME = "evasion.json"
REPORT_FILENAME = "report.html"
LOG_FILENAME = "evasion.log"
ARTIFACTS_ZIP = "artifacts.zip"


class ScanStatus(str, enum.Enum):
    """Terminal and non-terminal states of a verification scan.

    Values intentionally match the RQ JobStatus vocabulary used by analyses so
    the frontend can reuse AnalysisStatusBadge without a translation layer.
    """

    queued = "queued"
    started = "started"
    finished = "finished"
    failed = "failed"


class EvasionSubstatus(str, enum.Enum):
    """Fine-grained progress, mirroring analyzer.AnalysisSubstatus.

    Written into job.meta by the worker's substatus callback and surfaced by
    GET /api/evasion/scans/<id>/status. These are the fixed, cross-cutting
    phases every scan goes through regardless of which tools it runs; the
    per-tool phase in between "probing" and "collecting" is NOT one of
    these enum members - the worker writes a dynamic ``f"running_{tool_id}"``
    string instead (job.meta["substatus"] and EvasionScanMetadata.substatus
    are plain strings, not this enum), so the substatus vocabulary stays
    capability-driven rather than hardcoding today's two tool ids into the
    type itself.
    """

    preparing = "preparing"
    booting = "booting"
    probing = "probing"
    collecting = "collecting"
    reporting = "reporting"
    cleanup = "cleanup"
    done = "done"


class ToolStatus(str, enum.Enum):
    """Outcome of a single verifier run.

    ``unsupported`` is distinct from ``error``: it means the tool could not run
    in this environment for a known, reportable reason (for example PowerShell
    7 missing from the guest), not that it ran and misbehaved.
    """

    ok = "ok"
    error = "error"
    timeout = "timeout"
    unsupported = "unsupported"


class CheckStatus(str, enum.Enum):
    """Per-check outcome. Values are exactly PERDEDOR's finding statuses.

    ``skipped`` matters for correctness: al-khaser categories that print
    free-form text instead of a GOOD/BAD verdict must land here rather than in
    ``clean``, so the clean count is never silently inflated.
    """

    clean = "clean"
    detected = "detected"
    error = "error"
    skipped = "skipped"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Category(str, enum.Enum):
    """The four CHIMERA detection categories, as defined by PERDEDOR."""

    environment_artifact = "environment_artifact"
    timing = "timing"
    behavioural_interaction = "behavioural_interaction"
    design_specific = "design_specific"


class ScoreState(str, enum.Enum):
    passed = "pass"
    warn = "warn"
    fail = "fail"
    # No primary-tool score could be computed for this scan (the primary
    # tool didn't run, didn't complete, or completed with nothing applicable
    # to score) - kept distinct from every other state so an incomplete scan
    # can never be reported as a passing (or failing) numeric score.
    incomplete = "incomplete"


# Severity weights used by PERDEDOR's own scoring implementation. Duplicated
# here (rather than imported from perdedor_common) only so that al-khaser
# findings can be weighted consistently when perdedor is not part of a scan.
SEVERITY_WEIGHT = {
    Severity.info: 0.05,
    Severity.low: 0.15,
    Severity.medium: 0.35,
    Severity.high: 0.65,
    Severity.critical: 1.0,
}
