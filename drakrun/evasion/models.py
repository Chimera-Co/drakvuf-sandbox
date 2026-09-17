"""Normalized data model for the evasion verification subsystem.

Persistence follows the same idiom as analyses (drakrun.analyzer.analysis_metadata):
no database - an RQ job carries live state, and EvasionScanMetadata is the
durable on-disk record, one JSON file per scan directory.

The NormalizedCheck shape is deliberately identical to PERDEDOR's own finding
schema (schema/perdedor-report.schema.json in the perdedor repository), so a
PERDEDOR finding maps onto it with zero translation. al-khaser's parsed
results are normalized onto the same shape so both tools render through one
set of frontend components.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from drakrun.evasion.constants import (
    Category,
    CheckStatus,
    EvasionSubstatus,
    ScanStatus,
    ScoreState,
    Severity,
    ToolStatus,
)


class NormalizedCheck(BaseModel):
    """One check result, shaped like a PERDEDOR schema finding plus tool
    provenance and (for al-khaser, which has no native measured/expected
    concept) optional comparison fields."""

    id: str
    category: Category
    name: str
    description: str
    status: CheckStatus
    severity: Severity
    tool: str
    tool_version: Optional[str] = None
    evidence: Any = None
    remediation: Optional[str] = None
    error_detail: Optional[str] = None
    measured_value: Any = None
    expected_value: Any = None

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)


class ToolResult(BaseModel):
    """The result of running a single verifier adapter once."""

    tool: str
    tool_version: Optional[str] = None
    status: ToolStatus
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_s: Optional[float] = None
    exit_code: Optional[int] = None
    command: Optional[str] = None
    checks: List[NormalizedCheck] = Field(default_factory=list)
    # Raw artifact paths, relative to the scan directory - never discarded,
    # even when status is "error", so a malformed report is still auditable.
    raw_artifacts: List[str] = Field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)


class EvasionScanOptions(BaseModel):
    """The validated request that becomes an RQ job payload."""

    sandbox_id: str
    tools: List[str]
    profile: str = "full"  # "full" | "custom"
    # Per-tool option overrides, only meaningful when profile == "custom".
    # Shape is tool-specific and validated by that tool's adapter, e.g.
    # {"alkhaser": {"checks": ["DEBUG", "VBOX"], "sleep_seconds": 30}}.
    tool_options: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    timeout: Optional[int] = None

    def to_dict(self, exclude_none: bool = False) -> dict:
        return self.model_dump(mode="json", exclude_none=exclude_none)


class EvasionScore(BaseModel):
    """The CHIMERA evasion score for one scan.

    chimera_score is PERDEDOR's own weighted_score when PERDEDOR ran (the
    primary structured scoring source); al-khaser findings never change this
    number, only ``state`` and ``rationale`` (corroborating evidence, never
    averaged in).
    """

    chimera_score: Optional[float] = None
    state: ScoreState
    primary_tool: Optional[str] = None
    per_category: Dict[str, float] = Field(default_factory=dict)
    tool_scores: Dict[str, Any] = Field(default_factory=dict)
    rationale: List[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)


class EvasionScanMetadata(BaseModel):
    """Durable per-scan record, written to metadata.json - the evasion
    analogue of AnalysisMetadata."""

    model_config = ConfigDict(extra="allow")

    id: str
    status: Optional[str] = None
    substatus: Optional[str] = None
    sandbox: Dict[str, Any] = Field(default_factory=dict)
    options: EvasionScanOptions
    vm_id: Optional[int] = None
    time_started: Optional[str] = None
    time_execution_started: Optional[str] = None
    time_finished: Optional[str] = None
    tool_results: List[ToolResult] = Field(default_factory=list)
    score: Optional[EvasionScore] = None
    error: Optional[str] = None

    @classmethod
    def load_from_dict(cls, obj: Dict[str, Any]) -> "EvasionScanMetadata":
        return cls.model_validate(obj)

    @classmethod
    def load_from_file(cls, path: pathlib.Path) -> "EvasionScanMetadata":
        with path.open("r") as f:
            json_obj = json.load(f)
        return cls.load_from_dict(json_obj)

    def store_to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)

    def store_to_file(self, path: pathlib.Path) -> None:
        json_obj = self.store_to_dict()
        with path.open("w") as f:
            json.dump(json_obj, f, indent=2)


__all__ = [
    "NormalizedCheck",
    "ToolResult",
    "EvasionScanOptions",
    "EvasionScore",
    "EvasionScanMetadata",
    "ScanStatus",
    "EvasionSubstatus",
]
