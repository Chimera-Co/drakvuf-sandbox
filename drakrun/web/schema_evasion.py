"""Request/response models for the Sandbox Evasion API.

Mirrors drakrun.web.schema's conventions (pydantic BaseModel/RootModel,
AfterValidator for uuid4 path params, one options object per form/query).
EvasionScanPath does NOT inherit AnalysisRequestPath even though both
validate a uuid4 - its field is scan_id, not task_uid, and evasion scans and
analyses are different entities on a different queue, so the two path
models should stay independently evolvable.
"""

import uuid
from typing import Annotated, Any, Dict, List, Optional

from pydantic import AfterValidator, BaseModel, Field, RootModel


class EvasionScanPath(BaseModel):
    scan_id: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x, version=4)))] = (
        Field(description="Unique evasion scan ID")
    )


class EvasionScanFileQuery(BaseModel):
    filename: str


class ToolOptionField(BaseModel):
    """One entry in a tool's options_schema()["options"] list, rendered by
    the (future) frontend Custom panel with no tool-specific logic - the
    schema itself is honest about what each tool can and cannot configure."""

    name: str
    kind: str
    label: str
    choices: Optional[List[str]] = None
    default: Any = None
    minimum: Optional[int] = None
    note: Optional[str] = None


class ToolOptionsSchema(BaseModel):
    full_suite_only: bool
    options: List[ToolOptionField] = Field(default_factory=list)


class ToolInfo(BaseModel):
    id: str
    display_name: str
    supported_platforms: List[str]
    options_schema: ToolOptionsSchema


ToolListResponse = RootModel[List[ToolInfo]]


class SandboxToolInfo(ToolInfo):
    """A tool as offered by one specific sandbox - identical shape to
    ToolInfo, kept as a separate model since the two lists are populated by
    different logic (all adapters vs. one sandbox's capability
    intersection) and may diverge later."""


class SandboxInfo(BaseModel):
    id: str
    display_name: str
    platform: str
    os_version: Optional[str] = None
    firmware: Optional[str] = None
    hypervisor: str
    lifecycle: str
    available_tools: List[SandboxToolInfo]


SandboxListResponse = RootModel[List[SandboxInfo]]


class CreateScanRequest(BaseModel):
    sandbox_id: str
    tools: List[str]
    profile: str = "full"
    tool_options: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    timeout: Optional[int] = None


class CreateScanResponse(BaseModel):
    scan_id: str = Field(description="Unique evasion scan ID")


class EvasionScoreResponse(BaseModel):
    chimera_score: Optional[float] = None
    state: str
    primary_tool: Optional[str] = None
    per_category: Dict[str, float] = Field(default_factory=dict)
    tool_scores: Dict[str, Any] = Field(default_factory=dict)
    rationale: List[str] = Field(default_factory=list)


class ScanListEntry(BaseModel):
    id: str
    status: str
    substatus: Optional[str] = None
    sandbox: Dict[str, Any] = Field(default_factory=dict)
    profile: str
    tools: List[str]
    score: Optional[EvasionScoreResponse] = None
    time_started: Optional[str] = None
    time_finished: Optional[str] = None


ScanListResponse = RootModel[List[ScanListEntry]]


class ScanStatusResponse(BaseModel):
    id: str
    status: str
    substatus: Optional[str] = None
    vm_id: Optional[int] = None
    time_started: Optional[str] = None
    time_finished: Optional[str] = None
