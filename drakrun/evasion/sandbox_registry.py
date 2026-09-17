"""Sandbox registry: enumerate the environments that Sandbox Evasion can
target, and what each one declares about itself.

The registry is configuration-driven, mirroring the existing `preset` idiom
in drakrun.lib.config (a Dict[str, ...Section] populated from [<table>.<id>]
TOML tables). It deliberately does NOT enumerate running Xen domains: today
every vm-N is a disposable clone of the single vm-0 golden image, so listing
domains would report concurrency slots as if they were distinct sandbox
environments, which would be actively misleading. A future discovery adapter
can merge additional entries into get_sandbox_registry() without changing its
return type or any caller.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from drakrun.lib.config import DrakrunConfig, SandboxDefinitionSection
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH

logger = logging.getLogger(__name__)

DEFAULT_SANDBOX_ID = "default"


class SandboxDefinition(BaseModel):
    """A fully-resolved sandbox entry, as returned by the registry and
    snapshotted verbatim into each scan's metadata.json so historical runs
    stay readable even if the registry definition later changes."""

    id: str
    display_name: str
    platform: str
    os_version: Optional[str] = None
    firmware: Optional[str] = None
    hypervisor: str = "xen"
    lifecycle: str = "drakrun-vm"
    verifiers: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


class SandboxNotFound(Exception):
    def __init__(self, sandbox_id: str):
        super().__init__(f"Sandbox '{sandbox_id}' is not defined in the registry")
        self.sandbox_id = sandbox_id


def _section_to_definition(
    sandbox_id: str, section: SandboxDefinitionSection
) -> SandboxDefinition:
    return SandboxDefinition(
        id=sandbox_id,
        display_name=section.display_name or sandbox_id,
        platform=section.platform,
        os_version=section.os_version,
        firmware=section.firmware,
        hypervisor=section.hypervisor,
        lifecycle=section.lifecycle,
        verifiers=list(section.verifiers),
        metadata=dict(section.metadata),
    )


def _synthesize_default_sandbox(config: DrakrunConfig) -> SandboxDefinition:
    """Build a single sandbox entry from the live InstallInfo, for
    zero-config installs that have never declared a [sandbox.*] table.

    Best-effort only: InstallInfo and the storage backend require a real,
    provisioned drakrun install (root, Xen, an actual snapshot on disk), none
    of which exist on a plain development checkout. Anything that fails here
    is simply omitted from metadata rather than raising, so the registry
    always returns something usable.
    """
    metadata: Dict[str, Any] = {}
    display_name = "Windows 10 -- Current"

    try:
        install_info = InstallInfo.load(INSTALL_INFO_PATH)
    except (OSError, ValueError) as exc:
        logger.debug("No InstallInfo available for default sandbox synthesis: %s", exc)
        install_info = None

    if install_info is not None:
        metadata["storage_backend"] = install_info.storage_backend
        metadata["vcpus"] = str(install_info.vcpus)
        metadata["memory"] = str(install_info.memory)
        try:
            from drakrun.lib.storage import get_storage_backend

            backend = get_storage_backend(install_info)
            metadata["vm0_snapshot_time"] = str(backend.get_vm0_snapshot_time())
        except Exception as exc:  # noqa: BLE001 - best-effort diagnostic metadata only
            logger.debug("Could not read vm-0 snapshot time: %s", exc)

    return SandboxDefinition(
        id=DEFAULT_SANDBOX_ID,
        display_name=display_name,
        platform="windows",
        hypervisor="xen",
        lifecycle="drakrun-vm",
        verifiers=["perdedor", "alkhaser"],
        metadata=metadata,
    )


def get_sandbox_registry(config: DrakrunConfig) -> List[SandboxDefinition]:
    """Return every sandbox this installation currently declares.

    If no [sandbox.*] tables exist, synthesizes a single entry describing the
    one Windows 10 install this codebase actually manages today, so the
    feature works out of the box and the current sandbox is never hardcoded
    into either the backend or the frontend.
    """
    if not config.sandbox:
        return [_synthesize_default_sandbox(config)]

    return [
        _section_to_definition(sandbox_id, section)
        for sandbox_id, section in config.sandbox.items()
    ]


def resolve_sandbox(config: DrakrunConfig, sandbox_id: str) -> SandboxDefinition:
    """Look up one sandbox by id, raising SandboxNotFound if it doesn't
    exist. Callers (API layer and worker) both use this so an unknown id is
    rejected identically in both places."""
    for sandbox in get_sandbox_registry(config):
        if sandbox.id == sandbox_id:
            return sandbox
    raise SandboxNotFound(sandbox_id)


__all__ = [
    "SandboxDefinition",
    "SandboxNotFound",
    "DEFAULT_SANDBOX_ID",
    "get_sandbox_registry",
    "resolve_sandbox",
]
