"""Verifier adapter registry.

Each adapter turns validated request options into a real, verified command
for its tool and normalizes whatever that tool actually produced into a
ToolResult. Adding a new tool later means writing one adapter module and
registering it here - nothing else in the evasion subsystem needs to change,
per the "adapters/registrations without redesigning the system" requirement.
"""

from __future__ import annotations

from typing import Dict, List

from drakrun.evasion.verifiers.base import VerifierAdapter

_REGISTRY: Dict[str, VerifierAdapter] = {}


def register(adapter: VerifierAdapter) -> None:
    _REGISTRY[adapter.id] = adapter


def get_adapter(tool_id: str) -> VerifierAdapter:
    if tool_id not in _REGISTRY:
        raise KeyError(f"No verifier adapter registered for tool id '{tool_id}'")
    return _REGISTRY[tool_id]


def all_adapters() -> List[VerifierAdapter]:
    return list(_REGISTRY.values())


def get_adapters_for_platform(platform: str) -> List[VerifierAdapter]:
    """Every registered adapter that declares support for this platform -
    the raw material for the sandbox/tool capability intersection the API
    layer performs. A future Android-only adapter simply lists "android" in
    its own supported_platforms and starts showing up here; nothing in this
    function or its callers needs to change."""
    return [a for a in _REGISTRY.values() if platform in a.supported_platforms]


def _register_builtin_adapters() -> None:
    # Imported lazily, inside a function, so importing this package doesn't
    # force-load every adapter module (and their optional dependencies) as a
    # side effect of an unrelated import elsewhere in the codebase.
    from drakrun.evasion.verifiers.alkhaser import AlKhaserAdapter
    from drakrun.evasion.verifiers.perdedor import PerdedorAdapter

    for adapter_cls in (PerdedorAdapter, AlKhaserAdapter):
        register(adapter_cls())


_register_builtin_adapters()


__all__ = [
    "register",
    "get_adapter",
    "all_adapters",
    "get_adapters_for_platform",
]
