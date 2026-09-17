"""Tests for drakrun.evasion.sandbox_registry.

Covers the Phase 1 testing-strategy items "sandbox enumeration" and
"capability filtering" (see docs / implementation plan sec. 14):
- a config with 0, 1, and 3 [sandbox.*] tables
- the zero-config synthesized default
- unknown-id lookup raising SandboxNotFound
- a Linux-only sandbox excluding tools it did not declare (capability
  filtering itself - intersecting with what each adapter supports - is
  exercised in test_verifier_registry.py once the adapters exist; this file
  covers the registry's own declared-tools behaviour).
"""

import pytest

from drakrun.evasion.sandbox_registry import (
    DEFAULT_SANDBOX_ID,
    SandboxNotFound,
    get_sandbox_registry,
    resolve_sandbox,
)

_ONE_SANDBOX = """
[sandbox.win10-base]
display_name = "Windows 10 -- Current"
platform = "windows"
verifiers = ["perdedor", "alkhaser"]
"""

_THREE_SANDBOXES = """
[sandbox.win10-base]
display_name = "Windows 10 -- Current"
platform = "windows"
verifiers = ["perdedor", "alkhaser"]

[sandbox.win11-base]
display_name = "Windows 11 -- Current"
platform = "windows"
os_version = "11"
verifiers = ["perdedor", "alkhaser"]

[sandbox.linux-bios]
display_name = "Linux (BIOS)"
platform = "linux"
firmware = "bios"
verifiers = ["perdedor"]
"""


def test_zero_sandbox_tables_synthesizes_default(base_config):
    registry = get_sandbox_registry(base_config)

    assert len(registry) == 1
    assert registry[0].id == DEFAULT_SANDBOX_ID
    assert registry[0].platform == "windows"
    assert set(registry[0].verifiers) == {"perdedor", "alkhaser"}


def test_one_sandbox_table(config_factory):
    config = config_factory(_ONE_SANDBOX)
    registry = get_sandbox_registry(config)

    assert len(registry) == 1
    assert registry[0].id == "win10-base"
    assert registry[0].display_name == "Windows 10 -- Current"
    assert registry[0].platform == "windows"


def test_three_sandbox_tables(config_factory):
    config = config_factory(_THREE_SANDBOXES)
    registry = get_sandbox_registry(config)

    assert len(registry) == 3
    by_id = {s.id: s for s in registry}
    assert by_id["win10-base"].platform == "windows"
    assert by_id["win11-base"].os_version == "11"
    assert by_id["linux-bios"].platform == "linux"
    assert by_id["linux-bios"].firmware == "bios"


def test_linux_sandbox_does_not_declare_alkhaser(config_factory):
    """Capability filtering starts here: a sandbox simply never lists a tool
    it doesn't support, so the API layer's intersection with adapter
    platform-support has nothing to filter out in the first place."""
    config = config_factory(_THREE_SANDBOXES)
    linux_sandbox = resolve_sandbox(config, "linux-bios")

    assert "alkhaser" not in linux_sandbox.verifiers
    assert "perdedor" in linux_sandbox.verifiers


def test_resolve_unknown_sandbox_raises(config_factory):
    config = config_factory(_THREE_SANDBOXES)

    with pytest.raises(SandboxNotFound):
        resolve_sandbox(config, "does-not-exist")


def test_resolve_known_sandbox_roundtrips_fields(config_factory):
    config = config_factory(_THREE_SANDBOXES)
    sandbox = resolve_sandbox(config, "win11-base")

    assert sandbox.id == "win11-base"
    assert sandbox.display_name == "Windows 11 -- Current"
    assert sandbox.hypervisor == "xen"  # default, not declared in the fixture
    assert sandbox.lifecycle == "drakrun-vm"  # default


def test_sandbox_definition_to_dict_is_json_safe(config_factory):
    config = config_factory(_ONE_SANDBOX)
    sandbox = resolve_sandbox(config, "win10-base")
    data = sandbox.to_dict()

    assert data["id"] == "win10-base"
    assert isinstance(data["verifiers"], list)
