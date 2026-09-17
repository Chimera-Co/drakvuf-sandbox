"""Shared fixtures for the evasion-subsystem unit test tree.

These tests exercise only the parts of the Sandbox Evasion subsystem that
run without Xen, root, or a provisioned drakrun install: config/registry
parsing, adapters (against fixture bytes), scoring, and report generation.
See docs/usage/... (Windows-development limitations) for what is deferred to
the Debian/Xen environment instead.

DrakrunConfig loads from a fixed path (CONFIG_PATH) baked into its
model_config at class-definition time, and drakrun/web/api.py evaluates
load_config() at import time - so tests never rely on /etc/drakrun/config.toml
existing. Instead this fixture builds a DrakrunConfig subclass whose
model_config points at a temporary TOML file, the same trick used to smoke
test drakrun/lib/config.py during development.
"""

import pathlib

import pytest
from pydantic_settings import SettingsConfigDict

from drakrun.lib.config import DrakrunConfig

_BASE_TOML = """
[redis]
host = "localhost"

[network]
dns_server = "8.8.8.8"
out_interface = "default"
net_enable = true

[drakrun]
plugins = ["procmon"]
default_timeout = 60
"""


def make_config(tmp_path: pathlib.Path, extra_toml: str = "") -> DrakrunConfig:
    """Build a DrakrunConfig backed by a temporary TOML file containing the
    minimal required sections plus whatever extra_toml the test supplies."""
    toml_path = tmp_path / "config.toml"
    toml_path.write_text(_BASE_TOML + "\n" + extra_toml, encoding="utf-8")

    class _TestConfig(DrakrunConfig):
        model_config = SettingsConfigDict(
            extra="allow",
            toml_file=str(toml_path),
            env_prefix="drakrun_unit_test_unused__",
            nested_model_default_partial_update=True,
            env_nested_delimiter="__",
        )

    return _TestConfig()


@pytest.fixture
def config_factory(tmp_path):
    """Fixture form of make_config, bound to the test's own tmp_path."""

    def _factory(extra_toml: str = "") -> DrakrunConfig:
        return make_config(tmp_path, extra_toml)

    return _factory


@pytest.fixture
def base_config(config_factory) -> DrakrunConfig:
    """A DrakrunConfig with no [sandbox.*] or [evasion] customization at all -
    the zero-config / legacy-install case."""
    return config_factory()
