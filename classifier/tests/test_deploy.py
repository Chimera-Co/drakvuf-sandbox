"""Checks deploy/ exactly the way the sandbox runs it (CHIMERA's runner.py, vendored from sprint/final).

Skipped until scripts/05_package.py has built deploy/. Point CHIMERA_DEPLOY at another folder to test it.
"""

import copy
import json
import os
import time
from pathlib import Path

import pytest

from chimera_runner import run_classifier

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = Path(os.environ.get("CHIMERA_DEPLOY", ROOT / "deploy"))
FIXTURE = json.loads((ROOT / "fixtures" / "bginfo-96f7ee81-features.json").read_text())
pytestmark = pytest.mark.skipif(not (DEPLOY / "model.py").exists(), reason="deploy/ not built yet")


def run(features):
    return run_classifier(features, str(ROOT / "fixtures"), str(DEPLOY / "model.py"), timeout_s=60)


def test_fixture_gives_valid_verdict_fast():
    t = time.time()
    v = run(FIXTURE)
    assert "error" not in v, v
    assert v["label"] in ("malicious", "suspicious", "benign", "unknown")
    assert 0.0 <= v["score"] <= 1.0 and v["explanation"]
    assert time.time() - t < 60  # the sandbox runner's limit; a cold first LightGBM import can take seconds


def test_linux_and_empty_runs_are_unknown():
    linux = copy.deepcopy(FIXTURE)
    linux["run"]["guest_os"] = "linux"
    assert run(linux)["label"] == "unknown"
    empty = copy.deepcopy(FIXTURE)
    empty["api_calls"], empty["api_sequence"] = {}, []
    assert run(empty)["label"] == "unknown"


def test_garbage_input_does_not_crash():
    v = run({"schema": "chimera-features/1", "run": {"guest_os": "windows"}, "api_calls": {"LdrLoadDll": "x"},
             "api_sequence": [None, 5], "files": None, "registry": [], "processes": "?", "network": 3})
    assert "error" not in v, v


# ---------------------------------------------------------------- dynamic + static fusion
STATIC = {k: json.loads((ROOT / "fixtures" / "static" / f"static-{k}.json").read_text()) for k in ("pe", "elf", "pdf", "ps1")}
has_static = pytest.mark.skipif(not (DEPLOY / "static_meta.json").exists(), reason="no static models packaged")
LABELS = ("malicious", "suspicious", "benign", "unknown")


def with_static(static, base=FIXTURE, **run):
    f = copy.deepcopy(base)
    f["run"].update(run)
    f["static"] = static
    return f


@has_static
def test_both_parts_reported():
    v = run(with_static(STATIC["pe"]))
    assert "error" not in v, v
    assert set(v["components"]) == {"dynamic", "static"}
    assert v["components"]["static"]["model"] == "chimera-static-pe"
    assert v["components"]["dynamic"]["label"] in LABELS and v["model"] == "chimera-fusion"


@has_static
def test_static_decides_when_dynamic_cannot():
    linux = with_static(STATIC["elf"], guest_os="linux")
    v = run(linux)
    assert v["components"]["dynamic"]["label"] == "unknown"
    assert v["components"]["static"]["model"] == "chimera-static-elf"
    assert v["label"] == v["components"]["static"]["label"] != "unknown"


@has_static
def test_static_error_falls_back_to_dynamic():
    v = run(with_static({"schema": "chimera-static/1", "error": "container timed out"}))
    assert v["components"]["static"]["label"] == "unknown"
    assert v["label"] == v["components"]["dynamic"]["label"]


@has_static
def test_rules_only_never_malicious_alone():
    empty = copy.deepcopy(FIXTURE)
    empty["api_calls"], empty["api_sequence"] = {}, []
    v = run(with_static(STATIC["ps1"], base=empty))
    assert v["components"]["static"]["model"] == "chimera-static-rules"
    assert v["components"]["static"]["weight"] == 0.5
    assert v["label"] in ("suspicious", "benign", "unknown")


@has_static
def test_malicious_pdf_static_only():
    empty = copy.deepcopy(FIXTURE)
    empty["api_calls"], empty["api_sequence"] = {}, []
    v = run(with_static(STATIC["pdf"], base=empty))
    assert v["components"]["static"]["model"] == "chimera-static-pdf"
    assert v["label"] in LABELS and "error" not in v


def test_garbage_static_block_does_not_crash():
    for junk in ({"schema": "chimera-static/1", "type": {"format": "pe"}, "ml": {"ember_v3": {"vector": [1, 2]}}},
                 {"type": "x"}, [], "nope", None):
        v = run(with_static(junk))
        assert "error" not in v, (junk, v)
