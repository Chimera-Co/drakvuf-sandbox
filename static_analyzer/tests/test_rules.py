"""YARA rules: the shipped ruleset is intact and compiles; the build gate refuses empty or broken rules."""

import hashlib
import json
from pathlib import Path

import pytest

from chimera_static import universal as U
from chimera_static.analyze import _yara_severity, analyze

RULES = Path(__file__).resolve().parents[1] / "rules"
MARKER = b"CHIMERA-YARA-TEST-MARKER-7f3c"
TEAM_RULE = """rule CHIMERA_Test_Marker {
    meta: category = "MALWARE" tc_detection_factor = 5 description = "team-made test rule"
    strings: $a = "CHIMERA-YARA-TEST-MARKER-7f3c"
    condition: $a
}
"""


def test_vendored_files_match_their_pins():
    pin = json.loads((RULES / "reversinglabs" / "SOURCE.json").read_text())
    assert pin["commit"] == "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84" and (RULES / "reversinglabs" / "LICENSE").is_file()
    on_disk = {str(p.relative_to(RULES / "reversinglabs")) for p in (RULES / "reversinglabs").rglob("*.yara")}
    assert on_disk == set(pin["files"])  # nothing added or dropped
    for rel, digest in pin["files"].items():
        assert hashlib.sha256((RULES / "reversinglabs" / rel).read_bytes()).hexdigest() == digest, rel


def test_severity_mapping():
    assert _yara_severity({"category": "MALWARE", "tc_detection_factor": 5}) == "high"
    assert _yara_severity({"category": "MALWARE", "tc_detection_factor": 1}) == "medium"
    assert _yara_severity({"category": "INFO"}) == "medium"
    assert _yara_severity({"severity": "low", "category": "MALWARE"}) == "low"


yara = pytest.importorskip("yara")
from chimera_static.rules_build import build  # noqa: E402


def test_shipped_rules_compile(tmp_path):
    info = build(str(RULES), str(tmp_path / "rules.yarc"))
    assert info["rules"] >= 1000 and info["sources"][0]["commit"].startswith("e0a0be54")


@pytest.mark.parametrize("content", [None, "rule broken { condition: nope }"])
def test_gate_refuses_empty_or_broken(tmp_path, content):
    src = tmp_path / "src"
    src.mkdir()
    if content:
        (src / "x.yar").write_text(content)
    with pytest.raises(SystemExit):
        build(str(src), str(tmp_path / "rules.yarc"))


def test_team_rule_matches_and_is_reported(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "team.yar").write_text(TEAM_RULE)
    build(str(src), str(tmp_path / "rules.yarc"))
    monkeypatch.setenv("CHIMERA_STATIC_YARA", str(tmp_path / "rules.yarc"))
    monkeypatch.setattr(U, "_yara_rules", None)
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"padding " + MARKER + b" padding")
    r = analyze(str(sample), ember=False)
    hit = [f for f in r["findings"] if f["id"] == "yara_CHIMERA_Test_Marker"]
    assert hit and hit[0]["severity"] == "high"
    assert r["universal"]["yara_ruleset"]["rules"] == 1
    assert "yara" not in r["coverage"]["failed_stages"]
