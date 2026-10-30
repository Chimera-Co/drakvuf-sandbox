"""Maltrail trails index, sync and report attribution on a synthetic checkout (no real trail data)."""

import json
import subprocess
from datetime import datetime, timezone

import pytest

from drakrun.lib.config import IntelConfigSection
from drakrun.lib.intel import trails

APT = """# Copyright (c) fixture
# Aliases: fixture group, fg-1

# Reference: https://ref.example/one

c2.fixture-apt.example
evil.example
203.0.113.10
198.51.100.7:8443

# Reference: https://ref.example/two

http://203.0.113.20/gate.php
/panel/check.php?id=
[a-z]+\\.regex\\.example
"""
FILES = {
    "malware/apt_fixture.txt": APT,
    "malware/commodity_rat.txt": "# Reference: https://ref.example/rat\n\nwindowsupdate.example\n",
    "suspicious/parking_site.txt": "# Reference: https://ref.example/park\n\n192.0.2.0/24\n",
    "suspicious/onion.txt": "# Reference: https://ref.example/onion\n\n.onion\n",
    "LICENSE.md": "fixture licence\n",
}
META = {
    "commit": "fixture",
    "committed_at": "2026-10-28T20:00:00+00:00",
    "source": "fixture",
    "license_sha256": "0" * 64,
}
NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)


def checkout(root, files=FILES):
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


@pytest.mark.parametrize(
    "line,expected",
    [
        ("Evil.Example", ("domain", "evil.example")),
        ("203.0.113.10", ("ip", "203.0.113.10")),
        ("198.51.100.7:8443", ("ip_port", "198.51.100.7:8443")),
        ("192.0.2.0/24", ("cidr", "192.0.2.0/24")),
        ("http://203.0.113.20", ("ip", "203.0.113.20")),
        ("HOST.example/a/B.php", ("url", "host.example/a/B.php")),
        ("/panel/check.php?id=", ("path", "/panel/check.php?id=")),
        (".onion", ("tld", "onion")),
        ("tz.example    # Note: inline", ("domain", "tz.example")),
        ("[a-z]+\\.regex\\.example", None),
        ("2.56.177.203:0", None),
    ],
)
def test_entry_kinds(line, expected):
    assert trails.entry(line) == expected


def test_family_names():
    assert trails.family_of("malware", "apt_lazarus") == ("lazarus", True)
    assert trails.family_of("malware", "apt_12") == ("apt 12", True)
    assert trails.family_of("suspicious", "dynamic_domain") == ("dynamic domain", False)


def test_build_and_match(tmp_path):
    db = tmp_path / "trails.db"
    meta = trails.build(checkout(tmp_path / "trails"), db, META)
    assert meta["counts"] == {"malware": 7, "suspicious": 2}
    assert meta["skipped"] == {"malware": 1} and meta["apt_trails"] == 1
    result = trails.match(
        db,
        [
            ("domain", "x.c2.fixture-apt.example", "dynamic"),
            ("ip_port", "203.0.113.10:443", "dynamic"),
            ("url", "http://203.0.113.20/gate.php", "dynamic"),
            ("url", "http://any.example/panel/check.php?id=5&x=1", "dynamic"),
            ("ip", "192.0.2.9", "dynamic"),
            ("domain", "hidden.onion", "dynamic"),
            ("domain", "strings.onion", "static"),
            ("domain", "benign.example", "dynamic"),
        ],
        now=NOW,
    )
    by_indicator = {m["indicator"]: m for m in result["matches"]}
    assert set(by_indicator) == {
        "x.c2.fixture-apt.example",
        "203.0.113.10:443",
        "http://203.0.113.20/gate.php",
        "http://any.example/panel/check.php?id=5&x=1",
        "192.0.2.9",
    }
    # The .onion trail is a bare TLD: a weak note for the run-time name only, never a family.
    assert result["suspicious_tlds"] == [
        {
            "tld": "onion",
            "file": "suspicious/onion.txt",
            "indicators": ["hidden.onion"],
            "observed_in": ["dynamic"],
            "references": ["https://ref.example/onion"],
        }
    ]
    assert "suspicious/onion.txt" not in {f["file"] for f in result["families"]}
    first = by_indicator["x.c2.fixture-apt.example"]
    assert (first["family"], first["apt"], first["trail"]) == (
        "fixture",
        True,
        "c2.fixture-apt.example",
    )
    assert first["aliases"] == ["fixture group", "fg-1"]
    assert first["references"] == ["https://ref.example/one"]
    assert by_indicator["http://203.0.113.20/gate.php"]["references"] == [
        "https://ref.example/two"
    ]
    assert by_indicator["192.0.2.9"]["trail"] == "192.0.2.0/24"
    assert result["families"][0]["family"] == "fixture"
    assert len(result["families"][0]["indicators"]) == 4
    assert not result["stale"]


def git(directory, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example", "-C", str(directory), *args],
        check=True,
        capture_output=True,
    )


def test_sync_logs_the_diff_and_rebuilds(tmp_path, monkeypatch):
    monkeypatch.setattr(trails, "PROTOCOLS", ("file",))
    origin = checkout(tmp_path / "origin")
    git(origin, "init", "-q", "-b", "main")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "one")
    db, log = tmp_path / "trails.db", tmp_path / "changes.jsonl"
    local = tmp_path / "state" / "trails"
    url = f"file://{origin}"
    first = trails.sync(local, db, log, url=url)
    assert first["status"] == "rebuilt" and first["from"] is None
    assert trails.sync(local, db, log, url=url)["status"] == "unchanged"

    (origin / "malware/apt_fixture.txt").write_text(APT + "\nnew-c2.example\n")
    (origin / "LICENSE.md").write_text("changed licence\n")
    git(origin, "commit", "-qam", "two")
    third = trails.sync(local, db, log, url=url)
    assert third["status"] == "rebuilt" and third["license_changed"]
    assert third["files_changed"] == 1 and third["added"] == 2
    assert third["apt_added"] == [
        {"file": "malware/apt_fixture.txt", "indicators": ["new-c2.example"]}
    ]
    assert [json.loads(line)["status"] for line in log.read_text().splitlines()] == [
        "rebuilt",
        "unchanged",
        "rebuilt",
    ]
    found = trails.match(db, [("domain", "new-c2.example", "dynamic")], now=NOW)
    assert found["matches"][0]["family"] == "fixture"


def test_report_attributes_only_the_sample_tree(tmp_path):
    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
        iocs_export,
    )

    from .test_chimera_report import write_analysis

    db = tmp_path / "trails.db"
    trails.build(checkout(tmp_path / "trails"), db, META)
    directory = write_analysis(
        tmp_path / "analysis", verdict={"label": "benign", "explanation": []}
    )
    config = IntelConfigSection(
        enabled=True, db_path=tmp_path / "absent.db", trails_db_path=db
    )
    result = build_report(directory, intel_config=config)
    stage = result["stages"]["intel"]
    assert stage["status"] == "ok" and "Maltrail: fixture (APT)" in stage["reason"]
    matches = stage["payload"]["attribution"]["matches"]
    # windowsupdate.example is listed too, but only svchost (not the sample tree) asked for it.
    assert [(m["indicator"], m["observed_in"]) for m in matches] == [
        ("evil.example", "dynamic")
    ]
    assert matches[0]["evidence_ids"]
    claim = next(c for c in result["claims"] if c["id"] == "attribution-0")
    assert "fixture trail (APT group)" in claim["text"]
    assert result["assessment"]["attribution"] == [
        {"family": "fixture", "apt": True, "category": "malware"}
    ]
    assert any(
        i["source"] == "maltrail:malware/apt_fixture.txt"
        for i in iocs_export(result)["iocs"]
    )
    assert (directory / "intel-attribution.json").is_file()
    without = IntelConfigSection(enabled=True, db_path=tmp_path / "absent.db")
    assert build_report(directory, intel_config=without)["stages"]["intel"][
        "status"
    ] == "unavailable"


# suspicious/domain.txt upstream mixes bare TLDs with full domains.
TLD_FILES = {
    **FILES,
    "suspicious/domain.txt": "# Reference: https://ref.example/tld\n\n.cc\n.pw\ncz.cc\n",
}


def test_bare_tld_is_never_a_family(tmp_path):
    db = tmp_path / "trails.db"
    trails.build(checkout(tmp_path / "trails", TLD_FILES), db, META)
    result = trails.match(
        db,
        [
            # Random strings from a packed file's static strings.
            ("domain", "rgu.cc", "static"),
            ("domain", "p.pw", "static"),
            ("url", "http://fc.pw/x", "static"),
            # Names the sample used at run time.
            ("domain", "c2.example.cc", "dynamic"),
            ("url", "http://c2.example.cc/gate", "dynamic"),
            ("domain", "q.example.pw", "unattributed"),
            # A full domain listed in the same file still matches, from either origin.
            ("domain", "x.cz.cc", "static"),
            # A real family from a static string still matches.
            ("domain", "evil.example", "static"),
        ],
        now=NOW,
    )
    assert sorted((m["indicator"], m["file"]) for m in result["matches"]) == [
        ("evil.example", "malware/apt_fixture.txt"),
        ("x.cz.cc", "suspicious/domain.txt"),
    ]
    assert all(m["trail"] not in {"cc", "pw"} for m in result["matches"])
    families = {f["file"]: f for f in result["families"]}
    assert families["malware/apt_fixture.txt"]["apt"]
    assert families["suspicious/domain.txt"]["indicators"] == ["x.cz.cc"]
    weak = {t["tld"]: t for t in result["suspicious_tlds"]}
    assert set(weak) == {"cc", "pw"}
    assert weak["cc"]["indicators"] == ["c2.example.cc", "http://c2.example.cc/gate"]
    assert weak["cc"]["observed_in"] == ["dynamic"]
    assert weak["pw"] == {
        "tld": "pw",
        "file": "suspicious/domain.txt",
        "indicators": ["q.example.pw"],
        "observed_in": ["unattributed"],
        "references": ["https://ref.example/tld"],
    }


def test_static_tld_strings_add_no_attribution_or_runtime_iocs(tmp_path):
    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
        iocs_export,
    )

    from .test_chimera_report import write_analysis

    db = tmp_path / "trails.db"
    trails.build(checkout(tmp_path / "trails", TLD_FILES), db, META)
    strings = ["rgu.cc", "ut.cc", "p.pw", "fc.pw", "c2.fixture-apt.example"]
    static = {"universal": {"iocs": {"domains": strings}}}
    directory = write_analysis(
        tmp_path / "analysis",
        static=static,
        verdict={"label": "benign", "explanation": []},
    )
    report = json.loads((directory / "report.json").read_text())
    report["dns_queries"].append({"domain": "c2.example.cc", "process_seqid": 11})
    (directory / "report.json").write_text(json.dumps(report))
    config = IntelConfigSection(
        enabled=True, db_path=tmp_path / "absent.db", trails_db_path=db
    )
    result = build_report(directory, intel_config=config)
    stage = result["stages"]["intel"]
    attribution = stage["payload"]["attribution"]
    assert {f["family"] for f in attribution["families"]} == {"fixture"}
    assert [(t["tld"], t["indicators"]) for t in attribution["suspicious_tlds"]] == [
        ("cc", ["c2.example.cc"])
    ]
    assert attribution["suspicious_tlds"][0]["evidence_ids"]
    assert "Maltrail: fixture (APT)" in stage["reason"]
    assert "suspicious TLD only: .cc" in stage["reason"]
    assert "domain" not in stage["reason"].split("suspicious TLD")[0]
    assert result["assessment"]["attribution"] == [
        {"family": "fixture", "apt": True, "category": "malware"}
    ]
    assert not any(
        c["id"].startswith("attribution-") and "domain trail" in c["text"]
        for c in result["claims"]
    )
    maltrail = [
        i for i in iocs_export(result)["iocs"] if i["source"].startswith("maltrail:")
    ]
    # No IOC from a bare TLD; the static family hit keeps its "not observed in use" origin.
    assert sorted((i["value"], i["source"], i["observed_in"]) for i in maltrail) == [
        (
            "c2.fixture-apt.example",
            "maltrail:malware/apt_fixture.txt; string in the file (not observed in use)",
            "static",
        ),
        ("evil.example", "maltrail:malware/apt_fixture.txt", "dynamic"),
    ]
    on_disk = json.loads((directory / "intel-attribution.json").read_text())
    assert on_disk["suspicious_tlds"][0]["tld"] == "cc"
    assert all(m["trail"] not in {"cc", "pw"} for m in on_disk["matches"])
