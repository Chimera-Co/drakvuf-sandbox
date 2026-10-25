"""Synthetic provider responses; every connection and HTTP operation is mocked."""

import json
import socket
from unittest.mock import MagicMock
from urllib.error import HTTPError

import pytest

from drakrun.lib.config import IntelConfigSection
from drakrun.lib.intel.online import base, inventory, providers
from drakrun.lib.intel.online.cache import Cache
from drakrun.lib.intel.online.run import assessment, collect, run

HASH = "a" * 64
FIXTURES = {
    "virustotal": {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 12, "harmless": 2},
                "tags": ["fixture"],
                "popular_threat_classification": {
                    "suggested_threat_label": "test-family"
                },
            }
        }
    },
    "malwarebazaar": {
        "query_status": "ok",
        "data": [{"signature": "test-family", "tags": ["fixture"]}],
    },
    "threatfox": {
        "query_status": "ok",
        "data": [{"malware_printable": "test-family", "confidence_level": 90}],
    },
    "urlhaus": {
        "query_status": "ok",
        "threat": "malware_download",
        "tags": ["fixture"],
    },
    "otx": {
        "pulse_info": {
            "count": 1,
            "pulses": [{"name": "fixture", "attack_ids": ["T1059"]}],
        }
    },
    "abuseipdb": {"data": {"abuseConfidenceScore": 90, "totalReports": 5}},
    "greynoise": {
        "noise": True,
        "riot": True,
        "classification": "benign",
        "name": "scanner",
    },
    "hashlookup": {"SHA-256": HASH, "FileName": "known.exe", "source": "NSRL"},
    "hybridanalysis": [
        {"verdict": "malicious", "threat_score": 90, "vx_family": "test-family"}
    ],
    "urlscan": {
        "total": 1,
        "results": [
            {
                "result": "https://urlscan.io/api/v1/result/fixture/",
                "verdicts": {"overall": {"malicious": True}},
            }
        ],
    },
}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    config = IntelConfigSection(
        keys_dir=tmp_path / "keys",
        abusech_key_file=tmp_path / "abuse-key",
        cache_path=tmp_path / "cache.sqlite",
    )
    config.keys_dir.mkdir()
    config.abusech_key_file.write_text("secret-fixture-key")
    for provider in providers():
        (config.keys_dir / provider.id).write_text("secret-fixture-key\n")
    monkeypatch.setattr(base, "probe", lambda host: True)
    opener = MagicMock()
    monkeypatch.setattr(base.urllib.request, "build_opener", lambda *args: opener)
    return config, Cache(config.cache_path), opener


@pytest.mark.parametrize("provider", providers(), ids=lambda p: p.id)
def test_parsing_and_cache(provider, setup, caplog):
    config, cache, opener = setup
    kind = provider.types[0]
    value = (
        HASH if kind in base.HASHES else "8.8.8.8" if kind == "ip" else "example.org"
    )
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
        FIXTURES[provider.id]
    ).encode()
    result = provider.lookup(kind, value, config, cache)
    assert result["status"] == "ok"
    assert provider.lookup(kind, value, config, cache) == result
    assert opener.open.call_count == 1
    request = opener.open.call_args.args[0]
    assert request.full_url.startswith("https://")
    assert "secret-fixture-key" not in request.full_url
    assert opener.open.call_args.kwargs["timeout"] == 10
    assert "secret-fixture-key" not in json.dumps(result) + caplog.text
    assert "secret-fixture-key" not in json.dumps(inventory(config))


@pytest.mark.parametrize(
    "code,status",
    [(404, "not_found"), (401, "error"), (403, "error"), (429, "rate_limited")],
)
def test_http_failures(setup, code, status):
    config, cache, opener = setup
    opener.open.side_effect = HTTPError(
        "https://example.invalid/secret-fixture-key",
        code,
        "secret-fixture-key",
        {},
        None,
    )
    result = providers()[0].lookup("sha256", HASH, config, cache)
    assert result["status"] == status
    assert "secret-fixture-key" not in json.dumps(result)


def test_timeout_offline_missing_key(setup, monkeypatch):
    config, cache, opener = setup
    opener.open.side_effect = socket.timeout("secret-fixture-key")
    provider = providers()[0]
    assert (
        provider.lookup("sha256", HASH, config, cache)["details"]["reason"] == "timeout"
    )
    monkeypatch.setattr(base, "probe", lambda host: False)
    assert provider.lookup("sha256", HASH, config, cache)["status"] == "offline"
    (config.keys_dir / provider.id).unlink()
    assert provider.lookup("sha256", HASH, config, cache)["status"] == "not_configured"


def test_echo_rejected(setup, caplog):
    config, cache, opener = setup
    doc = FIXTURES["virustotal"]["data"]["attributes"].copy()
    doc["tags"] = ["secret-fixture-key"]
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
        {"data": {"attributes": doc}}
    ).encode()
    result = providers()[0].lookup("sha256", HASH, config, cache)
    assert result["status"] == "error"
    assert "secret-fixture-key" not in json.dumps(result) + caplog.text
    assert cache.get("virustotal", "sha256", HASH) is None


def test_budget_and_expiry(setup, monkeypatch):
    _, cache, _ = setup
    monkeypatch.setattr("drakrun.lib.intel.online.cache.time.time", lambda: 100000)
    assert cache.reserve("vt", 15, 1)
    assert not cache.reserve("vt", 15, 1)
    monkeypatch.setattr("drakrun.lib.intel.online.cache.time.time", lambda: 100020)
    assert not cache.reserve("vt", 15, 1)
    monkeypatch.setattr("drakrun.lib.intel.online.cache.time.time", lambda: 200000)
    assert cache.reserve("vt", 15, 1)


def test_selection_never_reads_sample(setup, tmp_path, monkeypatch):
    config, _, _ = setup
    config.max_observables = 2
    directory = tmp_path / "analysis"
    directory.mkdir()
    (directory / "metadata.json").write_text(json.dumps({"file": {"sha256": HASH}}))
    (directory / "static.json").write_text(
        json.dumps(
            {
                "universal": {
                    "iocs": {
                        "ips": [
                            "127.0.0.1",
                            "10.99.0.1",
                            "192.168.1.1",
                            "224.0.0.1",
                            "8.8.8.8",
                            "1.1.1.1",
                            "9.9.9.9",
                        ],
                        "domains": ["a.example", "b.example", "c.example"],
                        "urls": ["http://127.0.0.1/private"],
                    }
                }
            }
        )
    )
    from pathlib import Path

    original = Path.open

    def guarded(path, *args, **kwargs):
        assert path.suffix == ".json", "only JSON artifacts may be opened"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    result = collect(directory, directory, config)
    assert result[0] == ("sha256", HASH)
    assert [v for k, v in result if k == "ip"] == ["8.8.8.8", "1.1.1.1"]
    assert len([v for k, v in result if k == "domain"]) == 2
    assert not any(k == "url" for k, v in result)


@pytest.mark.parametrize(
    "provider,engines,label,expected,basis",
    [
        ("malwarebazaar", 0, "benign", "malicious", "known malware"),
        ("threatfox", 0, "benign", "malicious", "known malware"),
        ("virustotal", 10, "benign", "malicious", "engine consensus"),
        ("virustotal", 3, "benign", "suspicious", "engine consensus"),
        ("virustotal", 9, "malicious", "malicious", "engine consensus"),
        ("hashlookup", 0, "unknown", "benign", "known software"),
        ("hashlookup", 0, "malicious", "malicious", "behaviour model"),
    ],
)
def test_assessment(provider, engines, label, expected, basis):
    result = assessment(
        label,
        [
            dict(
                provider=provider,
                type="sha256",
                status="ok",
                verdict="harmless",
                detections={"malicious": engines},
            )
        ],
    )
    assert (result["label"], result["basis"]) == (expected, basis)


def test_offline_orchestration(setup, tmp_path, monkeypatch):
    config, _, opener = setup
    monkeypatch.setattr(base, "probe", lambda host: False)
    (tmp_path / "metadata.json").write_text(json.dumps({"file": {"sha256": HASH}}))
    result = run(tmp_path, tmp_path, config)
    assert result["connectivity"] == "offline"
    assert len(result["providers"]) == 10
    assert all(r["status"] == "offline" for r in result["results"])
    opener.open.assert_not_called()


def test_report_stage_and_evidence(tmp_path):
    import uuid

    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
    )

    from .test_chimera_report import write_analysis

    directory = write_analysis(
        tmp_path / str(uuid.uuid4()), verdict={"label": "benign", "explanation": []}
    )
    static_dir = tmp_path / "static"
    target = static_dir / directory.name
    target.mkdir(parents=True)
    (target / "intel-online.json").write_text(
        json.dumps(
            dict(
                schema="chimera-intel-online/1",
                connectivity="online",
                providers=[],
                results=[
                    dict(
                        provider="malwarebazaar",
                        observable=HASH,
                        type="sha256",
                        status="ok",
                        verdict="malicious",
                        family="fixture",
                    )
                ],
                summary={},
            )
        )
    )
    report = build_report(
        directory, static_dir=static_dir, intel_config=IntelConfigSection()
    )
    assert report["assessment"]["label"] == "malicious"
    assert report["stages"]["classifier"]["payload"]["label"] == "benign"
    assert report["stages"]["intel"]["status"] == "ok"
    assert report["stages"]["intel"]["payload"]["online"]["connectivity"] == "online"
    assert any(
        i["source"] == "intel:malwarebazaar" and i["evidence_ids"]
        for i in report["iocs"]
    )
    assert (directory / "intel-online.json").exists()
    assert any(
        c["id"] == "intel-online-0" and c["evidence_ids"] for c in report["claims"]
    )


@pytest.mark.parametrize(
    "name,doc",
    [
        ("malwarebazaar", {"query_status": "hash_not_found"}),
        ("threatfox", {"query_status": "no_result"}),
        ("urlhaus", {"query_status": "no_results"}),
        ("hybridanalysis", []),
        ("urlscan", {"results": []}),
        ("hashlookup", {}),
    ],
)
def test_provider_not_found(name, doc):
    provider = next(p for p in providers() if p.id == name)
    assert provider.parse(doc, provider.types[0], HASH)["status"] == "not_found"


def test_probe_socket_timeout(monkeypatch):
    monkeypatch.setattr(
        socket, "create_connection", MagicMock(side_effect=TimeoutError)
    )
    assert base.probe("example.invalid") is False
    socket.create_connection.assert_called_once_with(
        ("example.invalid", 443), timeout=3
    )


def test_response_cap(setup):
    config, cache, opener = setup
    opener.open.return_value.__enter__.return_value.read.return_value = b" " * (
        2 * 1024 * 1024 + 1
    )
    assert providers()[0].lookup("sha256", HASH, config, cache)["status"] == "error"


def test_redirect_refused():
    with pytest.raises(ValueError, match="redirect refused"):
        base.NoRedirect().redirect_request(
            None, None, 302, "", {}, "https://other.invalid"
        )


def test_enqueue_gates_and_queue(setup, monkeypatch):
    from types import SimpleNamespace

    from drakrun.lib.intel.online.run import enqueue

    config, _, _ = setup
    monkeypatch.setattr(
        "drakrun.lib.config.load_config", lambda: SimpleNamespace(intel=config)
    )
    queue = MagicMock()
    monkeypatch.setattr("rq.Queue", queue)
    assert enqueue("fixture", object(), {"intel_online": True}) is None
    config.online_enabled = True
    assert enqueue("fixture", object(), {"intel_online": False}) is None
    connection = object()
    enqueue("fixture", connection, {"intel_online": True})
    queue.assert_called_once_with(name="chimera-intel", connection=connection)
    assert queue.return_value.enqueue.call_args.args[1] == "fixture"


def test_memory_iocs_and_guest_address_excluded(setup, tmp_path):
    from types import SimpleNamespace

    config, _, _ = setup
    (tmp_path / "memdumps.json").write_text(
        json.dumps(
            {
                "scanned": [
                    {
                        "iocs": {
                            "domains": ["memory.example"],
                            "ips": ["8.8.8.8", "1.1.1.1"],
                        }
                    }
                ]
            }
        )
    )
    result = collect(tmp_path, tmp_path, config, SimpleNamespace(dns_server="8.8.8.8"))
    assert ("domain", "memory.example") in result
    assert ("ip", "8.8.8.8") not in result
    assert ("ip", "1.1.1.1") in result


def test_hashlookup_malicious_marker_cannot_make_benign():
    provider = next(p for p in providers() if p.id == "hashlookup")
    row = provider.parse(
        {"FileName": "fixture", "KnownMalicious": True}, "sha256", HASH
    )
    assert row["verdict"] != "harmless"


def test_pacing_waits_instead_of_skipping(setup, monkeypatch):
    config, cache, opener = setup
    provider = next(p for p in providers() if p.id == "virustotal")
    opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(
        FIXTURES["virustotal"]
    ).encode()
    clock = {"now": 1000.0}
    monkeypatch.setattr(
        "drakrun.lib.intel.online.cache.time.time", lambda: clock["now"]
    )
    monkeypatch.setattr(base.time, "monotonic", lambda: clock["now"])
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(base.time, "sleep", sleep)
    assert provider.lookup("sha256", HASH, config, cache)["status"] == "ok"
    assert provider.lookup("sha256", "b" * 64, config, cache)["status"] == "ok"
    assert slept == [15.0]  # VirusTotal's spacing, waited out once
    assert opener.open.call_count == 2


def test_daily_cap_and_long_waits_are_rate_limited(setup, monkeypatch):
    _, cache, _ = setup
    monkeypatch.setattr("drakrun.lib.intel.online.cache.time.time", lambda: 100000)
    assert cache.delay("vt", 15, 2) == 0.0
    assert cache.reserve("vt", 15, 2)
    assert cache.delay("vt", 15, 2) == 15.0
    monkeypatch.setattr("drakrun.lib.intel.online.cache.time.time", lambda: 100020)
    assert cache.reserve("vt", 15, 2)
    assert cache.delay("vt", 15, 2) is None  # today's budget is spent


def test_one_hash_per_sample_and_observed_first(setup, tmp_path):
    config, _, _ = setup
    directory = tmp_path / "ordered"
    directory.mkdir()
    (directory / "metadata.json").write_text(
        json.dumps({"file": {"sha256": HASH, "sha1": "c" * 40, "md5": "d" * 32}})
    )
    (directory / "report.json").write_text(
        json.dumps({"dns_queries": [{"domain": "observed.example"}]})
    )
    (directory / "static.json").write_text(
        json.dumps({"universal": {"iocs": {"domains": ["string.example"]}}})
    )
    selected = collect(directory, directory, config)
    assert selected[0] == ("sha256", HASH)
    assert ("sha1", "c" * 40) not in selected and ("md5", "d" * 32) not in selected
    domains = [v for k, v in selected if k == "domain"]
    assert domains == ["observed.example", "string.example"]


def test_per_provider_lookup_budget(setup, tmp_path, monkeypatch):
    config, _, _ = setup
    looked = []
    monkeypatch.setattr(
        base.Provider,
        "lookup",
        lambda self, kind, value, cfg, cache: looked.append((self.id, value))
        or self.result(kind, value),
    )
    directory = tmp_path / "budget"
    directory.mkdir()
    (directory / "report.json").write_text(
        json.dumps({"dns_queries": [{"domain": f"d{i}.example"} for i in range(12)]})
    )
    run(directory, directory, config)
    assert sum(1 for p, _ in looked if p == "virustotal") == 6
    assert sum(1 for p, _ in looked if p == "urlscan") == 5


def test_enqueue_uses_the_pipeline_job_id(setup, monkeypatch):
    from types import SimpleNamespace

    from drakrun.lib.intel.online.run import enqueue

    config, _, _ = setup
    config.online_enabled = True
    monkeypatch.setattr(
        "drakrun.lib.config.load_config", lambda: SimpleNamespace(intel=config)
    )
    queue = MagicMock()
    monkeypatch.setattr("rq.Queue", queue)
    enqueue("fixture", object(), {"intel_online": True})
    assert queue.return_value.enqueue.call_args.kwargs["job_id"] == (
        "intel-online-fixture"
    )
