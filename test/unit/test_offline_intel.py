"""Synthetic snapshots only: no provider access or sample data."""

import io
import json
import socket
import tarfile
from datetime import datetime, timedelta, timezone

import pytest

from drakrun.lib.config import IntelConfigSection
from drakrun.lib.intel import import_bundle, match, normalize, read_bundle
from drakrun.lib.intel.builder import build, parse_feed

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket, "socket", blocked)


def feed(name="test", fmt="text", kind="domain", **extra):
    return {
        "name": name,
        "format": fmt,
        "url": "https://feeds.example/test",
        "indicator_types": [kind],
        "license": "synthetic",
        "max_age_days": 1,
        **extra,
    }


def bundle(tmp_path, feeds=None, contents=None, now=NOW, **kwargs):
    feeds = feeds or [feed()]
    contents = contents or {"test": b"evil.example\n"}

    def fetcher(spec, *args):
        source = tmp_path / (spec["name"] + ".synthetic")
        source.write_bytes(contents[spec["name"]])
        return source.read_bytes(), "test-modified", '"etag"'

    return build(feeds, tmp_path, fetcher=fetcher, now=now, **kwargs)[0]


@pytest.mark.parametrize(
    "fmt,raw,kind,expected",
    [
        (
            "malwarebazaar",
            "# first_seen_utc,sha256_hash,md5_hash,sha1_hash,signature\n2026,"
            + "A" * 64
            + ","
            + "B" * 32
            + ","
            + "C" * 40
            + ",Synthetic\n",
            "sha256",
            3,
        ),
        (
            "urlhaus",
            '# comment\n"1","2026","https://EVIL.example/Case?Q=A","online","","malware","tag","reference","test"\n',
            "url",
            1,
        ),
        (
            "threatfox",
            '{"1":[{"ioc_type":"domain","ioc":"EVIL.example","tags":["test"]}]}',
            "domain",
            1,
        ),
        (
            "feodo",
            '[{"ip_address":"2001:db8::1","port":443,"malware":"test"}]',
            "ip",
            2,
        ),
        (
            "sslbl",
            "# Dateadded,SHA1,Listingreason\n2026," + "A" * 40 + ",test\n",
            "sslcert_sha1",
            1,
        ),
        (
            "sslbl",
            "# First_seen,Ja3_md5,Malware\n2026," + "A" * 32 + ",test\n",
            "ja3",
            1,
        ),
        ("misp_warninglist", '{"list":["Example.COM.","2001:db8::1"]}', "allowlist", 2),
        ("text", "# comment\nEVIL.example.\n", "domain", 1),
    ],
)
def test_formats(tmp_path, fmt, raw, kind, expected):
    source = tmp_path / "synthetic-feed"
    source.write_text(raw)
    rows = parse_feed(source.read_bytes(), feed(fmt=fmt, kind=kind))
    assert len(rows) == expected
    assert all("tags" in r and "reference" in r for r in rows)


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("domain", "BÜCHER.Example.", "xn--bcher-kva.example"),
        (
            "url",
            "HTTPS://BÜCHER.Example/Case?Q=A",
            "https://xn--bcher-kva.example/Case?Q=A",
        ),
        ("ip", "2001:0DB8::1", "2001:db8::1"),
        ("ip_port", "[2001:0DB8::1]:0443", "[2001:db8::1]:443"),
        ("sha256", "A" * 64, "a" * 64),
    ],
)
def test_normalization(kind, value, expected):
    assert normalize(kind, value) == expected


def test_import_match_history_and_suppression(tmp_path):
    specs = [
        feed(match_subdomains=True),
        feed("allow", "misp_warninglist", "allowlist"),
    ]
    path = bundle(
        tmp_path,
        specs,
        {"test": b"evil.example\nexample.com\n", "allow": b'{"list":["example.com"]}'},
    )
    manifest, files = read_bundle(path)
    assert manifest["schema"] == "chimera-intel-bundle/1"
    assert manifest["feeds"][0]["sha256"]
    db = tmp_path / "intel.db"
    for _ in range(4):
        import_bundle(path, db)
    import sqlite3

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM imports").fetchone()[0] == 3
    result = match(
        db,
        [
            ("domain", "sub.evil.example", "dynamic"),
            ("domain", "notevil.example", "static"),
            ("domain", "example.com", "dynamic"),
        ],
        NOW,
    )
    assert [r["indicator"] for r in result["matches"]] == ["sub.evil.example"]
    assert result["suppressed"][0]["allowlists"] == ["allow"]
    assert not result["feeds"][0]["stale"]
    assert all(f["stale"] for f in match(db, [], NOW + timedelta(days=2))["feeds"])


def test_exact_default_and_url_allowlist(tmp_path):
    path = bundle(tmp_path)
    db = tmp_path / "db"
    import_bundle(path, db)
    assert not match(db, [("domain", "sub.evil.example", "dynamic")], NOW)["matches"]


def rewrite(path, members):
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in members.items():
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))


@pytest.mark.parametrize("attack", ["traversal", "tamper", "symlink", "oversize"])
def test_reject_bad_bundles(tmp_path, attack):
    path = bundle(tmp_path)
    manifest, files = read_bundle(path)
    path.with_name(path.name + ".sha256").unlink()
    members = {"manifest.json": json.dumps(manifest).encode(), **files}
    if attack == "traversal":
        members["../outside"] = b"bad"
    elif attack == "tamper":
        members["test.jsonl"] += b"bad"
    rewrite(path, members)
    if attack == "symlink":
        with tarfile.open(path, "w:gz") as archive:
            item = tarfile.TarInfo("link")
            item.type = tarfile.SYMTYPE
            item.linkname = "/tmp/elsewhere"
            archive.addfile(item)
    with pytest.raises(ValueError):
        import_bundle(
            path, tmp_path / "db", max_bytes=5 if attack == "oversize" else 200000
        )
    assert not (tmp_path / "db").exists()


def test_checksum_and_credentials(tmp_path, caplog):
    path = bundle(tmp_path, key="synthetic-secret")
    assert b"synthetic-secret" not in path.read_bytes()
    manifest, files = read_bundle(path)
    assert all(b"synthetic-secret" not in data for data in files.values())
    assert "synthetic-secret" not in json.dumps(manifest) + caplog.text
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="checksum"):
        read_bundle(path)


def test_failed_update_retains_expiry(tmp_path):
    previous = bundle(tmp_path)

    def failed(*args):
        raise ValueError("synthetic-secret")

    target, success = build(
        [feed()],
        tmp_path,
        previous=previous,
        fetcher=failed,
        now=NOW + timedelta(days=2),
    )
    manifest, _ = read_bundle(target)
    assert not success
    assert manifest["feeds"][0]["expires_at"] == (NOW + timedelta(days=1)).isoformat()
    assert "failure" in manifest["feeds"][0]
    assert "synthetic-secret" not in json.dumps(manifest)


def test_report_statuses_and_evidence(tmp_path, monkeypatch):
    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
        iocs_export,
    )

    from .test_chimera_report import write_analysis

    directory = write_analysis(tmp_path / "analysis")
    config = IntelConfigSection(enabled=True, db_path=tmp_path / "db")
    assert (
        build_report(directory, intel_config=config)["stages"]["intel"]["status"]
        == "unavailable"
    )
    import_bundle(bundle(tmp_path), config.db_path)
    from types import SimpleNamespace

    monkeypatch.setattr(
        "drakrun.lib.config.load_config", lambda: SimpleNamespace(intel=config)
    )
    assert build_report(directory)["stages"]["intel"]["status"] == "stale"
    result = build_report(directory, intel_config=config)
    stage = result["stages"]["intel"]
    assert stage["status"] == "stale"
    assert stage["payload"]["matches"][0]["observed_in"] == "dynamic"
    assert stage["evidence_ids"]
    assert any(i["source"] == "intel:test" for i in iocs_export(result)["iocs"])
    fresh = bundle(
        tmp_path, now=datetime.now(timezone.utc), contents={"test": b"absent.example"}
    )
    import_bundle(fresh, config.db_path)
    stage = build_report(directory, intel_config=config)["stages"]["intel"]
    assert stage["status"] == "ok" and not stage["payload"]["matches"]
    assert "no match in" in stage["reason"] and "benign" in stage["reason"]


def test_fetch_headers_limits_and_conditional(monkeypatch):
    import urllib.error

    from drakrun.lib.intel.builder import NoRedirect, fetch

    requests = []

    class Response:
        headers = {"Last-Modified": "date", "ETag": "etag"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            assert size == 11
            return b"synthetic"

    class Opener:
        def open(self, request, timeout):
            assert timeout == 60
            requests.append(request)
            return Response()

    handlers = []

    def opener(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", opener)
    spec = feed(url="https://test.abuse.ch/export", auth_key=True)
    raw, modified, etag = fetch(
        spec,
        {"http_last_modified": "old", "http_etag": "oldetag"},
        "synthetic-secret",
        10,
    )
    assert (raw, modified, etag) == (b"synthetic", "date", "etag")
    assert len(requests) == 1 and requests[0].get_method() == "GET"
    headers = {key.lower(): value for key, value in requests[0].header_items()}
    assert headers == {
        "auth-key": "synthetic-secret",
        "if-modified-since": "old",
        "if-none-match": "oldetag",
    }
    assert handlers[1]._context.verify_mode == __import__("ssl").CERT_REQUIRED
    with pytest.raises(ValueError, match="redirect"):
        NoRedirect().redirect_request(
            requests[0], None, 302, "", {}, "https://elsewhere.example/"
        )
    with pytest.raises(ValueError, match="authentication"):
        fetch(feed(auth_key=True), None, "synthetic-secret", 10)

    class TooLarge(Response):
        def read(self, size):
            return b"x" * size

    monkeypatch.setattr(Opener, "open", lambda *args, **kwargs: TooLarge())
    with pytest.raises(ValueError, match="size cap"):
        fetch(spec, None, "synthetic-secret", 10)

    def unchanged(*args, **kwargs):
        raise urllib.error.HTTPError(spec["url"], 304, "unchanged", {}, None)

    monkeypatch.setattr(Opener, "open", unchanged)
    assert fetch(spec, {"http_etag": "oldetag"}, "synthetic-secret", 10) == (
        None,
        None,
        "oldetag",
    )


def test_observations_cover_static_and_tls(tmp_path):
    from drakrun.analyzer.postprocessing.plugins.build_chimera_report import (
        build_report,
    )

    directory = tmp_path / "analysis"
    directory.mkdir()
    static_dir = tmp_path / "static"
    (static_dir / "analysis").mkdir(parents=True)
    static = {
        "file": {"md5": "a" * 32},
        "universal": {
            "iocs": {
                "domains": ["evil.example"],
                "urls": ["https://evil.example/Case"],
                "ipv4": ["192.0.2.1"],
            }
        },
    }
    (static_dir / "analysis" / "static.json").write_text(json.dumps(static))
    (directory / "tls_sessions.json").write_text(
        json.dumps({"tls_handshakes": [{"sni": "evil.example", "ja3_md5": "b" * 32}]})
    )
    specs = [
        feed(),
        feed("ja3", kind="ja3"),
        feed("md5", kind="md5"),
        feed("ip", kind="ip"),
        feed("url", kind="url"),
    ]
    contents = {
        "test": b"evil.example",
        "ja3": b"b" * 32,
        "md5": b"a" * 32,
        "ip": b"192.0.2.1",
        "url": b"https://evil.example/Case",
    }
    db = tmp_path / "intel.db"
    import_bundle(bundle(tmp_path, specs, contents), db)
    result = build_report(
        directory,
        static_dir=static_dir,
        intel_config=IntelConfigSection(enabled=True, db_path=db),
    )
    matches = result["stages"]["intel"]["payload"]["matches"]
    assert {(r["type"], r["observed_in"]) for r in matches} == {
        ("md5", "sample"),
        ("domain", "static"),
        ("ip", "static"),
        ("url", "static"),
        ("domain", "dynamic"),
        ("ja3", "dynamic"),
    }
    artifact = (directory / "intel-evidence.json").read_bytes()
    from drakrun.lib.intel import digest

    assert all(
        e["sha256"] == digest(artifact)
        for e in result["evidence"]
        if e["artifact"] == "intel-evidence.json"
    )


def test_network_allowlist_never_suppresses_hashes(tmp_path):
    specs = [
        feed("url", kind="url"),
        feed("ip", kind="ip_port"),
        feed("hash", kind="sha256"),
        feed("allow", "misp_warninglist", "allowlist", match_subdomains=True),
    ]
    contents = {
        "url": b"https://sub.example.com/Case",
        "ip": b"192.0.2.1:443",
        "hash": b"a" * 64,
        "allow": b'{"list":["example.com", "192.0.2.1"]}',
    }
    db = tmp_path / "db"
    import_bundle(bundle(tmp_path, specs, contents), db)
    result = match(
        db,
        [
            ("url", "https://sub.example.com/Case", "static"),
            ("ip_port", "192.0.2.1:443", "dynamic"),
            ("sha256", "a" * 64, "sample"),
        ],
        NOW,
    )
    assert len(result["suppressed"]) == 2
    assert [r["type"] for r in result["matches"]] == ["sha256"]


def test_matches_are_bounded(tmp_path):
    db = tmp_path / "db"
    import_bundle(
        bundle(
            tmp_path,
            contents={"test": b"".join(f"n{i}.example\n".encode() for i in range(510))},
        ),
        db,
    )
    result = match(
        db, [("domain", f"n{i}.example", "dynamic") for i in range(510)], NOW
    )
    assert len(result["matches"]) == 500
    assert result["checked"]["domains"] == 510


@pytest.mark.parametrize(
    "field,value", [("schema", "unknown"), ("created", "2026-01-01"), ("feeds", [])]
)
def test_bad_manifest(tmp_path, field, value):
    path = bundle(tmp_path)
    manifest, files = read_bundle(path)
    manifest[field] = value
    path.with_name(path.name + ".sha256").unlink()
    rewrite(path, {"manifest.json": json.dumps(manifest).encode(), **files})
    with pytest.raises(ValueError):
        import_bundle(path, tmp_path / "db")


def test_partial_failure_and_status(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from click.testing import CliRunner

    from drakrun.cli.intel import intel

    spec = [feed(), feed("missing")]

    def fetcher(row, *args):
        if row["name"] == "missing":
            raise ValueError("synthetic failure")
        return b"evil.example", None, None

    path, success = build(spec, tmp_path, fetcher=fetcher, now=NOW)
    assert success
    db = tmp_path / "db"
    import_bundle(path, db)
    assert match(db, [], NOW)["failures"] == [
        {"name": "missing", "failure": "fetch or parse failed"}
    ]
    monkeypatch.setattr(
        "drakrun.cli.intel.load_config",
        lambda: SimpleNamespace(intel=IntelConfigSection(db_path=db)),
    )
    result = CliRunner().invoke(intel, ["status"])
    assert result.exit_code == 0
    assert "missing: missing" in result.output and "expired/stale" in result.output
    result = CliRunner().invoke(intel, ["import", str(path)])
    assert result.exit_code == 0 and "Imported 1 feeds" in result.output


def test_fetch_puts_abusech_key_in_path_only_at_request_time(monkeypatch):
    from drakrun.lib.intel.builder import fetch, parse_feed

    seen = []

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return b"{}"

    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            return Response()

    monkeypatch.setattr("urllib.request.build_opener", lambda *a: Opener())
    template = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    spec = feed(url=template, auth_key=True)
    fetch(spec, None, "SyntheticKey0123456789", 10)
    assert seen[0].full_url == "https://mb-api.abuse.ch/v2/files/exports/SyntheticKey0123456789/recent.csv"
    assert "auth-key" not in {k.lower() for k, _ in seen[0].header_items()}
    assert spec["url"] == template  # the feed list keeps the placeholder
    with pytest.raises(ValueError, match="authentication"):  # odd characters could rewrite the path
        fetch(spec, None, "../../other?x=1", 10)
    with pytest.raises(ValueError, match="authentication"):
        fetch(feed(url="https://example.org/{auth_key}/x", auth_key=True), None, "SyntheticKey0123456789", 10)
    # ThreatFox's 2026 JSON export names the indicator ioc_value
    rows = parse_feed(
        b'{"1": [{"ioc_value": "evil.example", "ioc_type": "domain", "malware_printable": "X"}]}',
        feed(format="threatfox", indicator_types=["domain"]),
    )
    assert [(r["type"], r["value"]) for r in rows] == [("domain", "evil.example")]
