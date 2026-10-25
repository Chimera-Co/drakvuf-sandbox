"""Offline indicator normalization, verified bundle import and exact matching."""

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tarfile
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SCHEMA = "chimera-intel-bundle/1"
TYPES = {
    "sha256",
    "md5",
    "sha1",
    "domain",
    "url",
    "ip",
    "ip_port",
    "ja3",
    "sslcert_sha1",
}


def normalize(kind, value):
    value = str(value).strip()
    if kind == "ja3" and re.fullmatch(r"\d+,[\d-]*,[\d-]*,[\d-]*,[\d-]*", value):
        value = hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()
    if kind in {"sha256", "md5", "sha1", "ja3", "sslcert_sha1"}:
        lengths = {"sha256": 64, "md5": 32, "sha1": 40, "ja3": 32, "sslcert_sha1": 40}
        if not re.fullmatch(r"[0-9a-fA-F]{%d}" % lengths[kind], value):
            raise ValueError("invalid digest")
        return value.lower()
    if kind == "domain":
        result = value.rstrip(".").encode("idna").decode("ascii").lower()
        if not result or any(
            not re.fullmatch(r"[a-z0-9_-]+", p) for p in result.split(".")
        ):
            raise ValueError("invalid domain")
        return result
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if kind == "ip_port":
        host, port = value.rsplit(":", 1)
        host = normalize("ip", host.strip("[]"))
        port = int(port)
        if not 0 < port < 65536:
            raise ValueError("invalid port")
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    if kind == "url":
        u = urlsplit(value)
        if (
            u.scheme.lower() not in {"http", "https"}
            or not u.hostname
            or u.username
            or u.password
        ):
            raise ValueError("invalid URL")
        try:
            host = normalize("ip", u.hostname)
        except ValueError:
            host = normalize("domain", u.hostname)
        if ":" in host:
            host = f"[{host}]"
        return urlunsplit(
            (
                u.scheme.lower(),
                host + (f":{u.port}" if u.port else ""),
                u.path,
                u.query,
                u.fragment,
            )
        )
    raise ValueError("unknown indicator type")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _read_bundle(path, max_bytes):
    path = Path(path)
    if max_bytes <= 0 or path.stat().st_size > max_bytes:
        raise ValueError("bundle exceeds size limit")
    checksum = Path(str(path) + ".sha256")
    if checksum.exists():
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if checksum.read_text().split()[0] != actual:
            raise ValueError("bundle checksum mismatch")
    files, total = {}, 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if (
                len(files) >= 1024
                or not member.isfile()
                or member.name in files
                or "/" in member.name
                or "\\" in member.name
                or member.name in {".", ".."}
            ):
                raise ValueError("unsafe bundle member")
            total += member.size
            if member.size > max_bytes or total > max_bytes:
                raise ValueError("bundle exceeds size limit")
            files[member.name] = archive.extractfile(member).read()
    manifest = json.loads(files.pop("manifest.json"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported bundle schema")
    expected = set()
    names = set()
    if not isinstance(manifest.get("feeds"), list) or not manifest["feeds"]:
        raise ValueError("bundle contains no feeds")
    timestamp(manifest["created"])
    if not isinstance(manifest["builder_version"], str):
        raise ValueError("invalid builder version")
    for feed in manifest["feeds"]:
        for field in (
            "name",
            "source_url",
            "fetched_at",
            "expires_at",
            "license",
            "file",
            "sha256",
            "normalized_sha256",
        ):
            if not isinstance(feed[field], str):
                raise ValueError("invalid feed metadata")
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", feed["name"]):
            raise ValueError("invalid feed name")
        for field in ("sha256", "normalized_sha256"):
            normalize("sha256", feed[field])
        if "match_subdomains" in feed and not isinstance(
            feed["match_subdomains"], bool
        ):
            raise ValueError("invalid subdomain rule")
        timestamp(feed["fetched_at"])
        timestamp(feed["expires_at"])
        if not isinstance(feed["counts"], dict) or any(
            type(n) is not int or n < 0 for n in feed["counts"].values()
        ):
            raise ValueError("invalid feed counts")
        name = feed["name"]
        if name in names:
            raise ValueError("duplicate feed")
        names.add(name)
        filename = feed["file"]
        if filename in expected:
            raise ValueError("duplicate feed file")
        expected.add(filename)
        if digest(files[filename]) != feed["normalized_sha256"]:
            raise ValueError("feed checksum mismatch")
    if set(files) != expected:
        raise ValueError("unexpected bundle files")
    return manifest, files


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return parsed


def read_bundle(path, max_bytes=200 * 1024 * 1024):
    try:
        return _read_bundle(path, max_bytes)
    except (
        KeyError,
        IndexError,
        TypeError,
        AttributeError,
        tarfile.TarError,
        UnicodeError,
    ) as exc:
        raise ValueError("invalid intel bundle") from exc


def import_bundle(bundle, db_path, max_bytes=200 * 1024 * 1024):
    manifest, files = read_bundle(bundle, max_bytes)
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if db_path.exists():
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as old:
            history = [
                r[0]
                for r in old.execute(
                    "SELECT manifest FROM imports ORDER BY rowid DESC LIMIT 2"
                )
            ][::-1]
    fd, temp = tempfile.mkstemp(dir=db_path.parent, prefix=".intel-")
    os.close(fd)
    try:
        with sqlite3.connect(temp) as db:
            db.executescript(
                "CREATE TABLE feeds(name TEXT PRIMARY KEY, metadata TEXT); CREATE TABLE indicators(type TEXT, value TEXT, feed TEXT, data TEXT); CREATE INDEX lookup ON indicators(type,value); CREATE TABLE imports(manifest TEXT);"
            )
            for item in history + [json.dumps(manifest)]:
                db.execute("INSERT INTO imports VALUES (?)", (item,))
            for feed in manifest["feeds"]:
                db.execute(
                    "INSERT INTO feeds VALUES (?,?)", (feed["name"], json.dumps(feed))
                )
                counts = Counter()
                for line in files[feed["file"]].splitlines():
                    row = json.loads(line)
                    if (
                        not isinstance(row, dict)
                        or not isinstance(row.get("type"), str)
                        or row.get("type") not in TYPES | {"allowlist"}
                    ):
                        raise ValueError("invalid indicator record")
                    if not isinstance(row.get("tags"), list) or not all(
                        isinstance(tag, str) for tag in row["tags"]
                    ):
                        raise ValueError("invalid indicator tags")
                    for field in (
                        "first_seen",
                        "last_seen",
                        "malware_family",
                        "reference",
                    ):
                        if row.get(field) is not None and not isinstance(
                            row[field], str
                        ):
                            raise ValueError("invalid indicator metadata")
                    kind = row["type"]
                    counts[kind] += 1
                    if kind == "allowlist":
                        key_type = row["indicator_type"]
                        if key_type not in {"domain", "ip"}:
                            raise ValueError("invalid allowlist type")
                    else:
                        key_type = kind
                    value = normalize(key_type, row["value"])
                    row["value"] = value
                    db.execute(
                        "INSERT INTO indicators VALUES (?,?,?,?)",
                        (kind, value, feed["name"], json.dumps(row)),
                    )
                if dict(counts) != feed["counts"]:
                    raise ValueError("indicator counts mismatch")
        os.replace(temp, db_path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return manifest


def match(db_path, observations, now=None):
    now = now or datetime.now(timezone.utc)
    with sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True) as db:
        feeds = {
            name: json.loads(data)
            for name, data in db.execute("SELECT name,metadata FROM feeds")
        }
        for feed in feeds.values():
            feed["stale"] = timestamp(feed["expires_at"]) < now
        matches, suppressed, checked, seen = (
            [],
            [],
            Counter(
                {
                    k: 0
                    for k in (
                        "hashes",
                        "domains",
                        "urls",
                        "ips",
                        "ip_ports",
                        "ja3",
                        "sslcert_sha1",
                    )
                }
            ),
            set(),
        )
        for kind, raw, origin in observations:
            try:
                value = normalize(kind, raw)
            except (ValueError, TypeError, UnicodeError):
                continue
            if (kind, value, origin) in seen:
                continue
            seen.add((kind, value, origin))
            checked[
                {
                    "sha256": "hashes",
                    "sha1": "hashes",
                    "md5": "hashes",
                    "domain": "domains",
                    "url": "urls",
                    "ip": "ips",
                    "ip_port": "ip_ports",
                }.get(kind, kind)
            ] += 1
            keys = [value]
            if kind == "domain":
                keys += [
                    ".".join(value.split(".")[i:])
                    for i in range(1, len(value.split(".")))
                ]
            allowed = []
            if kind in {"domain", "ip", "url", "ip_port"}:
                host_type, host = kind, value
                if kind == "url":
                    host = urlsplit(value).hostname
                    try:
                        host = normalize("ip", host)
                        host_type = "ip"
                    except ValueError:
                        host_type = "domain"
                if kind == "ip_port":
                    host_type, host = "ip", value.rsplit(":", 1)[0].strip("[]")
                allow_keys = [host]
                if host_type == "domain":
                    allow_keys += [
                        ".".join(host.split(".")[i:])
                        for i in range(1, len(host.split(".")))
                    ]
                for allow_key in allow_keys:
                    for name, data in db.execute(
                        "SELECT feed,data FROM indicators WHERE type='allowlist' AND value=?",
                        (allow_key,),
                    ):
                        if json.loads(data)["indicator_type"] == host_type and (
                            allow_key == host or feeds[name].get("match_subdomains")
                        ):
                            allowed.append(name)
            for key in keys:
                for name, data in db.execute(
                    "SELECT feed,data FROM indicators WHERE type=? AND value=?",
                    (kind, key),
                ):
                    feed = feeds[name]
                    if key != value and not feed.get("match_subdomains"):
                        continue
                    row = json.loads(data)
                    result = {
                        **row,
                        "indicator": value,
                        "observed_in": origin,
                        "feed": name,
                        "stale": feed["stale"],
                    }
                    target = suppressed if allowed else matches
                    if len(target) < 500:
                        target.append(
                            {**result, **({"allowlists": allowed} if allowed else {})}
                        )
        imported = json.loads(
            db.execute(
                "SELECT manifest FROM imports ORDER BY rowid DESC LIMIT 1"
            ).fetchone()[0]
        )
    return {
        "db_built_at": imported["created"],
        "failures": imported.get("failures", []),
        "feeds": list(feeds.values()),
        "matches": matches,
        "suppressed": suppressed,
        "checked": dict(checked),
    }
