"""Connected-host bundle builder. Nothing in the analysis path imports this module."""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import ssl
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from . import SCHEMA, digest, normalize, read_bundle

VERSION = "1"


def parse_feed(raw, feed):
    text = raw.decode("utf-8-sig")
    fmt = feed["format"]
    rows = []
    if fmt not in {
        "text",
        "misp_warninglist",
        "threatfox",
        "feodo",
        "malwarebazaar",
        "urlhaus",
        "sslbl",
    }:
        raise ValueError("unsupported feed format")

    def add(kind, value, source=None, **extra):
        if value is None:
            return
        source = source or {}
        try:
            normalized = normalize(extra.get("indicator_type", kind), value)
        except (ValueError, TypeError, UnicodeError):
            return
        tags = source.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        rows.append(
            {
                "type": kind,
                "value": normalized,
                "first_seen": source.get("first_seen")
                or source.get("first_seen_utc")
                or source.get("firstseen")
                or source.get("dateadded")
                or source.get("listingdate"),
                "last_seen": source.get("last_seen")
                or source.get("last_seen_utc")
                or source.get("lastseen"),
                "tags": tags,
                "malware_family": source.get("malware_family")
                or source.get("malware_printable")
                or source.get("signature")
                or source.get("malware")
                or source.get("listingreason"),
                "reference": source.get("reference"),
                **extra,
            }
        )

    if fmt == "text":
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                add(feed["indicator_types"][0], line)
    elif fmt == "misp_warninglist":
        obj = json.loads(text)
        for value in obj["list"]:
            try:
                normalize("ip", value)
                kind = "ip"
            except ValueError:
                kind = "domain"
            add("allowlist", value, indicator_type=kind)
    elif fmt in {"threatfox", "feodo"}:
        obj = json.loads(text)
        if isinstance(obj, dict):
            obj = obj.get("data", obj)
        if isinstance(obj, dict):
            obj = [
                r
                for records in obj.values()
                for r in (records if isinstance(records, list) else [records])
            ]
        for row in obj:
            if fmt == "feodo":
                ip = row.get("ip_address") or row.get("ip")
                add("ip", ip, row)
                if row.get("port"):
                    add("ip_port", f"{ip}:{row['port']}", row)
            else:
                kind = {
                    "ip:port": "ip_port",
                    "sha256_hash": "sha256",
                    "md5_hash": "md5",
                    "sha1_hash": "sha1",
                }.get(row.get("ioc_type"), row.get("ioc_type"))
                if kind in feed["indicator_types"]:
                    add(kind, row.get("ioc"), row)
    else:
        lines = []
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                candidate = line.lstrip()[1:].strip()
                if (
                    any(
                        header in candidate.lower()
                        for header in (
                            "sha256_hash",
                            "dateadded",
                            "first_seen_utc",
                            "ja3_md5",
                            "firstseen",
                            "listingdate",
                        )
                    )
                    and "," in candidate
                ):
                    lines.append(candidate)
            elif line.strip():
                lines.append(line)
        if fmt == "urlhaus" and lines and re.match(r'^"?\d', lines[0]):
            lines.insert(
                0,
                "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter",
            )
        reader = csv.DictReader(lines, skipinitialspace=True)
        headers = {h.strip().lower() for h in reader.fieldnames or []}
        required = {
            "malwarebazaar": {"sha256_hash", "md5_hash", "sha1_hash"},
            "urlhaus": {"url"},
            "sslbl": {
                "sha1",
                "sha1_hash",
                "sslcert_sha1",
                "ja3_md5",
                "ja3",
                "ja3_fingerprint",
            },
        }[fmt]
        if not headers & required:
            raise ValueError("unrecognized CSV header")
        for row in reader:
            row = {
                k.strip().lower(): v.strip() if isinstance(v, str) else v
                for k, v in row.items()
                if k
            }
            if fmt == "malwarebazaar":
                for kind in ("sha256", "md5", "sha1"):
                    add(kind, row.get(kind + "_hash"), row)
            elif fmt == "urlhaus":
                add(
                    "url",
                    row.get("url"),
                    {
                        **row,
                        "first_seen": row.get("dateadded"),
                        "reference": row.get("urlhaus_link"),
                    },
                )
            elif fmt == "sslbl":
                for kind, aliases in {
                    "sslcert_sha1": ("sha1", "sha1_hash", "sslcert_sha1"),
                    "ja3": ("ja3_md5", "ja3", "ja3_fingerprint"),
                }.items():
                    for field in aliases:
                        if row.get(field):
                            add(kind, row[field], row)
                            break
            else:
                raise ValueError("unsupported feed format")
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Refusing all redirects also prevents leaking authorization across hosts.
        raise ValueError("feed redirect refused")


def fetch(feed, previous, key, size_cap):
    if size_cap <= 0:
        raise ValueError("size cap must be positive")
    url = feed["url"]
    if key and key in unquote(url):
        raise ValueError("credential-bearing feed URL refused")
    u = urlsplit(url)
    if u.scheme != "https" or u.username or u.password or u.query or u.fragment:
        raise ValueError("feed URL must be credential-free HTTPS")
    headers = {}
    if previous:
        if previous.get("http_last_modified"):
            headers["If-Modified-Since"] = previous["http_last_modified"]
        if previous.get("http_etag"):
            headers["If-None-Match"] = previous["http_etag"]
    if feed.get("auth_key"):
        if not u.hostname or not u.hostname.endswith(".abuse.ch") or not key:
            raise ValueError("feed authentication unavailable")
        headers["Auth-Key"] = key
    opener = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(
            urllib.request.Request(url, headers=headers), timeout=60
        ) as response:
            raw = response.read(size_cap + 1)
            if len(raw) > size_cap:
                raise ValueError("feed size cap exceeded")
            return (
                raw,
                response.headers.get("Last-Modified"),
                response.headers.get("ETag"),
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and previous:
            return None, previous.get("http_last_modified"), previous.get("http_etag")
        raise ValueError("feed HTTP failure") from None


def build(
    feeds,
    output,
    previous=None,
    key=None,
    size_cap=200 * 1024 * 1024,
    fetcher=fetch,
    now=None,
):
    now = now or datetime.now(timezone.utc)
    previous_manifest, previous_files = (
        read_bundle(previous) if previous else ({"feeds": []}, {})
    )
    old = {f["name"]: f for f in previous_manifest["feeds"]}
    manifest = {
        "schema": SCHEMA,
        "created": now.isoformat(),
        "builder_version": VERSION,
        "feeds": [],
    }
    if size_cap <= 0:
        raise ValueError("size cap must be positive")
    files, successful = {}, 0
    if len({f["name"] for f in feeds}) != len(feeds):
        raise ValueError("duplicate feed name")
    for feed in feeds:
        name = feed["name"]
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise ValueError("invalid feed name")
        prior = old.get(name)
        try:
            raw, modified, etag = fetcher(
                feed, prior, key, feed.get("max_bytes", size_cap)
            )
            if raw is None:
                metadata = dict(prior)
                normalized = previous_files[prior["file"]]
            else:
                rows = parse_feed(raw, feed)
                normalized = b"".join(
                    (json.dumps(row, sort_keys=True) + "\n").encode() for row in rows
                )
                metadata = {
                    "name": name,
                    "source_url": urlunsplit(
                        (*urlsplit(feed["url"])[:2], urlsplit(feed["url"]).path, "", "")
                    ),
                    "fetched_at": now.isoformat(),
                    "http_last_modified": modified,
                    "http_etag": etag,
                    "sha256": digest(raw),
                    "counts": dict(Counter(r["type"] for r in rows)),
                    "license": feed["license"],
                    "expires_at": (
                        now + timedelta(days=feed["max_age_days"])
                    ).isoformat(),
                    "match_subdomains": bool(feed.get("match_subdomains", False)),
                }
            metadata.pop("failure", None)
            successful += 1
        except Exception:
            # Never include exception text: URLs and HTTP exceptions may contain secrets.
            if not prior:
                manifest.setdefault("failures", []).append(
                    {"name": name, "failure": "fetch or parse failed"}
                )
                continue
            metadata = {
                **prior,
                "failure": "fetch or parse failed; retained previous data",
            }
            normalized = previous_files[prior["file"]]
        metadata.update(file=f"{name}.jsonl", normalized_sha256=digest(normalized))
        files[metadata["file"]] = normalized
        manifest["feeds"].append(metadata)
    # A provider echoing an authorization value must not persist it in any field.
    files["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    if key and any(key.encode() in content for content in files.values()):
        raise ValueError("credential-like content rejected")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"chimera-intel-{now:%Y%m%dT%H%MZ}.tar.gz"
    fd, temporary = tempfile.mkstemp(dir=output)
    os.close(fd)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            for name, raw in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        with open(temporary, "rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        os.replace(temporary, target)
        checksum_temp = output / (target.name + ".sha256.tmp")
        checksum_temp.write_text(f"{checksum}  {target.name}\n")
        os.replace(checksum_temp, Path(str(target) + ".sha256"))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target, successful > 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feeds",
        type=Path,
        default=Path(__file__).resolve().parents[3]
        / "scripts/chimera/intel/feeds.toml",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--abusech-key-file", type=Path)
    parser.add_argument("--max-feed-bytes", type=int, default=200 * 1024 * 1024)
    args = parser.parse_args()
    key = args.abusech_key_file.read_text().strip() if args.abusech_key_file else None
    _, success = build(
        tomllib.loads(args.feeds.read_text())["feeds"],
        args.output,
        args.previous,
        key,
        args.max_feed_bytes,
    )
    return 0 if success else 1
