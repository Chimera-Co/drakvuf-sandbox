"""Adapt report artifacts to offline observations; never used as model features."""

import json
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from . import digest, match


def sample_scope(report):
    """Seqids of the started sample and everything it spawned (report.json processes + startup.process)."""
    root = (report.get("startup") or {}).get("process")
    if root is None:
        return set()
    children = {}
    for proc in report.get("processes") or []:
        if isinstance(proc, dict) and proc.get("parent_seqid") is not None:
            children.setdefault(proc["parent_seqid"], []).append(proc.get("seqid"))
    scope, stack = set(), [root]
    while stack:
        seqid = stack.pop()
        if seqid in scope:
            continue
        scope.add(seqid)
        stack.extend(children.get(seqid, []))
    return scope


def observations(metadata, report, static, tls, scope=None):
    """(kind, value, origin) triples. With `scope` (sample seqids), run-time rows are split by who made them:
    "dynamic" (the sample's process tree), "system" (only other guest processes) or "unattributed".
    """
    out = []
    row_origin = "dynamic"

    def add(kind, value, origin):
        if value is not None:
            out.append((kind, value, row_origin if origin == "dynamic" else origin))

    def attribute(row):
        nonlocal row_origin
        if scope is None:
            row_origin = "dynamic"
            return
        seqids = set(row.get("process_seqids") or [])
        if row.get("process_seqid") is not None:
            seqids.add(row["process_seqid"])
        row_origin = (
            "unattributed" if not seqids else "dynamic" if seqids & scope else "system"
        )

    for source in (
        metadata.get("file") or {},
        (report.get("info") or {}).get("file") or {},
        static.get("file") or {},
    ):
        for kind in ("sha256", "sha1", "md5"):
            add(kind, source.get(kind), "sample")
    for kind, values in (static.get("universal") or {}).get("iocs", {}).items():
        indicator_type = {
            "urls": "url",
            "domains": "domain",
            "ips": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
        }.get(kind)
        if indicator_type:
            for value in values or []:
                add(
                    indicator_type,
                    value.get("value") if isinstance(value, dict) else value,
                    "static",
                )
    for row in report.get("dns_queries") or []:
        attribute(row)
        add("domain", row.get("domain") or row.get("query"), "dynamic")
    for row in report.get("connections") or []:
        attribute(row)
        add("ip", row.get("remote_ip"), "dynamic")
        if row.get("remote_ip") and row.get("remote_port"):
            add("ip_port", f"{row['remote_ip']}:{row['remote_port']}", "dynamic")
    for key in ("http_requests", "tls_requests", "tls_handshakes"):
        for row in report.get(key) or []:
            attribute(row)
            host = row.get("server_name") or row.get("host") or row.get("sni")
            if host:
                try:
                    host = urlsplit("//" + host).hostname
                    add("domain", host, "dynamic")
                    add("ip", host, "dynamic")
                except ValueError:
                    pass
            url = row.get("url") or row.get("path")
            if url and not url.startswith(("http://", "https://")) and host:
                port = row.get("server_port")
                url = (
                    ("https" if key.startswith("tls") or port == 443 else "http")
                    + "://"
                    + (f"[{host}]" if ":" in host else host)
                    + (f":{port}" if port and port not in (80, 443) else "")
                    + url
                )
            add("url", url, "dynamic")
            add("ja3", row.get("ja3_md5") or row.get("ja3"), "dynamic")
            add("sslcert_sha1", row.get("sslcert_sha1"), "dynamic")
    if isinstance(tls, dict):
        attribute({})
        for row in tls.get("tls_handshakes") or []:
            add("domain", row.get("sni"), "dynamic")
            add("ja3", row.get("ja3_md5") or row.get("ja3"), "dynamic")
        for session in tls.get("sessions") or []:
            conn = session.get("connection") or {}
            add("domain", conn.get("sni"), "dynamic")
            add("ja3", conn.get("ja3_md5") or conn.get("ja3"), "dynamic")
            add("sslcert_sha1", conn.get("sslcert_sha1"), "dynamic")
    return out


def _offline_stage(directory, config, metadata, report, static, ev, static_path=None):
    base = {
        "status": "unavailable",
        "reason": "offline intel disabled or database missing",
        "producer": {"name": "chimera-offline-intel"},
        "payload": None,
        "evidence_ids": [],
    }
    if not config.enabled or not Path(config.db_path).is_file():
        return base
    directory = Path(directory)
    for candidate in (static_path, directory / "static.json"):
        if candidate is None:
            continue
        candidate = Path(candidate)
        if candidate.is_file():
            try:
                candidate_static = json.loads(candidate.read_bytes())
                if isinstance(candidate_static, dict):
                    static = candidate_static
                    break
            except (OSError, ValueError):
                pass
    try:
        tls = json.loads((directory / "tls_sessions.json").read_bytes())
    except (OSError, ValueError):
        tls = {}
    try:
        payload = match(config.db_path, observations(metadata, report, static, tls))
    except (
        OSError,
        ValueError,
        sqlite3.Error,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
    ):
        return {**base, "reason": "offline intel database unreadable or invalid"}
    raw = json.dumps(payload, sort_keys=True).encode()
    artifact = "intel-evidence.json"
    temporary = directory / (artifact + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(directory / artifact)
    ev.hashes[artifact] = digest(raw)
    eids = []
    for index, row in enumerate(payload["matches"]):
        eid = ev.add(artifact, f"/matches/{index}", "chimera-offline-intel")
        row["evidence_ids"] = [eid]
        eids.append(eid)
    feeds = payload["feeds"]
    if not feeds:
        return {**base, "reason": "offline intel database has no feeds"}
    status = "stale" if feeds and all(f["stale"] for f in feeds) else "ok"
    dates = ", ".join(sorted({str(f["fetched_at"])[:10] for f in feeds}))
    summary = (
        f"{len(payload['matches'])} offline matches"
        if payload["matches"]
        else f"no match in {len(feeds)} feeds dated {dates}; not a verdict of benign"
    )
    return {
        **base,
        "status": status,
        "reason": summary,
        "payload": payload,
        "evidence_ids": eids,
    }


def stage(directory, config, metadata, report, static, ev, static_path=None):
    offline = _offline_stage(
        directory, config, metadata, report, static, ev, static_path
    )
    from .online.run import read_json

    path = (
        Path(static_path).parent / "intel-online.json"
        if static_path
        else Path(directory) / "intel-online.json"
    )
    online = read_json(path)
    if online.get("schema") != "chimera-intel-online/1":
        return offline
    artifact = "intel-online.json"
    raw = path.read_bytes()
    # Evidence artifacts travel with the portable analysis report.
    if path != Path(directory) / artifact:
        temporary = Path(directory) / ".intel-online.json.tmp"
        temporary.write_bytes(raw)
        temporary.replace(Path(directory) / artifact)
    ev.hashes[artifact] = digest(raw)
    eids = list(offline["evidence_ids"])
    for index, row in enumerate(online.get("results", [])):
        row["evidence_ids"] = [
            ev.add(artifact, f"/results/{index}", "intel:" + row["provider"])
        ]
        eids.extend(row["evidence_ids"])
    has_data = any(r.get("status") == "ok" for r in online.get("results", []))
    return {
        **offline,
        "status": (
            "ok" if has_data or offline["status"] in {"ok", "stale"} else "unavailable"
        ),
        "reason": offline["reason"]
        + "; online intel: "
        + online.get("connectivity", "offline"),
        "payload": {**(offline.get("payload") or {}), "online": online},
        "evidence_ids": eids,
    }
