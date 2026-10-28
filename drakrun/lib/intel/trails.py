"""Maltrail trails (github.com/stamparm/trails): family / APT attribution of network indicators.

The trails repository holds one text file per family under malware/ (apt_* files are APT groups), malicious/
and suspicious/; `# Aliases:` names other names of the family and each `# Reference:` block cites the source of
the entries below it. `sync` keeps a shallow git checkout current, logs what each pull changed and rebuilds a
SQLite index that `match` reads. The data is under the Maltrail Trails Community Data License (internal defensive
use and research); it stays on the host and is never committed or bundled.
"""

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import normalize

TRAILS_URL = "https://github.com/stamparm/trails.git"
PROTOCOLS = ("https",)
CATEGORIES = ("malware", "malicious", "suspicious")
# Upstream publishes several times a day; a week without a successful pull marks matches stale.
STALE_AFTER = timedelta(days=7)
REGEX = re.compile(r"[\[\]\\*^$(){}|]")


def family_of(category, stem):
    """(family, apt) from a trail file name: apt_lazarus -> ("lazarus", True), apt_12 -> ("apt 12", True)."""
    apt = category == "malware" and stem.startswith("apt_")
    name = stem[4:] if apt else stem
    family = name.replace("_", " ")
    if apt and family[:1].isdigit():
        family = "apt " + family
    return family, apt


def entry(raw):
    """(kind, value) for one trail line, or None for regular expressions and lines that are not indicators."""
    value = raw.split("#", 1)[0].strip()
    if not value or REGEX.search(value):
        return None
    # Host-less request paths (matched on any host): "/gate.php", "/request/autok?user=".
    if value.startswith("/"):
        return "path", value
    if re.fullmatch(r"\.[A-Za-z0-9-]+", value):
        return "tld", value[1:].lower()
    if re.fullmatch(r"[0-9a-fA-F.:]+/\d+", value):
        try:
            return "cidr", str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    if value.lower().startswith(("http://", "https://")):
        value = value.split("://", 1)[1]
    host, _, path = value.partition("/")
    if path:
        return "url", host.lower() + "/" + path
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        if ":" in host:
            return "ip_port", normalize("ip_port", host)
        return "domain", normalize("domain", host)
    except (ValueError, UnicodeError):
        return None


def parse(root):
    """Yield (category, stem, aliases, references, (kind, value) or None) for every indicator line."""
    root = Path(root)
    for category in CATEGORIES:
        for path in sorted((root / category).glob("*.txt")):
            aliases, references, after_entries = [], (), False
            with path.open(encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#"):
                        text = line.lstrip("#").strip()
                        if text.lower().startswith("aliases:"):
                            aliases = [
                                a.strip() for a in text[8:].split(",") if a.strip()
                            ]
                        elif text.lower().startswith("reference:"):
                            # A reference after entries starts the next block.
                            if after_entries:
                                references, after_entries = (), False
                            references += (text[10:].strip(),)
                        continue
                    after_entries = True
                    yield category, path.stem, aliases, references, entry(line)


def build(root, db_path, meta):
    """Rebuild the index from a checkout into a new file, then swap it in; returns the stored metadata."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=db_path.parent, prefix=".trails-")
    os.close(fd)
    counts, skipped = Counter(), Counter()
    try:
        with sqlite3.connect(temp) as db:
            db.executescript(
                "CREATE TABLE trails(id INTEGER PRIMARY KEY, category TEXT, file TEXT, family TEXT, apt INTEGER,"
                " aliases TEXT, UNIQUE(category, file));"
                "CREATE TABLE refs(id INTEGER PRIMARY KEY, urls TEXT UNIQUE);"
                "CREATE TABLE entries(kind TEXT, value TEXT, trail INTEGER, ref INTEGER,"
                " PRIMARY KEY(kind, value, trail)) WITHOUT ROWID;"
                "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);"
            )
            trails, refs, batch = {}, {}, []
            for category, stem, aliases, references, parsed in parse(root):
                if parsed is None:
                    skipped[category] += 1
                    continue
                key = (category, stem)
                if key not in trails:
                    family, apt = family_of(category, stem)
                    trails[key] = db.execute(
                        "INSERT INTO trails(category,file,family,apt,aliases) VALUES (?,?,?,?,?)",
                        (category, stem, family, int(apt), json.dumps(aliases)),
                    ).lastrowid
                if references not in refs:
                    refs[references] = db.execute(
                        "INSERT INTO refs(urls) VALUES (?)", (json.dumps(references),)
                    ).lastrowid
                batch.append((*parsed, trails[key], refs[references]))
                counts[category] += 1
                if len(batch) >= 50000:
                    db.executemany(
                        "INSERT OR IGNORE INTO entries VALUES (?,?,?,?)", batch
                    )
                    batch = []
            db.executemany("INSERT OR IGNORE INTO entries VALUES (?,?,?,?)", batch)
            meta = {
                **meta,
                "built_at": datetime.now(timezone.utc).isoformat(),
                "counts": dict(counts),
                "skipped": dict(skipped),
                "trails": len(trails),
                "apt_trails": sum(1 for c, s in trails if family_of(c, s)[1]),
            }
            db.executemany(
                "INSERT INTO meta VALUES (?,?)",
                [(k, json.dumps(v)) for k, v in meta.items()],
            )
        os.chmod(temp, 0o644)
        os.replace(temp, db_path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return meta


def read_meta(db_path):
    with sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True) as db:
        return {k: json.loads(v) for k, v in db.execute("SELECT key,value FROM meta")}


def _git(checkout, *args, timeout=900):
    return subprocess.run(
        # HTTPS only and no hooks: the checkout is data.
        ["git", "-c", "protocol.allow=never"]
        + [arg for p in PROTOCOLS for arg in ("-c", f"protocol.{p}.allow=always")]
        + ["-c", "core.hooksPath=/dev/null", "-C", str(checkout), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    ).stdout


def changes(checkout, old, new, max_files=40, max_lines=25):
    """What a pull changed: per-file added/removed line counts, and the indicators added to APT trails."""
    files = []
    for row in _git(
        checkout, "diff", "--numstat", old, new, "--", *CATEGORIES
    ).splitlines():
        added, removed, path = row.split("\t", 2)
        files.append(
            {
                "file": path,
                "added": int(added) if added.isdigit() else 0,
                "removed": int(removed) if removed.isdigit() else 0,
            }
        )
    apt, current = {}, None
    for line in _git(
        checkout, "diff", "-U0", "--no-color", old, new, "--", "malware/apt_*"
    ).splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and current and not line.startswith("+#"):
            if line[1:].strip() and len(apt.setdefault(current, [])) < max_lines:
                apt[current].append(line[1:].strip())
    files.sort(key=lambda f: -(f["added"] + f["removed"]))
    return {
        "files_changed": len(files),
        "added": sum(f["added"] for f in files),
        "removed": sum(f["removed"] for f in files),
        "files": files[:max_files],
        "apt_added": [
            {"file": f, "indicators": v} for f, v in sorted(apt.items())[:max_files]
        ],
    }


def sync(checkout, db_path, log_path, url=TRAILS_URL, branch="main"):
    """Pull the trails repository (shallow), log the diff, rebuild the index when the commit changed."""
    checkout, db_path = Path(checkout), Path(db_path)
    record = {"at": datetime.now(timezone.utc).isoformat()}
    old = None
    if (checkout / ".git").is_dir():
        old = _git(checkout, "rev-parse", "HEAD").strip()
        _git(checkout, "fetch", "--quiet", "--depth", "1", "origin", branch)
        new = _git(checkout, "rev-parse", "FETCH_HEAD").strip()
        if new != old:
            record.update(changes(checkout, old, new))
            _git(checkout, "reset", "--quiet", "--hard", new)
            # The diff is logged; drop the old commit so the checkout stays one commit deep.
            _git(checkout, "reflog", "expire", "--expire=now", "--all")
            _git(checkout, "gc", "--quiet", "--prune=now")
    else:
        checkout.parent.mkdir(parents=True, exist_ok=True)
        _git(
            checkout.parent,
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            branch,
            url,
            checkout.name,
            timeout=1800,
        )
    new = _git(checkout, "rev-parse", "HEAD").strip()
    committed = _git(checkout, "log", "-1", "--format=%cI").strip()
    license_sha = hashlib.sha256((checkout / "LICENSE.md").read_bytes()).hexdigest()
    record.update({"from": old, "to": new, "committed_at": committed})
    previous = {}
    if db_path.is_file():
        try:
            previous = read_meta(db_path)
        except sqlite3.Error:
            previous = {}
    if previous.get("license_sha256") not in (None, license_sha):
        record["license_changed"] = True
    if previous.get("commit") == new:
        record["status"] = "unchanged"
    else:
        meta = build(
            checkout,
            db_path,
            {
                "commit": new,
                "committed_at": committed,
                "source": url,
                "license_sha256": license_sha,
            },
        )
        record.update(status="rebuilt", counts=meta["counts"], skipped=meta["skipped"])
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")
    return record


def _keys(kind, value):
    """Index keys an observation can match: the value, its parent domains, a URL's host, an ip:port's IP."""
    if kind == "domain":
        parts = value.split(".")
        return [("domain", ".".join(parts[i:])) for i in range(len(parts) - 1)] + [
            ("tld", parts[-1])
        ]
    if kind == "ip":
        return [("ip", value)]
    if kind == "ip_port":
        return [("ip_port", value), ("ip", value.rsplit(":", 1)[0].strip("[]"))]
    if kind == "url":
        u = urlsplit(value)
        host = (u.hostname or "") + (f":{u.port}" if u.port else "")
        path = u.path or "/"
        keys = [("url", host + path), ("path", path)]
        # A trail ending in the query ("?user=") matches requests whose query starts with it.
        for i, char in enumerate(u.query):
            if char in "=&":
                keys.append(("path", path + "?" + u.query[: i + 1]))
        if u.query:
            keys += [("url", host + path + "?" + u.query), ("path", path + "?" + u.query)]
        try:
            keys += _keys("ip", normalize("ip", u.hostname))
        except ValueError:
            keys += _keys("domain", u.hostname or "")
        return keys
    return []


def match(db_path, observations, now=None, limit=200):
    """Attribution of (kind, value, origin) observations; `families` groups the matches per trail file."""
    now = now or datetime.now(timezone.utc)
    meta = read_meta(db_path)
    rows, seen = [], set()
    with sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True) as db:
        cidrs = [
            (ipaddress.ip_network(v), t, r)
            for v, t, r in db.execute(
                "SELECT value,trail,ref FROM entries WHERE kind='cidr'"
            )
        ]
        for kind, raw, origin in observations:
            try:
                value = normalize(kind, raw)
            except (ValueError, TypeError, UnicodeError):
                continue
            hits = []
            for key in _keys(kind, value):
                hits += [
                    (key[1], t, r)
                    for t, r in db.execute(
                        "SELECT trail,ref FROM entries WHERE kind=? AND value=?", key
                    )
                ]
                if key[0] == "ip":
                    address = ipaddress.ip_address(key[1])
                    hits += [(str(n), t, r) for n, t, r in cidrs if address in n]
            for trail_value, trail, ref in hits:
                if (value, origin, trail) in seen or len(rows) >= limit:
                    continue
                seen.add((value, origin, trail))
                category, stem, family, apt, aliases = db.execute(
                    "SELECT category,file,family,apt,aliases FROM trails WHERE id=?",
                    (trail,),
                ).fetchone()
                urls = json.loads(
                    db.execute("SELECT urls FROM refs WHERE id=?", (ref,)).fetchone()[0]
                )
                rows.append(
                    {
                        "indicator": value,
                        "type": kind,
                        "observed_in": origin,
                        "trail": trail_value,
                        "category": category,
                        "file": f"{category}/{stem}.txt",
                        "family": family,
                        "apt": bool(apt),
                        "aliases": json.loads(aliases)[:8],
                        "references": urls[:3],
                    }
                )
    families = {}
    for row in rows:
        f = families.setdefault(
            row["file"],
            {
                "family": row["family"],
                "apt": row["apt"],
                "category": row["category"],
                "file": row["file"],
                "aliases": row["aliases"],
                "indicators": [],
                "observed_in": [],
            },
        )
        if row["indicator"] not in f["indicators"]:
            f["indicators"].append(row["indicator"])
        if row["observed_in"] not in f["observed_in"]:
            f["observed_in"].append(row["observed_in"])
    order = {"malware": 0, "malicious": 1, "suspicious": 2}
    committed = datetime.fromisoformat(meta["committed_at"])
    return {
        "source": meta.get("source"),
        "commit": meta.get("commit"),
        "committed_at": meta.get("committed_at"),
        "stale": now - committed > STALE_AFTER,
        "matches": rows,
        "families": sorted(
            families.values(),
            key=lambda f: (not f["apt"], order[f["category"]], -len(f["indicators"])),
        ),
    }
