"""Shared cache and transactional provider request budgets."""

import json
import sqlite3
import time
from pathlib import Path


class Cache:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        with self.connect() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS results(provider TEXT, kind TEXT, value TEXT, expires REAL, data TEXT, PRIMARY KEY(provider,kind,value)); CREATE TABLE IF NOT EXISTS budgets(provider TEXT PRIMARY KEY, last REAL, day INTEGER, count INTEGER);"
            )

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def get(self, provider, kind, value):
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM results WHERE provider=? AND kind=? AND value=? AND expires>?",
                (provider, kind, value, time.time()),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, provider, kind, value, result):
        ttl = 7 * 86400 if kind in {"sha256", "sha1", "md5"} else 86400
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO results VALUES (?,?,?,?,?)",
                (provider, kind, value, time.time() + ttl, json.dumps(result)),
            )

    def delay(self, provider, interval, cap):
        """Seconds until reserve() can succeed; None once today's cap is used up."""
        now = time.time()
        with self.connect() as db:
            row = db.execute(
                "SELECT last,day,count FROM budgets WHERE provider=?", (provider,)
            ).fetchone()
        if not row:
            return 0.0
        if row[1] == int(now // 86400) and row[2] >= cap:
            return None
        return max(0.0, row[0] + interval - now)

    def reserve(self, provider, interval, cap):
        now = time.time()
        day = int(now // 86400)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT last,day,count FROM budgets WHERE provider=?", (provider,)
            ).fetchone()
            count = row[2] if row and row[1] == day else 0
            if row and now - row[0] < interval or count >= cap:
                return False
            db.execute(
                "INSERT OR REPLACE INTO budgets VALUES (?,?,?,?)",
                (provider, now, day, count + 1),
            )
        return True
