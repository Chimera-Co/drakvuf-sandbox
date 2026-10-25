"""ThreatFox observable lookup adapter."""

import json

from .base import HASHES, NETWORK, Provider


class Adapter(Provider):
    id = "threatfox"
    label = "ThreatFox"
    host = "threatfox-api.abuse.ch"
    types = HASHES + NETWORK
    header = "Auth-Key"
    optional_key = False
    interval = 2
    daily_cap = 150
    max_lookups = 10

    def request(self, kind, value):

        body = (
            {"query": "search_hash", "hash": value}
            if kind in HASHES
            else {"query": "search_ioc", "search_term": value, "exact_match": True}
        )
        return (
            f"https://{self.host}/api/v1/",
            json.dumps(body).encode(),
            {"Content-Type": "application/json"},
        )

    def parse(self, doc, kind, value):

        if doc.get("query_status") != "ok":
            return {
                "status": (
                    "not_found"
                    if doc.get("query_status") in ("no_result", "hash_not_found")
                    else "error"
                )
            }
        a = doc["data"][0]
        return dict(
            verdict="malicious",
            family=a.get("malware_printable") or a.get("malware"),
            tags=a.get("tags") or [],
            first_seen=a.get("first_seen"),
            last_seen=a.get("last_seen"),
            permalink="https://threatfox.abuse.ch/browse/",
            details={
                k: a.get(k) for k in ("confidence_level", "ioc_type", "reference")
            },
        )
