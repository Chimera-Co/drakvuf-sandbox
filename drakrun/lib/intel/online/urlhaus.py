"""URLhaus observable lookup adapter."""

from urllib.parse import urlencode

from .base import HASHES, Provider


class Adapter(Provider):
    id = "urlhaus"
    label = "URLhaus"
    host = "urlhaus-api.abuse.ch"
    types = ("sha256", "md5", "domain", "ip", "url")
    header = "Auth-Key"
    optional_key = False
    interval = 2
    daily_cap = 150
    max_lookups = 10

    def request(self, kind, value):

        resource, field = (
            ("url", "url")
            if kind == "url"
            else ("payload", kind + "_hash") if kind in HASHES else ("host", "host")
        )
        return (
            f"https://{self.host}/v1/{resource}/",
            urlencode({field: value}).encode(),
            {},
        )

    def parse(self, doc, kind, value):

        if doc.get("query_status") != "ok":
            return {
                "status": (
                    "not_found"
                    if doc.get("query_status") in ("no_results", "no_result")
                    else "error"
                )
            }
        return dict(
            verdict="malicious",
            family=doc.get("signature"),
            tags=doc.get("tags") or [],
            first_seen=doc.get("firstseen") or doc.get("date_added"),
            last_seen=doc.get("lastseen"),
            permalink=doc.get("urlhaus_reference"),
            details={
                k: doc.get(k)
                for k in ("url_status", "threat", "payloads", "blacklists")
            },
        )
