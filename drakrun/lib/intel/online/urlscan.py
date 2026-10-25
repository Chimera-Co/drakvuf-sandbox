"""urlscan observable lookup adapter."""

from urllib.parse import urlencode

from .base import Provider


class Adapter(Provider):
    id = "urlscan"
    label = "urlscan"
    host = "urlscan.io"
    types = ("domain",)
    header = "API-Key"
    optional_key = True
    interval = 2
    daily_cap = 100
    max_lookups = 5

    def request(self, kind, value):

        return (
            f"https://{self.host}/api/v1/search/?"
            + urlencode({"q": "domain:" + value}),
            None,
            {},
        )

    def parse(self, doc, kind, value):

        rows = doc.get("results") or []
        count = sum(
            bool((r.get("verdicts") or {}).get("overall", {}).get("malicious"))
            for r in rows
        )
        return dict(
            status="ok" if rows else "not_found",
            verdict="suspicious" if count else "unknown",
            permalink=(
                (rows[0].get("result") or "").replace("/api/v1/result/", "/result/")
                if rows
                else None
            ),
            details={"count": doc.get("total", len(rows)), "malicious_count": count},
        )
