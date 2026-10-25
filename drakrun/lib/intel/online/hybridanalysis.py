"""Hybrid Analysis observable lookup adapter."""

from urllib.parse import urlencode

from .base import HASHES, Provider


class Adapter(Provider):
    id = "hybridanalysis"
    label = "Hybrid Analysis"
    host = "www.hybrid-analysis.com"
    types = HASHES
    header = "api-key"
    optional_key = False
    interval = 2
    max_lookups = 3

    def request(self, kind, value):

        return (
            f"https://{self.host}/api/v2/search/hash",
            urlencode({"hash": value}).encode(),
            {"User-Agent": "Falcon Sandbox"},
        )

    def parse(self, doc, kind, value):

        if not doc:
            return {"status": "not_found"}
        a = max(doc, key=lambda r: r.get("threat_score") or 0)
        return dict(
            verdict=(
                a.get("verdict")
                if a.get("verdict") in ("malicious", "suspicious", "harmless")
                else "unknown"
            ),
            family=a.get("vx_family"),
            permalink=f'https://www.hybrid-analysis.com/sample/{a.get("sha256",value)}',
            details={
                k: a.get(k)
                for k in (
                    "threat_score",
                    "av_detect",
                    "submit_name",
                    "environment_description",
                )
            },
        )
