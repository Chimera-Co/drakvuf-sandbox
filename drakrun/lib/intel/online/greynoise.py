"""GreyNoise observable lookup adapter."""

from urllib.parse import quote

from .base import Provider


class Adapter(Provider):
    id = "greynoise"
    label = "GreyNoise"
    host = "api.greynoise.io"
    types = ("ip",)
    header = "key"
    optional_key = True
    interval = 2
    daily_cap = 40
    max_lookups = 5

    def request(self, kind, value):

        return f"https://{self.host}/v3/community/{quote(value)}", None, {}

    def parse(self, doc, kind, value):

        return dict(
            verdict=(
                "harmless"
                if doc.get("riot") or doc.get("classification") == "benign"
                else (
                    "malicious"
                    if doc.get("classification") == "malicious"
                    else "unknown"
                )
            ),
            permalink=doc.get("link"),
            details={
                k: doc.get(k) for k in ("noise", "riot", "classification", "name")
            },
        )
