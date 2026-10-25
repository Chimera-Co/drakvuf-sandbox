"""AbuseIPDB observable lookup adapter."""

from urllib.parse import quote, urlencode

from .base import Provider


class Adapter(Provider):
    id = "abuseipdb"
    label = "AbuseIPDB"
    host = "api.abuseipdb.com"
    types = ("ip",)
    header = "Key"
    optional_key = False
    daily_cap = 900
    max_lookups = 10

    def request(self, kind, value):

        return (
            f"https://{self.host}/api/v2/check?" + urlencode({"ipAddress": value}),
            None,
            {"Accept": "application/json"},
        )

    def parse(self, doc, kind, value):

        a = doc["data"]
        return dict(
            verdict=(
                "malicious"
                if a.get("abuseConfidenceScore", 0) >= 80
                else "suspicious" if a.get("abuseConfidenceScore", 0) > 0 else "unknown"
            ),
            details={
                k: a.get(k)
                for k in (
                    "abuseConfidenceScore",
                    "totalReports",
                    "countryCode",
                    "isp",
                    "usageType",
                )
            },
            permalink=f"https://www.abuseipdb.com/check/{quote(value)}",
        )
