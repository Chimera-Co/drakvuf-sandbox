"""VirusTotal observable lookup adapter."""

import base64
from urllib.parse import quote

from .base import HASHES, NETWORK, Provider


class Adapter(Provider):
    id = "virustotal"
    label = "VirusTotal"
    host = "www.virustotal.com"
    types = HASHES + NETWORK
    header = "x-apikey"
    optional_key = False
    interval = 15
    daily_cap = 450
    max_lookups = 6

    def request(self, kind, value):

        resource = {"domain": "domains", "ip": "ip_addresses", "url": "urls"}.get(
            kind, "files"
        )
        ident = (
            base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            if kind == "url"
            else value
        )
        return (
            f'https://{self.host}/api/v3/{resource}/{quote(ident, safe="")}',
            None,
            {},
        )

    def parse(self, doc, kind, value):

        a = doc["data"]["attributes"]
        stats = {
            **dict.fromkeys(("malicious", "suspicious", "harmless", "undetected"), 0),
            **(a.get("last_analysis_stats") or {}),
        }
        malicious = stats.get("malicious", 0)
        return dict(
            verdict=(
                "malicious"
                if malicious >= 10
                else "suspicious" if malicious >= 3 else "unknown"
            ),
            detections={**stats, "total": sum(stats.values())},
            family=(a.get("popular_threat_classification") or {}).get(
                "suggested_threat_label"
            ),
            tags=a.get("tags") or [],
            first_seen=a.get("first_submission_date"),
            last_seen=a.get("last_submission_date"),
            permalink=f'https://www.virustotal.com/gui/{"file" if kind in HASHES else kind}/{quote(value, safe="")}',
            details={
                **{
                    k: a.get(k)
                    for k in (
                        "names",
                        "type_description",
                        "reputation",
                        "sandbox_verdicts",
                    )
                },
                "yara_rule_names": [
                    r.get("rule_name")
                    for r in (a.get("crowdsourced_yara_results") or [])[:20]
                ],
                "sigma_rule_names": [
                    r.get("rule_title")
                    for r in (a.get("crowdsourced_sigma_results") or [])[:20]
                ],
            },
        )
