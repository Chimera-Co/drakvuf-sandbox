"""AlienVault OTX observable lookup adapter."""

from urllib.parse import quote

from .base import HASHES, NETWORK, Provider


class Adapter(Provider):
    id = "otx"
    label = "AlienVault OTX"
    host = "otx.alienvault.com"
    types = HASHES + NETWORK
    header = "X-OTX-API-KEY"
    optional_key = False

    def request(self, kind, value):

        resource = (
            "file"
            if kind in HASHES
            else (
                "IPv6"
                if kind == "ip" and ":" in value
                else "IPv4" if kind == "ip" else kind
            )
        )
        return (
            f'https://{self.host}/api/v1/indicators/{resource}/{quote(value, safe="")}/general',
            None,
            {},
        )

    def parse(self, doc, kind, value):

        pulse = doc.get("pulse_info") or {}
        rows = pulse.get("pulses") or []
        return dict(
            verdict="suspicious" if pulse.get("count", 0) else "unknown",
            details={
                "pulse_count": pulse.get("count", 0),
                "pulse_names": [a.get("name") for a in rows[:20]],
                "malware_families": [a.get("malware_families") for a in rows[:20]],
                "adversary": [a.get("adversary") for a in rows[:20]],
                "attack_ids": [a.get("attack_ids") for a in rows[:20]],
            },
            permalink=f'https://otx.alienvault.com/indicator/{kind}/{quote(value, safe="")}',
        )
