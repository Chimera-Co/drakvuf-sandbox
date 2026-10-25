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
    max_details_bytes = 24576

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
        threat = a.get("popular_threat_classification") or {}
        # Engines that flagged it, malicious first; the label each one gave is what analysts compare.
        engines = sorted(
            (
                {
                    "engine": r.get("engine_name") or name,
                    "category": r.get("category"),
                    "result": r.get("result"),
                }
                for name, r in (a.get("last_analysis_results") or {}).items()
                if isinstance(r, dict)
                and r.get("category") in ("malicious", "suspicious")
            ),
            key=lambda e: (e["category"] != "malicious", e["engine"] or ""),
        )
        details = {
            "reputation": a.get("reputation"),
            "votes": a.get("total_votes"),
            "last_analysis_date": a.get("last_analysis_date"),
            "engines": engines[:20],
            "engines_flagged": len(engines),
            "threat": {
                "label": threat.get("suggested_threat_label"),
                "categories": [
                    c.get("value") for c in threat.get("popular_threat_category") or []
                ][:5],
                "names": [
                    c.get("value") for c in threat.get("popular_threat_name") or []
                ][:5],
            },
            "rules": {
                "yara": [
                    r.get("rule_name")
                    for r in (a.get("crowdsourced_yara_results") or [])[:20]
                ],
                "sigma": [
                    r.get("rule_title")
                    for r in (a.get("crowdsourced_sigma_results") or [])[:20]
                ],
                "ids": [
                    (r.get("rule_msg") or "")[:200]
                    for r in (a.get("crowdsourced_ids_results") or [])[:10]
                ],
            },
            "sandbox_verdicts": [
                {
                    "sandbox": name,
                    "category": v.get("category"),
                    "families": (v.get("malware_names") or [])[:5],
                }
                for name, v in list((a.get("sandbox_verdicts") or {}).items())[:10]
                if isinstance(v, dict)
            ],
        }
        if kind in HASHES:
            details["file"] = {
                "meaningful_name": a.get("meaningful_name"),
                "names": (a.get("names") or [])[:10],
                "type": a.get("type_description"),
                "type_tag": a.get("type_tag"),
                "magic": a.get("magic"),
                "size": a.get("size"),
                "times_submitted": a.get("times_submitted"),
                "unique_sources": a.get("unique_sources"),
                "signed": bool(a.get("signature_info")),
                "signer": (a.get("signature_info") or {}).get("signers"),
                "first_seen_itw": a.get("first_seen_itw_date"),
            }
        else:
            details["network"] = {
                "categories": sorted(set((a.get("categories") or {}).values()))[:10],
                "registrar": a.get("registrar"),
                "created": a.get("creation_date"),
                "country": a.get("country"),
                "as_owner": a.get("as_owner"),
                "asn": a.get("asn"),
                "network": a.get("network"),
                "final_url": a.get("last_final_url"),
                "http_code": a.get("last_http_response_code"),
                "title": a.get("title"),
            }
        return dict(
            verdict=(
                "malicious"
                if malicious >= 10
                else (
                    "suspicious"
                    if malicious >= 3
                    else (
                        "harmless"
                        if stats.get("harmless", 0) >= 10 and not malicious
                        else "unknown"
                    )
                )
            ),
            detections={**stats, "total": sum(stats.values())},
            family=threat.get("suggested_threat_label"),
            tags=a.get("tags") or [],
            first_seen=a.get("first_submission_date") or a.get("creation_date"),
            last_seen=a.get("last_submission_date") or a.get("last_analysis_date"),
            permalink=f'https://www.virustotal.com/gui/{"file" if kind in HASHES else {"ip": "ip-address"}.get(kind, kind)}/{quote(value if kind != "url" else base64.urlsafe_b64encode(value.encode()).decode().rstrip("="), safe="")}',
            details=details,
        )
