"""Host background orchestration: reads JSON artifacts only."""

import ipaddress
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from drakrun.lib.intel import normalize
from drakrun.lib.intel.report import observations, sample_scope

from . import inventory, providers
from .cache import Cache
from .noise import background, non_public, string_artifact


def read_json(path):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def collect(directory, static_directory, config, network=None):
    """(kind, value, origin) to look up: the sample's hash, then what its own processes contacted, then what
    nobody can attribute, then strings in the file. Other guest processes' traffic is not looked up.
    """
    metadata = read_json(directory / "metadata.json")
    static = read_json(static_directory / "static.json")
    report = read_json(directory / "report.json")
    scope = sample_scope(report)
    candidates = observations(
        metadata,
        report,
        static,
        read_json(directory / "tls_sessions.json"),
        scope=scope or None,
    )
    # Strings from memory dumps of the sample's own processes (unpacked code); other processes' dumps are
    # Windows talking to its own services.
    for row in read_json(static_directory / "memdumps.json").get("scanned", []):
        if not row.get("sample_tree"):
            continue
        candidates += [
            (kind, value, "memory")
            for kind, value, _ in observations(
                {}, {}, {"universal": {"iocs": row.get("iocs") or {}}}, {}
            )
        ]
    excluded = []
    if network is not None:
        values = (
            network.model_dump() if hasattr(network, "model_dump") else vars(network)
        )
        for value in values.values():
            try:
                excluded.append(ipaddress.ip_network(str(value), strict=False))
            except ValueError:
                pass
    # Most telling first: the sample's own hash, then indicators seen at run time, then strings in the file.
    origin_rank = {
        "sample": 0,
        "dynamic": 1,
        "memory": 2,
        "unattributed": 3,
        "static": 4,
    }
    kind_rank = {"sha256": 0, "sha1": 1, "md5": 2, "domain": 3, "url": 4, "ip": 5}
    candidates = sorted(
        candidates, key=lambda c: (origin_rank.get(c[2], 3), kind_rank.get(c[0], 9))
    )
    # One lookup per file: sha1/md5 of the sample only when there is no sha256.
    sample_sha256 = any(k == "sha256" and o == "sample" for k, _, o in candidates)
    selected, seen, counts = [], set(), Counter()
    for kind, value, origin in candidates:
        if kind not in kind_rank or origin not in origin_rank:
            continue
        if origin == "sample" and kind in ("sha1", "md5") and sample_sha256:
            continue
        try:
            value = normalize(kind, value)
            host = urlsplit(value).hostname if kind == "url" else value
            if kind in {"ip", "url", "domain"}:
                try:
                    ipaddress.ip_address(host)
                    host_kind = "ip"
                except ValueError:
                    host_kind = "domain"
                if origin in ("static", "memory") and string_artifact(
                    host_kind, host or ""
                ):
                    continue
                try:
                    address = ipaddress.ip_address(host)
                    if (
                        not address.is_global
                        or address.is_multicast
                        or address.is_reserved
                        or any(address in subnet for subnet in excluded)
                    ):
                        continue
                except ValueError:
                    if kind == "ip" or non_public(host):
                        continue
                    # Domain verdicts for Windows' own services say nothing; a URL the sample itself
                    # fetched from one (payload hosting) still does.
                    if background(host) and (kind == "domain" or origin != "dynamic"):
                        continue
            if (kind, value) in seen or counts[kind] >= config.max_observables:
                continue
        except (ValueError, TypeError, UnicodeError):
            continue
        selected.append((kind, value, origin))
        counts[kind] += 1
        seen.add((kind, value))
    return selected


def run(directory, static_directory, config, network=None):
    items = collect(directory, static_directory, config, network)
    results, states = [], []
    cache = Cache(config.cache_path)
    for provider, info in zip(providers(), inventory(config)):
        rows = []
        # A provider without its key is reported once in `providers`, not once per observable.
        if info["enabled"] and info["configured"]:
            wanted = [item for item in items if item[0] in provider.types]
            for kind, value, origin in wanted[: provider.max_lookups]:
                rows.append(
                    {**provider.lookup(kind, value, config, cache), "origin": origin}
                )
        statuses = Counter(row["status"] for row in rows)
        status = (
            "disabled"
            if not info["enabled"]
            else (
                "not_configured"
                if not info["configured"]
                else (
                    "unsupported"
                    if not rows
                    else next(
                        (
                            s
                            for s in (
                                "error",
                                "offline",
                                "rate_limited",
                                "not_configured",
                                "unsupported",
                            )
                            if statuses[s]
                        ),
                        "ok",
                    )
                )
            )
        )
        states.append(
            dict(
                id=provider.id,
                configured=info["configured"],
                status=status,
                queried=sum(statuses[s] for s in ("ok", "not_found")),
                errors=[
                    dict(status=s, count=n)
                    for s, n in statuses.items()
                    if s not in ("ok", "not_found")
                ],
            )
        )
        results.extend(rows)
    ran = any(
        r["status"] in {"ok", "not_found", "error", "rate_limited"} for r in results
    )
    offline = any(s["status"] == "offline" for s in states)
    return dict(
        schema="chimera-intel-online/1",
        analysis_id=directory.name,
        generated_at=datetime.now(timezone.utc).isoformat(),
        connectivity="partial" if ran and offline else "online" if ran else "offline",
        providers=states,
        results=results,
        summary=dict(
            observables=len(items),
            # A match is a provider calling it malicious or suspicious; "seen" only means the provider
            # knows the value (a urlscan search hit, a known-good file).
            matches=sum(
                r.get("verdict") in ("malicious", "suspicious") for r in results
            ),
            malicious=sum(r.get("verdict") == "malicious" for r in results),
            known_good=sum(r.get("verdict") == "harmless" for r in results),
            seen=sum(r["status"] == "ok" for r in results),
            lookups=sum(r["status"] in ("ok", "not_found") for r in results),
        ),
    )


def enqueue(analysis_id, connection, options=None, depends_on=None):
    from rq import Queue

    from drakrun.analyzer.static.worker import INTEL_QUEUE_NAME
    from drakrun.lib.config import load_config

    settings = load_config().intel
    if not settings.online_enabled or not (options or {}).get(
        "intel_online", settings.online_default
    ):
        return None
    return Queue(name=INTEL_QUEUE_NAME, connection=connection).enqueue(
        run_online_intel_job,
        analysis_id,
        job_id=f"intel-online-{analysis_id}",
        job_timeout=3600,
        result_ttl=3600,
        depends_on=depends_on,
    )


def run_online_intel_job(analysis_id):
    from drakrun.analyzer.static.worker import _refresh_report, _write_json, job_dir
    from drakrun.lib.config import load_config
    from drakrun.lib.paths import ANALYSES_DIR

    config = load_config()
    if not config.intel.online_enabled:
        return
    target = job_dir(analysis_id)
    target.mkdir(parents=True, exist_ok=True)
    try:
        doc = run(ANALYSES_DIR / target.name, target, config.intel, config.network)
    except Exception:
        doc = dict(
            schema="chimera-intel-online/1",
            analysis_id=target.name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            connectivity="offline",
            providers=[
                dict(
                    id=p.id,
                    configured=i["configured"],
                    status="error",
                    queried=0,
                    errors=["cache or artifact unavailable"],
                )
                for p, i in zip(providers(), inventory(config.intel))
            ],
            results=[],
            summary={},
        )
    _write_json(target, "intel-online.json", doc)
    _refresh_report(analysis_id)
    return doc["summary"]


def assessment(label, results):
    """Precedence: known malware hashes, engine consensus, known software, model."""
    hits = [r for r in results if r.get("status") == "ok"]
    for row in hits:
        if row["provider"] in {"malwarebazaar", "threatfox"} and row["type"] in {
            "sha256",
            "sha1",
            "md5",
        }:
            return dict(
                label="malicious",
                basis="known malware",
                reasons=[
                    f"{row['provider']} hash match: {row.get('family') or 'unknown family'}"
                ],
            )
    engines = max(
        [
            r.get("detections", {}).get("malicious", 0)
            for r in hits
            if r["provider"] == "virustotal"
        ]
        or [0]
    )
    if engines >= 3:
        return dict(
            label=(
                "malicious" if engines >= 10 or label == "malicious" else "suspicious"
            ),
            basis="engine consensus",
            reasons=[f"VirusTotal: {engines} malicious engines"],
        )
    if label != "malicious" and any(
        r["provider"] == "hashlookup" and r["verdict"] == "harmless" for r in hits
    ):
        return dict(
            label="benign",
            basis="known software",
            reasons=["CIRCL known software hash match"],
        )
    return dict(
        label=label, basis="behaviour model", reasons=["Classifier verdict retained"]
    )


def run_offline_recheck_job(analysis_id):
    """Match an existing analysis against the offline feeds now installed (rebuilds its report)."""
    from drakrun.analyzer.static.worker import _refresh_report

    _refresh_report(analysis_id)
