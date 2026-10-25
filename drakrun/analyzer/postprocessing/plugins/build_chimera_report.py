"""Combined CHIMERA report: one evidence-linked document per analysis.

Runs after classification and reads only what the analysis already produced (metadata.json,
report.json, features.json with the static result, classification.json). Writes:

    chimera-report.json   schema chimera-report/1 (docs/chimera/plan/report-intel-orchestration.md §2.3)
    chimera-report.html   one self-contained printable page: no scripts, no external requests

Behaviour is scoped to the sample's own process tree (the startup process and its descendants);
the rest of the guest's activity is counted but not listed. Every claim points at evidence entries
(artifact file + SHA-256 + a JSON-pointer selector), so a reader can check it against the raw data.
"""

import datetime
import hashlib
import html
import json
import logging
import pathlib
import re
from typing import Optional

from drakrun.version import __version__ as DRAKRUN_VERSION

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

SCHEMA = "chimera-report/1"
LIST_LIMIT = 25  # rows per list in the report; totals are always given
TECHNIQUE = re.compile(r"\[?(T\d{4}(?:\.\d{3})?)\]?")
VERDICT_TEXT = {
    "malicious": "Malicious",
    "suspicious": "Suspicious",
    "benign": "Benign",
    "unknown": "No verdict",
}


class _Evidence:
    """Collects evidence entries; ids are stable within one report (e1, e2, ...)."""

    def __init__(self, hashes: dict):
        self.hashes = hashes
        self.items: list = []
        self.ids: dict = {}

    def add(self, artifact: str, selector: str, producer: str) -> str:
        if (artifact, selector) in self.ids:
            return self.ids[(artifact, selector)]
        eid = self.ids[(artifact, selector)] = f"e{len(self.items) + 1}"
        self.items.append(
            {
                "id": eid,
                "artifact": artifact,
                "sha256": self.hashes.get(artifact, "0" * 64),
                "selector": selector,
                "producer": producer,
            }
        )
        return eid


def _read(path: pathlib.Path):
    try:
        raw = path.read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError):
        return None, None


def _subtree(processes: list, root: Optional[int]) -> set:
    if root is None:
        return set()
    children: dict = {}
    for p in processes:
        children.setdefault(p.get("parent_seqid"), []).append(p["seqid"])
    seen, todo = set(), [root]
    while todo:
        seqid = todo.pop()
        if seqid not in seen:
            seen.add(seqid)
            todo.extend(children.get(seqid, []))
    return seen


def _depth(processes: list, root: Optional[int], scope: set) -> int:
    parent = {p["seqid"]: p.get("parent_seqid") for p in processes}
    best = 0
    for seqid in scope:
        d, cur = 0, seqid
        while cur != root and cur in parent and d < 64:
            cur, d = parent[cur], d + 1
        best = max(best, d)
    return best


def _in_scope(item: dict, scope: set) -> bool:
    ids = item.get("process_seqids")
    if ids is None:
        ids = [item.get("process_seqid")]
    return any(i in scope for i in ids)


def _techniques(texts) -> list:
    return sorted({m.group(1) for t in texts for m in TECHNIQUE.finditer(str(t))})


def _stage_static(static, ev: _Evidence) -> dict:
    if not isinstance(static, dict):
        return {
            "status": "unavailable",
            "reason": "no static result (static analysis off, or it did not finish in time)",
            "producer": {},
            "payload": None,
            "evidence_ids": [],
        }
    producer = {
        "name": "chimera-static",
        "version": static.get("analyzer_version"),
        "image": (static.get("container") or {}).get("image"),
        "yara_ruleset": (static.get("universal") or {}).get("yara_ruleset"),
    }
    eid = ev.add("features.json", "/static", "chimera-static")
    if static.get("error"):
        return {
            "status": "failed",
            "reason": str(static["error"])[:300],
            "producer": producer,
            "payload": None,
            "evidence_ids": [eid],
        }
    coverage = static.get("coverage") or {}
    if coverage.get("complete") is True:
        status, reason = "ok", None
    elif not coverage:
        status, reason = "partial", "coverage not reported (older analyzer)"
    elif not coverage.get("type_plugin"):
        status = "partial"
        reason = f"no parser for {(static.get('type') or {}).get('format')} files"
    else:
        status = "partial"
        reason = "failed: " + ", ".join(coverage.get("failed_stages") or [])
    payload = {
        "format": (static.get("type") or {}).get("format"),
        "score": static.get("score"),
        "level": static.get("level"),
        "coverage": coverage or None,
        "findings": len(static.get("findings") or []),
        "hashes": {
            k: (static.get("file") or {}).get(k)
            for k in ("md5", "sha1", "sha256", "ssdeep", "tlsh")
        }
        | {"imphash": (static.get("pe") or {}).get("imphash")},
    }
    return {
        "status": status,
        "reason": reason,
        "producer": producer,
        "payload": payload,
        "evidence_ids": [eid],
    }


def build_report(analysis_dir: pathlib.Path) -> dict:
    analysis_dir = pathlib.Path(analysis_dir)
    loaded = {
        name: _read(analysis_dir / name)
        for name in (
            "metadata.json",
            "report.json",
            "features.json",
            "classification.json",
        )
    }
    hashes = {name: digest for name, (_, digest) in loaded.items() if digest}
    meta = loaded["metadata.json"][0] or {}
    report = loaded["report.json"][0] or {}
    features = loaded["features.json"][0] or {}
    verdict = loaded["classification.json"][0]
    ev = _Evidence(hashes)
    options = meta.get("options") or {}
    guest_os = options.get("guest_os") or "windows"
    info_file = (report.get("info") or {}).get("file") or meta.get("file") or {}
    sample_meta = features.get("sample") or {}

    processes = report.get("processes") or []
    startup = report.get("startup") or {}
    root = startup.get("process")
    scope = _subtree(processes, root)
    by_seqid = {p["seqid"]: p for p in processes}
    telemetry = (
        (report.get("info") or {}).get("telemetry") or meta.get("telemetry") or {}
    )

    claims, attack, iocs, limitations = [], [], [], []

    def claim(cid, text, kind, confidence, eids, rationale=None, seqid=None):
        c = {
            "id": cid,
            "text": text,
            "kind": kind,
            "confidence": confidence,
            "evidence_ids": eids,
        }
        if rationale:
            c["rationale"] = rationale
        if seqid is not None:
            c["process_seqid"] = seqid
        claims.append(c)

    # ---- dynamic: what the sample's own process tree did
    if report:
        start_eid = ev.add("report.json", "/startup", "drakrun")
        if startup.get("status") != "Success":
            claim(
                "start",
                f"The sample did not start ({startup.get('status') or 'no startup record'}).",
                "observed",
                "high",
                [start_eid],
            )
        tree_ids = [
            ev.add("report.json", f"/processes/{i}", "drakrun-procmon")
            for i, p in enumerate(processes)
            if p["seqid"] in scope
        ][:LIST_LIMIT]
        names = [
            by_seqid[s].get("name")
            for s in sorted(scope)
            if by_seqid.get(s, {}).get("name")
        ]
        if scope:
            claim(
                "processes",
                f"The sample's process tree has {len(scope)} process(es), depth "
                f"{_depth(processes, root, scope)}: "
                + ", ".join(
                    sorted(
                        set(n.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for n in names)
                    )[:12]
                ),
                "observed",
                "high",
                [start_eid] + tree_ids,
                seqid=root,
            )
        sections = [
            ("modified_files", "filename", "wrote or modified", "drakrun-filetracer"),
            ("deleted_files", "filename", "deleted", "drakrun-filetracer"),
        ]
        for key, field, verb, producer in sections:
            hits = [
                (i, x)
                for i, x in enumerate(report.get(key) or [])
                if _in_scope(x, scope)
            ]
            if hits:
                shown = ", ".join(x.get(field, "?") for _, x in hits[:6])
                claim(
                    key,
                    f"It {verb} {len(hits)} file(s): {shown}{' ...' if len(hits) > 6 else ''}",
                    "observed",
                    "high",
                    [
                        ev.add("report.json", f"/{key}/{i}", producer)
                        for i, _ in hits[:LIST_LIMIT]
                    ],
                )
        dns = [
            (i, x)
            for i, x in enumerate(report.get("dns_queries") or [])
            if _in_scope(x, scope)
        ]
        for i, x in dns:
            iocs.append(
                {
                    "type": "domain",
                    "value": x.get("domain"),
                    "source": "dns query by the sample",
                    "evidence_ids": [
                        ev.add("report.json", f"/dns_queries/{i}", "drakrun-socketmon")
                    ],
                }
            )
        conns = [
            (i, x)
            for i, x in enumerate(report.get("connections") or [])
            if _in_scope(x, scope)
        ]
        endpoints = sorted(
            {
                (x.get("protocol"), x.get("remote_ip"), x.get("remote_port"))
                for _, x in conns
            }
        )
        for proto, ip, port in endpoints:
            iocs.append(
                {
                    "type": "endpoint",
                    "value": f"{ip}:{port}",
                    "protocol": proto,
                    "source": "connection attempt by the sample",
                    "evidence_ids": [],
                }
            )
        http = [
            (i, x)
            for i, x in enumerate(report.get("http_requests") or [])
            if _in_scope(x, scope)
        ]
        for i, x in http:
            iocs.append(
                {
                    "type": "url",
                    "value": f"{x.get('server_name') or '?'}:{x.get('server_port') or '?'}{x.get('path') or ''}",
                    "method": x.get("verb"),
                    "user_agent": x.get("user_agent"),
                    "source": "HTTP request by the sample",
                    "evidence_ids": [
                        ev.add(
                            "report.json", f"/http_requests/{i}", "drakrun-tlsmon/pcap"
                        )
                    ],
                }
            )
        if dns or conns or http:
            claim(
                "network",
                f"It made {len(dns)} DNS quer(y/ies), {len(endpoints)} distinct connection endpoint(s) "
                f"and {len(http)} HTTP request(s). The network is simulated, so these are attempts, "
                "not confirmed contact with a real server.",
                "observed",
                "high",
                [
                    ev.add("report.json", f"/dns_queries/{i}", "drakrun")
                    for i, _ in dns[:5]
                ]
                + [
                    ev.add("report.json", f"/connections/{i}", "drakrun")
                    for i, _ in conns[:5]
                ],
            )
        for i, t in enumerate(report.get("ttps") or []):
            if _in_scope(t, scope):
                eid = ev.add("report.json", f"/ttps/{i}", "drakrun-ttps")
                for tech in _techniques(t.get("att&ck") or []):
                    attack.append(
                        {
                            "technique": tech,
                            "name": t.get("name"),
                            "source": "dynamic",
                            "evidence_ids": [eid],
                        }
                    )
        for i, m in enumerate(report.get("memdumps") or []):
            if m.get("process_seqid") in scope:
                reasons = sorted(
                    {
                        d.get("dump_reason")
                        for d in m.get("dumps") or []
                        if d.get("dump_reason")
                    }
                )
                targets = sorted(
                    {
                        d.get("target_process")
                        for d in m.get("dumps") or []
                        if d.get("target_process") is not None
                    }
                )
                outside = [t for t in targets if t not in scope]
                text = f"Memory of process {m.get('process_seqid')} was dumped ({', '.join(reasons)[:200]})"
                if outside:
                    text += f"; it wrote into {len(outside)} process(es) outside its own tree"
                claim(
                    f"memdump-{i}",
                    text + ".",
                    "observed",
                    "medium",
                    [ev.add("report.json", f"/memdumps/{i}", "drakrun-memdump")],
                    seqid=m.get("process_seqid"),
                )
        linux = report.get("linux") or {}
        for key, label in (
            ("fileless_execs", "fileless execution(s)"),
            ("permission_changes", "permission change(s)"),
            ("network_syscalls", "network syscall(s)"),
        ):
            rows = [
                (i, x)
                for i, x in enumerate(linux.get(key) or [])
                if _in_scope(x, scope)
            ]
            if rows:
                claim(
                    f"linux-{key}",
                    f"Linux: {len(rows)} {label} in the sample's tree.",
                    "observed",
                    "high",
                    [
                        ev.add("report.json", f"/linux/{key}/{i}", "drakrun-linux")
                        for i, _ in rows[:LIST_LIMIT]
                    ],
                )
        others = len(processes) - len(scope)
        if others > 0:
            limitations.append(
                f"Behaviour is listed for the sample's own process tree only; {others} other guest process(es) "
                "(the operating system's own activity) are in report.json but not here."
            )

    # ---- static
    static_stage = _stage_static(features.get("static"), ev)
    static = features.get("static") if isinstance(features.get("static"), dict) else {}
    for i, f in enumerate(static.get("findings") or []):
        if f.get("severity") in ("high", "medium"):
            eid = ev.add(
                "features.json",
                f"/static/findings/{i}",
                f"chimera-static:{f.get('source')}",
            )
            claim(
                f"static-{i}",
                f"{f.get('title')}"
                + (f" ({f.get('evidence')})" if f.get("evidence") else ""),
                "observed",
                "medium" if f.get("severity") == "medium" else "high",
                [eid],
                rationale="Found in the file's content or structure, not observed running.",
            )
            for tech in f.get("attack") or []:
                attack.append(
                    {
                        "technique": tech,
                        "name": f.get("title"),
                        "source": "static",
                        "evidence_ids": [eid],
                    }
                )
    for kind in ("urls", "domains", "ipv4"):
        for value in ((static.get("universal") or {}).get("iocs") or {}).get(kind, [])[
            :LIST_LIMIT
        ]:
            iocs.append(
                {
                    "type": kind.rstrip("s"),
                    "value": value,
                    "source": "string in the file (not observed in use)",
                    "evidence_ids": [],
                }
            )

    # ---- classifier
    if isinstance(verdict, dict):
        v_eid = ev.add("classification.json", "", "chimera-fusion")
        label = verdict.get("label") or "unknown"
        components = verdict.get("components") or {}
        classifier_stage = {
            "status": "ok" if label != "unknown" else "partial",
            "reason": (
                None
                if label != "unknown"
                else "; ".join(verdict.get("explanation") or [])[:300]
            ),
            "producer": {
                "name": verdict.get("model"),
                "version": verdict.get("model_version"),
            },
            "payload": verdict,
            "evidence_ids": [v_eid],
        }
        assessment = {
            "id": "assessment",
            "text": f"{VERDICT_TEXT.get(label, label)}. "
            + " ".join((verdict.get("explanation") or [])[:2]),
            "kind": "inferred",
            "confidence": "unknown",
            "evidence_ids": [v_eid],
            "rationale": "The decision score is a model output on a 0-1 scale where 0.50 is the malicious "
            "threshold; it is not a calibrated probability.",
        }
    else:
        label, components = "unknown", {}
        classifier_stage = {
            "status": "unavailable",
            "reason": "no classification.json",
            "producer": {},
            "payload": None,
            "evidence_ids": [],
        }
        assessment = {
            "id": "assessment",
            "text": "No verdict: the classifier did not run.",
            "kind": "coverage",
            "confidence": "unknown",
            "evidence_ids": [],
        }

    dynamic_stage = {
        "status": (
            "ok"
            if telemetry.get("complete")
            else ("failed" if meta.get("status") == "failed" else "partial")
        ),
        "reason": (
            None
            if telemetry.get("complete")
            else "telemetry incomplete or analysis failed"
        ),
        "producer": {
            "name": "drakvuf",
            "drakrun": DRAKRUN_VERSION,
            "vm_id": meta.get("vm_id"),
            "guest_os": guest_os,
            "timeout_s": options.get("timeout"),
        },
        "payload": {
            "processes_in_tree": len(scope),
            "processes_total": len(processes),
            "plugins": {
                k: v.get("status") for k, v in (telemetry.get("plugins") or {}).items()
            },
        },
        "evidence_ids": (
            [ev.add("metadata.json", "/telemetry", "drakrun")] if meta else []
        ),
        "started_at": meta.get("time_execution_started"),
        "finished_at": meta.get("time_finished"),
    }
    stages = {
        "static": static_stage,
        "dynamic": dynamic_stage,
        "classifier": classifier_stage,
        "intel": {
            "status": "unavailable",
            "reason": "no threat-intelligence lookup in this version",
            "producer": {},
            "payload": None,
            "evidence_ids": [],
        },
    }

    # ---- limitations that always apply, then the ones this run triggered
    limitations.insert(
        0,
        "The guest has no internet access: DNS, HTTP and HTTPS are answered by a simulator "
        "(INetSim), so network activity shows what the sample tried, not what a real server returned.",
    )
    if options.get("timeout"):
        limitations.append(
            f"The sample ran for at most {options.get('timeout')} s; later behaviour is not observed."
        )
    missing = sorted(
        k
        for k, v in (telemetry.get("plugins") or {}).items()
        if v.get("status") != "produced"
    )
    if missing:
        limitations.append(
            "Monitors with no output in this run: "
            + ", ".join(missing)
            + " (often nothing to report; a missing log is not proof of absence)."
        )
    if static_stage["status"] != "ok":
        limitations.append(
            f"Static analysis {static_stage['status']}: {static_stage['reason']}."
        )
    if guest_os == "linux":
        limitations.append(
            "The behaviour model is trained on Windows only; Linux verdicts rest on static analysis."
        )
    limitations.append(
        "Scores are decision scores, not probabilities; fusion weights are fixed, not fitted on "
        "paired CHIMERA runs."
    )

    status = (
        "failed"
        if meta.get("status") == "failed"
        else (
            "complete"
            if all(s["status"] == "ok" for k, s in stages.items() if k != "intel")
            else "partial"
        )
    )
    return {
        "schema": SCHEMA,
        "analysis_id": meta.get("id") or analysis_dir.name,
        "revision": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "mode": (
            "combined" if isinstance(features.get("static"), dict) else "dynamic-only"
        ),
        "status": status,
        "sample": {
            "sha256": info_file.get("sha256") or sample_meta.get("sha256") or "0" * 64,
            "size_bytes": int(
                info_file.get("size_bytes") or sample_meta.get("size_bytes") or 0
            ),
            "display_name": str(
                info_file.get("name") or options.get("sample_filename") or ""
            )[:255],
            "file_type": info_file.get("type") or sample_meta.get("file_type"),
        },
        "stages": stages,
        "assessment": assessment,
        "claims": claims,
        "evidence": ev.items,
        "attack": sorted(attack, key=lambda a: (a["technique"], a["source"])),
        "iocs": iocs,
        "limitations": limitations,
        "provenance": {
            "drakrun": DRAKRUN_VERSION,
            "guest_os": guest_os,
            "start_command": options.get("start_command"),
            "artifacts": hashes,
            "verdict_label": label,
            "components": {
                k: c.get("label") for k, c in components.items() if isinstance(c, dict)
            },
        },
    }


# ------------------------------------------------------------------ printable page
CSS = """
:root{--ink:#1d2433;--muted:#5b6475;--line:#d9dee7;--bg:#ffffff;--soft:#f4f6f9;
--mal:#b42318;--sus:#b54708;--ben:#027a48;--unk:#475467}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;padding-bottom:4px;
border-bottom:1px solid var(--line)}p{margin:6px 0}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12px;word-break:break-all}
.banner{display:flex;gap:16px;align-items:center;padding:16px;border:1px solid var(--line);
border-left:6px solid var(--unk);border-radius:6px;background:var(--soft);margin:16px 0}
.banner.malicious{border-left-color:var(--mal)}.banner.suspicious{border-left-color:var(--sus)}
.banner.benign{border-left-color:var(--ben)}
.label{font-size:20px;font-weight:700}.malicious .label{color:var(--mal)}.suspicious .label{color:var(--sus)}
.benign .label{color:var(--ben)}.unknown .label{color:var(--unk)}
table{width:100%;border-collapse:collapse;margin:6px 0}th,td{text-align:left;vertical-align:top;
padding:5px 8px;border-bottom:1px solid var(--line)}th{width:28%;color:var(--muted);font-weight:600}
thead th{width:auto;background:var(--soft)}
ul{margin:6px 0;padding-left:20px}li{margin:3px 0}
.chip{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:4px;font-size:12px;
color:var(--muted)}.ok{color:var(--ben)}.bad{color:var(--mal)}.part{color:var(--sus)}
a.ev{font-size:11px;color:var(--muted);text-decoration:none;margin-left:2px}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media print{main{max-width:none;padding:0}body{font-size:11pt}h2{break-after:avoid}
tr,li{break-inside:avoid}.banner{break-inside:avoid}a.ev{color:var(--muted)}@page{margin:16mm}}
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _refs(ids) -> str:
    return "".join(f'<a class="ev" href="#{_e(i)}">[{_e(i)}]</a>' for i in ids[:6])


def _status(s: str) -> str:
    cls = (
        "ok"
        if s in ("ok", "complete")
        else "bad" if s in ("failed", "timeout") else "part"
    )
    return f'<span class="{cls}">{_e(s)}</span>'


def render_html(r: dict) -> str:
    v = r["stages"]["classifier"].get("payload") or {}
    label = v.get("label") or "unknown"
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>CHIMERA report: {_e(r['sample']['display_name'])}</title><style>{CSS}</style></head><body><main>",
        f"<h1>CHIMERA analysis report</h1><p class='muted'>{_e(r['sample']['display_name'])} · analysis "
        f"<span class='mono'>{_e(r['analysis_id'])}</span> · generated {_e(r['generated_at'])}</p>",
        f"<div class='banner {_e(label)}'><div class='label'>{_e(VERDICT_TEXT.get(label, label))}</div><div>",
    ]
    if isinstance(v.get("score"), (int, float)):
        out.append(
            f"<div>Decision score <b>{v['score']:.2f}</b> <span class='muted'>(0.50 is the malicious "
            "threshold; not a probability)</span></div>"
        )
    out.append(
        f"<div class='muted'>Report status: {_status(r['status'])} · mode {_e(r['mode'])}"
        + (f" · family {_e(v.get('family'))}" if v.get("family") else "")
        + "</div></div></div>"
    )
    out.append(f"<p>{_e(r['assessment']['text'])}</p>")

    s = r["sample"]
    out.append("<h2>1. Sample</h2><table>")
    for k, val in (
        ("File name", s["display_name"]),
        ("SHA-256", s["sha256"]),
        ("Size", f"{s['size_bytes']} bytes"),
        ("Type", s.get("file_type")),
        ("Guest", r["provenance"].get("guest_os")),
        ("Start command", r["provenance"].get("start_command")),
    ):
        out.append(
            f"<tr><th>{_e(k)}</th><td class='{'mono' if k in ('SHA-256', 'Start command') else ''}'>"
            f"{_e(val)}</td></tr>"
        )
    out.append("</table>")

    out.append(
        "<h2>2. What each part of the analysis covered</h2><table><thead><tr><th>Part</th><th>Status</th>"
        "<th>Detail</th></tr></thead>"
    )
    for name, st in r["stages"].items():
        prod = st.get("producer") or {}
        detail = (
            st.get("reason")
            or ", ".join(
                f"{k} {val}"
                for k, val in prod.items()
                if isinstance(val, (str, int, float)) and val
            )[:200]
        )
        out.append(
            f"<tr><td>{_e(name)}</td><td>{_status(st['status'])}</td><td>{_e(detail)}"
            f"{_refs(st.get('evidence_ids') or [])}</td></tr>"
        )
    out.append("</table>")

    out.append("<h2>3. Key findings</h2>")
    if r["claims"]:
        out.append("<ul>")
        for c in r["claims"]:
            out.append(
                f"<li>{_e(c['text'])} <span class='chip'>{_e(c['kind'])}</span>{_refs(c['evidence_ids'])}"
                + (
                    f"<div class='muted'>{_e(c['rationale'])}</div>"
                    if c.get("rationale")
                    else ""
                )
                + "</li>"
            )
        out.append("</ul>")
    else:
        out.append(
            "<p class='muted'>No behaviour or static findings were recorded for the sample.</p>"
        )

    comps = v.get("components") or {}
    if comps:
        out.append(
            "<h2>4. Verdict parts</h2><table><thead><tr><th>Part</th><th>Label</th><th>Decision score</th>"
            "<th>Why</th></tr></thead>"
        )
        for name, c in comps.items():
            score = c.get("score")
            out.append(
                f"<tr><td>{_e(name)}</td><td>{_e(VERDICT_TEXT.get(c.get('label'), c.get('label')))}</td>"
                f"<td>{_e(f'{score:.2f}' if isinstance(score, (int, float)) else '–')}</td><td><ul>"
                + "".join(
                    f"<li>{_e(line)}</li>" for line in (c.get("explanation") or [])[:6]
                )
                + "</ul></td></tr>"
            )
        out.append("</table>")

    out.append("<h2>5. MITRE ATT&amp;CK</h2>")
    if r["attack"]:
        out.append(
            "<table><thead><tr><th>Technique</th><th>Seen as</th><th>Source</th></tr></thead>"
        )
        for a in r["attack"][:60]:
            out.append(
                f"<tr><td class='mono'>{_e(a['technique'])}</td><td>{_e(a.get('name'))}</td>"
                f"<td>{_e(a['source'])}{_refs(a.get('evidence_ids') or [])}</td></tr>"
            )
        out.append("</table>")
    else:
        out.append(
            "<p class='muted'>No technique was mapped for the sample's own activity.</p>"
        )

    out.append("<h2>6. Indicators</h2>")
    if r["iocs"]:
        out.append(
            "<table><thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead>"
        )
        for i in r["iocs"][:120]:
            out.append(
                f"<tr><td>{_e(i['type'])}</td><td class='mono'>{_e(i['value'])}</td><td>{_e(i['source'])}"
                f"{_refs(i.get('evidence_ids') or [])}</td></tr>"
            )
        out.append("</table>")
        if len(r["iocs"]) > 120:
            out.append(
                f"<p class='muted'>{len(r['iocs']) - 120} more in chimera-report.json.</p>"
            )
    else:
        out.append("<p class='muted'>None recorded.</p>")

    out.append(
        "<h2>7. Limitations</h2><ul>"
        + "".join(f"<li>{_e(x)}</li>" for x in r["limitations"])
        + "</ul>"
    )

    out.append(
        "<h2>8. Evidence</h2><p class='muted'>Each reference points into an artifact of this analysis; "
        "the SHA-256 identifies the exact file.</p><table><thead><tr><th>Id</th><th>Artifact</th>"
        "<th>Selector</th><th>Producer</th></tr></thead>"
    )
    for e in r["evidence"]:
        out.append(
            f"<tr id='{_e(e['id'])}'><td>{_e(e['id'])}</td><td>{_e(e['artifact'])}<div class='mono muted'>"
            f"{_e(e['sha256'][:16])}…</div></td><td class='mono'>{_e(e['selector'] or '/')}</td>"
            f"<td>{_e(e['producer'])}</td></tr>"
        )
    out.append("</table>")
    out.append(
        f"<footer>CHIMERA (drakrun {_e(r['provenance']['drakrun'])}) · schema {_e(r['schema'])} · "
        "print this page to save it as PDF.</footer></main></body></html>"
    )
    return "".join(out)


def build_chimera_report(context: PostprocessContext) -> None:
    report = build_report(context.analysis_dir)
    (context.analysis_dir / "chimera-report.json").write_text(
        json.dumps(report, indent=1, allow_nan=False), encoding="utf-8"
    )
    (context.analysis_dir / "chimera-report.html").write_text(
        render_html(report), encoding="utf-8"
    )
    context.update_metadata({"chimera_report": True})
