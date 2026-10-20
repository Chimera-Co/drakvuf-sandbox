"""TLS metadata from the guest capture and plaintext from INetSim, for either OS."""

import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit

import orjson

from drakrun.lib.inetsim_tls import match_tls_sessions, read_tls_sessions, utc_timestamp
from drakrun.lib.pcap_summary import summarize_pcap

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def attribute_handshakes(handshakes: list, connections: list) -> None:
    # Both socketmon and Linux behaviour export this shape. Linux's connection
    # attribution already resolves syscalls through the process tree, as for HTTP.
    for hello in handshakes:
        seqids = set()
        for conn in connections:
            if str(conn.get("protocol", "")).lower() != "tcp":
                continue
            if all(
                str(conn.get(key)) == str(hello[key])
                for key in ("local_ip", "local_port", "remote_ip", "remote_port")
            ):
                seqids.update(
                    s
                    for s in conn.get("process_seqids", [])
                    if s is not None and s >= 0
                )
        hello["process_seqids"] = sorted(seqids)
        hello["process_seqid"] = next(iter(seqids)) if len(seqids) == 1 else None


def handshake_error(raw: str) -> str:
    lower = raw.lower()
    if any(
        alert in lower
        for alert in ("unknown ca", "certificate unknown", "bad certificate")
    ):
        return "Client rejected the certificate"
    if "unexpected eof" in lower:
        return "TLS handshake failed; client may have rejected the certificate"
    return "TLS handshake failed"


def get_tls_info(context: PostprocessContext) -> None:
    linux = context.metadata.model_extra.get("linux") or {}
    guest_ip = next(
        iter((linux.get("network") or {}).get("addr", {}).get("ens3", [])), None
    )
    handshakes = summarize_pcap(context.analysis_dir / "dump.pcap", guest_ip)[
        "tls_handshakes"
    ]
    attribute_handshakes(handshakes, context.report.get("connections", []))
    sessions = []
    try:
        start = utc_timestamp(context.metadata.time_execution_started)
        # During a live run the worker sets time_finished after postprocessing.
        # For a saved analysis always use its recorded end, never the current time.
        end = (
            utc_timestamp(context.metadata.time_finished)
            if context.metadata.time_finished
            else datetime.now(timezone.utc).timestamp()
        )
        if end < start:
            raise ValueError("analysis ends before it starts")
    except (AttributeError, TypeError, ValueError) as exc:
        logger.warning(
            "Cannot select INetSim sessions without a valid analysis window: %s", exc
        )
    else:
        sessions = match_tls_sessions(
            read_tls_sessions(start, end, context.config.drakrun.inetsim_service_log),
            handshakes,
        )

    requests, failures = [], []
    for session in sessions:
        conn = session.get("connection", {})
        common = {
            "session_id": session["session_id"],
            "service": session["service"],
            "matched": session["matched"],
            "sni": conn.get("sni"),
            "process_seqid": conn.get("process_seqid"),
            "server_port": conn.get("remote_port"),
            "remote_ip": conn.get("remote_ip"),
        }
        if not session["matched"]:
            common["unmatched_reason"] = session["unmatched_reason"]
        for request in session["requests"]:
            headers = request["headers"]
            url = request.get("url")
            try:
                url_host = urlsplit(url).netloc if url else None
            except ValueError:
                url_host = None
            host = (
                headers.get("host")
                or conn.get("sni")
                or url_host
                or conn.get("remote_ip")
            )
            if not url and session["service"].startswith("https_") and host:
                url = (
                    request["path"]
                    if request["path"].startswith("https://")
                    else "https://" + host + request["path"]
                )
            # HTTPRow shares field names with the plaintext HTTP section.
            requests.append(
                {
                    **common,
                    "ts": session["start"],
                    "verb": request["method"],
                    "method": request["method"],
                    "path": url or request["path"],
                    "url": url,
                    "server_name": host,
                    "user_agent": headers.get("user-agent"),
                    "headers": headers,
                    "postdata": request.get("postdata"),
                    "response_status": request.get("response_status"),
                    "served_file": request.get("served_file"),
                }
            )
        if session.get("tls_error"):
            failures.append(
                {
                    **common,
                    "ts": session["start"],
                    "error": handshake_error(session["tls_error"]),
                    "tls_error": session["tls_error"],
                }
            )
    (context.analysis_dir / "tls_sessions.json").write_bytes(
        orjson.dumps(
            {"tls_handshakes": handshakes, "sessions": sessions},
            option=orjson.OPT_INDENT_2,
        )
    )
    context.update_report(
        {
            "tls_requests": requests,
            "tls_failures": failures,
            "tls_handshakes": handshakes,
        }
    )
