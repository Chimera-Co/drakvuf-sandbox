"""Read a time slice of INetSim's shared, host-local service log.

Reverse scanning assumes timestamp order, as in INetSim's append-only log. It
reads only the tail back to the analysis window, not the whole file into memory.
NAT preserves source ports normally; port rewrites and collisions stay unmatched.
"""

import logging
import pathlib
import re
from datetime import datetime, timezone
from typing import Iterable

logger = logging.getLogger(__name__)
DEFAULT_SERVICE_LOG = pathlib.Path("/var/log/chimera-inetsim/service.log")
WINDOW_SLACK_S = 5
LINE = re.compile(
    r"^\[(?P<time>[^]]+)\] \[(?P<pid>\d+)\] "
    r"\[(?P<service>\S+) (?P<id>\d+)\] "
    r"\[(?P<client>.+):(?P<port>\d+)\] (?P<message>.*)$"
)
TIME_PREFIX = re.compile(rb"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")
REQUEST = re.compile(r"^(\S+) (\S+) (HTTP/\S+)$")
STAT = re.compile(r"\d+ method=(\S+) url=(.*?) sent=(.*?) postdata=(.*)$")
TLS_SERVICES = {"https", "smtps", "pop3s", "imaps", "ftps", "ldaps", "nntps", "ircs"}


def utc_timestamp(value: str) -> float:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # Older metadata sometimes has naive ISO strings; metadata times are UTC.
    return (
        dt.replace(tzinfo=timezone.utc).timestamp()
        if dt.tzinfo is None
        else dt.timestamp()
    )


def reverse_lines(stream, chunk_size=65536):
    stream.seek(0, 2)
    position, tail = stream.tell(), b""
    while position:
        size = min(position, chunk_size)
        position -= size
        stream.seek(position)
        lines = (stream.read(size) + tail).split(b"\n")
        tail = lines[0]
        yield from reversed(lines[1:])
    if tail:
        yield tail


def parse_sessions(lines: Iterable[str], start: float, end: float) -> list:
    """Group chronological lines, including interleaved sessions and HTTP keep-alive."""
    sessions = {}
    for line in lines:
        match = LINE.match(line.rstrip("\r\n"))
        if match is None:
            continue
        fields = match.groupdict()
        try:
            # A naive datetime.timestamp() uses the host's local timezone, including DST.
            ts = datetime.strptime(fields["time"], "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            continue
        if not start <= ts <= end:
            continue
        key = (
            fields["pid"],
            fields["service"],
            fields["id"],
            fields["client"],
            fields["port"],
        )
        session = sessions.setdefault(
            key,
            {
                "session_id": fields["service"] + " " + fields["id"],
                "service": fields["service"],
                "client_ip": fields["client"],
                "source_port": int(fields["port"]),
                "start": ts,
                "end": ts,
                "requests": [],
            },
        )
        session["end"] = ts
        message = fields["message"]
        if message.startswith("info: Error setting up SSL:"):
            session["tls_error"] = message[len("info: ") :]
        if message == "connect":
            session["connected"] = True
        if message == "disconnect":
            session["disconnected"] = True
        kind, _, content = message.partition(": ")
        if kind in {"recv", "send"}:
            # Preserve plaintext for TLS services that do not speak HTTP as well.
            session.setdefault("received" if kind == "recv" else "sent", []).append(
                content
            )
        request_line = REQUEST.match(content) if kind == "recv" else None
        if request_line:
            method, path, version = request_line.groups()
            session["requests"].append(
                {
                    "request_line": content,
                    "method": method,
                    "path": path,
                    "version": version,
                    "headers": {},
                }
            )
        requests = session["requests"]
        if not requests:
            continue
        request = requests[-1]
        if kind == "recv" and not request_line:
            name, sep, value = content.partition(":")
            if sep:
                request["headers"][name.strip().lower()] = value.strip()
        elif kind == "send" and content.startswith("HTTP/"):
            request["response_status"] = content
        elif kind == "info" and content.startswith("Request URL: "):
            request["url"] = content[len("Request URL: ") :]
        elif kind == "info" and content.startswith("Sending file: "):
            request["served_file"] = content[len("Sending file: ") :]
        elif kind == "stat":
            stat = STAT.match(content)
            if stat:
                method, url, served, postdata = stat.groups()
                request.update(
                    method=method, url=url, served_file=served, postdata=postdata
                )
    return [
        session
        for session in sessions.values()
        if session["service"].split("_", 1)[0] in TLS_SERVICES
        or session.get("tls_error")
    ]


def read_tls_sessions(
    start: float, end: float, path: pathlib.Path = DEFAULT_SERVICE_LOG
) -> list:
    start, end = start - WINDOW_SLACK_S, end + WINDOW_SLACK_S
    selected = []
    local_start = datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S").encode()
    local_end = datetime.fromtimestamp(end).strftime("%Y-%m-%d %H:%M:%S").encode()
    try:
        with pathlib.Path(path).open("rb") as stream:
            for raw in reverse_lines(stream):
                # ISO local timestamps sort lexically. Convert the window once to host local time.
                prefix = TIME_PREFIX.match(raw)
                if prefix:
                    timestamp = prefix[1]
                    if timestamp < local_start:
                        break
                    if timestamp > local_end:
                        continue
                selected.append(raw.decode("utf-8", "replace"))
    except OSError as exc:
        logger.warning("Cannot read INetSim service log %s: %s", path, exc)
        return []
    return parse_sessions(reversed(selected), start, end)


def match_tls_sessions(
    sessions: list, handshakes: list, tolerance: float = WINDOW_SLACK_S
) -> list:
    """A unique port/time match is required; the shared log has lost guest addresses."""
    by_port = {}
    for hello in handshakes:
        by_port.setdefault(hello["local_port"], []).append(hello)
    choices = [
        [
            hello
            for hello in by_port.get(session["source_port"], [])
            if abs(hello["ts"] - session["start"]) <= tolerance
        ]
        for session in sessions
    ]
    uses = {}
    for candidates in choices:
        for hello in candidates:
            uses[id(hello)] = uses.get(id(hello), 0) + 1
    for session, candidates in zip(sessions, choices):
        session.pop("connection", None)
        session.pop("unmatched_reason", None)
        session["matched"] = len(candidates) == 1 and uses[id(candidates[0])] == 1
        if session["matched"]:
            session["connection"] = candidates[0].copy()
        else:
            session["unmatched_reason"] = (
                "ambiguous port/time match" if candidates else "no port/time match"
            )
    return sessions
