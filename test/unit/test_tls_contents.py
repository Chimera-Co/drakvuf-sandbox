"""Offline TLS capture, shared INetSim log and cross-OS report integration."""

import hashlib
import io
import json
import os
import socket
import struct
import time
from datetime import datetime, timezone

import pytest

from drakrun.analyzer.analysis_metadata import AnalysisMetadata
from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.postprocessing.plugins import POSTPROCESS_PLUGINS
from drakrun.analyzer.postprocessing.plugins.generate_report import generate_report
from drakrun.analyzer.postprocessing.plugins.get_linux_behaviour_info import (
    get_linux_behaviour_info,
)
from drakrun.analyzer.postprocessing.plugins.get_socket_info import get_socket_info
from drakrun.analyzer.postprocessing.plugins.get_tls_info import (
    attribute_handshakes,
    get_tls_info,
)
from drakrun.analyzer.postprocessing.plugins.plugin_base import PostprocessContext
from drakrun.analyzer.postprocessing.postprocess import GUEST_OS_ONLY
from drakrun.analyzer.postprocessing.process_tree import tree_from_log
from drakrun.lib.inetsim_tls import (
    match_tls_sessions,
    parse_sessions,
    read_tls_sessions,
    reverse_lines,
    utc_timestamp,
)
from drakrun.lib.pcap_summary import summarize_pcap, tls_client_hello


def vector(data, size=2):
    return len(data).to_bytes(size, "big") + data


def hello():
    extensions = [
        (0x1A1A, b""),  # GREASE must not enter JA3
        (0, vector(b"\0" + vector(b"c2.test"))),
        (10, vector(struct.pack("!HH", 0x2A2A, 29))),
        (11, vector(b"\0", 1)),
        (16, vector(vector(b"h2", 1) + vector(b"http/1.1", 1))),
        (43, vector(struct.pack("!HHH", 0x3A3A, 0x0304, 0x0303), 1)),
    ]
    body = (
        b"\x03\x03"
        + b"x" * 32
        + vector(b"", 1)
        + vector(struct.pack("!HHH", 0x0A0A, 4865, 49199))
        + vector(b"\0", 1)
        + vector(
            b"".join(
                struct.pack("!H", kind) + vector(data) for kind, data in extensions
            )
        )
    )
    return body


def record(data):
    return b"\x16\x03\x01" + vector(data)


def client_hello():
    body = hello()
    return record(b"\1" + vector(body, 3))


def packet(payload=b"", seq=1000, sport=58638, flags=0x18):
    tcp = (
        struct.pack("!HHIIBBHHH", sport, 443, seq, 0, 0x50, flags, 1024, 0, 0) + payload
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton("10.0.0.2"),
        socket.inet_aton("1.1.1.1"),
    )
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


def pcap(path, packets):
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in packets:
        data += (
            struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame))
            + frame
        )
    path.write_bytes(data)


@pytest.fixture
def local_time(monkeypatch):
    original = os.environ.get("TZ")
    monkeypatch.setenv("TZ", "Asia/Kolkata")
    time.tzset()
    yield
    if original is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = original
    time.tzset()


START = datetime(2026, 10, 20, 4, 25, 21, tzinfo=timezone.utc).timestamp()


def line(
    message, session=411781, port=58638, stamp="09:55:21", service="https_443_tcp"
):
    return f"[2026-10-20 {stamp}] [1138] [{service} {session}] [10.99.0.1:{port}] {message}"


def log_text():
    return (
        "\n".join(
            [
                line("connect", session=10, stamp="09:54:00"),  # outside the window
                line("connect"),
                line("connect", session=20, port=52582),
                line("recv: POST /gate HTTP/1.1"),
                line("recv: Host: c2.test"),
                line(
                    "info: Error setting up SSL: SSL accept attempt failed: unexpected eof while reading",
                    20,
                    52582,
                ),
                line("recv: User-Agent: probe/1"),
                line("disconnect", 20, 52582),
                line("info: Request URL: https://c2.test/gate"),
                line("send: HTTP/1.1 200 OK"),
                line("info: Sending file: /fake/sample.html"),
                line(
                    "stat: 1 method=POST url=https://c2.test/gate sent=/fake/sample.html postdata=a=1 b=2"
                ),
                line("disconnect", stamp="09:55:22"),
                line("connect", session=30, stamp="10:00:00"),  # later than the window
            ]
        )
        + "\n"
    )


def test_client_hello_fields_and_ja3(tmp_path):
    pcap(tmp_path / "dump.pcap", [(START, packet(client_hello()))])
    result = summarize_pcap(tmp_path / "dump.pcap", "10.0.0.2")
    (entry,) = result["tls_handshakes"]
    ja3 = "771,4865-49199,0-10-11-16-43,29,0"
    assert entry == dict(
        ts=START,
        sni="c2.test",
        alpn=["h2", "http/1.1"],
        tls_version="TLS 1.3",
        ja3=ja3,
        ja3_md5=hashlib.md5(ja3.encode()).hexdigest(),
        local_ip="10.0.0.2",
        local_port=58638,
        remote_ip="1.1.1.1",
        remote_port=443,
    )
    assert summarize_pcap(tmp_path / "dump.pcap", "10.0.0.3")["tls_handshakes"] == []


def test_fragmented_records_segments_and_retransmission(tmp_path):
    message = b"\1" + vector(hello(), 3)
    payload = record(message[:30]) + record(message[30:])
    frames = [
        (START, packet(payload[:2])),  # even the TLS record header is split
        (START, packet(payload[:2])),  # duplicate
        (START + 0.1, packet(payload[2:50], seq=1002)),
        (START + 0.2, packet(payload[40:], seq=1040)),  # overlap
        (START + 0.3, packet(payload)),
    ]
    pcap(tmp_path / "dump.pcap", frames)
    assert len(summarize_pcap(tmp_path / "dump.pcap")["tls_handshakes"]) == 1


def test_tls12_without_extensions():
    body = (
        b"\x03\x03"
        + b"x" * 32
        + vector(b"", 1)
        + vector(b"\x00\x2f")
        + vector(b"\0", 1)
    )
    parsed = tls_client_hello(body)
    assert parsed["tls_version"] == "TLS 1.2"
    assert parsed["sni"] is None
    assert parsed["alpn"] == []
    assert parsed["ja3"] == "771,47,,,"


def test_truncated_and_malformed_hello_never_crash(tmp_path):
    payload = client_hello()
    for size in range(len(payload)):
        pcap(tmp_path / "dump.pcap", [(START, packet(payload[:size]))])
        assert summarize_pcap(tmp_path / "dump.pcap")["tls_handshakes"] == []
    for offset in range(len(hello())):
        data = bytearray(hello())
        data[offset] = 255
        tls_client_hello(bytes(data))
    pcap(
        tmp_path / "dump.pcap",
        [(START, packet(b"\x16\x03\x01\xff\xff")), (START, b"\0" * 34)],
    )
    assert summarize_pcap(tmp_path / "dump.pcap")["tls_handshakes"] == []


def test_gaps_not_misparsed(tmp_path):
    payload = client_hello()
    pcap(
        tmp_path / "dump.pcap",
        [(START, packet(payload[:10])), (START, packet(payload[20:], seq=1020))],
    )
    assert summarize_pcap(tmp_path / "dump.pcap")["tls_handshakes"] == []


def test_interleaved_sessions_and_local_to_utc(tmp_path, local_time):
    path = tmp_path / "service.log"
    path.write_text(log_text())
    sessions = read_tls_sessions(START, START + 10, path)
    assert len(sessions) == 2
    request, failure = sessions
    assert request["start"] == START
    assert request["end"] == START + 1
    assert request["source_port"] == 58638
    assert request["requests"] == [
        {
            "request_line": "POST /gate HTTP/1.1",
            "method": "POST",
            "path": "/gate",
            "version": "HTTP/1.1",
            "headers": {"host": "c2.test", "user-agent": "probe/1"},
            "url": "https://c2.test/gate",
            "response_status": "HTTP/1.1 200 OK",
            "served_file": "/fake/sample.html",
            "postdata": "a=1 b=2",
        }
    ]
    assert "unexpected eof" in failure["tls_error"]
    assert not failure["requests"]
    assert utc_timestamp("2026-10-20T04:25:21Z") == START
    assert utc_timestamp("2026-10-20T04:25:21") == START
    assert utc_timestamp("2026-10-20T09:55:21+05:30") == START


def test_keepalive_and_other_tls_services(local_time):
    lines = [
        line("connect"),
        line("recv: GET /one HTTP/1.1"),
        line("recv: Host: one.test"),
        line("recv: GET /two HTTP/1.1"),
        line("recv: Host: two.test"),
        line(
            "info: Error setting up SSL: unknown ca", service="smtps_465_tcp", session=2
        ),
    ]
    sessions = parse_sessions(lines, START, START + 10)
    assert [r["path"] for r in sessions[0]["requests"]] == ["/one", "/two"]
    assert sessions[1]["service"] == "smtps_465_tcp"


def test_unique_port_time_match_only():
    hello = dict(local_port=123, ts=START, remote_ip="1.1.1.1")
    sessions = [
        dict(source_port=123, start=START),
        dict(source_port=456, start=START),
        dict(source_port=123, start=START + 100),
    ]
    matched = match_tls_sessions(sessions, [hello])
    assert [s["matched"] for s in matched] == [True, False, False]
    assert matched[0]["connection"] == hello
    ambiguous = match_tls_sessions(
        [dict(source_port=123, start=START)], [hello, {**hello, "remote_ip": "2.2.2.2"}]
    )
    assert not ambiguous[0]["matched"]
    assert ambiguous[0]["unmatched_reason"] == "ambiguous port/time match"
    reused = match_tls_sessions(
        [dict(source_port=123, start=START), dict(source_port=123, start=START + 1)],
        [hello],
    )
    assert not any(s["matched"] for s in reused)


def test_reverse_reader_stops_before_old_data(tmp_path, local_time, monkeypatch):
    path = tmp_path / "service.log"
    path.write_text("old history\n" * 20000 + log_text())
    seen = []
    import drakrun.lib.inetsim_tls as module

    original = module.reverse_lines

    def tracked(stream):
        for raw in original(stream):
            seen.append(raw)
            yield raw

    monkeypatch.setattr(module, "reverse_lines", tracked)
    assert len(read_tls_sessions(START, START + 10, path)) == 2
    assert len(seen) < 20
    assert list(reverse_lines(io.BytesIO(b"one\ntwo\nthree"), chunk_size=2)) == [
        b"three",
        b"two",
        b"one",
    ]


def test_missing_unreadable_log_warns(tmp_path, caplog, monkeypatch):
    assert read_tls_sessions(START, START + 10, tmp_path / "missing") == []
    assert "Cannot read INetSim" in caplog.text
    monkeypatch.setattr(
        type(tmp_path),
        "open",
        lambda *a, **kw: (_ for _ in ()).throw(PermissionError("denied")),
    )
    assert read_tls_sessions(START, START + 10, tmp_path / "denied") == []
    assert "denied" in caplog.text


@pytest.mark.parametrize("guest_os", ["linux", "windows"])
def test_report_and_real_connection_attribution(
    tmp_path, base_config, local_time, guest_os
):
    log = tmp_path / "service.log"
    log.write_text(log_text())
    base_config.drakrun.inetsim_service_log = log
    options = AnalysisOptions.with_config_defaults(base_config, guest_os=guest_os)
    metadata = AnalysisMetadata(
        id="tls-test",
        options=options,
        time_execution_started="2026-10-20T04:25:21Z",
        time_finished="2026-10-20T04:25:31Z",
    )
    metadata.model_extra["linux"] = {"network": {"addr": {"ens3": ["10.0.0.2"]}}}
    context = PostprocessContext(tmp_path, base_config, metadata)
    context.process_tree = tree_from_log(
        io.StringIO(json.dumps({"RunningProcess": "sample", "PID": 20, "PPID": 1}))
    )
    pcap(
        tmp_path / "dump.pcap",
        [
            (START, packet(flags=2)),
            (START, packet(client_hello())),
            (START, packet(flags=2, sport=52582)),
            (START, packet(client_hello(), sport=52582)),
        ],
    )
    event = {"PID": 20, "EventUID": "0x1", "TimeStamp": str(START)}
    if guest_os == "linux":
        event.update(Method="connect", addr="1.1.1.1:443")
        (tmp_path / "syscall.log").write_text(json.dumps(event) + "\n")
        get_linux_behaviour_info(context)
    else:
        event.update(
            Method="TcpCreateAndConnectTcbComplete",
            Protocol="TCP",
            LocalIp="10.0.0.2",
            LocalPort=58638,
            RemoteIp="1.1.1.1",
            RemotePort=443,
        )
        second = {**event, "LocalPort": 52582}
        (tmp_path / "socketmon.log").write_text(
            json.dumps(event) + "\n" + json.dumps(second) + "\n"
        )
        get_socket_info(context)
    get_tls_info(context)
    generate_report(context)
    report = json.loads((tmp_path / "report.json").read_text())
    (request,) = report["tls_requests"]
    (failure,) = report["tls_failures"]
    assert request["method"] == "POST"
    assert request["url"] == "https://c2.test/gate"
    assert request["user_agent"] == "probe/1"
    assert request["postdata"] == "a=1 b=2"
    assert request["process_seqid"] == 0  # seqid zero is a real process
    assert failure["process_seqid"] == 0
    assert failure["sni"] == "c2.test"
    assert "may have rejected" in failure["error"]
    artifact = json.loads((tmp_path / "tls_sessions.json").read_text())
    assert all(s["matched"] for s in artifact["sessions"])
    assert len(artifact["tls_handshakes"]) == 2
    get_tls_info(
        context
    )  # reprocessing still fills report even when the artifact exists
    assert context.report["tls_requests"] == report["tls_requests"]


def test_plugin_order_and_cross_os():
    names = [p.function.__name__ for p in POSTPROCESS_PLUGINS]
    assert (
        names.index("get_linux_behaviour_info")
        < names.index("get_tls_info")
        < names.index("generate_report")
    )
    assert names.index("get_socket_info") < names.index("get_tls_info")
    assert "get_tls_info" not in GUEST_OS_ONLY


def test_optional_log_retains_metadata_and_unset_process(tmp_path, base_config, caplog):
    base_config.drakrun.inetsim_service_log = tmp_path / "missing-service.log"
    metadata = AnalysisMetadata(
        id="missing-log",
        options=AnalysisOptions.with_config_defaults(base_config),
        time_execution_started="2026-10-20T04:25:21Z",
        time_finished="2026-10-20T04:25:31Z",
    )
    context = PostprocessContext(tmp_path, base_config, metadata)
    pcap(tmp_path / "dump.pcap", [(START, packet(client_hello()))])
    get_tls_info(context)
    assert "Cannot read INetSim service log" in caplog.text
    assert context.report["tls_requests"] == context.report["tls_failures"] == []
    assert context.report["tls_handshakes"][0]["sni"] == "c2.test"
    assert context.report["tls_handshakes"][0]["process_seqid"] is None
    assert (tmp_path / "tls_sessions.json").exists()


def test_process_ambiguity_stays_unassigned():
    entry = dict(
        local_ip="10.0.0.2", local_port=123, remote_ip="1.1.1.1", remote_port=443
    )
    connection = dict(entry, protocol="tcp", process_seqids=[2, 3])
    attribute_handshakes([entry], [connection])
    assert entry["process_seqids"] == [2, 3]
    assert entry["process_seqid"] is None
