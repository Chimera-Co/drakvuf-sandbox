"""Connections and DNS queries from the analysis pcap (tcpdump on the guest bridge, classic pcap).

The capture is taken on the drak bridge, before the containment DNAT, so destinations are the
ones the guest asked for. Only what the guest sent is read: TCP SYNs (connection attempts),
UDP datagrams, DNS query names, plaintext HTTP request heads and TLS ClientHellos. Pure Python, no capture
library needed.
"""

import hashlib
import pathlib
import socket
import struct
from typing import Any, Dict, List, Optional

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
LINKTYPE_ETHERNET = 1
HTTP_VERBS = (
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
    b"TRACE",
)
MAX_HELLO_BYTES = 128 * 1024
MAX_TLS_STREAMS = 1024


class _TLSReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if self.pos + size > len(self.data):
            raise ValueError("truncated TLS vector")
        result = self.data[self.pos : self.pos + size]
        self.pos += size
        return result

    def number(self, size: int = 2) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, size: int = 2) -> bytes:
        return self.take(self.number(size))


def _words(data: bytes) -> List[int]:
    if len(data) % 2:
        raise ValueError("odd TLS vector")
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


def _not_grease(value: int) -> bool:
    return value & 0x0F0F != 0x0A0A or value >> 8 != value & 0xFF


def tls_client_hello(body: bytes) -> Optional[Dict[str, Any]]:
    """Decode a complete handshake body. JA3 uses legacy_version, per JA3 convention."""
    try:
        reader = _TLSReader(body)
        legacy_version = reader.number()
        reader.take(32)  # random
        reader.vector(1)  # session ID
        ciphers = _words(reader.vector())
        reader.vector(1)  # compression methods
        extensions, groups, points, versions, alpn = [], [], [], [], []
        sni = None
        ext_reader = _TLSReader(reader.vector() if reader.pos < len(body) else b"")
        if reader.pos != len(body):
            raise ValueError("trailing ClientHello data")
        while ext_reader.pos < len(ext_reader.data):
            kind = ext_reader.number()
            data = _TLSReader(ext_reader.vector())
            extensions.append(kind)
            if kind == 0:  # server_name
                names = _TLSReader(data.vector())
                while names.pos < len(names.data):
                    name_type, name = names.number(1), names.vector()
                    if name_type == 0 and sni is None:
                        sni = name.decode("ascii", "replace")
            elif kind == 10:
                groups = _words(data.vector())
            elif kind == 11:
                points = list(data.vector(1))
            elif kind == 16:
                protocols = _TLSReader(data.vector())
                while protocols.pos < len(protocols.data):
                    alpn.append(protocols.vector(1).decode("ascii", "replace"))
            elif kind == 43:
                versions = [v for v in _words(data.vector(1)) if _not_grease(v)]
        ja3 = ",".join(
            [
                str(legacy_version),
                "-".join(str(v) for v in ciphers if _not_grease(v)),
                "-".join(str(v) for v in extensions if _not_grease(v)),
                "-".join(str(v) for v in groups if _not_grease(v)),
                "-".join(str(v) for v in points),
            ]
        )
        offered = max(versions or [legacy_version])
        return {
            "sni": sni,
            "alpn": alpn,
            "tls_version": {
                0x0301: "TLS 1.0",
                0x0302: "TLS 1.1",
                0x0303: "TLS 1.2",
                0x0304: "TLS 1.3",
            }.get(offered, hex(offered)),
            "ja3": ja3,
            "ja3_md5": hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest(),
        }
    except (ValueError, IndexError):
        return None


class _HelloStream:
    """Bounded, in-order TCP/TLS reassembly; overlap/retransmission is ignored.

    Gaps and out-of-order segments are deliberately not guessed. A SYN resets a reused tuple.
    Only the first ClientHello is retained (no encrypted renegotiation).
    """

    def __init__(self, seq: int, ts: float):
        self.seq, self.ts = seq, ts
        self.records = b""
        self.handshake = b""
        self.done = False

    def feed(self, seq: int, payload: bytes) -> Optional[Dict[str, Any]]:
        # Signed sequence difference also handles the 32-bit TCP sequence wrap.
        offset = ((seq - self.seq + 2**31) % 2**32) - 2**31
        if offset > 0:
            self.done = True
            return None
        payload = payload[-offset:]
        self.seq = (self.seq + len(payload)) % 2**32
        self.records += payload
        if len(self.records) + len(self.handshake) > MAX_HELLO_BYTES:
            self.done = True
        while not self.done and len(self.records) >= 5:
            size = int.from_bytes(self.records[3:5], "big")
            if self.records[0] != 22 or self.records[1] != 3 or size > 18432:
                self.done = True
                break
            if len(self.records) < size + 5:
                break
            self.handshake += self.records[5 : size + 5]
            self.records = self.records[size + 5 :]
            if len(self.handshake) < 4:
                continue
            length = int.from_bytes(self.handshake[1:4], "big")
            if self.handshake[0] != 1 or length > MAX_HELLO_BYTES - 4:
                self.done = True
            elif len(self.handshake) >= length + 4:
                self.done = True
                return tls_client_hello(self.handshake[4 : length + 4])
        return None


def http_request_head(payload: bytes) -> Optional[Dict[str, Any]]:
    # First segment of a plaintext HTTP request: "VERB path HTTP/x.y" and a few headers
    verb = payload.split(b" ", 1)[0]
    if verb not in HTTP_VERBS:
        return None
    lines = payload.split(b"\r\n")
    parts = lines[0].decode("ascii", "replace").split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None
    request = {"verb": parts[0], "path": parts[1][:2048], "version": parts[2]}
    for line in lines[1:40]:
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep:
            continue
        name = name.strip().lower()
        if name == "host":
            request["host"] = value.strip()[:255]
        elif name == "user-agent":
            request["user_agent"] = value.strip()[:512]
    return request


def dns_query_name(payload: bytes) -> Optional[str]:
    if len(payload) < 13 or payload[2] & 0x80:  # too short, or a response
        return None
    labels, i = [], 12
    while i < len(payload):
        n = payload[i]
        if n == 0:
            return ".".join(labels) if labels else None
        if n & 0xC0 or i + 1 + n > len(payload):
            return None
        labels.append(payload[i + 1 : i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None


def read_packets(path: pathlib.Path):
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) < 24 or header[:4] not in PCAP_MAGIC:
            return
        endian, ts_unit = PCAP_MAGIC[header[:4]]
        if struct.unpack(endian + "I", header[20:24])[0] != LINKTYPE_ETHERNET:
            return
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _ = struct.unpack(endian + "IIII", rec)
            if incl > 1024 * 1024:
                return  # unreasonable Ethernet capture length; avoid unbounded allocation
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + frac * ts_unit, data


def summarize_pcap(
    path: pathlib.Path, guest_ip: Optional[str] = None
) -> Dict[str, List[Dict[str, Any]]]:
    connections: Dict[tuple, Dict[str, Any]] = {}
    dns: List[Dict[str, Any]] = []
    http: List[Dict[str, Any]] = []
    tls: List[Dict[str, Any]] = []
    streams: Dict[tuple, _HelloStream] = {}
    if not path.exists():
        return {
            "connections": [],
            "dns_queries": [],
            "http_requests": [],
            "tls_handshakes": [],
        }
    for ts, frame in read_packets(path):
        if (
            len(frame) < 34 or frame[12:14] != b"\x08\x00"
        ):  # IPv4 only (IPv6 is dropped by containment)
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        total = int.from_bytes(ip[2:4], "big")
        if (
            ihl < 20
            or total < ihl
            or len(ip) < total
            or int.from_bytes(ip[6:8], "big") & 0x3FFF
        ):
            continue  # no IP fragment reassembly
        proto = ip[9]
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if guest_ip is not None and src != guest_ip:
            continue
        l4 = ip[ihl:total]
        if proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack("!HH", l4[:4])
            tcp_size = (l4[12] >> 4) * 4
            if tcp_size < 20 or tcp_size > len(l4):
                continue
            flags = l4[13]
            key = ("tcp", src, sport, dst, dport)
            if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                connections.setdefault(key, {"ts": ts})
                streams.pop(key, None)
            payload = l4[tcp_size:]
            request = http_request_head(payload) if payload else None
            if request is not None:
                http.append(
                    {
                        "ts": ts,
                        **request,
                        "remote_ip": dst,
                        "remote_port": dport,
                        "local_port": sport,
                    }
                )
            if payload:
                seq = (int.from_bytes(l4[4:8], "big") + bool(flags & 2)) % 2**32
                if key not in streams and payload[0] == 22:
                    if len(streams) >= MAX_TLS_STREAMS:
                        del streams[next(iter(streams))]
                    streams[key] = _HelloStream(seq, ts)
                stream = streams.get(key)
                if stream is not None and not stream.done:
                    hello = stream.feed(seq, payload)
                    if hello is not None:
                        connections.setdefault(key, {"ts": stream.ts})
                        tls.append(
                            {
                                "ts": stream.ts,
                                **hello,
                                "local_ip": src,
                                "local_port": sport,
                                "remote_ip": dst,
                                "remote_port": dport,
                            }
                        )
                    if stream.done:
                        stream.records = stream.handshake = b""
        elif proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack("!HH", l4[:4])
            key = ("udp", src, sport, dst, dport)
            connections.setdefault(key, {"ts": ts})
            if dport == 53:
                name = dns_query_name(l4[8:])
                if name:
                    dns.append(
                        {"ts": ts, "domain": name, "server": dst, "local_port": sport}
                    )
    return {
        "connections": [
            {
                "protocol": k[0],
                "local_ip": k[1],
                "local_port": k[2],
                "remote_ip": k[3],
                "remote_port": k[4],
                "ts": v["ts"],
            }
            for k, v in connections.items()
        ],
        "dns_queries": dns,
        "http_requests": http,
        "tls_handshakes": tls,
    }
