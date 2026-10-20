"""Connections and DNS queries from the analysis pcap (tcpdump on the guest bridge, classic pcap).

The capture is taken on the drak bridge, before the containment DNAT, so destinations are the
ones the guest asked for. Only what the guest sent is read: TCP SYNs (connection attempts),
UDP datagrams, and DNS query names. Pure Python, no capture library needed.
"""
import pathlib
import socket
import struct
from typing import Any, Dict, List, Optional

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
              b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
LINKTYPE_ETHERNET = 1


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
        labels.append(payload[i + 1:i + 1 + n].decode("ascii", "replace"))
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
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + frac * ts_unit, data


def summarize_pcap(path: pathlib.Path, guest_ip: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    connections: Dict[tuple, Dict[str, Any]] = {}
    dns: List[Dict[str, Any]] = []
    if not path.exists():
        return {"connections": [], "dns_queries": []}
    for ts, frame in read_packets(path):
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":  # IPv4 only (IPv6 is dropped by containment)
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if guest_ip is not None and src != guest_ip:
            continue
        l4 = ip[ihl:]
        if proto == 6 and len(l4) >= 14:
            sport, dport = struct.unpack("!HH", l4[:4])
            flags = l4[13]
            if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                key = ("tcp", src, sport, dst, dport)
                connections.setdefault(key, {"ts": ts})
        elif proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack("!HH", l4[:4])
            key = ("udp", src, sport, dst, dport)
            connections.setdefault(key, {"ts": ts})
            if dport == 53:
                name = dns_query_name(l4[8:])
                if name:
                    dns.append({"ts": ts, "domain": name, "server": dst, "local_port": sport})
    return {
        "connections": [
            {"protocol": k[0], "local_ip": k[1], "local_port": k[2], "remote_ip": k[3], "remote_port": k[4],
             "ts": v["ts"]}
            for k, v in connections.items()
        ],
        "dns_queries": dns,
    }
