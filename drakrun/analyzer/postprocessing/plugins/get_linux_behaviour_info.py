"""Report sections for Linux analyses, in the same shape as the Windows ones.

Sources: filetracer.log (Linux VFS hooks), syscall.log (syscalls plugin; connect/sendto/bind
addresses are decoded by the drakvuf-linuxnet build), dump.pcap (what the guest sent).
Events of the chimera-agent process itself (the serial channel) are left out.
"""
import gzip
import pathlib
from collections import Counter, defaultdict
from typing import Dict, Iterator, Optional

import orjson

from drakrun.lib.pcap_summary import summarize_pcap

from .plugin_base import PostprocessContext

MODIFIED = {"vfs_write", "do_truncate", "vfs_truncate", "vfs_fallocate", "vfs_mknod", "vfs_mkdir"}
DELETED = {"vfs_unlink", "vfs_rmdir"}
LINKS = {"vfs_symlink", "vfs_link"}
PERMISSIONS = {"chmod_common", "chown_common"}
NET_SYSCALLS = {"connect", "sendto", "sendmsg", "bind"}
DNS_MATCH_WINDOW_S = 2.0
MAX_SYSCALL_NAMES = 40


def read_json_lines(path: pathlib.Path) -> Iterator[dict]:
    gz = path.with_name(path.name + ".gz")
    if path.exists():
        stream = path.open("rb")
    elif gz.exists():
        stream = gzip.open(gz, "rb")
    else:
        return
    with stream:
        for line in stream:
            try:
                yield orjson.loads(line)
            except orjson.JSONDecodeError:
                continue


def endpoint(addr: str) -> Optional[tuple]:
    # "10.99.0.2:80" or "[2001:db8::1]:443"; unix:/netlink/family=N are not endpoints
    if not isinstance(addr, str) or ":" not in addr or addr.startswith(("unix:", "family=")):
        return None
    host, _, port = addr.rpartition(":")
    if not port.isdigit():
        return None
    return host.strip("[]"), int(port)


def get_linux_behaviour_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    tree = context.process_tree
    linux = context.metadata.model_extra.get("linux") or {}
    agent_pid = (linux.get("agent") or {}).get("pid")
    guest_ip = next(iter((linux.get("network") or {}).get("addr", {}).get("ens3", [])), None)

    def seqid_of(event: dict) -> Optional[int]:
        pid = event.get("PID")
        if pid is None or pid == agent_pid:
            return None  # the agent itself; the sample and its children have their own PIDs
        try:
            evtid = int(event.get("EventUID", "0"), 16)
        except ValueError:
            evtid = 0
        process = tree.get_process_for_evtid(pid, evtid) or tree.get_process(pid)
        return process.seqid if process is not None else -1

    modified, deleted, links, perms = defaultdict(set), defaultdict(set), [], []
    for event in read_json_lines(analysis_dir / "filetracer.log"):
        method = event.get("Method")
        name = event.get("FileName") or ""
        if "/.chimera-" in name:
            continue  # the agent's capture of the sample's stdout/stderr
        seqid = seqid_of(event)
        if seqid is None:
            continue
        if method in MODIFIED:
            modified[name].add(seqid)
        elif method in DELETED:
            deleted[name].add(seqid)
        elif method == "vfs_rename":
            modified[name].add(seqid)
            if event.get("old_name"):
                deleted[event["old_name"]].add(seqid)
        elif method in LINKS:
            links.append({"link": name, "target": event.get("oldname") or event.get("old_name"),
                          "method": method, "process_seqid": seqid})
        elif method in PERMISSIONS:
            perms.append({"filename": name, "method": method, "permissions": event.get("Permissions"),
                          "process_seqid": seqid})

    syscall_counts: Dict[int, Counter] = defaultdict(Counter)
    net_events = []
    for event in read_json_lines(analysis_dir / "syscall.log"):
        seqid = seqid_of(event)
        if seqid is None:
            continue
        method = event.get("Method")
        syscall_counts[seqid][method] += 1
        if method in NET_SYSCALLS:
            target = endpoint(event.get("addr") or event.get("dest_addr") or "")
            if target is not None:
                net_events.append({"method": method, "ip": target[0], "port": target[1],
                                   "ts": float(event.get("TimeStamp", 0)), "seqid": seqid})

    pcap = summarize_pcap(analysis_dir / "dump.pcap", guest_ip)
    by_endpoint = defaultdict(set)
    for ev in net_events:
        if ev["method"] != "bind":
            by_endpoint[(ev["ip"], ev["port"])].add(ev["seqid"])
    connections = []
    seen = set()
    for conn in pcap["connections"]:
        key = (conn["remote_ip"], conn["remote_port"])
        seen.add(key)
        connections.append({**{k: v for k, v in conn.items() if k != "ts"},
                            "process_seqids": sorted(by_endpoint.get(key, set()))})
    for key, seqids in by_endpoint.items():
        if key not in seen:  # attempted in a syscall but nothing on the wire (e.g. refused locally)
            connections.append({"protocol": None, "local_ip": None, "local_port": None,
                                "remote_ip": key[0], "remote_port": key[1], "process_seqids": sorted(seqids)})

    dns_queries = defaultdict(set)
    for query in pcap["dns_queries"]:
        senders = {ev["seqid"] for ev in net_events
                   if ev["port"] == 53 and ev["ip"] == query["server"]
                   and abs(ev["ts"] - query["ts"]) <= DNS_MATCH_WINDOW_S}
        dns_queries[query["domain"]].update(senders)

    context.update_report({
        "modified_files": [{"filename": f, "process_seqids": sorted(s)} for f, s in sorted(modified.items())],
        "deleted_files": [{"filename": f, "process_seqids": sorted(s)} for f, s in sorted(deleted.items())],
        "connections": connections,
        "dns_queries": [{"domain": d, "process_seqids": sorted(s)} for d, s in dns_queries.items()],
        "linux": {
            "links": links[:200],
            "permission_changes": perms[:200],
            "network_syscalls": net_events[:500],
            "syscall_counts": {
                str(seqid): dict(counts.most_common(MAX_SYSCALL_NAMES))
                for seqid, counts in sorted(syscall_counts.items())
            },
        },
    })
