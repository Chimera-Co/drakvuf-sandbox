# Vendored from chimera-console sprint/final @ 9e298d849aca5c92c4cb80bef40b1c531dd90970: drakrun/analyzer/classifier/features.py
# Only change: the pcap_summary import points at the local copy.
"""Extract bounded, sample-scoped features from postprocessed guest logs.

Counters count observed events (not confirmed effects). Depth is relative to the
sample, with depth zero for the sample itself. Unattributed events are excluded.
"""

import gzip
import heapq
import json
import math
import struct
from pathlib import Path

from .pcap_summary import summarize_pcap


def _object(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _number(value, default=0):
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _integer(value):
    try:
        return (
            int(value, 16)
            if isinstance(value, str) and value.startswith("0x")
            else int(value)
        )
    except (TypeError, ValueError, OverflowError):
        return None


def _event_id(value):
    try:
        return int(value, 16) if isinstance(value, str) else _integer(value)
    except ValueError:
        return None


def _read_json(path):
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            return json.load(stream)
    except (OSError, ValueError, RecursionError):
        return None


def _json_lines(path, compressed=False):
    try:
        stream = (
            gzip.open(path, "rt", encoding="utf-8", errors="replace")
            if compressed
            else path.open(encoding="utf-8", errors="replace")
        )
        with stream:
            for line in stream:
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        yield value
                except (ValueError, RecursionError):
                    continue
    except (OSError, EOFError):
        return


def _append_unique(target, value, limit=100):
    if isinstance(value, str) and value and len(target) < limit and value not in target:
        target.append(value)


def _pcap_dns_names(directory, sample_dns_flows):
    """DNS query names in dump.pcap sent from a socket socketmon attributes to the sample.

    API hooks miss resolvers that talk to the DNS server directly (e.g. nslookup). The
    capture also holds Windows' own background lookups, so a query is kept only when its
    (server, guest UDP source port) matches a sample-scoped UdpSendMessages event.
    """
    if not sample_dns_flows:
        return
    try:
        queries = summarize_pcap(directory / "dump.pcap")["dns_queries"]
    except (OSError, struct.error, ValueError):
        return
    for query in queries:
        if (query.get("server"), query.get("local_port")) in sample_dns_flows:
            yield query.get("domain")


class _Scope:
    def __init__(self, tree, startup):
        self.nodes = []
        pending = [(node, None, 0) for node in reversed(_list(tree))]
        while pending:
            node, parent, depth = pending.pop()
            if not isinstance(node, dict):
                continue
            self.nodes.append((node, parent, depth))
            pending.extend(
                (child, node, depth + 1)
                for child in reversed(_list(node.get("children")))
            )

        root = None
        seqid = _integer(startup.get("process"))
        pid = _integer(startup.get("pid"))
        if seqid is not None:
            root = next(
                (n for n, _, _ in self.nodes if _integer(n.get("seqid")) == seqid), None
            )
        if root is None and pid is not None:
            root = next(
                (n for n, _, _ in self.nodes if _integer(n.get("pid")) == pid), None
            )
        self.selected = []
        selected_ids = set()
        root_depth = 0
        for node, parent, depth in self.nodes:
            if node is root:
                root_depth = depth
            if node is root or (parent is not None and id(parent) in selected_ids):
                selected_ids.add(id(node))
                self.selected.append((node, depth - root_depth))
        self.selected_ids = selected_ids
        self.seqids = {_integer(n.get("seqid")) for n, _ in self.selected} - {None}
        self.by_pid = {}
        for node, _, _ in self.nodes:
            self.by_pid.setdefault(_integer(node.get("pid")), []).append(node)

    def event(self, event, early_child=False):
        pid = _integer(event.get("PID"))
        if pid is None:
            return False
        candidates = self.by_pid.get(pid, [])
        evtid = _event_id(event.get("EventUID"))
        timestamp = _number(event.get("TimeStamp"), None)
        matches = []
        for node in candidates:
            if evtid is not None:
                start = _integer(node.get("evtid_from"))
                end = _integer(node.get("evtid_to"))
                if (
                    start is not None
                    and evtid < start
                    or end is not None
                    and evtid > end
                ):
                    continue
            elif timestamp is not None:
                start = _number(node.get("ts_from"))
                end = _number(node.get("ts_to"), None)
                if timestamp < start or end is not None and timestamp > end:
                    continue
            elif len(candidates) != 1:
                # A PID alone cannot disambiguate reuse.
                continue
            matches.append(node)
        if not matches and early_child and evtid is not None:
            # Match ProcessTree.get_process_for_evtid: children can emit events
            # before the parent's kernel_clone returns and records their birth.
            later = [
                n
                for n in candidates
                if _integer(n.get("evtid_from")) is not None
                and _integer(n.get("evtid_from")) > evtid
            ]
            if later:
                matches = [min(later, key=lambda n: _integer(n.get("evtid_from")))]
        return len(matches) == 1 and id(matches[0]) in self.selected_ids

    def report_event(self, event):
        seqids = event.get("process_seqids", [event.get("process_seqid")])
        return any(_integer(s) in self.seqids for s in _list(seqids))

    def ttp(self, event):
        if self.report_event(event):
            return True
        for occurrence in _list(event.get("occurrences")):
            occurrence = _object(occurrence)
            pid, ppid = _integer(occurrence.get("pid")), _integer(
                occurrence.get("ppid")
            )
            matches = [
                n for n in self.by_pid.get(pid, []) if _integer(n.get("ppid")) == ppid
            ]
            if len(matches) == 1 and id(matches[0]) in self.selected_ids:
                return True
        return False


def extract_features(analysis_dir) -> dict:
    """Missing or malformed inputs yield empty features; large logs are streamed."""
    directory = Path(analysis_dir)
    report = _object(_read_json(directory / "report.json"))
    # report.info is generated from the live metadata before metadata.json is saved.
    metadata = {
        **_object(_read_json(directory / "metadata.json")),
        **_object(report.get("info")),
    }
    sample = _object(metadata.get("file"))
    options = _object(metadata.get("options"))
    is_linux = options.get("guest_os") == "linux"
    telemetry = _object(metadata.get("telemetry"))
    startup = {} if is_linux else _object(report.get("startup"))
    if is_linux or (
        _integer(startup.get("pid")) is None
        and _integer(startup.get("process")) is None
    ):
        inject = _object(_read_json(directory / "inject.log"))
        if inject.get("Status") == "Success":
            startup = {"pid": inject.get("InjectedPid")}
    scope = _Scope(_read_json(directory / "process_tree.json"), startup)
    features = {
        "schema": "chimera-features/1",
        "sample": {
            "sha256": sample.get("sha256") or "",
            "file_name": sample.get("name") or "",
            "file_type": sample.get("type") or "",
            "size_bytes": max(0, int(_number(sample.get("size_bytes")))),
        },
        "run": {
            "guest_os": "linux" if is_linux else "windows",
            "timeout_s": _number(
                telemetry.get("analysis_timeout_s"), _number(options.get("timeout"))
            ),
            "complete": telemetry.get("complete") is True,
            "vm_stalled": telemetry.get("vm_stalled") is True,
            "drakvuf_errors": [
                v for v in _list(telemetry.get("drakvuf_errors")) if isinstance(v, str)
            ][:100],
        },
        "processes": {
            "count": len(scope.selected),
            "max_depth": 0,
            "names": [],
            "command_lines": [],
            "exited_early": False,
        },
        "api_calls": {},
        "api_sequence": [],
        "files": {"created": 0, "written": 0, "deleted": 0, "paths": []},
        "registry": {
            "set_value": 0,
            "create_key": 0,
            "delete": 0,
            "keys": [],
            "autorun_touched": False,
        },
        "network": {
            "dns_queries": [],
            "connections": 0,
            "remote_endpoints": [],
            "http_requests": 0,
        },
        "ttps": [],
    }
    processes = features["processes"]
    for node, depth in scope.selected:
        processes["max_depth"] = max(processes["max_depth"], depth)
        _append_unique(processes["names"], node.get("procname"), 50)
        args = node.get("args")
        command = (
            " ".join(a for a in args if isinstance(a, str))
            if isinstance(args, list)
            else args
        )
        _append_unique(processes["command_lines"], command, 50)
    if scope.selected:
        root = scope.selected[0][0]
        end = _number(root.get("ts_to"), None)
        # Explicit exit within the requested observation window, not a DRAKVUF exit.
        processes["exited_early"] = (
            end is not None
            and 0 <= end - _number(root.get("ts_from")) < features["run"]["timeout_s"]
        )

    earliest = []
    api_path = directory / ("syscall.log" if is_linux else "apimon.log")
    compressed = is_linux and not api_path.exists()
    if compressed:
        api_path = api_path.with_name(api_path.name + ".gz")
    for index, event in enumerate(_json_lines(api_path, compressed=compressed)):
        if (not is_linux and event.get("Event") != "api_called") or not scope.event(
            event, early_child=is_linux
        ):
            continue
        name = event.get("Method")
        if not isinstance(name, str) or not name:
            continue
        calls = features["api_calls"]
        calls[name] = calls.get(name, 0) + 1
        # Keep the earliest 2000 even if records arrive out of timestamp order.
        entry = (-_number(event.get("TimeStamp"), index), -index, name)
        if len(earliest) < 2000:
            heapq.heappush(earliest, entry)
        elif entry > earliest[0]:
            heapq.heapreplace(earliest, entry)
    features["api_sequence"] = [item[2] for item in sorted(earliest, reverse=True)]

    if is_linux:
        # Linux VFS report entries are unique paths, not individual writes.
        for section, counter in (
            ("modified_files", "written"),
            ("deleted_files", "deleted"),
        ):
            for event in _list(report.get(section)):
                if isinstance(event, dict) and scope.report_event(event):
                    features["files"][counter] += 1
                    _append_unique(features["files"]["paths"], event.get("filename"))
        network = features["network"]
        for event in _list(report.get("connections")):
            if isinstance(event, dict) and scope.report_event(event):
                network["connections"] += 1
                ip, port = event.get("remote_ip"), event.get("remote_port")
                if isinstance(ip, str) and port is not None:
                    _append_unique(network["remote_endpoints"], f"{ip}:{port}")
        for event in _list(report.get("dns_queries")):
            if isinstance(event, dict) and scope.report_event(event):
                _append_unique(network["dns_queries"], event.get("domain"))
        return features

    files = features["files"]
    for event in _json_lines(directory / "filetracer.log"):
        if not scope.event(event):
            continue
        method = event.get("Method")
        if method == "NtCreateFile" and (
            "Status" not in event or _integer(event["Status"]) == 0
        ):
            # IoStatusBlock FILE_CREATED = 2; NtCreateFile also opens existing files.
            if _integer(event.get("IoStatusBlock")) == 2 or (
                "IoStatusBlock" not in event
                and event.get("CreateDisposition") == "FILE_CREATE"
            ):
                files["created"] += 1
        elif method == "NtWriteFile":
            files["written"] += 1
        elif (
            method == "NtDeleteFile"
            or method == "NtSetInformationFile"
            and event.get("Operation")
            in ("FileDispositionInformation", "FileDispositionInformationEx")
        ):
            files["deleted"] += 1
        _append_unique(files["paths"], event.get("FileName"))

    registry = features["registry"]
    for event in _json_lines(directory / "regmon.log"):
        if not scope.event(event):
            continue
        method = event.get("Method")
        if method == "NtSetValueKey":
            registry["set_value"] += 1
        elif method in ("NtCreateKey", "NtCreateKeyTransacted"):
            registry["create_key"] += 1
        elif method in ("NtDeleteKey", "NtDeleteValueKey"):
            registry["delete"] += 1
        key = event.get("Key")
        _append_unique(registry["keys"], key)
        if isinstance(key, str):
            key = key.lower().rstrip("\\")
            if any(
                part in key + "\\"
                for part in (
                    "\\software\\microsoft\\windows\\currentversion\\run\\",
                    "\\software\\microsoft\\windows\\currentversion\\runonce\\",
                    "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run\\",
                    "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\",
                )
            ):
                registry["autorun_touched"] = True

    network = features["network"]
    sample_dns_flows = set()
    socket_path = directory / "socketmon.log"
    for event in _json_lines(socket_path):
        if not scope.event(event):
            continue
        if event.get("Method") == "DnsQueryEx":
            _append_unique(network["dns_queries"], event.get("DnsName"))
        elif event.get("Method") in (
            "UdpSendMessages",
            "TcpCreateAndConnectTcbComplete",
            "TcpCreateAndConnectTcbRateLimitComplete",
        ):
            network["connections"] += 1
            ip, port = event.get("RemoteIp"), event.get("RemotePort")
            if isinstance(ip, str) and port is not None:
                _append_unique(network["remote_endpoints"], f"{ip}:{port}")
            local_port = _integer(event.get("LocalPort"))
            if (
                event.get("Method") == "UdpSendMessages"
                and _integer(port) == 53
                and isinstance(ip, str)
                and local_port
            ):
                sample_dns_flows.add((ip, local_port))
    if not socket_path.exists():
        for event in _list(report.get("connections")):
            if isinstance(event, dict) and scope.report_event(event):
                network["connections"] += 1
                ip, port = event.get("remote_ip"), event.get("remote_port")
                if isinstance(ip, str) and port is not None:
                    _append_unique(network["remote_endpoints"], f"{ip}:{port}")
        for event in _list(report.get("dns_queries")):
            if isinstance(event, dict) and scope.report_event(event):
                _append_unique(network["dns_queries"], event.get("domain"))
    # Merge flow-attributed capture names, ignoring case differences with the hooked names.
    seen = {n.lower() for n in network["dns_queries"]}
    for name in _pcap_dns_names(directory, sample_dns_flows):
        if isinstance(name, str) and name.lower() not in seen:
            seen.add(name.lower())
            _append_unique(network["dns_queries"], name.lower())
    network["http_requests"] = sum(
        1
        for e in _list(report.get("http_requests"))
        if isinstance(e, dict) and scope.report_event(e)
    )

    ttps = report.get("ttps")
    if not isinstance(ttps, list) or not ttps:
        ttps = _json_lines(directory / "ttps.json")
    for event in ttps:
        if not isinstance(event, dict) or not scope.ttp(event):
            continue
        name = event.get("name")
        if not isinstance(name, str):
            continue
        ttp = {
            "name": name,
            "attack": [
                a
                for a in _list(event.get("att&ck", event.get("attack")))
                if isinstance(a, str)
            ][:100],
        }
        if ttp not in features["ttps"]:
            features["ttps"].append(ttp)
        if len(features["ttps"]) >= 100:
            break
    return features
