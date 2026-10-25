"""Convert a WinMET (CAPEv2) report into CHIMERA's `chimera-features/1` view.

The goal is that a CAPE report and a CHIMERA run pass through the *same* feature code later.
So this module reproduces what CHIMERA's `drakrun/analyzer/classifier/features.py` would have
recorded for the same behaviour:

- scope: the sample's root process and its descendants only (CAPE also traces injected
  system processes);
- window: calls within `window_s` seconds of the root process's first call;
- `api_calls` / `api_sequence`: only APIs in CHIMERA's hooks.txt, with CAPE's `repeated`
  counts expanded, plus the inner calls DRAKVUF would also see (see aliases.json);
- `files` / `registry`: counted like filetracer / regmon. CAPE logs only the outermost call
  (RegSetValueExA, not the NtSetValueKey inside it), so both levels are added together.

Fields CAPE cannot provide are filled with neutral values and listed in
`aux["unavailable"]`, so the featurizer can exclude them on both sides.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import Counter
from datetime import date
from pathlib import Path

ADAPTER_VERSION = "1"
_HERE = Path(__file__).resolve().parent

SEQ_LIMIT = 2000  # same cap as CHIMERA's api_sequence
SEQ_ALL_LIMIT = 4000  # unfiltered sequence kept in aux, so filtering can be redone offline
LIST_LIMIT = 100

# CHIMERA features.py: autorun keys (lowercase, matched as substrings of key + "\\")
AUTORUN_PARTS = (
    "\\software\\microsoft\\windows\\currentversion\\run\\",
    "\\software\\microsoft\\windows\\currentversion\\runonce\\",
    "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run\\",
    "\\software\\microsoft\\windows nt\\currentversion\\winlogon\\",
)

# ---- file and registry counters (outer API + NT level, since CAPE logs only the outer one)
FILE_DELETE_APIS = {"NtDeleteFile", "DeleteFileA", "DeleteFileW", "RemoveDirectoryA", "RemoveDirectoryW"}
FILE_WRITE_APIS = {"NtWriteFile", "WriteFile", "WriteFileEx"}
FILE_COPY_APIS = {"CopyFileA", "CopyFileW", "CopyFileExA", "CopyFileExW", "CopyFile2"}
DIR_CREATE_APIS = {"CreateDirectoryA", "CreateDirectoryW", "CreateDirectoryExA", "CreateDirectoryExW"}
DISPOSITION_CLASSES = {"13", "64"}  # FileDispositionInformation(Ex)
REG_SET_APIS = {"NtSetValueKey", "RegSetValueExA", "RegSetValueExW", "RegSetValueA", "RegSetValueW",
                "RegSetKeyValueA", "RegSetKeyValueW"}
REG_CREATE_APIS = {"NtCreateKey", "NtCreateKeyTransacted", "RegCreateKeyExA", "RegCreateKeyExW",
                   "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyTransactedA", "RegCreateKeyTransactedW"}
REG_DELETE_APIS = {"NtDeleteKey", "NtDeleteValueKey", "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteKeyExA",
                   "RegDeleteKeyExW", "RegDeleteValueA", "RegDeleteValueW", "RegDeleteTreeA", "RegDeleteTreeW",
                   "RegDeleteKeyValueA", "RegDeleteKeyValueW"}
REG_KEY_ARGS = ("FullName", "ObjectAttributes", "Regkey", "KeyName", "SubKey")
FILE_PATH_ARGS = ("FileName", "HandleName", "ExistingFileName", "NewFileName", "DirectoryName", "PathName")

# ---- network intent, from API calls (WinMET's `network` section is empty)
DNS_APIS = {"DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8", "DnsQueryEx", "getaddrinfo", "GetAddrInfoW",
            "GetAddrInfoExW", "gethostbyname"}
CONNECT_APIS = {"connect", "WSAConnect", "ConnectEx", "WSAConnectByNameW", "WSAConnectByList"}
HTTP_APIS = {"HttpSendRequestA", "HttpSendRequestW", "HttpSendRequestExA", "HttpSendRequestExW",
             "WinHttpSendRequest", "InternetOpenUrlA", "InternetOpenUrlW", "URLDownloadToFileW",
             "URLDownloadToCacheFileW"}
DNS_NAME_ARGS = ("Name", "NodeName", "HostName", "pName")
_FILE_APIS = FILE_DELETE_APIS | FILE_WRITE_APIS | FILE_COPY_APIS | DIR_CREATE_APIS
_REG_APIS = REG_SET_APIS | REG_CREATE_APIS | REG_DELETE_APIS


def load_hooks(path: Path | None = None) -> frozenset[str]:
    names = set()
    for line in (path or _HERE / "hooks.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split(",")
            if len(parts) > 1:
                names.add(parts[1])
    return frozenset(names)


def load_aliases(path: Path | None = None) -> dict[str, list[str]]:
    data = json.loads((path or _HERE / "aliases.json").read_text(encoding="utf-8"))
    return {k: list(v) for k, v in data["implied"].items()}


def hooks_sha256(path: Path | None = None) -> str:
    return hashlib.sha256((path or _HERE / "hooks.txt").read_bytes()).hexdigest()


# ---------------------------------------------------------------- helpers
_date_cache: dict[str, int] = {}


def _ts(value) -> float | None:
    """'2024-08-02 10:29:46,767' -> seconds (float). Fast path; None if malformed."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    try:
        day = _date_cache.get(value[:10])
        if day is None:
            day = date(int(value[0:4]), int(value[5:7]), int(value[8:10])).toordinal()
            _date_cache[value[:10]] = day
        seconds = int(value[11:13]) * 3600 + int(value[14:16]) * 60 + int(value[17:19])
        ms = int(value[20:23]) if len(value) >= 23 else 0
        return day * 86400.0 + seconds + ms / 1000.0
    except ValueError:
        return None


def _int(value, default=None):
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return default


def _args(call) -> dict:
    out = {}
    for arg in call.get("arguments") or ():
        if isinstance(arg, dict) and "name" in arg:
            out[arg["name"]] = arg.get("value")
    return out


def _append_unique(target: list, value, limit=LIST_LIMIT):
    if isinstance(value, str) and value and len(target) < limit and value not in target:
        target.append(value)


def _printable_host(name) -> bool:
    if not isinstance(name, str) or not name or len(name) > 253 or "\\x" in name:
        return False
    try:
        ipaddress.ip_address(name)
        return False  # IP literals are not DNS queries
    except ValueError:
        pass
    return all(c.isalnum() or c in "-._" for c in name)


# ---------------------------------------------------------------- scope
def _select_scope(report: dict):
    """Return (root_pid, {pid: depth}, ordered processes in scope, method)."""
    processes = [p for p in report.get("behavior", {}).get("processes", []) if isinstance(p, dict)]
    if not processes:
        return None, {}, [], "no_processes"
    target = ((report.get("target") or {}).get("file") or {})
    tname = (target.get("name") or "").lower()
    by_pid = {}
    for p in processes:
        by_pid.setdefault(p.get("process_id"), p)

    def first_seen(p):
        t = _ts(p.get("first_seen"))
        return t if t is not None else float("inf")

    root, method = None, ""
    if tname:
        named = [p for p in processes if (p.get("process_name") or "").lower() == tname]
        named_pids = {p.get("process_id") for p in named}
        tops = [p for p in named if p.get("parent_id") not in named_pids]
        if tops:
            root, method = min(tops, key=first_seen), "name"
        if root is None:
            by_path = [p for p in processes if tname and tname in (p.get("module_path") or "").lower()]
            if by_path:
                root, method = min(by_path, key=first_seen), "module_path"
    if root is None:
        root, method = processes[0], "first_process"  # CAPE lists the initial process first

    depth = {root.get("process_id"): 0}
    changed = True
    while changed:  # small lists; iterate to a fixed point
        changed = False
        for p in processes:
            pid, ppid = p.get("process_id"), p.get("parent_id")
            if pid not in depth and ppid in depth:
                depth[pid] = depth[ppid] + 1
                changed = True
    scoped = [p for p in processes if p.get("process_id") in depth]
    return root.get("process_id"), depth, scoped, method


# ---------------------------------------------------------------- main entry
def adapt_report(report: dict, label: dict | None = None, *, window_s: float = 180.0,
                 hooks: frozenset[str] | None = None, implied: dict[str, list[str]] | None = None,
                 volume: int | None = None) -> dict:
    hooks = hooks if hooks is not None else load_hooks()
    implied = implied if implied is not None else load_aliases()
    target = ((report.get("target") or {}).get("file") or {})
    sha256 = (target.get("sha256") or "").lower()

    root_pid, depth, scoped, root_method = _select_scope(report)
    root = next((p for p in scoped if p.get("process_id") == root_pid), None)
    t0 = _ts(root.get("first_seen")) if root else None

    # ---- collect calls in scope and window, in time order
    events = []  # (t, proc_order, idx, call)
    total_calls = 0
    for order, proc in enumerate(scoped):
        for idx, call in enumerate(proc.get("calls") or ()):
            if not isinstance(call, dict):
                continue
            total_calls += 1
            t = _ts(call.get("timestamp"))
            if t0 is None and t is not None:
                t0 = t
            events.append((t if t is not None else float("inf"), order, idx, call))
    if t0 is None:
        t0 = 0.0
    events.sort(key=lambda e: (e[0], e[1], e[2]))
    limit_t = t0 + window_s
    in_window = [e for e in events if e[0] <= limit_t]
    if events and not in_window:
        # timestamps missing or before t0: keep the order, ignore the window
        in_window = events

    api_all = Counter()
    seq_all: list[str] = []
    api_calls = Counter()
    api_seq: list[str] = []
    files = {"created": 0, "written": 0, "deleted": 0, "paths": []}
    registry = {"set_value": 0, "create_key": 0, "delete": 0, "keys": [], "autorun_touched": False}
    network = {"dns_queries": [], "connections": 0, "remote_endpoints": [], "http_requests": 0}
    dns_seen = set()
    last_t = t0

    for t, _order, _idx, call in in_window:
        api = call.get("api")
        if not isinstance(api, str) or not api:
            continue
        if t != float("inf"):
            last_t = max(last_t, t)
        n = 1 + max(0, _int(call.get("repeated"), 0) or 0)
        api_all[api] += n
        if len(seq_all) < SEQ_ALL_LIMIT:
            seq_all.extend([api] * min(n, SEQ_ALL_LIMIT - len(seq_all)))

        seen_names = [api] + implied.get(api, [])
        for name in seen_names:
            if name in hooks:
                api_calls[name] += n
                if len(api_seq) < SEQ_LIMIT:
                    api_seq.extend([name] * min(n, SEQ_LIMIT - len(api_seq)))

        category = call.get("category")
        args = None

        # files
        if category == "filesystem" or api in _FILE_APIS:
            args = _args(call)
            ok = call.get("status") is not False
            if api == "NtCreateFile":
                if ok and str(args.get("ExistedBefore", "")).lower() == "no" and str(args.get("CreateDisposition")) != "1":
                    files["created"] += n
            elif api in DIR_CREATE_APIS:
                if ok:
                    files["created"] += n
            elif api in FILE_COPY_APIS:
                files["created"] += n
                files["written"] += n
            elif api in FILE_WRITE_APIS:
                files["written"] += n
            elif api in FILE_DELETE_APIS:
                files["deleted"] += n
            elif api == "NtSetInformationFile" and str(args.get("FileInformationClass")) in DISPOSITION_CLASSES:
                files["deleted"] += n
            for key in FILE_PATH_ARGS:
                _append_unique(files["paths"], args.get(key))

        # registry (CHIMERA counts attempts, not only successes)
        if category == "registry" or api in _REG_APIS:
            args = args if args is not None else _args(call)
            if api in REG_SET_APIS:
                registry["set_value"] += n
            elif api in REG_CREATE_APIS:
                registry["create_key"] += n
            elif api in REG_DELETE_APIS:
                registry["delete"] += n
            key = next((args.get(k) for k in REG_KEY_ARGS if isinstance(args.get(k), str) and args.get(k)), None)
            if key:
                _append_unique(registry["keys"], key)
                if not registry["autorun_touched"]:
                    probe = key.lower().rstrip("\\") + "\\"
                    if any(part in probe for part in AUTORUN_PARTS):
                        registry["autorun_touched"] = True

        # network intent
        if api in DNS_APIS:
            args = args if args is not None else _args(call)
            name = next((args.get(k) for k in DNS_NAME_ARGS if args.get(k)), None)
            if _printable_host(name) and name.lower() not in dns_seen:
                dns_seen.add(name.lower())
                _append_unique(network["dns_queries"], name.lower())
        elif api in CONNECT_APIS:
            args = args if args is not None else _args(call)
            network["connections"] += n
            ip, port = args.get("ip") or args.get("IP"), args.get("port") or args.get("Port")
            if isinstance(ip, str) and ip and port is not None:
                _append_unique(network["remote_endpoints"], f"{ip}:{port}")
        elif api in HTTP_APIS:
            network["http_requests"] += n

    # ---- processes
    names: list[str] = []
    for p in scoped:
        _append_unique(names, p.get("module_path") or p.get("process_name"), 50)
    processes = {
        "count": len(scoped),
        "max_depth": max(depth.values()) if depth else 0,
        "names": names,
        "command_lines": [],
        "exited_early": False,
    }

    features = {
        "schema": "chimera-features/1",
        "sample": {
            "sha256": sha256,
            "file_name": target.get("name") or "",
            "file_type": target.get("type") or "",
            "size_bytes": max(0, _int(target.get("size"), 0) or 0),
        },
        "run": {"guest_os": "windows", "timeout_s": float(window_s), "complete": True,
                "vm_stalled": False, "drakvuf_errors": []},
        "processes": processes,
        "api_calls": dict(api_calls),
        "api_sequence": api_seq,
        "files": files,
        "registry": registry,
        "network": network,
        "ttps": [],
    }

    label = label or {}
    avclass, cape = label.get("avclass"), label.get("cape")
    family = avclass if avclass and cape and avclass.lower() == cape.lower() else None
    return {
        "id": sha256,
        "source": "winmet",
        "volume": volume,
        "adapter_version": ADAPTER_VERSION,
        "label": {"malicious": 1, "avclass": avclass, "cape": cape, "family": family},
        "features": features,
        "aux": {
            "root_method": root_method,
            "root_name": (root or {}).get("process_name"),
            "procs_total": len((report.get("behavior") or {}).get("processes") or []),
            "procs_scope": len(scoped),
            "calls_scope": total_calls,
            "calls_window": len(in_window),
            "observed_s": round(max(0.0, last_t - t0), 3),
            "window_s": float(window_s),
            "network_source": "api_calls",
            "unavailable": ["processes.command_lines", "processes.exited_early", "ttps",
                            "run.vm_stalled", "run.drakvuf_errors"],
            "api_counts_all": dict(api_all),
            "seq_all": seq_all,
            "signatures": [s.get("name") for s in report.get("signatures") or () if isinstance(s, dict)][:200],
            "detections": [d.get("family") for d in report.get("detections") or () if isinstance(d, dict)][:20],
        },
    }
