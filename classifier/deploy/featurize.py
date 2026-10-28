"""chimera-features/1 dict -> named numeric features. Shared by training and the sandbox.

Standalone on purpose (stdlib only, reads hooks.txt next to this file): the packager copies
this file into deploy/, and the sandbox imports it from there. Never import project code here.

Feature groups (prefix before the first ":"):
  api       presence of each hooks.txt API (0/1)
  apilog    log1p(count) per API
  apishare  count / total hooked calls, per API
  tot       totals: hooked calls, distinct APIs, sequence lengths
  grp       behaviour groups (injection, persistence, ...): log1p(calls) and distinct APIs used
  file      log1p of created / written / deleted
  reg       log1p of set_value / create_key / delete, autorun_touched
  proc      log1p(process count), tree depth
  ng2, ng3  hashed 2-/3-grams over the API sequence with consecutive repeats collapsed
  net       DNS / connections / HTTP counts (off by default: WinMET has no network capture)
"""

from __future__ import annotations

import math
import zlib
from pathlib import Path

FEATURIZE_VERSION = "2"  # 2: optional API vocabulary (APIs both sandboxes can observe)
NGRAM_BUCKETS = 512
DEFAULT_GROUPS = ("api", "apilog", "apishare", "tot", "grp", "file", "reg", "proc", "ng2", "ng3")
ALL_GROUPS = DEFAULT_GROUPS + ("net",)


def _load_hooks() -> tuple[str, ...]:
    names = set()
    for line in (Path(__file__).resolve().with_name("hooks.txt")).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and len(line.split(",")) > 1:
            names.add(line.split(",")[1])
    return tuple(sorted(names))


HOOKED_APIS = _load_hooks()
_HOOKED = frozenset(HOOKED_APIS)

_GROUP_SPEC = {
    "injection": ("process injection APIs", ["WriteProcessMemory", "CreateRemoteThread", "RtlCreateUserThread",
                  "VirtualProtectEx", "SetWindowsHookExA", "SetWindowsHookExW", "ReadProcessMemory"]),
    "persistence": ("registry/service persistence APIs", ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                    "RegCreateKeyExW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
                    "OpenSCManagerA", "OpenSCManagerW", "ControlService", "DeleteService"]),
    "execution": ("process creation APIs", ["CreateProcessA", "CreateProcessInternalW", "CreateProcessWithLogonW",
                  "CreateProcessWithTokenW", "ShellExecuteExW", "system", "RtlCreateUserProcess"]),
    "network": ("network APIs", ["socket", "connect", "WSAConnect", "WSAConnectByNameW", "WSAConnectByList",
                "ConnectEx", "send", "sendto", "recv", "recvfrom", "WSASend", "WSASendTo", "WSARecv", "bind",
                "listen", "accept", "getaddrinfo", "GetAddrInfoW", "gethostbyname", "DnsQuery_A", "DnsQuery_W",
                "DnsQuery_UTF8", "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
                "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "InternetWriteFile",
                "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen",
                "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse",
                "URLDownloadToFileW", "URLDownloadToCacheFileW"]),
    "crypto": ("crypto APIs", [n for n in HOOKED_APIS if n.startswith("Crypt")]),
    "anti_analysis": ("anti-analysis / environment checks", ["IsDebuggerPresent", "GetTickCount", "GetTickCount64",
                      "timeGetTime", "GetCursorPos", "GetLastInputInfo", "GlobalMemoryStatus", "GlobalMemoryStatusEx",
                      "GetSystemInfo", "GetDiskFreeSpaceA", "GetDiskFreeSpaceW", "GetDiskFreeSpaceExA",
                      "GetDiskFreeSpaceExW", "SetUnhandledExceptionFilter", "SetErrorMode", "FindWindowA",
                      "FindWindowW", "FindWindowExA", "FindWindowExW", "SetupDiGetClassDevsA", "SetupDiGetClassDevsW",
                      "SetupDiGetDeviceRegistryPropertyA", "SetupDiGetDeviceRegistryPropertyW"]),
    "discovery": ("system discovery APIs", ["Process32FirstW", "Process32NextW", "CreateToolhelp32Snapshot",
                  "GetComputerNameA", "GetComputerNameW", "GetUserNameA", "GetUserNameW", "GetAdaptersAddresses",
                  "GetAdaptersInfo", "NetGetJoinInformation", "NetUserGetInfo", "NetUserGetLocalGroups",
                  "GetCurrentHwProfileW", "IsUserAdmin", "GetVolumeInformationByHandleW", "LsaOpenPolicy"]),
    "file_search": ("file enumeration APIs", ["FindFirstFileExA", "FindFirstFileExW", "FindNextFileW"]),
    "file_ops": ("file copy/move/delete APIs", ["CopyFileA", "CopyFileW", "CopyFileExW", "DeleteFileA",
                 "DeleteFileW", "MoveFileWithProgressW", "MoveFileWithProgressTransactedW", "RemoveDirectoryA",
                 "RemoveDirectoryW", "CreateDirectoryW", "CreateDirectoryExW"]),
    "spying": ("input capture APIs", ["GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
               "UnhookWindowsHookEx"]),
    "credentials": ("credential access APIs", ["CryptUnprotectData", "PStoreCreateInstance", "LsaOpenPolicy"]),
    "shutdown": ("shutdown/restart APIs", ["ExitWindowsEx", "InitiateShutdownW", "InitiateSystemShutdownW",
                 "InitiateSystemShutdownExW"]),
    "script": ("script engine APIs", ["COleScript_ParseScriptText", "JsEval", "JsParseScript", "JsRunScript",
               "CDocument_write"]),
    "com": ("COM object creation", ["CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject",
            "CLSIDFromProgID"]),
    "privilege": ("privilege APIs", ["LookupPrivilegeValueW"]),
}
GROUPS = {k: (label, tuple(a for a in apis if a in _HOOKED)) for k, (label, apis) in _GROUP_SPEC.items()}


def _names() -> list[str]:
    names = []
    for prefix in ("api", "apilog", "apishare"):
        names += [f"{prefix}:{a}" for a in HOOKED_APIS]
    names += ["tot:calls_log", "tot:distinct", "tot:seq_log", "tot:seq_collapsed_log"]
    for g in GROUPS:
        names += [f"grp:{g}:calls_log", f"grp:{g}:distinct"]
    names += ["file:created_log", "file:written_log", "file:deleted_log"]
    names += ["reg:set_value_log", "reg:create_key_log", "reg:delete_log", "reg:autorun_touched"]
    names += ["proc:count_log", "proc:max_depth"]
    names += [f"ng2:{i}" for i in range(NGRAM_BUCKETS)] + [f"ng3:{i}" for i in range(NGRAM_BUCKETS)]
    names += ["net:dns_log", "net:connections_log", "net:endpoints_log", "net:http_log"]
    return names


ALL_FEATURE_NAMES = tuple(_names())


def feature_names(groups=DEFAULT_GROUPS) -> list[str]:
    groups = set(groups)
    return [n for n in ALL_FEATURE_NAMES if n.split(":", 1)[0] in groups]


def _num(value) -> float:
    try:
        v = float(value)
        return v if math.isfinite(v) and v > 0 else 0.0
    except (TypeError, ValueError):
        return 0.0


def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


def collapsed_sequence(features: dict) -> list[str]:
    out = []
    for name in features.get("api_sequence") or ():
        if isinstance(name, str) and (not out or out[-1] != name):
            out.append(name)
    return out


def ngram_bucket(gram: tuple[str, ...]) -> int:
    return zlib.crc32("|".join(gram).encode("utf-8")) % NGRAM_BUCKETS


def restrict(features: dict, allowed) -> dict:
    """Keep only APIs in `allowed` (both in the counts and the sequence) before anything is computed.

    Used to drop APIs one sandbox cannot observe (hooking blind spots), so neither their presence nor
    their absence can tell CAPE-converted data from CHIMERA runs. None = keep everything."""
    if allowed is None:
        return features
    allowed = allowed if isinstance(allowed, (set, frozenset)) else frozenset(allowed)
    out = dict(features)
    out["api_calls"] = {k: v for k, v in _obj(features.get("api_calls")).items() if k in allowed}
    out["api_sequence"] = [s for s in (features.get("api_sequence") or ()) if s in allowed]
    return out


def featurize(features: dict, allowed=None) -> dict[str, float]:
    """Sparse {feature name: value}; names not present are 0."""
    features = restrict(features, allowed)
    out: dict[str, float] = {}
    calls = {k: _num(v) for k, v in _obj(features.get("api_calls")).items() if k in _HOOKED}
    calls = {k: v for k, v in calls.items() if v > 0}
    total = sum(calls.values())
    for api, n in calls.items():
        out[f"api:{api}"] = 1.0
        out[f"apilog:{api}"] = math.log1p(n)
        out[f"apishare:{api}"] = n / total
    seq = [s for s in (features.get("api_sequence") or ()) if isinstance(s, str)]
    col = collapsed_sequence(features)
    out["tot:calls_log"] = math.log1p(total)
    out["tot:distinct"] = float(len(calls))
    out["tot:seq_log"] = math.log1p(len(seq))
    out["tot:seq_collapsed_log"] = math.log1p(len(col))
    for g, (_label, apis) in GROUPS.items():
        used = [calls[a] for a in apis if a in calls]
        if used:
            out[f"grp:{g}:calls_log"] = math.log1p(sum(used))
            out[f"grp:{g}:distinct"] = float(len(used))
    files, reg = _obj(features.get("files")), _obj(features.get("registry"))
    for key in ("created", "written", "deleted"):
        out[f"file:{key}_log"] = math.log1p(_num(files.get(key)))
    for key in ("set_value", "create_key", "delete"):
        out[f"reg:{key}_log"] = math.log1p(_num(reg.get(key)))
    out["reg:autorun_touched"] = 1.0 if reg.get("autorun_touched") is True else 0.0
    procs = _obj(features.get("processes"))
    out["proc:count_log"] = math.log1p(_num(procs.get("count")))
    out["proc:max_depth"] = _num(procs.get("max_depth"))
    for n, prefix in ((2, "ng2"), (3, "ng3")):
        for i in range(len(col) - n + 1):
            key = f"{prefix}:{ngram_bucket(tuple(col[i:i + n]))}"
            out[key] = out.get(key, 0.0) + 1.0
    for key in [k for k in out if k.startswith("ng")]:
        out[key] = math.log1p(out[key])
    net = _obj(features.get("network"))
    out["net:dns_log"] = math.log1p(len(net.get("dns_queries") or ()))
    out["net:connections_log"] = math.log1p(_num(net.get("connections")))
    out["net:endpoints_log"] = math.log1p(len(net.get("remote_endpoints") or ()))
    out["net:http_log"] = math.log1p(_num(net.get("http_requests")))
    return {k: v for k, v in out.items() if v}


def vectorize(features: dict, names, allowed=None) -> list[float]:
    sparse = featurize(features, allowed)
    return [sparse.get(n, 0.0) for n in names]


def hooked_call_count(features: dict, allowed=None) -> int:
    keep = _HOOKED if allowed is None else _HOOKED & frozenset(allowed)
    return int(sum(_num(v) for k, v in _obj(features.get("api_calls")).items() if k in keep))


# DRAKVUF sees every loader call (also from system DLLs initialising); CAPE logs the outer
# LoadLibrary/GetModuleHandle instead. Their n-grams were the top features of a model that only
# told the sandboxes apart (v0 draft, 23 Oct), so they never enter the shared vocabulary.
LOADER_NOISE = frozenset({"LdrLoadDll", "LdrGetDllHandle", "LdrGetProcedureAddress"})
# Partly invisible to DRAKVUF: in CHIMERA runs FindNextFileW (21%) appears far more often than
# FindFirstFileExW (5%), which is impossible for real behaviour: FindFirstFileW reaches kernelbase
# without passing the hooked kernel32 export. CAPE sees both (60% / 49%). FindNextFileW stays.
PARTIAL_BLIND = frozenset({"FindFirstFileExW", "FindFirstFileExA"})


def coverage_vocabulary(cape_freq: dict, chimera_freq: dict, cape_blind=(0.03, 0.15), drakvuf_blind=0.15,
                        ubiquitous=(0.80, 0.30)) -> tuple[list[str], dict[str, str]]:
    """Which hooked APIs both sandboxes can observe. Returns (kept, {dropped: reason}).

    cape_blind:    CAPE sees it in <= 3% of reports but CHIMERA in >= 15% of runs -> CAPE does not hook it.
    drakvuf_blind: CAPE sees it in >= 15% of reports and CHIMERA never              -> DRAKVUF's hook never fires.
    ubiquitous:    CAPE sees it in >= 80% (C-runtime start-up calls) but CHIMERA in <= 30%.
    """
    kept, dropped = [], {}
    for api in HOOKED_APIS:
        c, h = cape_freq.get(api, 0.0), chimera_freq.get(api, 0.0)
        if api in LOADER_NOISE:
            dropped[api] = f"DLL-loader internals, not mappable between sandboxes (CAPE {c:.1%}, CHIMERA {h:.1%})"
        elif api in PARTIAL_BLIND:
            dropped[api] = (f"partly invisible to DRAKVUF: FindNextFileW is seen more often than this "
                            f"(CAPE {c:.1%}, CHIMERA {h:.1%})")
        elif c <= cape_blind[0] and h >= cape_blind[1]:
            dropped[api] = f"CAPE blind spot (CAPE {c:.1%}, CHIMERA {h:.1%})"
        elif c >= drakvuf_blind and h == 0.0:
            dropped[api] = f"DRAKVUF blind spot (CAPE {c:.1%}, CHIMERA 0%)"
        elif c >= ubiquitous[0] and h <= ubiquitous[1]:
            dropped[api] = f"start-up call CHIMERA mostly misses (CAPE {c:.1%}, CHIMERA {h:.1%})"
        else:
            kept.append(api)
    return kept, dropped


# ------------------------------------------------------------------ fusion inputs
FUSION_FEATURES = ("dynamic_logit", "dynamic_abstained", "static_logit", "static_abstained", "static_rules_only")


def _logit(p: float) -> float:
    p = min(1 - 1e-6, max(1e-6, float(p)))
    return math.log(p / (1 - p))


def fusion_vector(dynamic_p, static_label, static_p, static_model) -> list[float]:
    """Inputs of the fitted fusion (logistic regression), the same in training and in the sandbox.

    A component that gave no verdict (label unknown, no score, not run) contributes 0 and sets its
    "abstained" flag, so the fusion learns how much an abstention says instead of guessing."""
    d_ok = dynamic_p is not None
    s_ok = static_p is not None and static_label not in (None, "unknown")
    return [_logit(dynamic_p) if d_ok else 0.0, 0.0 if d_ok else 1.0,
            _logit(static_p) if s_ok else 0.0, 0.0 if s_ok else 1.0,
            1.0 if s_ok and static_model == "chimera-static-rules" else 0.0]


# ------------------------------------------------------------------ explanations
def concept(name: str) -> str:
    """Feature name -> the thing a human would recognise (several features share one)."""
    prefix, _, rest = name.partition(":")
    if prefix in ("api", "apilog", "apishare"):
        return f"api:{rest}"
    if prefix == "grp":
        return f"grp:{rest.split(':')[0]}"
    return name


def describe(concept_name: str, features: dict, direction: int) -> str | None:
    """Readable reason for one concept. direction=+1 pushes to malicious, -1 to benign."""
    calls = _obj(features.get("api_calls"))
    kind, _, rest = concept_name.partition(":")
    if kind == "api":
        n = int(_num(calls.get(rest)))
        return f"called {rest} ×{n}" if n else f"did not call {rest}"
    if kind == "grp":
        label, apis = GROUPS.get(rest, (rest, ()))
        used = [f"{a} ×{int(_num(calls.get(a)))}" for a in apis if _num(calls.get(a))]
        return f"{label}: {', '.join(used[:4])}" if used else f"no {label}"
    if kind in ("ng2", "ng3"):
        n, bucket = (2 if kind == "ng2" else 3), int(rest)
        col = collapsed_sequence(features)
        grams = {}
        for i in range(len(col) - n + 1):
            g = tuple(col[i:i + n])
            if ngram_bucket(g) == bucket:
                grams[g] = grams.get(g, 0) + 1
        if not grams:
            return None if direction > 0 else None
        g = max(grams, key=grams.get)
        return f"API call pattern {' → '.join(g)} (×{grams[g]})"
    files, reg, procs = _obj(features.get("files")), _obj(features.get("registry")), _obj(features.get("processes"))
    simple = {
        "file:created_log": lambda: f"created {int(_num(files.get('created')))} files",
        "file:written_log": lambda: f"{int(_num(files.get('written')))} file writes",
        "file:deleted_log": lambda: f"deleted {int(_num(files.get('deleted')))} files",
        "reg:set_value_log": lambda: f"{int(_num(reg.get('set_value')))} registry value writes",
        "reg:create_key_log": lambda: f"{int(_num(reg.get('create_key')))} registry key creates",
        "reg:delete_log": lambda: f"{int(_num(reg.get('delete')))} registry deletes",
        "reg:autorun_touched": lambda: "accessed an autorun registry key (Run/RunOnce/Winlogon)"
        if reg.get("autorun_touched") else "no autorun registry access",
        "proc:count_log": lambda: f"{int(_num(procs.get('count')))} processes in the sample's tree",
        "proc:max_depth": lambda: f"process tree depth {int(_num(procs.get('max_depth')))}",
        "tot:calls_log": lambda: f"{hooked_call_count(features)} monitored API calls in total",
        "tot:distinct": lambda: f"{len([k for k in calls if k in _HOOKED])} distinct monitored APIs",
    }
    if concept_name in simple:
        return simple[concept_name]()
    if concept_name.startswith("tot:seq"):
        return "length of the API call sequence"
    return None
