"""Deep static pass: capa capabilities and FLOSS-decoded strings, run after the fast pass and never on its clock.

Writes `chimera-deep/1`. Both tools disassemble and emulate code with vivisect, which can take minutes on large
or packed files, so each one runs under its own wall-clock alarm and a failure or timeout in one never loses the
other. Nothing here executes the sample: vivisect emulates instructions in Python.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import time

from . import ANALYZER_VERSION
from .identify import identify
from .safety import read_sample, write_output

SCHEMA = "chimera-deep/1"
CAPA_RULES = os.environ.get("CHIMERA_CAPA_RULES", "/opt/chimera-static/capa-rules")
CAPA_SIGS = os.environ.get("CHIMERA_CAPA_SIGS", "/opt/chimera-static/capa-sigs")
CAPA_FORMATS = {"pe", "elf"}
FLOSS_FORMATS = {"pe"}
MAX_BYTES = 16 * 1024 * 1024
MAX_RULES = 200
MAX_STRINGS = 300


class _Timeout(Exception):
    pass


@contextlib.contextmanager
def _alarm(seconds: float):
    def fire(signum, frame):
        raise _Timeout()

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, max(1.0, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _run_cli(main, argv: list[str]) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    if code not in (0, None):
        raise RuntimeError(f"exit code {code}")
    return out.getvalue()


@contextlib.contextmanager
def _no_spinner():
    # capa's loader shows a rich "status" spinner even with -q, and the spinner starts a refresh thread. The
    # hardened process may not start threads (RLIMIT_NPROC 0), so the spinner becomes a no-op while capa runs.
    import rich.console

    original = rich.console.Console.status
    rich.console.Console.status = lambda self, *args, **kwargs: contextlib.nullcontext()
    try:
        yield
    finally:
        rich.console.Console.status = original


def _capa(path: str, fmt: str) -> dict:
    import capa.main

    with _no_spinner():
        doc = json.loads(_run_cli(capa.main.main, ["-q", "-j", "-r", CAPA_RULES, "-s", CAPA_SIGS, "-f", fmt, path]))
    rules = []
    for name, match in (doc.get("rules") or {}).items():
        meta = match.get("meta") or {}
        if meta.get("lib") or (meta.get("namespace") or "").startswith("internal"):
            continue  # library and helper rules are building blocks, not capabilities
        rules.append({
            "name": name,
            "namespace": meta.get("namespace"),
            # tactic/technique names come from the rule, so the dashboard can draw an ATT&CK matrix
            "attack": [{k: a.get(k) for k in ("id", "tactic", "technique", "subtechnique")}
                       for a in meta.get("attack") or [] if a.get("id")],
            "mbc": [{k: m.get(k) for k in ("id", "objective", "behavior")} for m in meta.get("mbc") or [] if m.get("id")],
            "matches": len(match.get("matches") or []),
        })
    rules.sort(key=lambda r: (r["namespace"] or "", r["name"]))
    return {"version": (doc.get("meta") or {}).get("version"), "rules_total": len(rules), "rules": rules[:MAX_RULES],
            "library_signatures": bool(os.path.isdir(CAPA_SIGS) and os.listdir(CAPA_SIGS))}


def _floss(path: str) -> dict:
    import floss.main

    doc = json.loads(_run_cli(floss.main.main, ["-q", "-j", "--disable-progress", "--only", "stack", "tight",
                                                "decoded", "--", path]))
    strings = doc.get("strings") or {}
    out = {}
    for kind, key in (("stack", "stack_strings"), ("tight", "tight_strings"), ("decoded", "decoded_strings")):
        values = [str(s.get("string", ""))[:300] for s in strings.get(key) or [] if isinstance(s, dict)]
        out[kind] = {"count": len(values), "sample": values[:MAX_STRINGS]}
    return {"version": (doc.get("metadata") or {}).get("version"), **out}


def run_deep(path: str, out_dir: str | None, file_name: str = "", timeout_s: float = 240.0) -> dict:
    t0 = time.monotonic()
    result: dict = {"schema": SCHEMA, "analyzer_version": ANALYZER_VERSION, "errors": [], "timings_s": {},
                    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    data, info = read_sample(path)
    fmt = identify(data, file_name or os.path.basename(path)).get("format", "unknown")
    result["format"] = fmt
    del data
    # capa gets 60% of what is left, FLOSS the rest; files over the size cap get neither
    tools = [] if info["size"] > MAX_BYTES else [("capa", fmt in CAPA_FORMATS, 0.6), ("floss", fmt in FLOSS_FORMATS, 1.0)]
    if info["size"] > MAX_BYTES:
        result["errors"].append({"stage": "deep", "error": f"skipped: file over {MAX_BYTES} bytes"})
    for name, applies, share in tools:
        if not applies:
            result[name] = None
            continue
        remaining = timeout_s - (time.monotonic() - t0)
        if remaining < 5:
            result["errors"].append({"stage": name, "error": "skipped: time budget"})
            continue
        started = time.monotonic()
        try:
            with _alarm(remaining * share):
                result[name] = _capa(path, fmt) if name == "capa" else _floss(path)
        except _Timeout:
            result["errors"].append({"stage": name, "error": f"timed out after {remaining * share:.0f}s"})
        except MemoryError:
            result["errors"].append({"stage": name, "error": "MemoryError (limit reached)"})
        except Exception as exc:
            result["errors"].append({"stage": name, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
        finally:
            result["timings_s"][name] = round(time.monotonic() - started, 3)
    result["duration_s"] = round(time.monotonic() - t0, 3)
    if out_dir:
        write_output(os.path.join(out_dir, "deep.json"), json.dumps(result, allow_nan=False).encode())
    return result
