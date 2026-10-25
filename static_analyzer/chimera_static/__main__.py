"""Entry point inside the sandbox container:

    python -I -m chimera_static /in/sample /out --name invoice.exe --timeout 60

    python -I -m chimera_static /in/sample /out --deep --timeout 240     (capa + FLOSS -> /out/deep.json)

Writes /out/static.json. Exit 0 = written (even if some stages failed, see "errors"),
2 = the sample was refused (not a regular file, unreadable), 3 = internal error.
"""

import os

# Single-threaded numeric libraries: the process forbids new threads/processes after start-up.
for _var in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

import argparse  # noqa: E402
import json  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

from . import ANALYZER_VERSION, SCHEMA  # noqa: E402
from .safety import SampleError, harden_process, write_output  # noqa: E402

# Import every parser *before* hardening (imports may start threads or read many files).
from . import analyze as _analyze  # noqa: E402
from .plugins import elf as _elf, pdf as _pdf, pe as _pe  # noqa: E402,F401
from . import ember as _ember  # noqa: E402,F401
from . import deep as _deep  # noqa: E402

try:  # the deep tools are large; load them now, while threads and file opens are still allowed
    import capa.main  # noqa: E402,F401
    import floss.main  # noqa: E402,F401
except ImportError:  # pragma: no cover - images without the deep tools
    pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="chimera_static")
    ap.add_argument("sample")
    ap.add_argument("out_dir")
    ap.add_argument("--name", default="", help="original file name (for extension checks)")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--memory-mb", type=int, default=2048)
    ap.add_argument("--no-ember", action="store_true")
    ap.add_argument("--no-signature", action="store_true")
    ap.add_argument("--deep", action="store_true", help="capa + FLOSS instead of the fast pass")
    a = ap.parse_args(argv)
    hardening = harden_process(cpu_seconds=int(a.timeout) + 10, memory_bytes=a.memory_mb * 1024 * 1024)
    if a.deep:
        try:
            _deep.run_deep(a.sample, a.out_dir, file_name=a.name, timeout_s=a.timeout)
            return 0
        except SampleError as exc:
            code, error = 2, str(exc)
        except Exception as exc:  # pragma: no cover - last resort
            code, error = 3, f"{type(exc).__name__}: {str(exc)[:500]}"
        failed = {"schema": _deep.SCHEMA, "analyzer_version": ANALYZER_VERSION, "error": error}
        try:
            write_output(os.path.join(a.out_dir, "deep.json"), json.dumps(failed).encode())
        except OSError:
            pass
        print(error, file=sys.stderr)
        return code
    try:
        _analyze.analyze(a.sample, a.out_dir, file_name=a.name, timeout_s=a.timeout,
                         verify_signature=not a.no_signature, ember=not a.no_ember, hardening=hardening)
        return 0
    except SampleError as exc:
        code, error = 2, str(exc)
    except Exception as exc:  # pragma: no cover - last resort
        code, error = 3, f"{type(exc).__name__}: {str(exc)[:500]}"
    failed = {"schema": SCHEMA, "analyzer_version": ANALYZER_VERSION, "error": error, "hardening": hardening,
              "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        write_output(os.path.join(a.out_dir, "static.json"), json.dumps(failed).encode())
    except OSError:
        pass
    print(error, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
