"""Run one Linux analysis from the command line (bench/bring-up; the worker uses the same function).

    sudo /opt/chimera/venv/bin/python scripts/chimera/linux/bench/run_linux.py SAMPLE [--timeout 60] [--vm-id 1]
            [--out-root /var/lib/drakrun/linux/test-runs]
Prints the output directory and a one-line JSON summary.
"""
import argparse
import json
import logging
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[4]))

from drakrun.analyzer.analysis_metadata import AnalysisMetadata, FileMetadata  # noqa: E402
from drakrun.analyzer.analysis_options import AnalysisOptions  # noqa: E402
from drakrun.analyzer.linux_analyzer import analyze_linux_file  # noqa: E402
from drakrun.lib.config import load_config  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--vm-id", type=int, default=1)
    parser.add_argument("--out-root", type=pathlib.Path, default=pathlib.Path("/var/lib/drakrun/linux/test-runs"))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(name)s %(message)s")

    out = args.out_root / str(uuid.uuid4())
    out.mkdir(parents=True)
    options = AnalysisOptions.with_config_defaults(
        load_config(), host_sample_path=args.sample, sample_filename=args.sample.name,
        timeout=args.timeout, guest_os="linux")
    metadata = AnalysisMetadata(id=out.name, options=options, vm_id=args.vm_id,
                                file=FileMetadata.evaluate(args.sample, args.sample.name))
    started = time.time()
    error = None
    try:
        extra = analyze_linux_file(args.vm_id, out, metadata)
    except Exception as exc:  # recorded, so a reliability series can count failures
        extra, error = {}, f"{type(exc).__name__}: {exc}"
        logging.exception("analysis failed")
    metadata_out = {**metadata.model_dump(mode="json"), **extra, "error": error,
                    "elapsed_s": round(time.time() - started, 1)}
    (out / "metadata.json").write_text(json.dumps(metadata_out, indent=2, default=str))
    telemetry = extra.get("telemetry") or {}
    print(out)
    print(json.dumps({"id": out.name, "error": error, "elapsed_s": metadata_out["elapsed_s"],
                      "complete": telemetry.get("complete"), "missing": telemetry.get("missing_plugins"),
                      "monitor_ready": (extra.get("linux") or {}).get("monitor_ready"),
                      "postprocess_failed": [k for k, v in (extra.get("postprocess") or {}).items()
                                             if str(v).startswith("failed")]}))


if __name__ == "__main__":
    main()
