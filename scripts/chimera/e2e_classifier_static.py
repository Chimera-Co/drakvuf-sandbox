#!/usr/bin/env python3
"""End-to-end check of static analysis + classifier, through CHIMERA's real code paths.

    sudo /opt/chimera/venv/bin/python scripts/chimera/e2e_classifier_static.py \
        --analysis-dir /var/lib/drakrun/analyses/<id> --sample /path/to/that/sample

Steps (each prints PASS/FAIL):
  1. isolation  - from inside a container started with the production flags, try to reach the
                  network, write the root fs, modify/execute the sample, exec from /tmp, fork and
                  allocate past the limit. Every attempt must be blocked.
  2. static     - stage the sample (0440, never +x) and run the real static job
                  (drakrun.analyzer.static.worker.run_static_job -> container -> static.json)
  3. classify   - run the real classify_sample plugin on a copy of the analysis folder (or on the
                  fixture features when no folder is given): features.json gets the static report,
                  the deployed model.py runs in CHIMERA's runner, the verdict has both components
Nothing here touches /var/lib/drakrun or Redis; everything runs in a temporary folder.
Exit code 0 = all steps passed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))  # use this checkout's drakrun

from drakrun.analyzer.classifier.runner import run_classifier  # noqa: E402
from drakrun.analyzer.static import sandbox  # noqa: E402
from drakrun.analyzer.static import worker as static_worker  # noqa: E402
from drakrun.lib.config import ClassifierConfigSection, StaticConfigSection  # noqa: E402

PROBE = r"""
import json, os, socket, subprocess, threading
out = {"uid": os.getuid(), "capeff": [l.split()[1] for l in open("/proc/self/status") if l.startswith("CapEff")][0]}
def t(name, fn):
    try:
        fn(); out[name] = "ALLOWED"
    except Exception as e:
        out[name] = "blocked"
t("network", lambda: socket.create_connection(("1.1.1.1", 53), timeout=3))
t("dns", lambda: socket.getaddrinfo("example.com", 80))
t("write_rootfs", lambda: open("/evil", "w"))
t("write_sample", lambda: open("/in/sample", "ab"))
t("chmod_sample", lambda: os.chmod("/in/sample", 0o755))
t("exec_sample", lambda: subprocess.run(["/in/sample"], check=True))
def tmp_exec():
    open("/tmp/x.sh", "w").write("#!/bin/sh\necho hi\n"); os.chmod("/tmp/x.sh", 0o755)
    subprocess.run(["/tmp/x.sh"], check=True)
t("exec_tmp", tmp_exec)
from chimera_static.safety import harden_process
out["hardening"] = harden_process(30)
t("fork_after_hardening", lambda: subprocess.run(["/bin/true"], check=True))
t("thread_after_hardening", lambda: threading.Thread(target=lambda: None).start())
t("alloc_4g", lambda: bytearray(4 * 1024 ** 3))
print(json.dumps(out))
"""


def step(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{': ' + detail if detail else ''}", flush=True)
    return ok


def isolation(settings, work: Path, sample: Path) -> bool:
    aid = str(uuid.uuid4())
    job = work / "probe" / aid
    sandbox.stage_sample(sample, job, settings)
    out = job / "out"
    out.mkdir(mode=0o777)
    cmd = sandbox.build_command(settings, aid, job / "in" / "sample", out, "probe")
    i = cmd.index(settings.image)
    cmd = cmd[:i] + ["--entrypoint", "python", settings.image, "-I", "-c", PROBE]
    proc = subprocess.run(cmd, capture_output=True, timeout=120)
    try:
        res = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    except (IndexError, ValueError):
        return step("isolation", False, proc.stderr.decode()[-500:])
    allowed = [k for k, v in res.items() if v == "ALLOWED"]
    probes = [k for k, v in res.items() if v in ("ALLOWED", "blocked")]
    hard = res.get("hardening", {})
    ok = not allowed and res["uid"] != 0 and int(res["capeff"], 16) == 0 and all(hard.values())
    return step("isolation", ok, f"uid {res['uid']}, CapEff {res['capeff']}, blocked "
                f"{sum(res[k] == 'blocked' for k in probes)}/{len(probes)}, allowed {allowed or 'none'}, "
                f"self-limits {sum(hard.values())}/{len(hard)}")


def static(settings, work: Path, sample: Path, name: str):
    aid = str(uuid.uuid4())
    base = work / "static"
    sandbox.stage_sample(sample, static_worker.job_dir(aid, base), settings)
    staged_mode = oct((static_worker.job_dir(aid, base) / "in" / "sample").stat().st_mode & 0o777)
    static_worker.load_config = lambda: SimpleNamespace(static=settings)  # the job reads its settings from config
    t = time.time()
    summary = static_worker.run_static_job(aid, name, str(base))
    result = static_worker.load_static(aid, base)
    ok = (result is not None and not result.get("error") and summary.get("error") is None
          and not (static_worker.job_dir(aid, base) / "in").exists())
    detail = (f"{time.time() - t:.1f}s, staged {staged_mode}, format {result.get('type', {}).get('format')}, "
              f"score {result.get('score')} ({result.get('level')}), {len(result.get('findings', []))} findings, "
              f"EMBER vector {'yes' if result.get('ml') else 'no'}, staged copy removed"
              if result else f"no static.json ({summary})")
    step("static", ok, detail)
    return (aid, base, result) if ok else (None, None, None)


def classify(model: Path, aid: str, base: Path, analysis_dir: Path | None, work: Path) -> bool:
    from drakrun.analyzer.postprocessing.plugins.classify_sample import classify_sample

    static_worker.STATIC_DIR = base  # where classify_sample looks for static.json
    if analysis_dir:
        target = work / "analysis"
        shutil.copytree(analysis_dir, target, ignore=shutil.ignore_patterns("dumps.zip", "*.pcap", "screenshots"))
        captured = {}
        ctx = SimpleNamespace(
            config=SimpleNamespace(classifier=ClassifierConfigSection(enabled=True, model_path=model, timeout_s=60),
                                   static=StaticConfigSection(enabled=True, wait_s=5)),
            metadata=SimpleNamespace(id=aid, options=SimpleNamespace(mode="combined")),  # the default mode
            analysis_dir=target, update_metadata=captured.update)
        t = time.time()
        classify_sample(ctx)
        verdict = captured.get("classification", {})
        features = json.loads((target / "features.json").read_text())
        how = f"classify_sample plugin on a copy of {analysis_dir.name}"
    else:
        features = json.loads((REPO / "classifier/fixtures/bginfo-96f7ee81-features.json").read_text())
        features["static"] = static_worker.load_static(aid, base)
        t = time.time()
        verdict = run_classifier(features, str(work), str(model), 60)
        how = "runner on the fixture features (pass --analysis-dir for the plugin path)"
    comps = verdict.get("components", {})
    ok = ("error" not in verdict and verdict.get("label") in ("malicious", "suspicious", "benign", "unknown")
          and isinstance(features.get("static"), dict) and {"dynamic", "static"} <= set(comps))
    step("classify", ok, f"{how}, {time.time() - t:.1f}s")
    print(json.dumps({k: verdict.get(k) for k in ("label", "score", "family", "model", "model_version")}, indent=1))
    for name, c in comps.items():
        print(f"   {name:8} {c.get('label'):10} score {c.get('score')}  model {c.get('model')}")
    for line in verdict.get("explanation", [])[:6]:
        print(f"   - {line}")
    if verdict.get("error"):
        print("   error:", verdict["error"])
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=Path, default=REPO / "test" / "test.exe")
    ap.add_argument("--name", default=None, help="original file name (default: the sample's name)")
    ap.add_argument("--analysis-dir", type=Path, help="a finished CHIMERA analysis folder (copied, never changed)")
    ap.add_argument("--model", type=Path, default=Path("/etc/drakrun/classifier/model.py"),
                    help="deployed model.py (default /etc/drakrun/classifier, falls back to classifier/deploy)")
    ap.add_argument("--engine", choices=["podman", "docker"], default="podman")
    ap.add_argument("--image", default="localhost/chimera-static:0.1.0")
    ap.add_argument("--skip-isolation", action="store_true")
    a = ap.parse_args()
    model = a.model if a.model.exists() else REPO / "classifier" / "deploy" / "model.py"
    settings = StaticConfigSection(enabled=True, engine=a.engine, image=a.image)
    print(f"engine {a.engine}, image {a.image}, model {model}, sample {a.sample}")
    results = []
    with tempfile.TemporaryDirectory(prefix="chimera-e2e-") as tmp:
        work = Path(tmp)
        work.chmod(0o711)
        if not a.skip_isolation:
            results.append(isolation(settings, work, a.sample))
        aid, base, _ = static(settings, work, a.sample, a.name or a.sample.name)
        results.append(aid is not None)
        if aid:
            results.append(classify(model, aid, base, a.analysis_dir, work))
    print("ALL PASSED" if all(results) else "SOME STEPS FAILED")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
