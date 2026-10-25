#!/usr/bin/python3
"""CHIMERA static-analysis VM agent (runs inside the Debian domU, no network device).

Protocol (dom0 is the only party; see drakrun/analyzer/static/vm_backend.py):
  1. dom0 hot-plugs a read-only job disk (xvdb) and an empty result disk (xvdc), then writes the job id to
     xenstore data/chimera/request.
  2. Job disk: 8-byte magic CHIMJOB1, 4-byte big-endian spec length, JSON spec, then the sample at offset
     SAMPLE_OFFSET. The spec lists steps: {name, argv (podman only), outputs, prepare}.
  3. The agent runs each step with its timeout and collects the listed output files (size-capped).
  4. Result disk: 8-byte magic CHIMRES1, 8-byte big-endian length, 32-byte sha256, JSON envelope. Then it
     writes the job id to data/chimera/done. dom0 validates everything it reads; it never mounts a disk the
     guest wrote.
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time

JOB_DEV, RESULT_DEV = "/dev/xvdb", "/dev/xvdc"
WORK = "/work/job"
SAMPLE_OFFSET = 1 << 20
MAX_SPEC = SAMPLE_OFFSET - 12
MAX_FILE = 48 << 20
KEY = "data/chimera/"


def log(msg):
    print(f"chimera-static-agent: {msg}", flush=True)


def xs_read(key):
    r = subprocess.run(["xenstore-read", KEY + key], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def xs_write(key, value):
    subprocess.run(["xenstore-write", KEY + key, value], check=False)


def wait_dev(path, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if os.path.exists(path):
            return True
        time.sleep(0.2)
    return False


def read_job():
    with open(JOB_DEV, "rb") as dev:
        head = dev.read(12)
        if head[:8] != b"CHIMJOB1":
            raise ValueError("bad job magic")
        (length,) = struct.unpack(">I", head[8:12])
        if length > MAX_SPEC:
            raise ValueError("job spec too large")
        spec = json.loads(dev.read(length))
        size = int(spec["sample_size"])
        dev.seek(SAMPLE_OFFSET)
        os.makedirs(f"{WORK}/in", mode=0o711)
        sample = f"{WORK}/in/sample"
        digest = hashlib.sha256()
        with open(sample, "wb") as out:
            left = size
            while left:
                chunk = dev.read(min(left, 1 << 20))
                if not chunk:
                    raise ValueError("job disk shorter than the sample")
                digest.update(chunk)
                out.write(chunk)
                left -= len(chunk)
        if digest.hexdigest() != spec["sample_sha256"]:
            raise ValueError("sample sha256 mismatch")
        os.chown(sample, 0, int(spec["gid"]))
        os.chmod(sample, 0o440)
    return spec


def prepare(step, spec):
    for directory in step.get("prepare", {}).get("dirs", []):
        path = os.path.join(WORK, directory)
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chown(path, int(spec["uid"]), int(spec["gid"]))
    for name, text in step.get("prepare", {}).get("files", {}).items():
        path = os.path.join(WORK, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chown(path, int(spec["uid"]), int(spec["gid"]))


def run_step(step, spec):
    argv = step["argv"]
    if not argv or argv[0] != "podman":
        return {"name": step["name"], "error": "only podman steps are allowed"}
    prepare(step, spec)
    rec = {"name": step["name"], "files": {}}
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              timeout=float(step["timeout_s"]))
        rec.update(exit_code=proc.returncode, stderr=proc.stderr.decode("utf-8", "replace")[-2000:])
    except subprocess.TimeoutExpired:
        rec["timed_out"] = True
        for verb in (["kill"], ["rm", "-f"]):
            subprocess.run(["podman", *verb, step["container"]], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)
    for name in step.get("outputs", []):
        path = os.path.join(WORK, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        if os.path.getsize(path) > MAX_FILE:
            rec["files"][name] = None
            continue
        with open(path, "rb") as fh:
            rec["files"][name] = fh.read().decode("utf-8", "replace")
    return rec


def write_result(envelope):
    data = json.dumps(envelope).encode()
    with open(RESULT_DEV, "r+b") as dev:
        dev.write(b"CHIMRES1" + struct.pack(">Q", len(data)) + hashlib.sha256(data).digest())
        dev.write(data)
        dev.flush()
        os.fsync(dev.fileno())


def handle(job_id):
    shutil.rmtree(WORK, ignore_errors=True)
    envelope = {"job": job_id, "steps": []}
    try:
        if not (wait_dev(JOB_DEV) and wait_dev(RESULT_DEV)):
            raise RuntimeError("job disks did not appear")
        spec = read_job()
        if spec.get("job") != job_id:
            raise ValueError("job id mismatch")
        for step in spec["steps"]:
            envelope["steps"].append(run_step(step, spec))
    except Exception as exc:  # report, never die: dom0 waits for done
        envelope["error"] = f"{type(exc).__name__}: {exc}"[:500]
    try:
        write_result(envelope)
    except Exception as exc:
        log(f"cannot write result: {exc}")
    shutil.rmtree(WORK, ignore_errors=True)
    xs_write("done", job_id)


def main():
    last = xs_read("done")
    xs_write("ready", "1")
    log("ready")
    while True:
        job_id = xs_read("request")
        if job_id and job_id != last and len(job_id) <= 64:
            log(f"job {job_id}")
            handle(job_id)
            last = job_id
        time.sleep(0.3)


if __name__ == "__main__":
    sys.exit(main())
