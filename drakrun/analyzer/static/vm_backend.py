"""Run the static analyzer containers inside the static-analysis Xen VM instead of dom0.

The VM (scripts/chimera/static-vm/) has no network device. dom0 hot-plugs two raw disks per job: a read-only
job disk (header, JSON spec, the sample) and an empty result disk; it signals through xenstore and the guest
agent answers the same way. The guest runs exactly the podman command lines sandbox.py builds for dom0, so
every isolation flag stays in one place. dom0 never mounts anything the guest wrote: it reads one
length-prefixed, sha256-checked JSON envelope from the raw result disk and validates it like a container's
output.

One job at a time (flock shared by the fast and deep workers). A job that times out, or a disk that will not
detach, restarts the VM; the VM also restarts every `vm_restart_every` jobs. Its root disk is read-only and
its scratch disk is reformatted at boot, so a restart returns it to the built image.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import struct
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from drakrun.lib.paths import RUN_DIR

logger = logging.getLogger(__name__)

VM_DIR = Path("/var/lib/chimera-static-vm")
GUEST_WORK = Path("/work/job")
SAMPLE_OFFSET = 1 << 20
RESULT_HEADER = 8 + 8 + 32
JOB_DISK, RESULT_DISK = "xvdb", "xvdc"
DETACH_TIMEOUT_S = 30
JOB_SLACK_S = 60


class VmUnavailable(RuntimeError):
    """The VM is not running or not ready: the caller may fall back to the dom0 container."""


def _run(argv, timeout=30, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=check)


def domid(name: str) -> Optional[int]:
    try:
        return int(_run(["xl", "domid", name], check=True).stdout.strip())
    except (subprocess.SubprocessError, ValueError, FileNotFoundError):
        return None


def _xs_path(dom: int, key: str) -> str:
    return f"/local/domain/{dom}/data/chimera/{key}"


def xs_read(dom: int, key: str) -> Optional[str]:
    proc = _run(["xenstore-read", _xs_path(dom, key)], check=False)
    return proc.stdout.strip()[:128] if proc.returncode == 0 else None


def xs_write(dom: int, key: str, value: str) -> None:
    path = _xs_path(dom, key)
    _run(["xenstore-write", path, value])
    _run(["xenstore-chmod", path, "n0", f"r{dom}"])  # dom0 owns it; the guest may only read


def ready(settings) -> Optional[int]:
    dom = domid(settings.vm_name)
    if dom is not None and xs_read(dom, "ready") == "1":
        return dom
    return None


def restart_vm(settings) -> Optional[int]:
    logger.warning("Restarting static-analysis VM %s", settings.vm_name)
    subprocess.run(["systemctl", "restart", "chimera-static-vm.service"], capture_output=True, timeout=180)
    deadline = time.monotonic() + settings.vm_boot_timeout_s
    while time.monotonic() < deadline:
        dom = ready(settings)
        if dom is not None:
            return dom
        time.sleep(1)
    return None


@contextlib.contextmanager
def _vm_lock():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    with (RUN_DIR / "static-vm.lock").open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _count_job(settings) -> bool:
    """Count a job; True when the VM is due for its periodic restart."""
    counter = RUN_DIR / "static-vm.jobs"
    try:
        n = int(counter.read_text()) + 1
    except (OSError, ValueError):
        n = 1
    due = n >= settings.vm_restart_every
    counter.write_text("0" if due else str(n))
    return due


def write_job_disk(path: Path, spec: dict, sample: Path) -> None:
    body = json.dumps(spec).encode()
    if 12 + len(body) > SAMPLE_OFFSET:
        raise ValueError("job spec too large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out, sample.open("rb") as src:
        out.write(b"CHIMJOB1" + struct.pack(">I", len(body)) + body)
        out.seek(SAMPLE_OFFSET)
        while chunk := src.read(1 << 20):
            out.write(chunk)
        size = out.tell()
        out.truncate(max(SAMPLE_OFFSET + 512, (size + 511) // 512 * 512))


def read_result_disk(path: Path, max_bytes: int) -> dict:
    with path.open("rb") as fh:
        head = fh.read(RESULT_HEADER)
        if head[:8] != b"CHIMRES1":
            raise ValueError("no result written")
        (length,) = struct.unpack(">Q", head[8:16])
        if length > max_bytes:
            raise ValueError("result too large")
        data = fh.read(length)
    if len(data) != length or hashlib.sha256(data).digest() != head[16:48]:
        raise ValueError("result checksum mismatch")
    envelope = json.loads(data)
    if not isinstance(envelope, dict):
        raise ValueError("result is not an object")
    return envelope


def _attach(settings, disk: str, target: Path, access: str) -> None:
    _run(["xl", "block-attach", settings.vm_name,
          f"format=raw,vdev={disk},access={access},backendtype=phy,target={target}"], timeout=60)


def _detach(settings, disk: str) -> bool:
    try:
        _run(["xl", "block-detach", settings.vm_name, disk], timeout=DETACH_TIMEOUT_S)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _attached(settings) -> set[str]:
    try:
        out = _run(["xl", "block-list", settings.vm_name], check=False).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return set()
    names = {"51728": JOB_DISK, "51744": RESULT_DISK}  # xvdb / xvdc device numbers
    return {names[line.split()[0]] for line in out.splitlines()[1:] if line.split() and line.split()[0] in names}


def run_job(settings, steps: list[dict], sample: Path) -> dict:
    """Send one job (a list of podman steps) to the VM; return the guest's envelope. Raises VmUnavailable when
    the VM is not there; any other failure is returned as {"error": ...}."""
    job_id = uuid.uuid4().hex
    digest = hashlib.sha256()
    with sample.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    spec = {"job": job_id, "sample_size": sample.stat().st_size, "sample_sha256": digest.hexdigest(),
            "uid": settings.container_uid, "gid": settings.container_gid, "steps": steps}
    wall = sum(float(step["timeout_s"]) for step in steps) + JOB_SLACK_S
    with _vm_lock():
        dom = ready(settings)
        if dom is None and settings.vm_autostart:
            dom = restart_vm(settings)
        if dom is None:
            raise VmUnavailable(f"static VM {settings.vm_name} is not ready")
        job_dir = VM_DIR / "jobs" / job_id
        job_dir.mkdir(mode=0o700, parents=True)
        job_disk, result_disk = job_dir / "job.img", job_dir / "result.img"
        healthy = True
        try:
            write_job_disk(job_disk, spec, sample)
            fd = os.open(result_disk, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.ftruncate(fd, settings.vm_result_disk_mb << 20)
            os.close(fd)
            _attach(settings, JOB_DISK, job_disk, "ro")
            _attach(settings, RESULT_DISK, result_disk, "rw")
            xs_write(dom, "request", job_id)
            deadline = time.monotonic() + wall
            while xs_read(dom, "done") != job_id:
                if time.monotonic() > deadline:
                    healthy = False
                    return {"error": f"static VM job timed out after {wall:.0f}s"}
                if domid(settings.vm_name) != dom:
                    healthy = False
                    return {"error": "static VM stopped during the job"}
                time.sleep(0.25)
            healthy = _detach(settings, JOB_DISK) & _detach(settings, RESULT_DISK)
            return read_result_disk(result_disk, settings.vm_result_disk_mb << 20)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            healthy = False
            return {"error": f"static VM job failed: {str(exc)[:300]}"}
        finally:
            for disk in _attached(settings):
                healthy = _detach(settings, disk) and healthy
            for path in (job_disk, result_disk):
                with contextlib.suppress(OSError):
                    path.unlink()
            with contextlib.suppress(OSError):
                job_dir.rmdir()
            if not healthy or _count_job(settings):
                restart_vm(settings)


def _step_status(envelope: dict, name: str) -> tuple[dict, Optional[str], Optional[str]]:
    """(status, file text, error) of the job's single step."""
    steps = envelope.get("steps") if isinstance(envelope.get("steps"), list) else []
    step = steps[0] if steps and isinstance(steps[0], dict) else {}
    files = step.get("files") if isinstance(step.get("files"), dict) else {}
    text = files.get(name)
    status = {"exit_code": step.get("exit_code"), "stderr": str(step.get("stderr", ""))[-2000:],
              "backend": "vm"}
    if envelope.get("error") or step.get("error"):
        return status, None, str(envelope.get("error") or step.get("error"))[:300]
    if step.get("timed_out"):
        return status, None, "timed out in the static VM"
    return status, text if isinstance(text, str) else None, None


def analyze_in_vm(settings, analysis_id: str, job_dir: Path, file_name: str, deep: bool) -> dict:
    from .sandbox import DEEP_SCHEMA, GRACE_S, SCHEMA, build_command, container_name

    schema, output = (DEEP_SCHEMA, "deep.json") if deep else (SCHEMA, "static.json")
    argv = build_command(settings, analysis_id, GUEST_WORK / "in" / "sample", GUEST_WORK / "out", file_name,
                         deep)
    timeout = (settings.deep_timeout_s if deep else settings.timeout_s) + GRACE_S
    step = {"name": "deep" if deep else "static", "argv": argv, "timeout_s": timeout,
            "container": container_name(analysis_id, deep), "prepare": {"dirs": ["out"]},
            "outputs": [f"out/{output}"]}
    envelope = run_job(settings, [step], job_dir / "in" / "sample")
    if "steps" not in envelope:
        return {"schema": schema, "error": envelope.get("error", "static VM returned nothing")}
    status, text, error = _step_status(envelope, f"out/{output}")
    if error:
        return {"schema": schema, "error": error, "container": status}
    try:
        if not text:
            raise ValueError(f"no {output} written")
        if len(text) > settings.max_output_bytes:
            raise ValueError(f"{output} too large")
        result = json.loads(text)
        if not isinstance(result, dict) or result.get("schema") != schema:
            raise ValueError(f"{output} has the wrong schema")
    except ValueError as exc:
        return {"schema": schema, "error": str(exc), "container": status}
    result["container"] = {"engine": settings.engine, "image": settings.image, **status}
    return result


def ghidra_in_vm(settings, analysis_id: str, job_dir: Path, targets: list[dict]) -> dict:
    from .sandbox import build_ghidra_command, ghidra_wall_s

    argv = build_ghidra_command(settings, analysis_id, GUEST_WORK / "in" / "sample", GUEST_WORK / "ghidra-work",
                                GUEST_WORK / "ghidra-out")
    step = {"name": "ghidra", "argv": argv, "timeout_s": ghidra_wall_s(settings),
            "container": f"chimera-ghidra-{uuid.UUID(analysis_id)}",
            "prepare": {"dirs": ["ghidra-work", "ghidra-out"],
                        "files": {"ghidra-work/targets.json": json.dumps({"addresses": targets[:200]})}},
            "outputs": ["ghidra-out/ghidra.json"]}
    envelope = run_job(settings, [step], job_dir / "in" / "sample")
    if "steps" not in envelope:
        return {"error": envelope.get("error", "static VM returned nothing")}
    status, text, error = _step_status(envelope, "ghidra-out/ghidra.json")
    if error:
        return {"error": error}
    if status.get("exit_code") != 0:
        return {"error": f"decompiler exited with {status.get('exit_code')}: {status.get('stderr', '')[-500:]}"}
    if not text:
        return {"error": "no ghidra.json written"}
    if len(text) > settings.max_output_bytes:
        return {"error": "ghidra.json too large"}
    try:
        doc = json.loads(text)
    except ValueError:
        return {"error": "ghidra.json is not valid JSON"}
    return doc if isinstance(doc, dict) else {"error": "ghidra.json is not an object"}
