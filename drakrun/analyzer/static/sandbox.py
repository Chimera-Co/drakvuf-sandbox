"""Run chimera_static on one sample inside a locked-down container.

Why a container, not a VM: the analyzer only *reads* the file, needs no hypervisor features,
and finishes in seconds. A dedicated Xen domU would compete with the analysis VMs for memory
(see worker memory admission), add a file-transfer channel to secure, and slow every upload.
A container with the flags below gives the isolation that matters for a parser bug: no
network, no capabilities, no privilege gain, unprivileged uid, read-only root filesystem,
noexec everywhere, and memory/CPU/PID/time limits. CHIMERA's dom0 already parses hostile
data at a similar level (capa on memory dumps, pcap parsing), so this keeps the risk where
it is instead of adding a new class. A gVisor runtime or a VM is the upgrade path
(docs/chimera/static-analysis.md).

Inside the container chimera_static additionally limits itself (rlimits, no new threads or
processes, no core dumps; chimera_static/safety.py). Nothing in this path executes the sample.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA = "chimera-static/1"
GRACE_S = 30  # wall-clock allowance on top of the analyzer's own timeout


def container_name(analysis_id: str) -> str:
    return f"chimera-static-{uuid.UUID(analysis_id)}"


def build_command(settings, analysis_id: str, sample: Path, out_dir: Path, file_name: str) -> list[str]:
    """The full container command line. Every isolation flag lives here."""
    sample_opts = "ro,noexec,nosuid,nodev" if settings.engine == "podman" else "ro"
    out_opts = "rw,noexec,nosuid,nodev" if settings.engine == "podman" else "rw"
    memory = f"{settings.memory_mb}m"
    return [
        settings.engine, "run", "--rm",
        "--name", container_name(analysis_id),
        "--network", "none",                       # no network at all
        "--read-only",                             # read-only root filesystem
        "--cap-drop", "ALL",                       # no Linux capabilities
        "--security-opt", "no-new-privileges",     # setuid binaries cannot raise privileges
        "--user", f"{settings.container_uid}:{settings.container_gid}",
        "--pids-limit", str(settings.pids_limit),
        "--memory", memory, "--memory-swap", memory,
        "--cpus", str(settings.cpus),
        "--ulimit", "core=0", "--ulimit", "nofile=256:256",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{sample}:/in/sample:{sample_opts}",
        "-v", f"{out_dir}:/out:{out_opts}",
        settings.image,
        "/in/sample", "/out",
        "--name", file_name[:255],
        "--timeout", str(int(settings.timeout_s)),
        "--memory-mb", str(settings.memory_mb),
    ]


def stage_sample(source: Path, job_dir: Path, settings) -> Path:
    """Copy the upload for the container: never executable, readable only by the container's uid."""
    job_dir.mkdir(mode=0o711, parents=True, exist_ok=True)  # traverse, not list
    in_dir = job_dir / "in"
    in_dir.mkdir(mode=0o711, exist_ok=True)
    staged = in_dir / "sample"
    tmp = in_dir / ".sample.tmp"
    with source.open("rb") as src, os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                                                     0o400), "wb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
    if os.geteuid() == 0:
        os.chown(tmp, 0, settings.container_gid)
        os.chmod(tmp, 0o440)                      # root + container group may read; nobody may execute
    else:  # development without root: the container's uid is not ours
        os.chmod(tmp, 0o444)
    os.replace(tmp, staged)
    return staged


def _prepare_out(job_dir: Path, settings) -> Path:
    out = job_dir / "out"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(mode=0o700)
    if os.geteuid() == 0:
        os.chown(out, settings.container_uid, settings.container_gid)
    else:
        os.chmod(out, 0o777)  # development only (rootless engine maps uids)
    return out


def run_in_container(settings, analysis_id: str, job_dir: Path, file_name: str) -> dict:
    """Run the analyzer; return the parsed, validated static.json (or an error document)."""
    staged = job_dir / "in" / "sample"
    out = _prepare_out(job_dir, settings)
    command = build_command(settings, analysis_id, staged, out, file_name)
    wall = settings.timeout_s + GRACE_S
    try:
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=wall)
        status = {"exit_code": proc.returncode, "stderr": proc.stderr.decode("utf-8", "replace")[-2000:]}
    except subprocess.TimeoutExpired:
        subprocess.run([settings.engine, "kill", container_name(analysis_id)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        subprocess.run([settings.engine, "rm", "-f", container_name(analysis_id)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return {"schema": SCHEMA, "error": f"static analysis timed out after {wall:.0f}s"}
    except FileNotFoundError:
        return {"schema": SCHEMA, "error": f"container engine {settings.engine!r} not installed"}
    result_path = out / "static.json"
    try:
        if result_path.is_symlink() or not result_path.is_file():
            raise ValueError("no static.json written")
        if result_path.stat().st_size > settings.max_output_bytes:
            raise ValueError("static.json too large")
        result = json.loads(result_path.read_bytes())
        if not isinstance(result, dict) or result.get("schema") != SCHEMA:
            raise ValueError("static.json has the wrong schema")
    except (OSError, ValueError) as exc:
        return {"schema": SCHEMA, "error": f"{exc}", "container": status}
    result["container"] = {"engine": settings.engine, "image": settings.image, **status}
    return result
