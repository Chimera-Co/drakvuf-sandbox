"""Run chimera_static on one sample inside a locked-down container.

The container runs either in dom0 (backend "container") or inside the static-analysis Xen VM (backend "vm",
vm_backend.py): a domU with no network device that receives the sample on a read-only raw disk and returns
JSON on another, so a parser exploit lands in a throwaway VM instead of dom0. Both use the command lines
built here, with every isolation flag: no network, no capabilities, no privilege gain, unprivileged uid,
read-only root filesystem, noexec everywhere, and memory/CPU/PID/time limits.

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
DEEP_SCHEMA = "chimera-deep/1"
GRACE_S = 30  # wall-clock allowance on top of the analyzer's own timeout


def container_name(analysis_id: str, deep: bool = False) -> str:
    return f"chimera-static-{uuid.UUID(analysis_id)}" + ("-deep" if deep else "")


def build_command(settings, analysis_id: str, sample: Path, out_dir: Path, file_name: str,
                  deep: bool = False) -> list[str]:
    """The full container command line. Every isolation flag lives here; the deep pass only changes time,
    memory and the --deep switch."""
    sample_opts = "ro,noexec,nosuid,nodev" if settings.engine == "podman" else "ro"
    out_opts = "rw,noexec,nosuid,nodev" if settings.engine == "podman" else "rw"
    memory_mb = settings.deep_memory_mb if deep else settings.memory_mb
    timeout_s = settings.deep_timeout_s if deep else settings.timeout_s
    memory = f"{memory_mb}m"
    return [
        settings.engine, "run", "--rm",
        "--name", container_name(analysis_id, deep),
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
        "--timeout", str(int(timeout_s)),
        "--memory-mb", str(memory_mb),
    ] + (["--deep"] if deep else [])


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


def run_in_container(settings, analysis_id: str, job_dir: Path, file_name: str, deep: bool = False) -> dict:
    """Run the analyzer; return the parsed, validated static.json, or deep.json with deep=True (or an error
    document)."""
    if getattr(settings, "backend", "container") == "vm":
        from .vm_backend import VmUnavailable, analyze_in_vm
        try:
            return analyze_in_vm(settings, analysis_id, job_dir, file_name, deep)
        except VmUnavailable as exc:
            if not settings.vm_fallback_container:
                return {"schema": DEEP_SCHEMA if deep else SCHEMA, "error": str(exc)}
            logger.warning("%s; running in the dom0 container", exc)
    schema, output = (DEEP_SCHEMA, "deep.json") if deep else (SCHEMA, "static.json")
    staged = job_dir / "in" / "sample"
    out = _prepare_out(job_dir, settings)
    command = build_command(settings, analysis_id, staged, out, file_name, deep)
    wall = (settings.deep_timeout_s if deep else settings.timeout_s) + GRACE_S
    try:
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=wall)
        status = {"exit_code": proc.returncode, "stderr": proc.stderr.decode("utf-8", "replace")[-2000:]}
    except subprocess.TimeoutExpired:
        subprocess.run([settings.engine, "kill", container_name(analysis_id, deep)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        subprocess.run([settings.engine, "rm", "-f", container_name(analysis_id, deep)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return {"schema": schema, "error": f"static analysis timed out after {wall:.0f}s"}
    except FileNotFoundError:
        return {"schema": schema, "error": f"container engine {settings.engine!r} not installed"}
    result_path = out / output
    try:
        if result_path.is_symlink() or not result_path.is_file():
            raise ValueError(f"no {output} written")
        if result_path.stat().st_size > settings.max_output_bytes:
            raise ValueError(f"{output} too large")
        result = json.loads(result_path.read_bytes())
        if not isinstance(result, dict) or result.get("schema") != schema:
            raise ValueError(f"{output} has the wrong schema")
    except (OSError, ValueError) as exc:
        return {"schema": schema, "error": f"{exc}", "container": status}
    result["container"] = {"engine": settings.engine, "image": settings.image, "backend": "container", **status}
    return result


GHIDRA_STARTUP_S = 90  # JVM start, import and the script itself, on top of analysis + decompile budgets


def ghidra_wall_s(settings) -> float:
    return settings.ghidra_analysis_timeout_s + settings.ghidra_decompile_budget_s + GHIDRA_STARTUP_S


def build_ghidra_command(settings, analysis_id: str, sample: Path, work: Path, out_dir: Path) -> list[str]:
    """Decompiler container: the analyzer's isolation flags; more PIDs (JVM threads) and a disk-backed /work."""
    opts = "noexec,nosuid,nodev" if settings.engine == "podman" else ""
    ro, rw = ("ro," + opts).rstrip(","), ("rw," + opts).rstrip(",")
    memory = f"{settings.ghidra_memory_mb}m"
    heap = f"{max(512, settings.ghidra_memory_mb - 512)}M"  # leave room for the JVM's native memory
    return [
        settings.engine, "run", "--rm",
        "--name", f"chimera-ghidra-{uuid.UUID(analysis_id)}",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", f"{settings.container_uid}:{settings.container_gid}",
        "--pids-limit", "256",
        "--memory", memory, "--memory-swap", memory,
        "--cpus", "2",
        "--ulimit", "core=0", "--ulimit", "nofile=1024:1024",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "-v", f"{sample}:/in/sample:{ro}",
        "-v", f"{work}:/work:{rw}",
        "-v", f"{out_dir}:/out:{rw}",
        settings.ghidra_image,
        "/in/sample", "/work", "/out",
        str(int(settings.ghidra_analysis_timeout_s)), heap, str(int(settings.ghidra_max_functions)),
        str(int(settings.ghidra_decompile_budget_s)),
    ]


def run_ghidra(settings, analysis_id: str, job_dir: Path, targets: list[dict]) -> dict:
    """Decompile the staged sample; return ghidra.json's content, or {"error": ...}. Never raises."""
    if getattr(settings, "backend", "container") == "vm":
        from .vm_backend import VmUnavailable, ghidra_in_vm
        try:
            return ghidra_in_vm(settings, analysis_id, job_dir, targets)
        except VmUnavailable as exc:
            if not settings.vm_fallback_container:
                return {"error": str(exc)}
            logger.warning("%s; decompiling in the dom0 container", exc)
        except Exception as exc:  # never raises, like the container path
            return {"error": str(exc)[:300]}
    staged = job_dir / "in" / "sample"
    work, out = job_dir / "ghidra-work", job_dir / "ghidra-out"
    for directory in (work, out):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(mode=0o700)
    (work / "targets.json").write_text(json.dumps({"addresses": targets[:200]}), encoding="utf-8")
    for directory in (work, out):
        if os.geteuid() == 0:
            for path in (directory, *directory.iterdir()):
                os.chown(path, settings.container_uid, settings.container_gid)
        else:
            os.chmod(directory, 0o777)  # development only (rootless engine maps uids)
    name = f"chimera-ghidra-{uuid.UUID(analysis_id)}"
    wall = ghidra_wall_s(settings)
    try:
        proc = subprocess.run(build_ghidra_command(settings, analysis_id, staged, work, out),
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              timeout=wall)
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace")[-500:]
            return {"error": f"decompiler exited with {proc.returncode}: {tail}"}
        result_path = out / "ghidra.json"
        if result_path.is_symlink() or not result_path.is_file():
            return {"error": "no ghidra.json written"}
        if result_path.stat().st_size > settings.max_output_bytes:
            return {"error": "ghidra.json too large"}
        doc = json.loads(result_path.read_bytes())
        return doc if isinstance(doc, dict) else {"error": "ghidra.json is not an object"}
    except subprocess.TimeoutExpired:
        for verb in ("kill", "rm"):
            subprocess.run([settings.engine, verb, *(["-f"] if verb == "rm" else []), name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return {"error": f"decompiler timed out after {wall:.0f}s"}
    except FileNotFoundError:
        return {"error": f"container engine {settings.engine!r} not installed"}
    except (OSError, ValueError) as exc:
        return {"error": str(exc)[:300]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)
