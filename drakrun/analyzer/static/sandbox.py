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
from typing import Optional

logger = logging.getLogger(__name__)

SCHEMA = "chimera-static/1"
DEEP_SCHEMA = "chimera-deep/1"
GRACE_S = 30  # wall-clock allowance on top of the analyzer's own timeout


def container_name(analysis_id: str, deep: bool = False) -> str:
    return f"chimera-static-{uuid.UUID(analysis_id)}" + ("-deep" if deep else "")


def build_command(
    settings,
    analysis_id: str,
    sample: Path,
    out_dir: Path,
    file_name: str,
    deep: bool = False,
) -> list[str]:
    """The full container command line. Every isolation flag lives here; the deep pass only changes time,
    memory and the --deep switch."""
    sample_opts = "ro,noexec,nosuid,nodev" if settings.engine == "podman" else "ro"
    out_opts = "rw,noexec,nosuid,nodev" if settings.engine == "podman" else "rw"
    memory_mb = settings.deep_memory_mb if deep else settings.memory_mb
    timeout_s = settings.deep_timeout_s if deep else settings.timeout_s
    memory = f"{memory_mb}m"
    return [
        settings.engine,
        "run",
        "--rm",
        "--name",
        container_name(analysis_id, deep),
        "--network",
        "none",  # no network at all
        "--read-only",  # read-only root filesystem
        "--cap-drop",
        "ALL",  # no Linux capabilities
        "--security-opt",
        "no-new-privileges",  # setuid binaries cannot raise privileges
        "--user",
        f"{settings.container_uid}:{settings.container_gid}",
        "--pids-limit",
        str(settings.pids_limit),
        "--memory",
        memory,
        "--memory-swap",
        memory,
        "--cpus",
        str(settings.cpus),
        "--ulimit",
        "core=0",
        "--ulimit",
        "nofile=256:256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "-v",
        f"{sample}:/in/sample:{sample_opts}",
        "-v",
        f"{out_dir}:/out:{out_opts}",
        settings.image,
        "/in/sample",
        "/out",
        "--name",
        file_name[:255],
        "--timeout",
        str(int(timeout_s)),
        "--memory-mb",
        str(memory_mb),
    ] + (["--deep"] if deep else [])


def stage_sample(source: Path, job_dir: Path, settings) -> Path:
    """Copy the upload for the container: never executable, readable only by the container's uid."""
    job_dir.mkdir(mode=0o711, parents=True, exist_ok=True)  # traverse, not list
    in_dir = job_dir / "in"
    in_dir.mkdir(mode=0o711, exist_ok=True)
    staged = in_dir / "sample"
    tmp = in_dir / ".sample.tmp"
    with source.open("rb") as src, os.fdopen(
        os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o400), "wb"
    ) as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
    if os.geteuid() == 0:
        os.chown(tmp, 0, settings.container_gid)
        os.chmod(tmp, 0o440)  # root + container group may read; nobody may execute
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


def run_in_container(
    settings,
    analysis_id: str,
    job_dir: Path,
    file_name: str,
    deep: bool = False,
    lock_wait_s: Optional[float] = None,
) -> dict:
    """Run the analyzer; return the parsed, validated static.json, or deep.json with deep=True (or an error
    document). With the VM backend, `lock_wait_s` bounds the wait for the VM (None: as long as it takes).
    """
    if getattr(settings, "backend", "container") == "vm":
        from .vm_backend import VmUnavailable, analyze_in_vm

        try:
            return analyze_in_vm(
                settings, analysis_id, job_dir, file_name, deep, lock_wait_s
            )
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
        proc = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=wall,
        )
        status = {
            "exit_code": proc.returncode,
            "stderr": proc.stderr.decode("utf-8", "replace")[-2000:],
        }
    except subprocess.TimeoutExpired:
        subprocess.run(
            [settings.engine, "kill", container_name(analysis_id, deep)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        subprocess.run(
            [settings.engine, "rm", "-f", container_name(analysis_id, deep)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return {
            "schema": schema,
            "error": f"static analysis timed out after {wall:.0f}s",
        }
    except FileNotFoundError:
        return {
            "schema": schema,
            "error": f"container engine {settings.engine!r} not installed",
        }
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
    result["container"] = {
        "engine": settings.engine,
        "image": settings.image,
        "backend": "container",
        **status,
    }
    return result


GHIDRA_STARTUP_S = 90  # JVM start, import and the script itself, on top of analysis + decompile budgets


GHIDRA_LOG = "headless.log"  # run.sh passes -log /out/headless.log
LOG_TAIL_LINES = 40


def ghidra_wall_s(settings) -> float:
    return (
        settings.ghidra_analysis_timeout_s
        + settings.ghidra_decompile_budget_s
        + GHIDRA_STARTUP_S
    )


def ghidra_failure(
    wall: float,
    exit_code: Optional[int] = None,
    stderr: str = "",
    log: Optional[str] = None,
) -> dict:
    """{"error", "stderr", "log"} for a decompiler run that produced nothing usable. Ghidra's analysis timeout
    only asks the running analyzer to stop, so a run can overshoot it; the end of its headless log shows which
    phase it was in (import, "ANALYZING all memory and code", the script, the save)."""
    if exit_code is None:
        error = f"decompiler timed out after {wall:.0f}s"
    elif exit_code == 137:
        # The step limit is reported as a timeout; 137 is a SIGKILL from elsewhere, e.g. the memory limit.
        error = "decompiler was killed (exit 137, SIGKILL before the time limit)"
    else:
        error = f"decompiler exited with {exit_code}"
    # stderr starts with the JVM's banner; its last line is the one that says what went wrong.
    last = [line for line in (stderr or "").splitlines() if line.strip()][-1:]
    if last and exit_code is not None:
        error += ": " + last[0].strip()[:200]
    doc = {"error": error, "stderr": (stderr or "")[-500:]}
    lines = [line for line in (log or "").splitlines() if line.strip()]
    if lines:
        doc["log"] = "\n".join(lines[-LOG_TAIL_LINES:])[-4000:]
    return doc


def ghidra_result(text: Optional[str], max_bytes: int, timed_out: bool = False) -> dict:
    """ghidra.json's content, or {"error": ...}. After a timeout a complete ghidra.json means the script had
    finished before the kill (Ghidra was still in post-analysis or the save): keep it and say so.
    """
    if not text:
        return {"error": "no ghidra.json written"}
    if len(text) > max_bytes:
        return {"error": "ghidra.json too large"}
    try:
        doc = json.loads(text)
    except ValueError:
        return {"error": "ghidra.json is not valid JSON"}
    if not isinstance(doc, dict):
        return {"error": "ghidra.json is not an object"}
    if timed_out:
        if not isinstance(doc.get("functions"), list):
            return {"error": "ghidra.json is not a decompiler result"}
        doc["timed_out"] = True
    return doc


def build_ghidra_command(
    settings, analysis_id: str, sample: Path, work: Path, out_dir: Path
) -> list[str]:
    """Decompiler container: the analyzer's isolation flags; more PIDs (JVM threads) and a disk-backed /work."""
    opts = "noexec,nosuid,nodev" if settings.engine == "podman" else ""
    ro, rw = ("ro," + opts).rstrip(","), ("rw," + opts).rstrip(",")
    memory = f"{settings.ghidra_memory_mb}m"
    heap = f"{max(512, settings.ghidra_memory_mb - 512)}M"  # leave room for the JVM's native memory
    return [
        settings.engine,
        "run",
        "--rm",
        "--name",
        f"chimera-ghidra-{uuid.UUID(analysis_id)}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        f"{settings.container_uid}:{settings.container_gid}",
        "--pids-limit",
        "256",
        "--memory",
        memory,
        "--memory-swap",
        memory,
        "--cpus",
        "2",
        "--ulimit",
        "core=0",
        "--ulimit",
        "nofile=1024:1024",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "-v",
        f"{sample}:/in/sample:{ro}",
        "-v",
        f"{work}:/work:{rw}",
        "-v",
        f"{out_dir}:/out:{rw}",
        settings.ghidra_image,
        "/in/sample",
        "/work",
        "/out",
        str(int(settings.ghidra_analysis_timeout_s)),
        heap,
        str(int(settings.ghidra_max_functions)),
        str(int(settings.ghidra_decompile_budget_s)),
    ]


def _read_out(path: Path, max_bytes: int) -> Optional[str]:
    """Up to `max_bytes` of a file the container wrote, as text; None when it is missing or a symlink."""
    if path.is_symlink() or not path.is_file():
        return None
    with path.open("rb") as fh:
        return fh.read(max_bytes).decode("utf-8", "replace")


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
    (work / "targets.json").write_text(
        json.dumps({"addresses": targets[:200]}), encoding="utf-8"
    )
    for directory in (work, out):
        if os.geteuid() == 0:
            for path in (directory, *directory.iterdir()):
                os.chown(path, settings.container_uid, settings.container_gid)
        else:
            os.chmod(directory, 0o777)  # development only (rootless engine maps uids)
    name = f"chimera-ghidra-{uuid.UUID(analysis_id)}"
    wall = ghidra_wall_s(settings)
    try:
        proc = subprocess.run(
            build_ghidra_command(settings, analysis_id, staged, work, out),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=wall,
        )
        if proc.returncode != 0:
            return ghidra_failure(
                wall,
                proc.returncode,
                proc.stderr.decode("utf-8", "replace"),
                _read_out(out / GHIDRA_LOG, settings.max_output_bytes),
            )
        return ghidra_result(
            _read_out(out / "ghidra.json", settings.max_output_bytes + 1),
            settings.max_output_bytes,
        )
    except subprocess.TimeoutExpired as exc:
        for verb in ("kill", "rm"):
            subprocess.run(
                [settings.engine, verb, *(["-f"] if verb == "rm" else []), name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        doc = ghidra_result(
            _read_out(out / "ghidra.json", settings.max_output_bytes + 1),
            settings.max_output_bytes,
            timed_out=True,
        )
        if "error" not in doc:
            return doc
        return ghidra_failure(
            wall,
            stderr=(exc.stderr or b"").decode("utf-8", "replace"),
            log=_read_out(out / GHIDRA_LOG, settings.max_output_bytes),
        )
    except FileNotFoundError:
        return {"error": f"container engine {settings.engine!r} not installed"}
    except (OSError, ValueError) as exc:
        return {"error": str(exc)[:300]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)
