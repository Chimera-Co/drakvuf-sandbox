"""Process hardening for the static analyzer. Defence in depth *inside* the container.

The container (see ../README.md) already gives: no network, read-only root, no capabilities,
an unprivileged user, a noexec sample mount and memory/CPU/PID limits. This module adds
limits the process applies to itself before it touches the sample, so a parser bug or a
decompression bomb stays bounded even if the container is misconfigured:

- no core dumps, no new privileges (Linux), no child processes (RLIMIT_NPROC=0 on Linux),
- capped address space, CPU time, open files and output file size,
- umask 077, and the sample is opened read-only, without following symlinks, regular files only.

Nothing in chimera_static ever executes, imports or loads the sample.
"""

from __future__ import annotations

import ctypes
import os
import resource
import stat
import sys

MAX_SAMPLE_BYTES = 256 * 1024 * 1024
DEFAULT_MEMORY_BYTES = 2 * 1024 ** 3
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class SampleError(Exception):
    """The input is not something we will analyse (not a regular file, too large, ...)."""


def _set(limit, value):
    try:
        soft, hard = resource.getrlimit(limit)
        new = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(limit, (new, new))
        return True
    except (ValueError, OSError):
        return False


def harden_process(cpu_seconds: int = 120, memory_bytes: int = DEFAULT_MEMORY_BYTES) -> dict:
    """Apply self-limits. Returns which ones took effect (recorded in static.json)."""
    os.umask(0o077)
    applied = {
        "core": _set(resource.RLIMIT_CORE, 0),
        "cpu_s": _set(resource.RLIMIT_CPU, int(cpu_seconds)),
        "nofile": _set(resource.RLIMIT_NOFILE, 256),
        "fsize": _set(resource.RLIMIT_FSIZE, MAX_OUTPUT_BYTES),
    }
    if sys.platform.startswith("linux"):
        applied["as"] = _set(resource.RLIMIT_AS, int(memory_bytes))
        applied["nproc"] = _set(resource.RLIMIT_NPROC, 0)  # fork/exec of anything now fails
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE = 38, 4
            applied["no_new_privs"] = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            applied["not_dumpable"] = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
        except OSError:
            applied["no_new_privs"] = False
    return applied


def read_sample(path: str, max_bytes: int = MAX_SAMPLE_BYTES) -> tuple[bytes, dict]:
    """Read the sample safely. Returns (bytes, info). Never changes its permissions."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SampleError(f"cannot open sample: {exc.strerror}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SampleError("sample is not a regular file")
        info = {"size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode)),
                "executable_bits": bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
                "truncated": st.st_size > max_bytes}
        chunks, remaining = [], min(st.st_size, max_bytes)
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 8 * 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), info
    finally:
        os.close(fd)


def write_output(path: str, data: bytes) -> None:
    """Atomic write, mode 0640, never executable."""
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o640)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
    finally:
        os.close(fd)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
