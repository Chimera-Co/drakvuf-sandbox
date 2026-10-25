"""Serialize Xen memory checks and restores across all worker processes."""

import contextlib
import fcntl
import logging
import pathlib
import subprocess
import time
from typing import Callable, Optional

from .config import WorkerConfigSection
from .paths import RUN_DIR

logger = logging.getLogger(__name__)


def xen_free_memory_mb() -> int:
    output = subprocess.check_output(["xl", "info"], text=True, timeout=10)
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "free_memory":
            memory = int(value.strip())
            if memory >= 0:
                return memory
    raise RuntimeError("xl info did not report valid free_memory (MB)")


@contextlib.contextmanager
def memory_admission(
    memory_mb: int,
    config: WorkerConfigSection,
    lock_dir: Optional[pathlib.Path] = None,
    read_free_memory: Optional[Callable[[], int]] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
):
    """Hold the host lock from admission until the caller finishes restore.

    The timeout includes waiting for the lock. Release it between unsuccessful
    memory checks so a smaller guest can be admitted while a larger one waits.
    flock is released automatically if a worker process dies.
    """
    lock_dir = lock_dir if lock_dir is not None else RUN_DIR
    lock_dir.mkdir(parents=True, exist_ok=True)
    read_free_memory = read_free_memory or xen_free_memory_mb
    required = memory_mb + config.memory_admission_margin_mb
    started = clock()
    deadline = started + config.memory_admission_timeout
    next_log = started
    with (lock_dir / "admission.lock").open("a") as lock_file:
        while True:
            locked = False
            admitted = False
            reason = "another worker is restoring a domain"
            try:
                try:
                    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    pass
                if locked:
                    free = read_free_memory()
                    admitted = free >= required
                    reason = f"Xen free memory {free} MB, need {required} MB"
                if admitted:
                    waited = clock() - started
                    if waited >= config.memory_admission_poll_interval:
                        logger.info("Memory admission granted after %.1f s", waited)
                    yield waited
                    return
            finally:
                if locked:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

            now = clock()
            if now >= deadline:
                raise TimeoutError(
                    f"Memory admission timed out after {now - started:.1f} s: {reason}"
                )
            if now >= next_log:
                logger.info("Waiting for memory admission: %s", reason)
                next_log = now + 60
            sleep(min(config.memory_admission_poll_interval, deadline - now))
