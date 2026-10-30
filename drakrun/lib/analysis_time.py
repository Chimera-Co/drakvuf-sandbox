"""
Long analyses and the two optional time accelerations for samples that wait before acting.

- Clock speed-up: scripts/chimera/clock-scale/chimera-clock-scale sets a paused, restored Windows
  guest's TSC frequency to N times its own (hardware TSC scaling). The guest calibrated its TSC
  before the snapshot, so its TSC, QueryPerformanceCounter and deadline-timer interrupts run N
  times faster than real time: sleeps, timers and tick-count loops all finish N times sooner.
- Sleep shortening: DRAKVUF's delaymon rewrites relative NtDelayExecution delays longer than a
  threshold (scripts/chimera/patches/drakvuf-da982ab-delaymon-shorten-delays.patch).

Both are off unless an analysis asks for them: a sample can notice either (CPU work takes N
times longer in guest time; a shortened sleep is visible to a tick-count check around it).
"""

import json
import pathlib
import shutil
import subprocess
import time
from typing import Any, Dict, Optional

from .config import AnalysisTimeConfigSection


class ClockScaleError(RuntimeError):
    pass


def required_free_disk_gb(timeout_s: int, settings: AnalysisTimeConfigSection) -> float:
    return settings.min_free_disk_gb + settings.free_disk_gb_per_hour * timeout_s / 3600


def check_free_disk(
    path: pathlib.Path, timeout_s: int, settings: AnalysisTimeConfigSection
) -> Optional[str]:
    """Returns why an analysis of timeout_s real seconds should not start, or None."""
    # The directory may not exist yet: _free_gb measures the file system it will be on.
    free_gb = _free_gb(path)
    needed_gb = required_free_disk_gb(timeout_s, settings)
    if free_gb < needed_gb:
        return (
            f"not enough free disk for a {timeout_s} s analysis: "
            f"{free_gb:.1f} GB free, {needed_gb:.1f} GB needed"
        )
    return None


def _free_gb(path: pathlib.Path) -> float:
    while not path.exists() and path != path.parent:
        path = path.parent
    return shutil.disk_usage(path).free / 1024**3


def wait_watching_disk(
    proc: subprocess.Popen,
    timeout_s: Optional[float],
    output_dir: pathlib.Path,
    settings: AnalysisTimeConfigSection,
    poll_s: float = 30,
) -> bool:
    """
    proc.wait(timeout_s), checking free disk every poll_s. DRAKVUF's memory dumps and log grow
    for as long as it runs (a 1-hour idle run on H3, 30 Oct: 3.8 GB in the first 25 minutes,
    then about 3 GB per hour), and postprocessing copies the log once more while splitting it
    (that run peaked at 7.6 GB and kept 2.7 GB). When free disk falls below min_free_disk_gb
    plus the log's size, DRAKVUF is asked to stop (SIGTERM) and this returns True.
    Raises subprocess.TimeoutExpired like Popen.wait.
    """
    deadline = None if timeout_s is None else time.monotonic() + timeout_s
    log_path = output_dir / "drakmon.log"
    while True:
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise subprocess.TimeoutExpired(proc.args, timeout_s)
        try:
            proc.wait(poll_s if remaining is None else min(poll_s, remaining))
            return False
        except subprocess.TimeoutExpired:
            pass
        log_gb = log_path.stat().st_size / 1024**3 if log_path.exists() else 0
        if _free_gb(output_dir) < settings.min_free_disk_gb + log_gb:
            proc.terminate()
            proc.wait(120)
            return True


def validate_time_options(
    timeout_s: Optional[int],
    clock_scale: int,
    settings: AnalysisTimeConfigSection,
) -> Optional[str]:
    """Returns why the requested analysis time settings are not accepted, or None."""
    if timeout_s is not None and not 0 < timeout_s <= settings.max_timeout_s:
        return f"timeout must be between 1 and {settings.max_timeout_s} seconds"
    if not 1 <= clock_scale <= settings.clock_scale_max:
        return f"clock_scale must be between 1 and {settings.clock_scale_max}"
    if clock_scale > 1 and not settings.clock_scale_enabled:
        return "clock speed-up is not available on this server's image"
    return None


def public_settings(settings: AnalysisTimeConfigSection) -> Dict[str, Any]:
    """What the upload form needs to know about analysis time."""
    return {
        "max_timeout_s": settings.max_timeout_s,
        "clock_scale_enabled": settings.clock_scale_enabled,
        "clock_scale_max": settings.clock_scale_max,
        "sleep_skip_above_ms": settings.sleep_skip_above_ms,
        "sleep_skip_to_ms": settings.sleep_skip_to_ms,
    }


def sleep_skip_drakvuf_args(settings: AnalysisTimeConfigSection) -> Dict[str, Any]:
    return {
        "--delaymon-skip-above": settings.sleep_skip_above_ms,
        "--delaymon-skip-to": settings.sleep_skip_to_ms,
    }


def summarize_delay_shortening(analysis_dir: pathlib.Path) -> Dict[str, Any]:
    """Counts the delays delaymon shortened (delaymon.log, written by split_drakmon_log)."""
    shortened = failed = skipped_ms = 0
    processes = set()
    log_path = analysis_dir / "delaymon.log"
    if log_path.exists():
        with log_path.open() as log_file:
            for line in log_file:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("Shortened") == "yes":
                    shortened += 1
                    # DelayIntervalMs is the raw interval: negative for a relative delay
                    requested_ms = -float(entry.get("DelayIntervalMs", 0))
                    skipped_ms += int(requested_ms) - int(entry.get("ShortenedToMs", 0))
                    processes.add(entry.get("ProcessName"))
                elif entry.get("Shortened") == "failed":
                    failed += 1
    return {
        "delays_shortened": shortened,
        "delays_not_shortened": failed,
        "delay_skipped_ms": skipped_ms,
        "delay_shortened_processes": sorted(p for p in processes if p),
    }


def apply_clock_scale(
    vm_name: str, factor: int, settings: AnalysisTimeConfigSection
) -> Dict[str, Any]:
    """Speeds up the clock of the paused domain vm_name factor times; returns the helper's report."""
    domid = subprocess.run(
        ["xl", "domid", vm_name], capture_output=True, text=True, check=True
    ).stdout.strip()
    result = subprocess.run(
        [str(settings.clock_scale_helper), domid, str(factor)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise ClockScaleError(
            f"{settings.clock_scale_helper} failed ({result.returncode}): "
            f"{result.stderr.strip()[:300]}"
        )
    return json.loads(result.stdout)
