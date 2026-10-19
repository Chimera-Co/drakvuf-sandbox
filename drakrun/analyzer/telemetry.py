"""
Telemetry completeness summary stored in each analysis' metadata.

An analysis can end with status "finished" while some telemetry is missing
(DRAKVUF crashed or was killed, a plugin produced nothing). This records what
was actually collected so reports and benchmarks don't treat "no log" as
"no behaviour". Note: a "missing" plugin log can mean either that the plugin
saw no events or that it failed; the log alone can't tell them apart, which
is why the DRAKVUF return code and hard-timeout flag are recorded alongside.
"""

import pathlib
import re
from typing import Any, Dict, List, Optional

# Artefacts that matter more than the plugin's log itself.
EXTRA_ARTEFACTS = {
    "memdump": ["dumps.zip"],
    "tlsmon": ["wireshark_key_file.txt"],
}

# Plugins that only act on the guest (hidsim injects mouse input) and never write a log.
NO_LOG_PLUGINS = {"hidsim"}

# DRAKVUF reports internal failures on stderr but can still exit with code 0,
# e.g. "Critical error in re-copying remapped gfn" (seen with apimon under
# heavy registry/WMI load on this host).
DRAKVUF_ERROR_PATTERN = re.compile(r"Critical error|VMI_ERROR|Failed to|Segmentation fault|Assertion")
MAX_ERROR_LINES = 10
# DRAKVUF stopping this much earlier than the analysis window counts as an early exit.
EARLY_EXIT_MARGIN_S = 10


def drakvuf_error_lines(stderr_path: pathlib.Path) -> List[str]:
    if not stderr_path.is_file():
        return []
    errors = []
    with stderr_path.open("r", errors="replace") as f:
        for line in f:
            if DRAKVUF_ERROR_PATTERN.search(line):
                errors.append(line.strip()[:300])
                if len(errors) >= MAX_ERROR_LINES:
                    break
    return errors


def file_status(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {"status": "missing", "bytes": 0}
    size = path.stat().st_size
    return {"status": "produced" if size > 0 else "empty", "bytes": size}


def summarize_telemetry(
    analysis_dir: pathlib.Path,
    plugins: List[str],
    drakvuf_returncode: Optional[int],
    drakvuf_hard_timeout: bool,
    drakvuf_runtime_s: Optional[float] = None,
    analysis_timeout_s: Optional[int] = None,
    vm_stalled: bool = False,
    vm_max_stall_s: Optional[float] = None,
) -> Dict[str, Any]:
    plugin_status = {}
    for plugin in plugins:
        if plugin in NO_LOG_PLUGINS:
            plugin_status[plugin] = {"status": "no_log", "bytes": 0}
            continue
        entry = file_status(analysis_dir / f"{plugin}.log")
        for artefact in EXTRA_ARTEFACTS.get(plugin, []):
            entry[artefact] = file_status(analysis_dir / artefact)["status"]
        plugin_status[plugin] = entry

    screenshots_dir = analysis_dir / "screenshots"
    screenshots = len(list(screenshots_dir.iterdir())) if screenshots_dir.is_dir() else 0

    errors = drakvuf_error_lines(analysis_dir / "drakvuf_stderr.log")
    exited_early = (
        drakvuf_runtime_s is not None
        and analysis_timeout_s is not None
        and not drakvuf_hard_timeout
        and drakvuf_runtime_s < analysis_timeout_s - EARLY_EXIT_MARGIN_S
    )
    return {
        "drakvuf_returncode": drakvuf_returncode,
        "drakvuf_hard_timeout": drakvuf_hard_timeout,
        "drakvuf_runtime_s": None if drakvuf_runtime_s is None else round(drakvuf_runtime_s, 1),
        "drakvuf_exited_early": exited_early,
        "drakvuf_errors": errors,
        # Guest vCPUs made no progress while DRAKVUF was attached (see StallMonitor).
        "vm_stalled": vm_stalled,
        "vm_max_stall_s": None if vm_max_stall_s is None else round(vm_max_stall_s, 1),
        # One verdict for reports and benchmarks: the engine ran the whole window cleanly.
        "complete": drakvuf_returncode == 0
        and not drakvuf_hard_timeout
        and not exited_early
        and not errors
        and not vm_stalled,
        "plugins": plugin_status,
        "missing_plugins": sorted(
            name for name, entry in plugin_status.items() if entry["status"] not in ("produced", "no_log")
        ),
        "pcap": file_status(analysis_dir / "dump.pcap"),
        "screenshots": screenshots,
    }
