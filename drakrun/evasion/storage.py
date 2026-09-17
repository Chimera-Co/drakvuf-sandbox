"""Scan-directory helpers for the evasion subsystem.

Mirrors the layout convention already used for analyses
(drakrun.web.storage / drakrun.lib.paths.ANALYSES_DIR): one directory per
scan, named by its UUID4 id, holding metadata.json / evasion.json /
report.html plus a raw/<tool>/ subtree of untouched tool output.

This module is deliberately self-contained rather than importing
drakrun.web.storage yet: that module's check_path/send_analysis_file/
list_analysis_files helpers are reused once the HTTP layer (Phase D) needs
to serve these files over the API, at which point they will be generalized
to take a base directory instead of hardcoding ANALYSES_DIR. Until then,
duplicating the (small, load-bearing) path-traversal guard here means this
module has no half-finished dependency on an API layer that doesn't exist
yet.
"""

from __future__ import annotations

import pathlib
import zipfile
from typing import List, Optional

from drakrun.evasion.constants import ARTIFACTS_ZIP, RAW_SUBDIR


class PathTraversalError(Exception):
    """Raised when a requested relative path would escape the scan
    directory - the same defence drakrun.web.storage.check_path provides
    for analyses, reproduced here for the evasion artifact tree."""


def get_scan_dir(evasion_dir: pathlib.Path, scan_id: str) -> pathlib.Path:
    return evasion_dir / scan_id


def check_path(relative_path: str, base: pathlib.Path) -> pathlib.Path:
    """Resolve relative_path under base, raising PathTraversalError if the
    result would fall outside base (e.g. via '../..' segments)."""
    candidate = (base / relative_path).resolve()
    base_resolved = base.resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        raise PathTraversalError(
            f"'{relative_path}' escapes the scan directory"
        ) from None
    return candidate


def list_scan_files(scan_dir: pathlib.Path) -> List[str]:
    """Every file under scan_dir, as POSIX-style paths relative to it -
    matches drakrun.web.storage.list_analysis_files' shape for the analogous
    analyses endpoint."""
    if not scan_dir.exists():
        return []
    return sorted(
        p.relative_to(scan_dir).as_posix() for p in scan_dir.rglob("*") if p.is_file()
    )


def build_artifacts_zip(
    scan_dir: pathlib.Path, zip_path: Optional[pathlib.Path] = None
) -> pathlib.Path:
    """Zip every file under scan_dir/raw/ (the untouched, per-tool native
    output) into one downloadable archive, mirroring the zipfile pattern
    already used for memory dumps
    (drakrun.analyzer.postprocessing.plugins.process_dumps.process_dumps).
    Does not include metadata.json/evasion.json/report.html - those are
    already individually downloadable and are not "raw tool artifacts"."""
    if zip_path is None:
        zip_path = scan_dir / ARTIFACTS_ZIP

    raw_dir = scan_dir / RAW_SUBDIR
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        if raw_dir.exists():
            for file_path in sorted(raw_dir.rglob("*")):
                if file_path.is_file():
                    zipf.write(file_path, file_path.relative_to(scan_dir))
    return zip_path


__all__ = [
    "PathTraversalError",
    "get_scan_dir",
    "check_path",
    "list_scan_files",
    "build_artifacts_zip",
]
