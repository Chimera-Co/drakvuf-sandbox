"""Android APK static scan through MobSF, on the deep queue.

Each APK gets a fresh MobSF container that is removed afterwards:

    podman run -d --network none --cap-drop ALL --security-opt no-new-privileges ... <mobsf image>
    podman exec <name> python3 -c DRIVER /input/sample.apk <timeout>   # upload, scan, report_json on 127.0.0.1
    podman rm -f <name>

The container has no network device, so MobSF's optional online lookups (VirusTotal, Play Store, domain
checks) fail closed and the sample never leaves the host. The driver talks to MobSF on the container's own
loopback and prints the JSON report; the host keeps a bounded summary in mobsf.json (schema chimera-mobsf/1)
beside static.json. Informational only: it never feeds the classifier.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from drakrun.lib.config import load_config

logger = logging.getLogger(__name__)

SCHEMA = "chimera-mobsf/1"
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_ITEMS = 60
SEVERITY_RANK = {"high": 0, "warning": 1, "medium": 1, "info": 2, "low": 2, "secure": 3, "good": 3}

# Runs inside the MobSF container (its own Python and requests); argv: sample path, timeout in seconds.
DRIVER = r"""
import os, sys, time
import requests
sample, deadline = sys.argv[1], time.time() + float(sys.argv[2])
base = "http://127.0.0.1:8000"
auth = {"Authorization": os.environ["MOBSF_API_KEY"]}
while True:
    try:
        if requests.get(base + "/api/v1/scans", headers=auth, timeout=5).status_code < 500:
            break
    except requests.RequestException:
        pass
    if time.time() > deadline:
        sys.exit("MobSF did not start in time")
    time.sleep(2)
left = lambda: max(10, deadline - time.time())
with open(sample, "rb") as fh:
    up = requests.post(base + "/api/v1/upload", headers=auth, timeout=left(),
                       files={"file": ("sample.apk", fh, "application/octet-stream")})
up.raise_for_status()
digest = up.json()["hash"]
requests.post(base + "/api/v1/scan", headers=auth, data={"hash": digest}, timeout=left()).raise_for_status()
report = requests.post(base + "/api/v1/report_json", headers=auth, data={"hash": digest}, timeout=left())
report.raise_for_status()
sys.stdout.write(report.text)
"""


def container_name(analysis_id: str) -> str:
    return f"chimera-mobsf-{uuid.UUID(analysis_id)}"


def build_run_command(settings, analysis_id: str, input_dir: Path, api_key: str) -> list[str]:
    memory = f"{settings.mobsf_memory_mb}m"
    return [
        settings.engine, "run", "-d", "--rm",
        "--name", container_name(analysis_id),
        "--network", "none",                       # no network device: nothing leaves the host
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "1024",
        "--memory", memory, "--memory-swap", memory,
        "--cpus", "2",
        "--ulimit", "core=0",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m",
        "--volume", f"{input_dir}:/input:ro,noexec,nosuid,nodev",
        "--env", f"MOBSF_API_KEY={api_key}",
        settings.mobsf_image,
    ]


def _top(items, key=None):
    items = list(items or [])
    if key:
        items.sort(key=key)
    return items[:MAX_ITEMS]


def _rank(severity) -> int:
    return SEVERITY_RANK.get(str(severity or "").lower(), 4)


def _meta(value: dict) -> dict:
    return value.get("metadata") if isinstance(value.get("metadata"), dict) else {}


def summarise(report: dict) -> dict:
    """The parts of a MobSF APK report an analyst reads first, bounded in size."""
    appsec = report.get("appsec") if isinstance(report.get("appsec"), dict) else {}
    findings = [
        {"title": f.get("title"), "severity": level, "section": f.get("section"),
         "description": str(f.get("description") or "")[:400]}
        for level in ("high", "warning", "info", "hotspot")
        for f in appsec.get(level) or [] if isinstance(f, dict)
    ]
    raw_permissions = report.get("permissions") if isinstance(report.get("permissions"), dict) else {}
    permissions = [
        {"name": name, "status": v.get("status"), "info": v.get("info"),
         "description": str(v.get("description") or "")[:300]}
        for name, v in raw_permissions.items() if isinstance(v, dict)
    ]
    code = report.get("code_analysis") if isinstance(report.get("code_analysis"), dict) else {}
    code_findings = [
        {"id": rule, "severity": _meta(v).get("severity"),
         "description": str(_meta(v).get("description") or "")[:400],
         "cwe": _meta(v).get("cwe"), "owasp": _meta(v).get("owasp-mobile"), "masvs": _meta(v).get("masvs"),
         "files": len(v.get("files") or {})}
        for rule, v in (code.get("findings") or {}).items() if isinstance(v, dict)
    ]
    manifest = report.get("manifest_analysis") if isinstance(report.get("manifest_analysis"), dict) else {}
    manifest_findings = [
        {"title": f.get("title"), "severity": f.get("severity"),
         "description": str(f.get("description") or "")[:400]}
        for f in manifest.get("manifest_findings") or [] if isinstance(f, dict)
    ]
    trackers = report.get("trackers") if isinstance(report.get("trackers"), dict) else {}
    malware = report.get("malware_permissions") if isinstance(report.get("malware_permissions"), dict) else {}
    domains = report.get("domains") or {}
    urls = [u.get("urls") if isinstance(u, dict) else [u] for u in report.get("urls") or []]
    return {
        "app": {k: report.get(k) for k in ("app_name", "package_name", "version_name", "min_sdk",
                                           "target_sdk", "main_activity", "md5", "sha256", "size")},
        "security_score": appsec.get("security_score"),
        "counts": {level: len(appsec.get(level) or []) for level in ("high", "warning", "info", "secure",
                                                                     "hotspot")},
        "findings": _top(findings, key=lambda f: _rank(f["severity"])),
        "permissions": _top(permissions, key=lambda p: (p["status"] != "dangerous", p["name"])),
        "permissions_total": len(permissions),
        "malware_permissions": {
            "top": _top(malware.get("top_malware_permissions")),
            "matched": malware.get("total_malware_permissions"),
            "other_abused": _top(malware.get("other_abused_permissions")),
        },
        "trackers": [{"name": t.get("name"), "categories": t.get("categories")}
                     for t in _top(trackers.get("trackers")) if isinstance(t, dict)],
        "code_findings": _top(code_findings, key=lambda f: (_rank(f["severity"]), -f["files"])),
        "manifest_findings": _top(manifest_findings, key=lambda f: _rank(f["severity"])),
        "exported": report.get("exported_count") if isinstance(report.get("exported_count"), dict) else None,
        "domains": _top(domains.keys() if isinstance(domains, dict) else domains),
        "urls": _top(dict.fromkeys(u for group in urls for u in group or [] if isinstance(u, str))),
        "apkid": report.get("apkid") if isinstance(report.get("apkid"), dict) else None,
    }


def _stage(directory: Path) -> Path:
    """A copy MobSF's own (non-root) user can read; never executable."""
    target = directory / "mobsf-in"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(mode=0o711)
    fd = os.open(target / "sample.apk", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, "wb") as out, (directory / "in" / "sample").open("rb") as src:
        shutil.copyfileobj(src, out, 1 << 20)
    return target


def scan(settings, analysis_id: str, directory: Path, runner=subprocess.run) -> dict:
    started = time.time()
    doc = {"schema": SCHEMA, "image": settings.mobsf_image, "error": None}
    name = container_name(analysis_id)
    input_dir = None
    try:
        input_dir = _stage(directory)
        runner(build_run_command(settings, analysis_id, input_dir, secrets.token_hex(32)), check=True,
               capture_output=True, timeout=120)
        out = runner([settings.engine, "exec", name, "python3", "-c", DRIVER, "/input/sample.apk",
                      str(int(settings.mobsf_timeout_s))],
                     capture_output=True, timeout=settings.mobsf_timeout_s + 60)
        if out.returncode != 0:
            doc["error"] = (out.stderr or b"").decode(errors="replace").strip()[-500:] or "MobSF scan failed"
        elif len(out.stdout) > MAX_REPORT_BYTES:
            doc["error"] = "MobSF report too large"
        else:
            report = json.loads(out.stdout)
            if not isinstance(report, dict):
                raise ValueError("report is not an object")
            doc.update(summarise(report))
    except subprocess.TimeoutExpired:
        doc["error"] = "MobSF timed out"
    except subprocess.CalledProcessError as exc:
        doc["error"] = f"MobSF container did not start: {(exc.stderr or b'').decode(errors='replace')[-300:]}"
    except (OSError, ValueError) as exc:
        doc["error"] = f"MobSF scan failed: {str(exc)[:300]}"
    finally:
        try:
            runner([settings.engine, "rm", "-f", "-t", "5", name], capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            logger.warning("[static] could not remove MobSF container %s", name)
        if input_dir is not None:
            shutil.rmtree(input_dir, ignore_errors=True)
    doc["wall_s"] = round(time.time() - started, 2)
    return doc


def run_mobsf_job(analysis_id: str, base: Optional[str] = None) -> dict:
    """RQ job on the deep queue: scan, write mobsf.json beside static.json, refresh the report."""
    from .worker import STATIC_DIR, _refresh_report, _write_json, job_dir

    settings = load_config().static
    directory = job_dir(analysis_id, Path(base) if base else None)
    try:
        doc = scan(settings, analysis_id, directory)
    finally:
        shutil.rmtree(directory / "in", ignore_errors=True)
    _write_json(directory, "mobsf.json", doc)
    if base is None or Path(base) == STATIC_DIR:
        _refresh_report(analysis_id)
    logger.info("[static] MobSF %s: score %s, error %s", analysis_id, doc.get("security_score"),
                doc.get("error"))
    return {"security_score": doc.get("security_score"), "error": doc.get("error")}


def load_mobsf(analysis_id: str, base: Optional[Path] = None) -> Optional[dict]:
    from .worker import job_dir

    try:
        doc = json.loads((job_dir(analysis_id, base) / "mobsf.json").read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == SCHEMA else None
