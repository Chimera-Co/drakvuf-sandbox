"""Android APK and iOS IPA static scan through MobSF, on the deep queue.

With [static] backend = "vm" (the default deployment) MobSF runs inside the static-analysis Xen VM
(vm_backend.mobsf_in_vm), never on the host. Otherwise each app gets a fresh dom0 container that is removed
afterwards:

    podman run -d --network none --cap-drop ALL --security-opt no-new-privileges ... <mobsf image>
    podman exec <name> python3 -c DRIVER /input/sample.apk <timeout>   # upload, scan, report_json on 127.0.0.1
    podman rm -f <name>

The container has no network device, so MobSF's optional online lookups (VirusTotal, Play Store, domain
checks) fail closed and the sample never leaves the host. The driver talks to MobSF on the container's own
loopback and prints the JSON report; the host keeps a bounded summary in mobsf.json (schema chimera-mobsf/1)
beside static.json. Informational only: it never feeds the classifier.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import time
import uuid
import zipfile
from pathlib import Path
from typing import Optional

from drakrun.lib.config import load_config

logger = logging.getLogger(__name__)

SCHEMA = "chimera-mobsf/1"
MAX_REPORT_BYTES = 160 * 1024 * 1024
MAX_ITEMS = 60
# Decompiled sources kept per app (the driver and the host both enforce these).
MAX_SOURCE_FILES = 3000
MAX_SOURCE_FILE_BYTES = 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 48 * 1024 * 1024  # base64 in the report envelope stays under the VM's 48 MiB file cap
SOURCES_NAME = "mobsf-sources.zip"
MOBSF_UID = 9901  # the image's "mobsf" user, which owns its home (~/.MobSF)
SOURCE_PATH = re.compile(r"[A-Za-z0-9_$.\-]+(?:/[A-Za-z0-9_$.\-]+)*\.(?:java|kt)")
SEVERITY_RANK = {"high": 0, "warning": 1, "medium": 1, "info": 2, "low": 2, "secure": 3, "good": 3}

# Runs inside the MobSF container (its own Python and requests); argv: sample path, timeout in seconds, the
# source limits and optionally the upload name (its extension picks MobSF's analyzer). Prints {"report", "sources_found", "sources_zip" (base64)}.
DRIVER = r"""
import os, sys, time
MAX_FILES, MAX_FILE, MAX_TOTAL = (int(v) for v in sys.argv[3:6])
import requests
sample, deadline = sys.argv[1], time.time() + float(sys.argv[2])
upload_name = sys.argv[6] if len(sys.argv) > 6 else os.path.basename(sample)
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
                       files={"file": (upload_name, fh, "application/octet-stream")})
up.raise_for_status()
digest = up.json()["hash"]
requests.post(base + "/api/v1/scan", headers=auth, data={"hash": digest}, timeout=left()).raise_for_status()
report = requests.post(base + "/api/v1/report_json", headers=auth, data={"hash": digest}, timeout=left())
report.raise_for_status()
report = report.json()
# JADX's Java/Kotlin output for the analyst to read: the app's own package first, libraries last, bounded.
import base64, io, json, zipfile
root = os.path.join(os.path.expanduser("~"), ".MobSF", "uploads", digest, "java_source")
pkg = str(report.get("package_name") or "").replace(".", "/") + "/"
libs = ("android/", "androidx/", "kotlin/", "kotlinx/", "com/google/", "okhttp3/", "okio/", "retrofit2/",
        "io/reactivex/", "org/intellij/", "org/jetbrains/", "javax/", "j$/")
found = []
for dp, _, fns in os.walk(root, followlinks=False):
    for fn in fns:
        p = os.path.join(dp, fn)
        if fn.endswith((".java", ".kt")) and not os.path.islink(p):
            rel = os.path.relpath(p, root)
            found.append((0 if pkg != "/" and rel.startswith(pkg) else 2 if rel.startswith(libs) else 1, rel,
                          os.path.getsize(p)))
found.sort()
buf, kept, total = io.BytesIO(), 0, 0
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for _, rel, size in found:
        if kept >= MAX_FILES or size > MAX_FILE or total + size > MAX_TOTAL:
            continue
        z.write(os.path.join(root, rel), rel)
        kept, total = kept + 1, total + size
sys.stdout.write(json.dumps({"report": report, "sources_found": len(found),
                             "sources_zip": base64.b64encode(buf.getvalue()).decode()}))
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


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _meta(value: dict) -> dict:
    return value.get("metadata") if isinstance(value.get("metadata"), dict) else {}


def _ios_binary(report: dict) -> list:
    raw = _dict(report.get("binary_analysis"))
    raw = _dict(raw.get("findings")) or raw
    return [{"title": str(name)[:200], "severity": v.get("severity"),
             "description": str(v.get("detailed_desc") or v.get("description") or "")[:400],
             "cwe": v.get("cwe"), "owasp": v.get("owasp-mobile"), "masvs": v.get("masvs")}
            for name, v in raw.items() if isinstance(v, dict)]


def _ios_hardening(report: dict) -> list:
    return [{"title": str(name)[:100], "severity": v.get("severity"),
             "description": str(v.get("description") or "")[:400]}
            for name, v in _dict(report.get("macho_analysis")).items() if isinstance(v, dict)]


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
                                           "target_sdk", "main_activity", "md5", "sha256", "size",
                                           "bundle_id", "app_version", "min_os_version", "sdk_name",
                                           "platform", "app_type")},
        # iOS only: findings in the Mach-O binary, its hardening flags and App Transport Security.
        "binary_findings": _top(_ios_binary(report), key=lambda f: _rank(f["severity"])),
        "binary_hardening": _top(_ios_hardening(report), key=lambda f: _rank(f["severity"])),
        "ats_findings": [
            {"title": str(f.get("issue") or f.get("title") or "")[:200], "severity": f.get("severity"),
             "description": str(f.get("description") or "")[:400]}
            for f in _top(_dict(report.get("ats_analysis")).get("ats_findings"),
                          key=lambda f: _rank(f.get("severity") if isinstance(f, dict) else None))
            if isinstance(f, dict)
        ],
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
        "apkid": [
            {"file": name, "category": category, "values": values[:10] if isinstance(values, list) else values}
            for name, found in (report.get("apkid") if isinstance(report.get("apkid"), dict) else {}).items()
            if isinstance(found, dict)
            for category, values in found.items()
        ][:MAX_ITEMS],
        # Code-level behaviour and sensitive Android API use (from the JADX decompilation).
        "behaviour": _top(
            [{"id": rule, "label": _meta(v).get("label"), "description": str(_meta(v).get("description") or "")[:300],
              "files": len(v.get("files") or {})}
             for rule, v in _dict(report.get("behaviour")).items() if isinstance(v, dict)],
            key=lambda b: -b["files"]),
        "android_api": _top(
            [{"id": api, "description": str(_meta(v).get("description") or "")[:200], "files": len(v.get("files") or {})}
             for api, v in _dict(report.get("android_api")).items() if isinstance(v, dict)],
            key=lambda a: -a["files"]),
        "network_security": [
            {"scope": f.get("scope"), "severity": f.get("severity"), "description": str(f.get("description") or "")[:300]}
            for f in _top(_dict(report.get("network_security")).get("network_findings"), key=lambda f: _rank(
                f.get("severity") if isinstance(f, dict) else None))
            if isinstance(f, dict)
        ],
        "certificate": {
            "info": str(_dict(report.get("certificate_analysis")).get("certificate_info") or "")[:1500],
            "findings": [
                {"severity": f[0], "description": str(f[1])[:300], "title": f[2] if len(f) > 2 else None}
                for f in _dict(report.get("certificate_analysis")).get("certificate_findings") or []
                if isinstance(f, (list, tuple)) and len(f) >= 2
            ][:20],
        },
        "secrets_total": len(report.get("secrets") or []),
        "secrets": [str(x)[:200] for x in (report.get("secrets") or [])[:20]],
    }


def _stage(directory: Path, fmt: str = "apk") -> Path:
    """A copy MobSF's own (non-root) user can read; never executable."""
    target = directory / "mobsf-in"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir()
    staged = target / f"sample.{fmt}"  # MobSF picks the analyzer by the extension
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as out, (directory / "in" / "sample").open("rb") as src:
        shutil.copyfileobj(src, out, 1 << 20)
    # Explicit modes: the deep worker runs with UMask=0077, which would hide the file from MobSF's user.
    os.chmod(staged, 0o444)
    os.chmod(target, 0o711)
    return target


def _driver_args(settings) -> list[str]:
    return [str(int(settings.mobsf_timeout_s)), str(MAX_SOURCE_FILES), str(MAX_SOURCE_FILE_BYTES),
            str(MAX_SOURCE_TOTAL_BYTES)]


def _finish(doc: dict, directory: Path, stdout: bytes) -> None:
    if len(stdout) > MAX_REPORT_BYTES:
        doc["error"] = "MobSF report too large"
        return
    envelope = json.loads(stdout)
    report = envelope.get("report") if isinstance(envelope, dict) else None
    if not isinstance(report, dict):
        raise ValueError("report is not an object")
    doc.update(summarise(report))
    doc["sources"] = keep_sources(directory, envelope.get("sources_zip"), envelope.get("sources_found"),
                                  report.get("package_name"))


def scan(settings, analysis_id: str, directory: Path, runner=subprocess.run, fmt: str = "apk") -> dict:
    """In the static VM when [static] backend is "vm" (never falling back to dom0: a hostile app's parser
    bugs then hit a throwaway domU, not the host); otherwise in a dom0 container."""
    if fmt not in ("apk", "ipa"):
        raise ValueError(f"MobSF scans APK and IPA files, not {fmt}")
    if getattr(settings, "backend", "container") == "vm":
        return _scan_in_vm(settings, analysis_id, directory, fmt)
    return _scan_in_container(settings, analysis_id, directory, runner, fmt)


def _scan_in_vm(settings, analysis_id: str, directory: Path, fmt: str) -> dict:
    from .vm_backend import VmUnavailable, mobsf_in_vm

    started = time.time()
    doc = {"schema": SCHEMA, "image": settings.mobsf_image, "format": fmt, "backend": "vm", "error": None}
    try:
        got = mobsf_in_vm(settings, analysis_id, directory, fmt, DRIVER, _driver_args(settings),
                          secrets.token_hex(32))
        if got.get("error"):
            doc["error"] = str(got["error"])[:500]
        else:
            _finish(doc, directory, got["text"].encode())
    except VmUnavailable as exc:
        doc["error"] = f"static VM unavailable, MobSF not run: {str(exc)[:300]}"
    except (OSError, ValueError) as exc:
        doc["error"] = f"MobSF scan failed: {str(exc)[:300]}"
    doc["wall_s"] = round(time.time() - started, 2)
    return doc


def _scan_in_container(settings, analysis_id: str, directory: Path, runner, fmt: str) -> dict:
    started = time.time()
    doc = {"schema": SCHEMA, "image": settings.mobsf_image, "format": fmt, "backend": "container", "error": None}
    name = container_name(analysis_id)
    input_dir = None
    try:
        input_dir = _stage(directory, fmt)
        runner(build_run_command(settings, analysis_id, input_dir, secrets.token_hex(32)), check=True,
               capture_output=True, timeout=120)
        out = runner([settings.engine, "exec", name, "python3", "-c", DRIVER, f"/input/sample.{fmt}",
                      *_driver_args(settings)],
                     capture_output=True, timeout=settings.mobsf_timeout_s + 60)
        if out.returncode != 0:
            doc["error"] = (out.stderr or b"").decode(errors="replace").strip()[-500:] or "MobSF scan failed"
        else:
            _finish(doc, directory, out.stdout)
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


def keep_sources(directory: Path, encoded, found, package) -> dict:
    """Re-pack the container's decompiled sources into mobsf-sources.zip, keeping only plain, bounded entries.

    The archive comes from a container that just processed a hostile APK, so nothing in it is trusted: names
    must be relative Java/Kotlin paths, sizes are re-checked while reading, and nothing is ever extracted."""
    info = {"language": "java", "files": [], "found": found if isinstance(found, int) else None,
            "truncated": False, "package": package if isinstance(package, str) else None}
    target = directory / SOURCES_NAME
    target.unlink(missing_ok=True)
    try:
        raw = base64.b64decode(encoded or "", validate=True)
        src = zipfile.ZipFile(io.BytesIO(raw))
    except (binascii.Error, ValueError, zipfile.BadZipFile):
        info["error"] = "no decompiled sources"
        return info
    total = 0
    tmp = directory / (SOURCES_NAME + ".tmp")
    with src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as out:
        for entry in src.infolist():
            name = entry.filename
            if (len(info["files"]) >= MAX_SOURCE_FILES or entry.is_dir() or ".." in name.split("/")
                    or not SOURCE_PATH.fullmatch(name) or entry.file_size > MAX_SOURCE_FILE_BYTES
                    or total + entry.file_size > MAX_SOURCE_TOTAL_BYTES):
                info["truncated"] = True
                continue
            with src.open(entry) as fh:
                data = fh.read(MAX_SOURCE_FILE_BYTES + 1)
            if len(data) > MAX_SOURCE_FILE_BYTES:
                info["truncated"] = True
                continue
            out.writestr(name, data)
            total += len(data)
            info["files"].append({"path": name, "size": len(data),
                                  "app": bool(info["package"]) and name.startswith(info["package"].replace(".", "/") + "/")})
    os.replace(tmp, target)
    if isinstance(found, int) and found > len(info["files"]):
        info["truncated"] = True
    if any(f["path"].endswith(".kt") for f in info["files"]):
        info["language"] = "java+kotlin"
    return info


def read_source(analysis_id: str, path: str, base: Optional[Path] = None) -> Optional[str]:
    """One decompiled file, only if mobsf.json lists it; None otherwise."""
    from .worker import job_dir

    doc = load_mobsf(analysis_id, base)
    listed = {f.get("path") for f in ((doc or {}).get("sources") or {}).get("files") or []}
    if path not in listed or not SOURCE_PATH.fullmatch(path):
        return None
    try:
        with zipfile.ZipFile(job_dir(analysis_id, base) / SOURCES_NAME) as z, z.open(path) as fh:
            return fh.read(MAX_SOURCE_FILE_BYTES).decode("utf-8", errors="replace")
    except (OSError, KeyError, zipfile.BadZipFile):
        return None


def run_mobsf_job(analysis_id: str, base: Optional[str] = None) -> dict:
    """RQ job on the deep queue: scan, write mobsf.json beside static.json, refresh the report."""
    from .worker import STATIC_DIR, _refresh_report, _write_json, job_dir

    settings = load_config().static
    directory = job_dir(analysis_id, Path(base) if base else None)
    try:
        static = json.loads((directory / "static.json").read_text())
        fmt = (static.get("type") or {}).get("format")
    except (OSError, ValueError, AttributeError):
        fmt = None
    try:
        doc = scan(settings, analysis_id, directory, fmt="ipa" if fmt == "ipa" else "apk")
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
