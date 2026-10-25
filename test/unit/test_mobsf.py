import json
import subprocess
from types import SimpleNamespace

from drakrun.analyzer.static import mobsf
from drakrun.lib.config import StaticConfigSection

AID = "8f14e45f-ceea-467a-9575-1c4b5d6e7f80"

REPORT = {
    "app_name": "Flashlight", "package_name": "com.example.light", "version_name": "1.2", "target_sdk": "33",
    "appsec": {"security_score": 41,
               "high": [{"title": "App can read SMS", "section": "permissions", "description": "x" * 900}],
               "warning": [{"title": "Cleartext traffic", "section": "manifest"}],
               "info": [], "secure": [{"title": "ok"}], "hotspot": []},
    "permissions": {"android.permission.CAMERA": {"status": "normal", "info": "camera", "description": "d"},
                    "android.permission.READ_SMS": {"status": "dangerous", "info": "read SMS", "description": "d"}},
    "code_analysis": {"findings": {
        "android_logging": {"files": {"a.java": "1"}, "metadata": {"severity": "info", "description": "logs"}},
        "android_sql_raw": {"files": {"b.java": "1", "c.java": "2"},
                            "metadata": {"severity": "warning", "cwe": "CWE-89", "masvs": "storage-14"}}}},
    "manifest_analysis": {"manifest_findings": [{"title": "Debuggable", "severity": "high"}]},
    "trackers": {"trackers": [{"name": "Firebase", "categories": "Analytics"}]},
    "malware_permissions": {"top_malware_permissions": ["android.permission.READ_SMS"],
                            "total_malware_permissions": 1},
    "domains": {"c2.example": {"bad": "no"}},
    "behaviour": {"00013": {"files": {"a.java": "1", "b.java": "2"},
                            "metadata": {"label": ["file"], "description": "Read file and put it into a stream"}}},
    "android_api": {"api_sms": {"files": {"a.java": "1"}, "metadata": {"description": "Send SMS"}}},
    "network_security": {"network_findings": [{"scope": ["*"], "severity": "warning", "description": "trusts user CAs"},
                                              {"scope": ["*"], "severity": "high", "description": "cleartext"}]},
    "certificate_analysis": {"certificate_info": "Binary is signed", "certificate_findings": [["high", "SHA1 used", "Weak hash"]]},
    "apkid": {"classes.dex": {"anti_vm": ["Build.FINGERPRINT check"], "compiler": ["r8"]}},
    "secrets": ["\"api_key\" : \"x\""],
    "urls": [{"urls": ["http://c2.example/a", "http://c2.example/a"], "path": "x"}],
}


def source_zip(entries):
    import base64
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return base64.b64encode(buf.getvalue()).decode()


def envelope(entries=None):
    entries = {"com/example/light/Main.java": "class Main {}"} if entries is None else entries
    return json.dumps({"report": REPORT, "sources_found": len(entries),
                       "sources_zip": source_zip(entries)}).encode()


def stage(tmp_path):
    directory = tmp_path / AID
    (directory / "in").mkdir(parents=True)
    (directory / "in" / "sample").write_bytes(b"PK\x03\x04apk")
    return directory


def test_run_command_isolates_the_container(tmp_path):
    cmd = mobsf.build_run_command(StaticConfigSection(), AID, tmp_path, "k")
    joined = " ".join(cmd)
    assert "--network none" in joined and "--cap-drop ALL" in joined and "no-new-privileges" in joined
    assert f"{tmp_path}:/input:ro,noexec,nosuid,nodev" in cmd and cmd[-1] == "localhost/chimera-mobsf:4.5.3"


def test_summary_orders_by_severity_and_bounds_text():
    doc = mobsf.summarise(REPORT)
    assert doc["security_score"] == 41 and doc["counts"]["high"] == 1 and doc["counts"]["secure"] == 1
    assert [f["severity"] for f in doc["findings"]] == ["high", "warning"]
    assert len(doc["findings"][0]["description"]) == 400
    assert doc["permissions"][0]["name"] == "android.permission.READ_SMS"  # dangerous first
    assert [f["id"] for f in doc["code_findings"]] == ["android_sql_raw", "android_logging"]
    assert doc["urls"] == ["http://c2.example/a"] and doc["domains"] == ["c2.example"]
    assert doc["trackers"] == [{"name": "Firebase", "categories": "Analytics"}]
    assert doc["behaviour"][0]["files"] == 2 and doc["android_api"][0]["id"] == "api_sms"
    assert [f["severity"] for f in doc["network_security"]] == ["high", "warning"]
    assert doc["certificate"]["findings"][0]["title"] == "Weak hash"
    assert {"file": "classes.dex", "category": "anti_vm", "values": ["Build.FINGERPRINT check"]} in doc["apkid"]
    assert doc["secrets_total"] == 1


def test_summary_survives_unexpected_shapes():
    doc = mobsf.summarise({"appsec": [], "permissions": ["x"], "code_analysis": None, "urls": ["http://a"]})
    assert doc["security_score"] is None and doc["permissions"] == [] and doc["urls"] == ["http://a"]


def test_scan_writes_summary_and_always_removes_container(tmp_path):
    directory = stage(tmp_path)
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd[:2])
        if cmd[1] == "exec":
            assert (directory / "mobsf-in" / "sample.apk").read_bytes() == b"PK\x03\x04apk"
            return SimpleNamespace(returncode=0, stdout=envelope(), stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    doc = mobsf.scan(StaticConfigSection(), AID, directory, runner=runner)
    assert doc["error"] is None and doc["app"]["package_name"] == "com.example.light"
    assert [f["path"] for f in doc["sources"]["files"]] == ["com/example/light/Main.java"]
    assert [c[1] for c in calls] == ["run", "exec", "rm"]
    assert not (directory / "mobsf-in").exists()


def test_scan_failure_is_recorded_not_raised(tmp_path):
    directory = stage(tmp_path)

    def runner(cmd, **kwargs):
        if cmd[1] == "run":
            raise subprocess.CalledProcessError(125, cmd, stderr=b"image not known")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    doc = mobsf.scan(StaticConfigSection(), AID, directory, runner=runner)
    assert "image not known" in doc["error"] and doc["schema"] == "chimera-mobsf/1"
    assert not (directory / "mobsf-in").exists()


def test_staged_copy_is_readable_by_mobsf_whatever_the_umask(tmp_path):
    import os
    import stat

    directory = stage(tmp_path)
    old = os.umask(0o077)
    try:
        target = mobsf._stage(directory)
    finally:
        os.umask(old)
    assert stat.S_IMODE((target / "sample.apk").stat().st_mode) == 0o444
    assert stat.S_IMODE(target.stat().st_mode) == 0o711


def test_only_plain_bounded_source_paths_are_kept_and_served(tmp_path, monkeypatch):
    directory = tmp_path / AID
    directory.mkdir()
    info = mobsf.keep_sources(directory, source_zip({
        "com/example/light/Main.java": "class Main { int x = 1; }",
        "../../etc/evil.java": "x",
        "/abs/Root.java": "x",
        "com/example/light/notes.txt": "x",
        "okhttp3/Call.kt": "fun call() {}",
        "big/Huge.java": "x" * (mobsf.MAX_SOURCE_FILE_BYTES + 1),
    }), 6, "com.example.light")
    assert [f["path"] for f in info["files"]] == ["com/example/light/Main.java", "okhttp3/Call.kt"]
    assert info["files"][0]["app"] and not info["files"][1]["app"]
    assert info["truncated"] and info["language"] == "java+kotlin"
    (directory / "mobsf.json").write_text(json.dumps({"schema": mobsf.SCHEMA, "sources": info}))
    monkeypatch.setattr("drakrun.analyzer.static.worker.job_dir", lambda aid, base=None: directory)
    assert "int x = 1" in mobsf.read_source(AID, "com/example/light/Main.java")
    assert mobsf.read_source(AID, "../../etc/evil.java") is None
    assert mobsf.read_source(AID, "big/Huge.java") is None


def test_missing_or_bad_sources_do_not_fail_the_scan(tmp_path):
    info = mobsf.keep_sources(tmp_path, "not base64!", None, None)
    assert info["files"] == [] and info["error"]


def test_ios_report_is_summarised():
    doc = mobsf.summarise({
        "app_name": "Notes", "bundle_id": "com.example.notes", "min_os_version": "15.0",
        "appsec": {"security_score": 55, "high": [], "warning": [{"title": "ATS off", "section": "ats"}]},
        "binary_analysis": {"findings": {"Uses insecure API memcpy": {"severity": "warning", "detailed_desc": "memcpy",
                                                                       "cwe": "CWE-676"}}},
        "macho_analysis": {"pie": {"severity": "info", "description": "PIE on"},
                           "stack_canary": {"severity": "high", "description": "no canary"}},
        "ats_analysis": {"ats_findings": [{"issue": "Arbitrary loads allowed", "severity": "high",
                                           "description": "NSAllowsArbitraryLoads"}]},
        "permissions": {"NSCameraUsageDescription": {"status": "dangerous", "info": "camera", "description": "d"}},
    })
    assert doc["app"]["bundle_id"] == "com.example.notes" and doc["security_score"] == 55
    assert doc["binary_findings"][0]["cwe"] == "CWE-676"
    assert [h["title"] for h in doc["binary_hardening"]] == ["stack_canary", "pie"]
    assert doc["ats_findings"][0]["title"] == "Arbitrary loads allowed"


def test_vm_backend_runs_mobsf_in_the_static_vm_only(tmp_path, monkeypatch):
    from drakrun.analyzer.static import vm_backend

    directory = stage(tmp_path)
    settings = StaticConfigSection(backend="vm")
    sent = {}

    def run_job(settings_, steps, sample, uid=None):
        sent.update(steps=steps, sample=sample, uid=uid)
        return {"steps": [{"exit_code": 0, "stderr": "", "files": {"mobsf-out/mobsf.json": envelope().decode()}}]}

    monkeypatch.setattr(vm_backend, "run_job", run_job)
    host = []
    doc = mobsf.scan(settings, AID, directory, runner=lambda *a, **k: host.append(a), fmt="apk")
    assert not host, "nothing may run on the host"
    assert doc["error"] is None and doc["backend"] == "vm" and doc["security_score"] == 41
    assert doc["sources"]["files"][0]["path"] == "com/example/light/Main.java"
    argv = sent["steps"][0]["argv"]
    assert argv[0] == "podman" and sent["uid"] == mobsf.MOBSF_UID
    for flag in (["--network", "none"], ["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"]):
        assert any(argv[i:i + 2] == flag for i in range(len(argv)))
    assert "/work/job/in:/input:ro,noexec,nosuid,nodev" in argv and argv[-1] == "sample.apk"


def test_vm_unavailable_fails_closed(tmp_path, monkeypatch):
    from drakrun.analyzer.static import vm_backend

    def run_job(*a, **k):
        raise vm_backend.VmUnavailable("static VM chimera-static is not ready")

    monkeypatch.setattr(vm_backend, "run_job", run_job)
    host = []
    doc = mobsf.scan(StaticConfigSection(backend="vm", vm_fallback_container=True), AID, stage(tmp_path),
                     runner=lambda *a, **k: host.append(a))
    assert not host and "not run" in doc["error"]
