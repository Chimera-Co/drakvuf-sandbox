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
    "urls": [{"urls": ["http://c2.example/a", "http://c2.example/a"], "path": "x"}],
}


def stage(tmp_path):
    directory = tmp_path / AID
    (directory / "in").mkdir(parents=True)
    (directory / "in" / "sample").write_bytes(b"PK\x03\x04apk")
    return directory


def test_run_command_isolates_the_container(tmp_path):
    cmd = mobsf.build_run_command(StaticConfigSection(), AID, tmp_path, "k")
    joined = " ".join(cmd)
    assert "--network none" in joined and "--cap-drop ALL" in joined and "no-new-privileges" in joined
    assert f"{tmp_path}:/input:ro,noexec,nosuid,nodev" in cmd and cmd[-1].endswith(":v4.5.3")


def test_summary_orders_by_severity_and_bounds_text():
    doc = mobsf.summarise(REPORT)
    assert doc["security_score"] == 41 and doc["counts"]["high"] == 1 and doc["counts"]["secure"] == 1
    assert [f["severity"] for f in doc["findings"]] == ["high", "warning"]
    assert len(doc["findings"][0]["description"]) == 400
    assert doc["permissions"][0]["name"] == "android.permission.READ_SMS"  # dangerous first
    assert [f["id"] for f in doc["code_findings"]] == ["android_sql_raw", "android_logging"]
    assert doc["urls"] == ["http://c2.example/a"] and doc["domains"] == ["c2.example"]
    assert doc["trackers"] == [{"name": "Firebase", "categories": "Analytics"}]


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
            return SimpleNamespace(returncode=0, stdout=json.dumps(REPORT).encode(), stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    doc = mobsf.scan(StaticConfigSection(), AID, directory, runner=runner)
    assert doc["error"] is None and doc["app"]["package_name"] == "com.example.light"
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
