"""Linux checklist schema, adapter/scoring, and serial session tests (no Xen)."""

import base64
import hashlib
import importlib.util
import json
import shlex
import time
from pathlib import Path

import pytest

from drakrun.evasion.constants import CheckStatus, ToolStatus
from drakrun.evasion.linux_guest_runner import READ_CHUNK_BYTES, LinuxGuestSession
from drakrun.evasion.scoring import compute_score
from drakrun.evasion.verifiers.base import (
    MAX_REPORT_BYTES,
    ReportTooLarge,
    VerifierTimeout,
)
from drakrun.evasion.verifiers.linux_vmcheck import LinuxVmcheckAdapter

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "drakrun/data/linux/chimera-vmcheck.py"
)
spec = importlib.util.spec_from_file_location("chimera_vmcheck", SCRIPT)
vmcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vmcheck)


def raw_report(status="ok"):
    return {
        "tool": "chimera-vmcheck",
        "version": "1.0",
        "total": 2,
        "detected": 1,
        "checks": [
            {
                "id": "cpu.hypervisor_flag",
                "category": "cpu",
                "detected": True,
                "evidence": {"hypervisor_flag": True},
                "technique": "CPUID flag",
                "status": "ok",
            },
            {
                "id": "activity.desktop_session",
                "category": "activity",
                "detected": False,
                "evidence": {},
                "technique": "Desktop session",
                "status": status,
            },
        ],
    }


@pytest.fixture
def guest_tree(tmp_path):
    files = {
        "proc/cpuinfo": "processor : 0\nflags : hypervisor sse\n",
        "proc/meminfo": "MemTotal: 1048576 kB\n",
        "proc/modules": "xen_netfront 123 0 - Live 0\nkvm_intel 123 0 - Live 0\n",
        "proc/uptime": "30.00 20.00\n",
        "proc/self/status": "TracerPid:\t0\n",
        "proc/sys/kernel/hostname": "chimera-test",
        "proc/consoles": "ttyS0 -W- (EC p a) 4:64\n",
        "proc/1/cmdline": "python3\0/opt/chimera/chimera-agent.py\0",
        "proc/2/cmdline": "xfce4-session\0",
        "etc/passwd": "root:x:0:0::/root:/bin/bash\nanalyst:x:1000:1000::/home/analyst:/bin/bash\n",
        "sys/hypervisor/type": "xen",
        "proc/xen/capabilities": "",
        "sys/class/net/eth0/address": "00:16:3e:12:34:56",
        "sys/block/xvda/device/model": "QEMU HARDDISK",
        "sys/block/xvda/device/vendor": "Xen",
        "sys/block/xvda/size": "83886080",
        "sys/bus/pci/devices/0000:00:01.0/vendor": "0x5853",
        "sys/devices/system/clocksource/clocksource0/current_clocksource": "xen",
        "usr/bin/strace": "",
        "home/analyst/.bash_history": "private contents must not appear",
    }
    for field in (
        "sys_vendor",
        "product_name",
        "bios_vendor",
        "board_vendor",
        "chassis_vendor",
        "product_serial",
    ):
        files["sys/class/dmi/id/" + field] = "Xen HVM domU"
    for name, data in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
    return tmp_path


def fake_command(argv):
    if argv[0] == "lscpu":
        return 0, "Hypervisor vendor: Xen", ""
    if argv[0] == "dmesg":
        return 0, "Hypervisor detected: Xen HVM", ""
    if argv[0] in ("systemd-detect-virt", "virt-what"):
        return 0, "xen", ""
    if argv[0] == "who":
        return 0, "analyst tty7 2026-01-01 00:00", ""
    if argv[0] == "python3":
        return 0, '{"rc": 0, "errno": 0}', ""
    raise AssertionError(argv)


def test_checker_schema_and_xen_evidence(guest_tree):
    report = vmcheck.Checker(guest_tree, command=fake_command, environ={}).report()
    assert report["tool"] == "chimera-vmcheck"
    assert report["total"] == len(report["checks"]) >= 32
    assert report["detected"] == sum(c["detected"] for c in report["checks"])
    assert len({c["id"] for c in report["checks"]}) == report["total"]
    for check in report["checks"]:
        assert {"id", "category", "detected", "evidence", "technique"} <= check.keys()
        assert type(check["detected"]) is bool
    by_id = {c["id"]: c for c in report["checks"]}
    for ident in (
        "cpu.hypervisor_flag",
        "cpu.hypervisor_vendor",
        "hypervisor.sysfs",
        "hypervisor.proc_xen",
        "kernel.vm_modules",
        "dmi.product_name",
        "devices.mac_oui",
        "devices.disk_identity",
        "devices.pci_vendor",
        "kernel.clocksource",
        "kernel.hypervisor_log",
        "sandbox.agent_processes",
        "sandbox.serial_console",
    ):
        assert by_id[ident]["detected"], ident
    assert not by_id["activity.desktop_session"]["detected"]
    assert not by_id["activity.logged_in"]["detected"]
    assert not by_id["activity.shell_history"]["detected"]
    assert "private contents" not in json.dumps(report)
    assert len(LinuxVmcheckAdapter()._normalize(report)) == report["total"]


def test_missing_tools_and_permission_denied_are_skipped(guest_tree):
    def unavailable(argv):
        if argv[0] in ("virt-what", "systemd-detect-virt"):
            raise FileNotFoundError(argv[0])
        if argv[0] in ("dmesg", "journalctl"):
            return 1, "", "Permission denied"
        return fake_command(argv)

    (guest_tree / "sys/class/dmi/id/product_serial").unlink()
    report = vmcheck.Checker(guest_tree, command=unavailable, environ={}).report()
    by_id = {c["id"]: c for c in report["checks"]}
    for ident in (
        "utilities.virt_what",
        "utilities.systemd_detect_virt",
        "kernel_log.unavailable",
        "dmi.product_serial",
    ):
        assert by_id[ident]["status"] == "skipped"
        assert by_id[ident]["detected"] is False
    normalized = LinuxVmcheckAdapter()._normalize(report)
    assert (
        next(c for c in normalized if c.id == "utilities.virt_what").status
        == CheckStatus.skipped
    )


def test_empty_fixture_does_not_probe_host(tmp_path):
    report = vmcheck.Checker(
        tmp_path,
        command=lambda argv: (_ for _ in ()).throw(FileNotFoundError()),
        environ={},
    ).report()
    assert any(c["status"] == "skipped" for c in report["checks"])
    assert all(
        c["detected"] is False for c in report["checks"] if c["status"] == "skipped"
    )
    LinuxVmcheckAdapter()._normalize(report)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(total=999),
        lambda r: r.update(detected=0),
        lambda r: r["checks"][0].update(detected="false"),
        lambda r: r["checks"][1].update(id=r["checks"][0]["id"]),
        lambda r: r["checks"][0].update(status="skipped"),
        lambda r: r["checks"][0].update(category="unknown"),
    ],
)
def test_verifier_rejects_invalid_report(mutate):
    report = raw_report()
    mutate(report)
    with pytest.raises(ValueError):
        LinuxVmcheckAdapter()._normalize(report)


def test_linux_scoring_and_insufficient_coverage():
    from drakrun.evasion.models import ToolResult

    adapter = LinuxVmcheckAdapter()
    result = ToolResult(
        tool=adapter.id, status=ToolStatus.ok, checks=adapter._normalize(raw_report())
    )
    score = compute_score([result])
    assert score.primary_tool == "chimera-vmcheck"
    assert score.chimera_score == 67.5
    assert score.state == "fail"
    assert score.per_category["environment_artifact"] == 35.0
    result.checks[0].status = CheckStatus.skipped
    result.checks[1].status = CheckStatus.skipped
    assert compute_score([result]).state == "incomplete"
    assert compute_score([result]).chimera_score is None


@pytest.mark.parametrize("mode", ["ok", "timeout", "bad-json", "nonzero", "missing"])
def test_verifier_run_preserves_raw_and_errors(tmp_path, mode):
    from fake_guest_session import FakeGuestSession

    session = FakeGuestSession(
        run_result=(1 if mode == "nonzero" else 0, b"stdout", b"stderr"),
        files=(
            {}
            if mode == "missing"
            else {
                "/var/lib/console-helper/linux-report.json": (
                    b"{" if mode == "bad-json" else json.dumps(raw_report()).encode()
                )
            }
        ),
        raise_on_run=VerifierTimeout("deadline") if mode == "timeout" else None,
    )
    result = LinuxVmcheckAdapter().run(session, {}, tmp_path, time.time() + 10)
    assert result.status == (
        ToolStatus.ok
        if mode == "ok"
        else ToolStatus.timeout if mode == "timeout" else ToolStatus.error
    )
    assert session.put_file_calls[0][0] == SCRIPT
    assert session.run_calls[0][0][:2] == [
        "python3",
        "/home/arjun/Downloads/vmcheck.py",
    ]
    if mode not in ("missing", "timeout"):
        assert "raw/chimera-vmcheck/linux-report.json" in result.raw_artifacts
    if mode == "ok":
        assert compute_score([result]).chimera_score == 67.5


class FakeAgent:
    def __init__(self, files=None):
        self.files = files or {}
        self.calls = []
        self.truncate = False
        self.bad_hash = False

    def call(self, command, args=None, timeout=30):
        self.calls.append((command, args, timeout))
        if command == "stat":
            data = self.files[args["path"]]
            return {
                "size": len(data),
                "sha256": "bad" if self.bad_hash else hashlib.sha256(data).hexdigest(),
            }
        if command == "exec":
            argv, cwd, seconds, base = json.loads(args["argv"][-1])
            self.files[base + ".out"] = b"hello"
            self.files[base + ".err"] = b""
            self.files[base + ".done"] = b'{"rc":0,"timeout":false}'
            return {"pid": 123}
        assert command == "sh"
        cmd = args["cmd"]
        if cmd.startswith("if test"):
            tokens = shlex.split(cmd)
            path = tokens[3].rstrip(";")
            return {"rc": 0, "stdout": self.files[path].decode(), "stderr": ""}
        argv = shlex.split(cmd)
        if argv[:2] == ["python3", "-c"]:
            path, offset, count = argv[-3:]
            data = self.files[path][int(offset) : int(offset) + int(count)]
            out = base64.b64encode(data).decode()
            return {"rc": 0, "stdout": out[:-4] if self.truncate else out, "stderr": ""}
        assert cmd.startswith("mkdir -p -- ")
        return {"rc": 0, "stdout": "", "stderr": ""}


def session_for(agent, uploader=None):
    return LinuxGuestSession(
        "vm-2", Path("kernel.json"), agent, {"pid": 42}, uploader=uploader
    )


def test_session_chunked_binary_report_and_quoted_path(tmp_path):
    data = bytes(range(256)) * 1000
    remote = "/tmp/report 'quoted' $(never).json"
    agent = FakeAgent({remote: data})
    local = tmp_path / "report"
    session_for(agent).get_file(remote, local)
    assert local.read_bytes() == data
    chunks = [call for call in agent.calls if call[0] == "sh"]
    assert len(chunks) == (len(data) + READ_CHUNK_BYTES - 1) // READ_CHUNK_BYTES
    assert all(
        int(shlex.split(call[1]["cmd"])[-1]) <= READ_CHUNK_BYTES for call in chunks
    )


@pytest.mark.parametrize("failure", ["truncate", "bad_hash", "too_large"])
def test_session_rejects_corrupt_or_oversize_report(tmp_path, failure):
    agent = FakeAgent({"/report": b"abcde" * 100})
    if failure == "too_large":
        agent.call = lambda *a, **kw: {"size": MAX_REPORT_BYTES + 1}
    else:
        setattr(agent, failure, True)
    with pytest.raises((RuntimeError, ReportTooLarge)):
        session_for(agent).get_file("/report", tmp_path / "result")
    assert not (tmp_path / "result").exists()


def test_session_upload_reuses_injector_and_verifies_hash(tmp_path):
    path = tmp_path / "checker.py"
    path.write_bytes(b"print('check')")
    agent = FakeAgent()
    uploads = []

    def uploader(vm, kernel, pid, local, remote):
        uploads.append((vm, kernel, pid, local, remote))
        agent.files[remote] = local.read_bytes()

    session = session_for(agent, uploader)
    session.put_file(path, "/work/checker.py")
    assert uploads == [("vm-2", Path("kernel.json"), 42, path, "/work/checker.py")]
    session.drakvuf_attached = True
    with pytest.raises(RuntimeError, match="DRAKVUF"):
        session.put_file(path, "/work/checker.py")


def test_session_exec_polls_completion_and_collects_output():
    agent = FakeAgent()
    result = session_for(agent).run(["python3", "/check.py"], timeout=2, cwd="/work")
    assert tuple(result) == (0, b"hello", b"")
    launched = next(args for command, args, timeout in agent.calls if command == "exec")
    assert json.loads(launched["argv"][-1])[:3] == [
        ["python3", "/check.py"],
        "/work",
        2,
    ]
    with pytest.raises(VerifierTimeout):
        session_for(agent).run(["python3"], timeout=0)


@pytest.mark.parametrize("timeout", [False, True])
def test_guest_runner_enforces_child_deadline(tmp_path, timeout):
    import subprocess
    import sys
    from drakrun.evasion.linux_guest_runner import _RUNNER

    base = str(tmp_path / "command")
    argv = [
        sys.executable,
        "-c",
        "import time; time.sleep(10)" if timeout else "print('finished')",
    ]
    subprocess.run(
        [
            sys.executable,
            "-c",
            _RUNNER,
            json.dumps([argv, str(tmp_path), 0.1 if timeout else 5, base]),
        ],
        check=True,
        timeout=10,
    )
    done = json.loads(Path(base + ".done").read_text())
    assert done["timeout"] is timeout
    assert done["rc"] == (-9 if timeout else 0)
    if not timeout:
        assert Path(base + ".out").read_bytes() == b"finished\n"


@pytest.mark.parametrize(
    "bookmarks,detected", [("", True), ('<bookmark href="file:///private"/>', False)]
)
def test_recent_files_require_xbel_bookmarks(guest_tree, bookmarks, detected):
    path = guest_tree / "home/analyst/.local/share/recently-used.xbel"
    path.parent.mkdir(parents=True)
    path.write_text(f"<xbel>{bookmarks}</xbel>")
    results = list(vmcheck.Checker(guest_tree, command=fake_command).check_desktop())
    check = next(c for c in results if c[0] == "activity.recent_files")
    assert check[3] is detected
    assert "file:///private" not in json.dumps(check)


def test_guest_runner_launch_error_publishes_nonzero_result(tmp_path):
    import subprocess
    import sys
    from drakrun.evasion.linux_guest_runner import _RUNNER

    base = str(tmp_path / "missing")
    subprocess.run(
        [
            sys.executable,
            "-c",
            _RUNNER,
            json.dumps([[str(tmp_path / "absent")], str(tmp_path), 5, base]),
        ],
        check=True,
        timeout=10,
    )
    result = json.loads(Path(base + ".done").read_text())
    assert result == {"rc": 127, "timeout": False}
    assert b"No such file" in Path(base + ".err").read_bytes()


def test_session_pauses_cpuid_hiding_for_injector_uploads(monkeypatch, tmp_path):
    from drakrun.evasion import linux_guest_runner
    from drakrun.lib import cpuid_hide

    events = []
    monkeypatch.setattr(cpuid_hide, "available", lambda: True)
    monkeypatch.setattr(
        cpuid_hide, "attach", lambda vm: events.append(("attach", vm)) or object()
    )
    monkeypatch.setattr(cpuid_hide, "detach", lambda p: events.append(("detach",)))

    payload = tmp_path / "check.py"
    payload.write_bytes(b"print(1)\n")
    digest = __import__("hashlib").sha256(payload.read_bytes()).hexdigest()

    class Agent:
        def call(self, op, args=None, timeout=None):
            if op == "stat":
                return {"size": payload.stat().st_size, "sha256": digest}
            if op == "sh":
                return {"rc": 0, "stdout": ""}
            raise AssertionError(op)

        def close(self):
            events.append(("close",))

    session = linux_guest_runner.LinuxGuestSession(
        "vm-1",
        tmp_path / "kernel.json",
        Agent(),
        {"pid": 1},
        uploader=lambda *a: events.append(("upload",)),
        hide_cpuid=True,
    )
    session._hide()
    session.put_file(payload, "/home/arjun/Downloads/check.py")
    session._hide()
    session.close()
    assert events == [
        ("attach", "vm-1"),
        ("detach",),
        ("upload",),
        ("attach", "vm-1"),
        ("detach",),
        ("close",),
    ]
