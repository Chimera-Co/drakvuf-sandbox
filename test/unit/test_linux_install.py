"""drakrun install / postinstall / modify-vm0 / make-profile with --guest-os linux."""

import json
import pathlib

import pytest
from click.testing import CliRunner

from drakrun.cli import install as install_cli
from drakrun.cli import make_profile as make_profile_cli
from drakrun.cli import modify_vm0 as modify_vm0_cli
from drakrun.cli import postinstall as postinstall_cli
from drakrun.lib import linux_install


@pytest.fixture(autouse=True)
def as_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


@pytest.fixture
def config(monkeypatch):
    class Config:
        network = object()

    for module in (install_cli, postinstall_cli, modify_vm0_cli):
        monkeypatch.setattr(module, "load_config", lambda: Config)
    return Config


class FakeAgent:
    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def call(self, command, args=None, timeout=30):
        self.calls.append((command, args))
        return {"rc": 0, "stdout": self.stdout, "stderr": ""}


def test_prepare_for_snapshot_cleans_and_reports_kernel():
    agent = FakeAgent("cron.service loaded failed failed\n6.1.0-54-amd64\n")
    state = linux_install.prepare_for_snapshot(agent)
    assert state == {"kernel": "6.1.0-54-amd64", "failed_units": ["cron.service loaded failed failed"]}
    command = agent.calls[0][1]["cmd"]
    assert "rm -rf /var/lib/console-helper/*" in command and "journalctl --vacuum-time" in command


def test_install_linux_uses_linux_defaults(tmp_path, monkeypatch, config):
    calls = {}
    monkeypatch.setattr(install_cli, "sanity_check", lambda: None)
    monkeypatch.setattr(install_cli, "make_dirs", lambda: None)
    monkeypatch.setattr(install_cli, "initialize_config_files", lambda: None)
    monkeypatch.setattr(install_cli, "banner", lambda text: calls.setdefault("banner", text))

    class Info:
        vcpus, memory, vnc_passwd = 4, 4096, "x"

    def fake_install(source, network, **kwargs):
        calls["install"] = (source, network, kwargs)
        return Info

    monkeypatch.setattr(linux_install, "install_linux", fake_install)
    image = tmp_path / "debian.qcow2"
    image.write_bytes(b"")
    result = CliRunner().invoke(install_cli.install, ["--guest-os", "linux", str(image)])
    assert result.exit_code == 0, result.output
    source, network, kwargs = calls["install"]
    assert source == image and network is config.network
    assert kwargs == dict(vcpus=4, memory=4096, disk_size="128G", profile="desktop", built_image=None)
    assert "postinstall --guest-os linux" in calls["banner"]


def test_postinstall_linux_routes(monkeypatch, config):
    seen = []
    monkeypatch.setattr(linux_install, "postinstall_linux", lambda network, settle: seen.append(settle) or {})
    result = CliRunner().invoke(postinstall_cli.postinstall, ["--guest-os", "linux", "--settle", "5"])
    assert result.exit_code == 0, result.output
    assert seen == [5]


@pytest.mark.parametrize("action,function", [("commit", "commit_modify"), ("rollback", "rollback_modify")])
def test_modify_vm0_linux_routes(monkeypatch, config, action, function):
    seen = []
    monkeypatch.setattr(linux_install, function, lambda network: seen.append(network) or {})
    result = CliRunner().invoke(modify_vm0_cli.modify_vm0, [action, "--guest-os", "linux"])
    assert result.exit_code == 0, result.output
    assert seen == [config.network]


def test_make_profile_linux_requires_debug_package():
    result = CliRunner().invoke(make_profile_cli.make_profile, ["--guest-os", "linux"])
    assert result.exit_code != 0
    assert "--debug-package" in result.output


def test_make_linux_profile_flattens_iov_iter(tmp_path, monkeypatch):
    monkeypatch.setattr(linux_install, "LINUX_GOLDEN_DIR", tmp_path)
    profile = {"user_types": {
        "iov_iter": {"fields": {
            "count": {"offset": 8, "type": {"kind": "base", "name": "long"}},
            "": {"offset": 16, "anonymous": True, "type": {"kind": "union", "name": "unnamed_1"}},
        }},
        "unnamed_1": {"fields": {"iov": {"offset": 0, "type": {"kind": "pointer"}}}},
    }}

    def fake_run(argv, stdout=None, check=False):
        if argv[0] == "dpkg-deb":
            debug = pathlib.Path(argv[3]) / "usr/lib/debug/boot"
            debug.mkdir(parents=True)
            (debug / "vmlinux-6.1.0-54-amd64").write_bytes(b"")
        else:
            stdout.write(json.dumps(profile).encode())

    monkeypatch.setattr(linux_install.subprocess, "run", fake_run)
    target = linux_install.make_linux_profile(tmp_path / "dbg.deb")
    fields = json.loads(target.read_text())["user_types"]["iov_iter"]["fields"]
    assert fields["iov"]["offset"] == 16
    assert (tmp_path / "kernel.orig.json").exists()


def test_wait_for_vm_network_renews_a_stale_snapshot_address(monkeypatch):
    from drakrun.lib import linux_agent

    monkeypatch.setattr(linux_agent.time, "sleep", lambda s: None)
    replies = iter([
        {"addr": {"lo": ["127.0.0.1"], "ens3": ["10.13.0.2"]}},
        {"addr": {"lo": ["127.0.0.1"], "ens3": []}},
        {"addr": {"lo": ["127.0.0.1"], "ens3": ["10.13.1.2"]}},
    ])
    calls = []

    class Agent:
        def call(self, op, args=None, timeout=None):
            calls.append(op)
            return next(replies) if op == "net" else {"rc": 0, "stdout": ""}

    result = linux_agent.wait_for_vm_network(Agent(), 1)
    assert result["ready"] and result["renewed"]
    assert calls == ["net", "sh", "net", "net"]
