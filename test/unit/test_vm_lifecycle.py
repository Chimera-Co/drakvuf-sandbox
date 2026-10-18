"""
VM lifecycle reliability: stuck qemu device models, restore-failure cleanup and
the per-VM lock (see docs/chimera/containment-results-2026-10-19.md, finding R6).
"""

import signal
import subprocess

import pytest

from drakrun.analyzer import run_tools
from drakrun.lib import xen

DOM0_DISK_BACKEND = ["/usr/local/lib/xen/bin/qemu-system-i386", "-xen-domid", "0", "-xen-attach"]


def qemu(domid):
    return ["/usr/local/lib/xen/bin/qemu-system-i386", "-xen-domid", str(domid), "-no-shutdown"]


@pytest.fixture
def fake_procs(monkeypatch):
    procs = {}
    monkeypatch.setattr(xen, "_iter_process_cmdlines", lambda: list(procs.items()))
    return procs


@pytest.fixture
def fake_kill(monkeypatch, fake_procs):
    """os.kill stand-in: SIGKILL removes the process, other signals are ignored (stuck qemu)."""
    sent = []

    def kill(pid, sig):
        if pid not in fake_procs:
            raise ProcessLookupError(pid)
        if sig == signal.SIGKILL:
            sent.append(pid)
            del fake_procs[pid]

    monkeypatch.setattr(xen.os, "kill", kill)
    monkeypatch.setattr(xen.time, "sleep", lambda _: None)
    return sent


def test_find_device_models_maps_pid_to_domid(fake_procs):
    fake_procs.update({856: DOM0_DISK_BACKEND, 74797: qemu(7), 100: ["/usr/bin/python3", "-xen-domid", "9"]})
    assert xen.find_device_models() == {856: 0, 74797: 7}


def test_reap_kills_stuck_device_model_but_never_dom0(fake_procs, fake_kill):
    fake_procs.update({856: DOM0_DISK_BACKEND, 74797: qemu(7)})
    assert xen.reap_device_models(7, grace=0) == [74797]
    assert fake_kill == [74797]
    assert 856 in fake_procs
    assert xen.reap_device_models(0, grace=0) == []
    assert 856 in fake_procs


def test_reap_is_noop_when_device_model_already_exited(fake_procs, fake_kill):
    fake_procs.update({856: DOM0_DISK_BACKEND})
    assert xen.reap_device_models(7, grace=0) == []
    assert fake_kill == []


XL_LIST = """Name                                        ID   Mem VCPUs\tState\tTime(s)
Domain-0                                     0 10240     8     r-----    3433.2
vm-2                                         9  4096     2     r-----       3.0
(null)                                       7    18     2     --p--d      78.5
"""


def test_xen_list_domains_parses_dying_null_domain(monkeypatch):
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: XL_LIST)
    domains = xen.xen_list_domains()
    assert domains[7] == ("(null)", "--p--d")
    assert domains[9] == ("vm-2", "r-----")


def test_reap_orphans_spares_live_domains(monkeypatch, fake_procs, fake_kill):
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: XL_LIST)
    # 7 is dying, 9 is live, 11 no longer exists at all
    fake_procs.update({856: DOM0_DISK_BACKEND, 1: qemu(7), 2: qemu(9), 3: qemu(11)})
    assert sorted(xen.reap_orphaned_device_models()) == [1, 3]
    assert set(fake_procs) == {856, 2}


def test_vm_lock_is_exclusive_and_released(tmp_path):
    with run_tools.vm_lock(1, lock_dir=tmp_path):
        with pytest.raises(RuntimeError, match="already in use"):
            with run_tools.vm_lock(1, lock_dir=tmp_path):
                pass
        # a different VM is independent
        with run_tools.vm_lock(2, lock_dir=tmp_path):
            pass
    with run_tools.vm_lock(1, lock_dir=tmp_path):
        pass


class FakeVM:
    calls = []

    def __init__(self, vm_id, install_info, network_conf):
        self.vm_id = vm_id

    def restore(self):
        FakeVM.calls.append("restore")
        raise RuntimeError("Failed to restore VM vm-1")

    def destroy(self):
        FakeVM.calls.append("destroy")


def test_failed_restore_is_still_cleaned_up(monkeypatch, tmp_path):
    FakeVM.calls = []
    monkeypatch.setattr(run_tools, "VirtualMachine", FakeVM)
    monkeypatch.setattr(run_tools, "RUN_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="Failed to restore"):
        with run_tools.run_vm(1, None, None):
            pass
    assert FakeVM.calls == ["restore", "destroy"]
