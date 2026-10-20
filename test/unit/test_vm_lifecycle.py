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
    is_running = False

    def __init__(self, vm_id, install_info, network_conf):
        self.vm_id = vm_id

    def restore(self):
        FakeVM.calls.append("restore")
        raise RuntimeError("Failed to restore VM vm-1")

    def destroy(self):
        FakeVM.calls.append("destroy")


def test_failed_restore_is_still_cleaned_up(monkeypatch, tmp_path, base_config):
    from types import SimpleNamespace

    FakeVM.calls = []
    monkeypatch.setattr(run_tools, "VirtualMachine", FakeVM)
    monkeypatch.setattr(run_tools, "RUN_DIR", tmp_path)
    monkeypatch.setattr(run_tools, "load_config", lambda: base_config)
    monkeypatch.setattr("drakrun.lib.memory_admission.xen_free_memory_mb", lambda: 9999)
    with pytest.raises(RuntimeError, match="Failed to restore"):
        with run_tools.run_vm(1, SimpleNamespace(memory=5120), None):
            pass
    assert FakeVM.calls == ["restore", "destroy"]


def test_fast_singlestep_flag_is_switchable(monkeypatch):
    from types import SimpleNamespace

    import drakrun.lib.drakvuf_cmdline as cmdline

    monkeypatch.setattr(cmdline, "get_dll_cmdline_args", lambda _: [])
    common = dict(
        vm_name="vm-1",
        kernel_profile_path="/k.json",
        vmi_info=SimpleNamespace(vmi_offsets=SimpleNamespace(kpgd=0x1AA000)),
        drakvuf_version_info=None,
    )
    assert "-F" in cmdline.get_base_drakvuf_cmdline(**common)
    assert "-F" not in cmdline.get_base_drakvuf_cmdline(**common, fast_singlestep=False)


def _monitor(cpu_times, threshold_s=run_tools.VM_STALL_THRESHOLD_S):
    samples = iter(cpu_times)
    clock = {"now": 0.0}
    monitor = run_tools.StallMonitor(
        "vm-1",
        threshold_s=threshold_s,
        read_cpu_time=lambda name: next(samples),
        clock=lambda: clock["now"],
    )
    return monitor, clock


def test_stall_monitor_stops_drakvuf_once_when_guest_cpu_freezes():
    # Observed apimon hang: CPU time stops at 37.2 while DRAKVUF stays alive.
    monitor, clock = _monitor([30.0, 33.5, 37.2] + [37.2] * 10)
    stops = []
    monitor.on_stall = lambda: stops.append(clock["now"])
    for _ in range(13):
        monitor.sample()
        clock["now"] += 5
    assert monitor.stalled is True
    assert stops == [30.0]
    assert monitor.max_stall_s == 50.0


def test_stall_monitor_ignores_slow_progress_and_unreadable_samples():
    # A healthy guest gains CPU time at least every ~2 s (measured); here only
    # every 10 s, and xl sometimes fails.
    samples = [10.0 + 0.1 * (i // 2) if i % 7 else None for i in range(28)]
    monitor, clock = _monitor(samples)
    for _ in range(28):
        monitor.sample()
        clock["now"] += 5
    assert monitor.stalled is False
    assert monitor.max_stall_s < run_tools.VM_STALL_THRESHOLD_S


def test_xl_cpu_time_parses_time_column(monkeypatch):
    out = (
        "Name                                        ID   Mem VCPUs\tState\tTime(s)\n"
        "vm-1                                        62  5121     4     ------      37.2\n"
    )
    monkeypatch.setattr(
        run_tools.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=out, stderr=""),
    )
    assert run_tools.xl_cpu_time("vm-1") == 37.2
    monkeypatch.setattr(
        run_tools.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout="", stderr="no domain"),
    )
    assert run_tools.xl_cpu_time("vm-1") is None
