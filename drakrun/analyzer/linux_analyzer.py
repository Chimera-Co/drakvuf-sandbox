"""Analysis of a Linux ELF sample in the Linux guest (Debian 12, see docs/chimera/linux-sandbox.md).

Same output layout and metadata as the Windows analyzer (drakmon.log, inject.log, dump.pcap,
telemetry, guest_clock), so postprocessing and the portal work unchanged. Differences:
  - the guest is driven by chimera-agent over the serial port instead of drakshell
  - the sample is uploaded with the DRAKVUF injector (Linux writefile, the agent is the target)
  - DRAKVUF is started first and the agent launches the sample only after a marker command
    shows up in procmon, so the sample's first events are not lost
"""
import json
import logging
import pathlib
import re
import secrets
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from drakrun.lib.config import NetworkConfigSection, load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.linux_agent import LinuxAgent, set_guest_clock
from drakrun.lib.linux_install import (  # noqa: F401
    DESKTOP_USER,
    GUEST_WORK_DIR,
    LINUX_GOLDEN_DIR,
    LINUX_INSTALL_INFO_PATH,
)
from drakrun.lib.paths import PACKAGE_DATA_PATH

from .analysis_metadata import AnalysisMetadata
from .postprocessing import postprocess_analysis_dir
from .run_tools import (
    StallMonitor,
    log_activity_watchdog,
    process_graceful_exit,
    run_screenshotter,
    run_tcpdump,
    run_vm,
)
from .telemetry import summarize_telemetry

log = logging.getLogger(__name__)

# DRAKVUF plugins with a Linux implementation that produce analysis telemetry
# (drakvuf/src/plugins/plugins.h, drakvuf_plugin_os_support)
LINUX_PLUGINS = {
    "procmon", "syscalls", "filetracer", "unixsocketmon", "ptracemon", "ebpfmon",
    "rebootmon", "cpuidmon", "debugmon", "procdump2",
}
DEFAULT_LINUX_PLUGINS = ["procmon", "syscalls", "filetracer", "unixsocketmon", "ptracemon", "ebpfmon"]
# Linux plugins outside the default set that a request may add
OPTIONAL_LINUX_PLUGINS = ["cpuidmon", "rebootmon", "debugmon", "procdump2"]
READY_TIMEOUT_S = 30
# Desktop session of the guest (data/linux/desktop.sh): the sample gets its display, so GUI programs
# can draw and are seen in the live view and screenshots
SAMPLE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "en_IN.UTF-8",
    "DISPLAY": ":0",
    "XAUTHORITY": f"/home/{DESKTOP_USER}/.Xauthority",
}
# DRAKVUF build with the Linux sockaddr decoder (scripts/chimera/patches/drakvuf-linuxnet-sockaddr.patch),
# used for Linux only so the Windows pipeline keeps its validated binary
LINUX_DRAKVUF = "/usr/local/bin/drakvuf-linuxnet"


def linux_plugins(requested: List[str]) -> List[str]:
    # The configured plugin list is the Windows one; Linux always gets its default set,
    # plus any optional Linux plugin the request names
    return DEFAULT_LINUX_PLUGINS + [p for p in OPTIONAL_LINUX_PLUGINS if p in requested]


def guest_file_name(sample_filename: Optional[str]) -> str:
    name = pathlib.PurePosixPath(sample_filename or "sample").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".") or "sample"
    return name[:100]


def linux_drakvuf_cmdline(
    vm_name: str, kernel_profile: pathlib.Path, plugins: List[str], timeout: int,
    extra_args: Optional[Dict[str, Any]] = None,
) -> List[str]:
    binary = LINUX_DRAKVUF if pathlib.Path(LINUX_DRAKVUF).exists() else "drakvuf"
    args = [binary, "-o", "json", "-r", kernel_profile.as_posix(), "-d", vm_name, "-t", str(timeout)]
    for plugin in plugins:
        args.extend(["-a", plugin])
    if "syscalls" in plugins:
        args.extend(["--syscall-hooks-list", (PACKAGE_DATA_PATH / "linux-syscalls.txt").as_posix()])
    for key, value in (extra_args or {}).items():
        if value is True:
            args.append(key)
        elif value not in (None, False):
            args.extend([key, str(value)])
    return args


def upload_sample(vm_name: str, kernel_profile: pathlib.Path, agent_pid: int,
                  host_path: pathlib.Path, guest_path: str) -> Dict[str, Any]:
    # Linux writefile runs inside the agent process: it must be making syscalls (it polls every 0.5 s)
    cmd = ["injector", "-o", "json", "-d", vm_name, "-r", kernel_profile.as_posix(),
           "-i", str(agent_pid), "-m", "writefile", "-B", host_path.as_posix(), "-e", guest_path,
           "--timeout", "60"]
    last_error = None
    for attempt in range(3):
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("Plugin") == "inject":
                if entry.get("Status") == "Success":
                    return entry
                last_error = entry
        log.warning("Linux upload attempt %d failed: rc=%s %s", attempt + 1, result.returncode, last_error)
        time.sleep(2)
    raise RuntimeError(f"Failed to upload the sample to the Linux guest: {last_error}")


def wait_for_marker(drakmon_file: pathlib.Path, marker: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    needle = marker.encode()
    while time.monotonic() < deadline:
        try:
            if needle in drakmon_file.read_bytes():
                return True
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False


def analyze_linux_file(
    vm_id: int,
    output_dir: pathlib.Path,
    metadata: AnalysisMetadata,
    substatus_callback=None,
) -> Dict[str, Any]:
    from .analyzer import AnalysisSubstatus

    config = load_config()
    install_info = InstallInfo.load(LINUX_INSTALL_INFO_PATH)
    kernel_profile = install_info.snapshot_dir / "kernel.json"
    options = metadata.options
    options.guest_os = "linux"
    options.plugins = linux_plugins(options.plugins)
    # The configured extra DRAKVUF arguments are for the Windows guest. Linux always hides Xen from CPUID
    # (cpuidmon -s), as the golden image was booted with it hidden (lib/cpuid_hide.py)
    if "cpuidmon" not in options.plugins:
        options.plugins.append("cpuidmon")
    options.extra_drakvuf_args = {"-s": True}
    timeout = options.timeout or config.drakrun.default_timeout

    network_conf = NetworkConfigSection(
        out_interface=config.network.out_interface,
        dns_server=config.network.dns_server,
        net_enable=options.net_enable,
    )
    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.starting_vm)

    linux_info: Dict[str, Any] = {"plugins": options.plugins}
    drakvuf_returncode = None
    drakvuf_hard_timeout = False
    drakvuf_runtime_s = None
    guest_clock = None
    stall_monitor = StallMonitor(f"vm-{vm_id}")
    drakmon_file = output_dir / "drakmon.log"
    drakvuf_err_file = output_dir / "drakvuf_stderr.log"

    with run_vm(vm_id, install_info, network_conf, no_restore=options.no_vm_restore) as vm:
        if substatus_callback is not None:
            substatus_callback(AnalysisSubstatus.preparing_vm)
        agent = LinuxAgent(f"/var/run/drakrun/{vm.vm_name}.sock")
        try:
            agent_info = agent.wait_ready(60)
            linux_info["agent"] = agent_info
            guest_clock = set_guest_clock(agent)
            linux_info["network"] = agent.call("net", {"timeout": 30}, timeout=45)
            agent.call("prepare")

            exec_argv = None
            if options.host_sample_path is not None:
                guest_path = f"{GUEST_WORK_DIR}/{guest_file_name(options.sample_filename or options.host_sample_path.name)}"
                upload = upload_sample(vm.vm_name, kernel_profile, agent_info["pid"], options.host_sample_path, guest_path)
                stat = agent.call("stat", {"path": guest_path})
                if metadata.file is not None and stat["sha256"] != metadata.file.sha256:
                    raise RuntimeError(f"Uploaded sample hash mismatch: {stat['sha256']}")
                agent.call("chmod", {"path": guest_path, "mode": 0o755})
                linux_info["upload"] = {"guest_path": guest_path, "sha256": stat["sha256"], "size": stat["size"],
                                        "injector": upload.get("Status")}
                exec_argv = [guest_path]
            if isinstance(options.start_command, list) and options.start_command:
                exec_argv = [str(a) for a in options.start_command]
            elif isinstance(options.start_command, str) and options.start_command:
                exec_argv = ["/bin/sh", "-c", options.start_command]
            options.start_command = exec_argv

            if substatus_callback is not None:
                substatus_callback(AnalysisSubstatus.analyzing, updated_options=True)

            cmdline = linux_drakvuf_cmdline(vm.vm_name, kernel_profile, options.plugins, timeout,
                                            options.extra_drakvuf_args)
            log.info("Starting DRAKVUF: %s", cmdline)
            stop_watchdog = threading.Event()
            watchdog = threading.Thread(target=log_activity_watchdog, args=(drakmon_file, stop_watchdog),
                                        daemon=True, name="drakvuf-watchdog")
            watchdog.start()
            with run_tcpdump(vm.get_network_info(), output_dir / "dump.pcap"), \
                    run_screenshotter(vm_id, install_info, output_dir, enabled=not options.no_screenshotter), \
                    drakmon_file.open("wb") as out, drakvuf_err_file.open("wb") as err:
                drakvuf = subprocess.Popen(cmdline, stdout=out, stderr=err, cwd=output_dir)
                stall_monitor.on_stall = drakvuf.terminate
                stall_thread = threading.Thread(target=stall_monitor.run, args=(stop_watchdog,), daemon=True)
                stall_thread.start()
                with process_graceful_exit(drakvuf):
                    started = time.monotonic()
                    # Launch gate: a marker command must appear in procmon before the sample runs
                    # (a random argument only: the sample can list processes too)
                    marker = secrets.token_hex(8)
                    agent.call("exec", {"argv": ["/bin/true", marker]})
                    linux_info["monitor_ready"] = wait_for_marker(drakmon_file, marker, READY_TIMEOUT_S)
                    linux_info["monitor_ready_s"] = round(time.monotonic() - started, 1)
                    if not linux_info["monitor_ready"]:
                        log.warning("Marker not seen in %d s; starting the sample anyway", READY_TIMEOUT_S)
                    if exec_argv:
                        launched = agent.call("exec", {"argv": exec_argv, "cwd": GUEST_WORK_DIR, "env": SAMPLE_ENV})
                        inject = {"Plugin": "inject", "Method": "AgentExec", "Status": "Success",
                                  "ProcessName": exec_argv[0], "Arguments": " ".join(exec_argv[1:]),
                                  "InjectedPid": launched["pid"]}
                    else:
                        inject = None
                    agent.close()  # nothing more from the agent while the sample runs
                    if inject is not None:
                        (output_dir / "inject.log").write_text(json.dumps(inject) + "\n")
                    try:
                        drakvuf.wait(timeout + 30)
                    except subprocess.TimeoutExpired:
                        drakvuf_hard_timeout = True
                        drakvuf.terminate()
                        drakvuf.wait(10)
                    drakvuf_returncode = drakvuf.returncode
                    drakvuf_runtime_s = time.monotonic() - started
            stop_watchdog.set()
            watchdog.join(timeout=1)
            stall_thread.join(timeout=1)
        finally:
            agent.close()

    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.postprocessing)

    def telemetry():
        return summarize_telemetry(
            output_dir, options.plugins, drakvuf_returncode, drakvuf_hard_timeout,
            drakvuf_runtime_s=drakvuf_runtime_s, analysis_timeout_s=timeout,
            vm_stalled=stall_monitor.stalled, vm_max_stall_s=stall_monitor.max_stall_s,
        )

    metadata.model_extra["telemetry"] = telemetry()
    metadata.model_extra["linux"] = linux_info
    extra_metadata = postprocess_analysis_dir(output_dir, config, metadata)
    extra_metadata["guest_clock"] = guest_clock
    extra_metadata["linux"] = linux_info
    extra_metadata["telemetry"] = telemetry()
    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.done)
    return extra_metadata
