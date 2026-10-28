"""Containment tests for the Windows guest: the C0-C6 set of containment-results-2026-10-19.md
(run by hand that day), plus L1 (the host's own SSH server on its LAN address) and L2 (link-local
169.254.0.0/16, the cloud metadata address, gets no answer, not even INetSim's), as in the Linux test.

    sudo /opt/chimera/venv/bin/python windows_containment_test.py EVIDENCE_DIR [--vm-id 1]

Restores the Windows golden snapshot in the vm slot, runs the post-restore script (DHCP renew), runs
each probe inside the guest as its own short PowerShell command through drakshell (a command line is
capped at 2048 bytes), captures the host's uplink for the whole time, and records the drop counters
before and after. Writes EVIDENCE_DIR/{results.json, guest.json, uplink.pcap, counters-*.txt} and
prints the pass table. Needs the vm slot free (stop drakrun-worker@N and drakrun-evasion-worker@N).
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

from drakrun.analyzer.post_restore import get_post_restore_command, prepare_ps_command
from drakrun.analyzer.run_tools import run_vm
from drakrun.evasion.guest_runner import connect_guest_session
from drakrun.lib.config import NetworkConfigSection, load_config
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.networking import make_network_info_for_vm
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_INFO_PATH, VMI_KERNEL_PROFILE_PATH

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
from containment_test import counters, lan_addresses, sh  # noqa: E402

PRELUDE = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';"
JSON_ERR = 'catch{@{error="$($_.Exception.Message)"}|ConvertTo-Json -c}'


def http(url):
    return (PRELUDE + f"try{{$r=Invoke-WebRequest -UseBasicParsing -TimeoutSec 8 '{url}';"
            "@{status=[int]$r.StatusCode;inetsim=($r.Content -match 'inetsim')}|ConvertTo-Json -c}" + JSON_ERR)


def tcp(host, port, read=False):
    # Kept short: with a banner read this is the longest probe
    banner = ("$s=$c.GetStream();$s.ReadTimeout=5000;$b=New-Object byte[] 64;"
              "$o.banner=-join[char[]]$b[0..($s.Read($b,0,64)-1)];") if read else ""
    return ("$c=New-Object Net.Sockets.TcpClient;$o=@{connected=$false};"
            f"try{{$o.connected=$c.ConnectAsync('{host}',{port}).Wait(5000);{banner}}}"
            "catch{$o.error=$_.Exception.InnerException.Message}$c.Close();$o|ConvertTo-Json -c")


PROBES = {
    "C1_dns_example_com": PRELUDE + "try{@{ip=[Net.Dns]::GetHostAddresses('example.com')[0].IPAddressToString}"
                          "|ConvertTo-Json -c}" + JSON_ERR,
    "C2_http_by_name": http("http://example.com/"),
    "C3_http_direct_ip": http("http://203.0.113.10/"),
    "C3_udp_dns_8888": PRELUDE + "try{@{answer_ip=(Resolve-DnsName example.com -Server 8.8.8.8 -Type A -DnsOnly "
                       "-QuickTimeout)[0].IPAddress}|ConvertTo-Json -c}" + JSON_ERR,
    "L2_metadata_http": http("http://169.254.169.254/latest/meta-data/"),
    "L2_link_local_tcp": tcp("169.254.1.1", 443),
    # Windows treats 169.254.0.0/16 as on-link even with no route for it: it ARPs for the address
    # instead of sending to the gateway, so the host's DROP rule never sees a packet. Neighbour
    # entries left Unreachable (ARP never answered; proxy_arp is off) are the evidence.
    "L2_route": "$ProgressPreference='SilentlyContinue';"
                "@{routes=@(Get-NetRoute -AddressFamily IPv4|?{$_.DestinationPrefix -like '169.254.*' -or "
                "$_.DestinationPrefix -eq '0.0.0.0/0'}|%{\"$($_.DestinationPrefix)>$($_.NextHop)\"});"
                "neigh=@(Get-NetNeighbor -AddressFamily IPv4|?{$_.IPAddress -like '169.254.*'}"
                "|%{\"$($_.IPAddress)=$($_.State)\"})}|ConvertTo-Json -c",
    "C6_ipv6_all_nodes": PRELUDE + "$i=(Get-NetAdapter|?{$_.Status -eq 'Up'})[0].ifIndex;"
                         "$o=(ping -6 -n 3 \"ff02::1%$i\"|Out-String);@{reply=($o -match 'Received = [1-9]')}"
                         "|ConvertTo-Json -c",
    "net_address": PRELUDE + "@{addr=@(Get-NetIPAddress -AddressFamily IPv4|?{$_.IPAddress -ne '127.0.0.1'}"
                   "|%{$_.IPAddress})}|ConvertTo-Json -c",
}


def run_probe(session, script):
    command = prepare_ps_command(script)
    rc, stdout, stderr = session.run(command, timeout=60)
    lines = [line for line in stdout.decode(errors="replace").splitlines() if line.strip().startswith("{")]
    if not lines:
        return {"error": f"no JSON (rc={rc}): {stderr.decode(errors='replace')[-300:]}"}
    return json.loads(lines[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence_dir", type=pathlib.Path)
    ap.add_argument("--vm-id", type=int, default=1)
    ap.add_argument("--uplink", default="wlp0s20f3")
    args = ap.parse_args()
    ev = args.evidence_dir
    ev.mkdir(parents=True, exist_ok=True)

    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    network_conf = NetworkConfigSection(out_interface=config.network.out_interface,
                                        dns_server=config.network.dns_server, net_enable=True)
    gateway = make_network_info_for_vm(args.vm_id, network_conf).gateway_address
    for port in (22, 5000, 6379, 7070):
        PROBES[f"C5_dom0_{port}"] = tcp(gateway, port)
    router, host_ip = lan_addresses(args.uplink)
    PROBES["C4_lan_router_http"] = http(f"http://{router}/")
    PROBES["L1_host_lan_ssh"] = tcp(host_ip, 22, read=True)

    results = {"C0_net_check_before": subprocess.run(["chimera-net-check", "--require-inetsim"],
                                                     capture_output=True, text=True).returncode == 0}
    before = counters(ev / "counters-before.txt")
    results.update(lan_router=router, host_lan_ip=host_ip)
    uplink_filter = ("net 10.13.0.0/16 or host 203.0.113.10 or host 8.8.8.8 or host 2001:db8::1 "
                     f"or (host {router} and tcp port 80)")
    capture = subprocess.Popen(["tcpdump", "-i", args.uplink, "-n", "-U", "-w", str(ev / "uplink.pcap"),
                                uplink_filter], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    guest = {}
    try:
        started = time.monotonic()
        with run_vm(args.vm_id, install_info, network_conf) as vm:
            results["restore_s"] = round(time.monotonic() - started, 2)
            session = connect_guest_session(vm.vm_name, Injector(vm.vm_name, vmi_info,
                                                                 VMI_KERNEL_PROFILE_PATH.as_posix()))
            session.drakshell.check_call(get_post_restore_command(network_conf.net_enable))
            for name, script in PROBES.items():
                guest[name] = run_probe(session, script)
        (ev / "guest.json").write_text(json.dumps(guest, indent=1))
    finally:
        time.sleep(2)
        capture.terminate()
        capture.wait(10)
    after = counters(ev / "counters-after.txt")
    uplink_packets = int(sh(f"tcpdump -r {ev / 'uplink.pcap'} -n 2>/dev/null | wc -l").strip() or 0)

    def http_inetsim(entry):
        return entry.get("status") == 200 and entry.get("inetsim") is True

    results["guest"] = guest
    results["gateway"] = gateway
    results["counters_before"], results["counters_after"] = before, after
    results["uplink_packets"] = uplink_packets
    results["C0_net_check_after"] = subprocess.run(["chimera-net-check", "--require-inetsim"],
                                                   capture_output=True, text=True).returncode == 0
    results["pass"] = {
        "C0": results["C0_net_check_before"] and results["C0_net_check_after"],
        "C1": guest["C1_dns_example_com"].get("ip") == "10.99.0.2",
        "C2": http_inetsim(guest["C2_http_by_name"]),
        "C3": http_inetsim(guest["C3_http_direct_ip"]) and guest["C3_udp_dns_8888"].get("answer_ip") == "10.99.0.2",
        "C4": http_inetsim(guest["C4_lan_router_http"]),
        "C5": not any(guest[f"C5_dom0_{p}"]["connected"] for p in (22, 5000, 6379, 7070))
              and after.get("CHIMERA_IN", 0) > before.get("CHIMERA_IN", 0),
        "C6": guest["C6_ipv6_all_nodes"].get("reply") is False,
        "L1": not guest["L1_host_lan_ssh"].get("banner", "").startswith("SSH-"),
        "L2": "error" in guest["L2_metadata_http"] and guest["L2_link_local_tcp"]["connected"] is False
              and (after.get("CHIMERA_RAW_link_local", 0) > before.get("CHIMERA_RAW_link_local", 0)
                   or {"169.254.169.254=Unreachable", "169.254.1.1=Unreachable"}
                   <= set(guest["L2_route"].get("neigh", []))),
        "uplink_clean": uplink_packets == 0,
    }
    results["all_pass"] = all(results["pass"].values())
    (ev / "results.json").write_text(json.dumps(results, indent=1))
    print(json.dumps(results["pass"]), "all_pass:", results["all_pass"])


if __name__ == "__main__":
    main()
