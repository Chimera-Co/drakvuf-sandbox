"""Containment tests for the Linux guest (the C0-C6 set of containment-results-2026-10-19.md, run
from the Linux guest), plus L1: the guest must not reach the host's own SSH server on its LAN address.

    sudo /opt/chimera/venv/bin/python containment_test.py EVIDENCE_DIR [--vm-id 1]

Restores the Linux golden snapshot in the vm slot, runs every probe inside the guest through
chimera-agent, captures the host's uplink for the whole time, and records the CHIMERA_IN / CHIMERA6
drop counters before and after. Writes EVIDENCE_DIR/{results.json, guest.txt, uplink.pcap, counters-*.txt}
and prints the pass table. Needs the vm slot free (stop drakrun-worker@N first).
"""
import argparse
import json
import pathlib
import subprocess
import time

from drakrun.analyzer.run_tools import run_vm
from drakrun.lib.config import NetworkConfigSection, load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.linux_agent import LinuxAgent

LINUX_GOLDEN_DIR = pathlib.Path("/var/lib/drakrun/linux/golden")

# Runs inside the guest (python3 is there for chimera-agent). One JSON object on stdout.
GUEST_PROBES = r'''
import json, socket, urllib.request
r = {}
def http(url):
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            body = resp.read(4096).decode(errors="replace")
            return {"status": resp.status, "inetsim": "inetsim" in body.lower(), "head": body[:120]}
    except Exception as e:
        return {"error": repr(e)[:200]}
def tcp(host, port, read=False):
    s = socket.socket(); s.settimeout(5)
    try:
        s.connect((host, port))
        banner = s.recv(64).decode(errors="replace") if read else ""
        return {"connected": True, "banner": banner}
    except Exception as e:
        return {"connected": False, "error": repr(e)[:200]}
    finally:
        s.close()
def udp_dns(server):
    q = bytes.fromhex("abcd01000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    try:
        s.sendto(q, (server, 53)); data = s.recv(512)
        return {"answered": True, "answer_ip": socket.inet_ntoa(data[-4:])}
    except Exception as e:
        return {"answered": False, "error": repr(e)[:200]}
    finally:
        s.close()
try:
    r["C1_dns_example_com"] = socket.gethostbyname("example.com")
except Exception as e:
    r["C1_dns_example_com"] = repr(e)
r["C2_http_by_name"] = http("http://example.com/")
r["C3_http_direct_ip"] = http("http://203.0.113.10/")
r["C3_udp_dns_8888"] = udp_dns("8.8.8.8")
r["C4_lan_router_http"] = http("http://192.168.0.1/")
gw = [l.split()[2] for l in open("/proc/net/route").read().splitlines()[1:] if l.split()[1] == "00000000"]
gw_ip = socket.inet_ntoa(bytes.fromhex(gw[0])[::-1]) if gw else "10.13.1.1"
r["C5_gateway"] = gw_ip
for port in (22, 5000, 6379):
    r[f"C5_dom0_{port}"] = tcp(gw_ip, port)
r["L1_host_lan_ssh"] = tcp("192.168.0.125", 22, read=True)
for name, addr in (("C6_ipv6_all_nodes", ("ff02::1%ens3", 9, 0, 0)), ("C6_ipv6_global", ("2001:db8::1", 80, 0, 0))):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        for _ in range(10):
            s.sendto(b"chimera-v6", addr)
        s.recv(64); r[name] = {"reply": True}
    except Exception as e:
        r[name] = {"reply": False, "error": repr(e)[:200]}
    finally:
        s.close()
print(json.dumps(r))
'''


def sh(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def counters(path: pathlib.Path) -> dict:
    text = sh("iptables -L CHIMERA_IN -v -x -n; ip6tables -L CHIMERA6 -v -x -n")
    path.write_text(text)
    totals = {}
    chain = None
    for line in text.splitlines():
        if line.startswith("Chain "):
            chain = line.split()[1]
            totals[chain] = 0
        elif chain and line.split() and line.split()[0].isdigit():
            totals[chain] += int(line.split()[0])
    return totals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence_dir", type=pathlib.Path)
    ap.add_argument("--vm-id", type=int, default=1)
    ap.add_argument("--uplink", default="wlp0s20f3")
    args = ap.parse_args()
    ev = args.evidence_dir
    ev.mkdir(parents=True, exist_ok=True)

    config = load_config()
    install_info = InstallInfo.load(LINUX_GOLDEN_DIR / "install.json")
    network_conf = NetworkConfigSection(out_interface=config.network.out_interface,
                                        dns_server=config.network.dns_server, net_enable=True)
    results = {"C0_net_check_before": subprocess.run(["chimera-net-check", "--require-inetsim"],
                                                     capture_output=True, text=True).returncode == 0}
    before = counters(ev / "counters-before.txt")
    # Everything the guest could send to the outside world: its own subnet, the probe targets, the router
    uplink_filter = ("net 10.13.0.0/16 or host 203.0.113.10 or host 8.8.8.8 or host 2001:db8::1 "
                     "or (host 192.168.0.1 and tcp port 80)")
    capture = subprocess.Popen(["tcpdump", "-i", args.uplink, "-n", "-U", "-w", str(ev / "uplink.pcap"),
                                uplink_filter], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    try:
        started = time.monotonic()
        with run_vm(args.vm_id, install_info, network_conf) as vm:
            results["restore_s"] = round(time.monotonic() - started, 2)
            agent = LinuxAgent(f"/var/run/drakrun/{vm.vm_name}.sock")
            try:
                agent.wait_ready(60)
                results["guest_net"] = agent.call("net", {"timeout": 30}, timeout=45)
                out = agent.call("sh", {"cmd": "python3 - <<'EOF'\n" + GUEST_PROBES + "EOF\n", "timeout": 150},
                                 timeout=170)
            finally:
                agent.close()
        (ev / "guest.txt").write_text(json.dumps(out, indent=1))
        guest = json.loads(out["stdout"].strip().splitlines()[-1])
    finally:
        time.sleep(2)
        capture.terminate()
        capture.wait(10)
    after = counters(ev / "counters-after.txt")
    uplink_packets = int(sh(f"tcpdump -r {ev / 'uplink.pcap'} -n 2>/dev/null | wc -l").strip() or 0)

    def http_inetsim(entry):
        return entry.get("status") == 200 and entry.get("inetsim") is True

    results["guest"] = guest
    results["counters_before"], results["counters_after"] = before, after
    results["uplink_packets"] = uplink_packets
    results["C0_net_check_after"] = subprocess.run(["chimera-net-check", "--require-inetsim"],
                                                   capture_output=True, text=True).returncode == 0
    results["pass"] = {
        "C0": results["C0_net_check_before"] and results["C0_net_check_after"],
        "C1": guest["C1_dns_example_com"] == "10.99.0.2",
        "C2": http_inetsim(guest["C2_http_by_name"]),
        "C3": http_inetsim(guest["C3_http_direct_ip"]) and guest["C3_udp_dns_8888"].get("answer_ip") == "10.99.0.2",
        "C4": http_inetsim(guest["C4_lan_router_http"]),
        "C5": not any(guest[f"C5_dom0_{p}"]["connected"] for p in (22, 5000, 6379))
              and after.get("CHIMERA_IN", 0) > before.get("CHIMERA_IN", 0),
        "C6": not guest["C6_ipv6_all_nodes"]["reply"] and not guest["C6_ipv6_global"]["reply"],
        "L1": not guest["L1_host_lan_ssh"].get("banner", "").startswith("SSH-"),
        "uplink_clean": uplink_packets == 0,
    }
    results["all_pass"] = all(results["pass"].values())
    (ev / "results.json").write_text(json.dumps(results, indent=1))
    print(json.dumps(results["pass"]), "all_pass:", results["all_pass"])


if __name__ == "__main__":
    main()
