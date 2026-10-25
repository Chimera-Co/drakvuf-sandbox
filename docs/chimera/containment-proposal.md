# Containment Change Proposal (M2b) — v2, APPLIED 2026-10-19

**Date:** 2026-10-19 · **Status:** applied and verified; see `containment-results-2026-10-19.md` (C-1…C13 PASS, plus implementation changes found during testing: bridge netfilter disabled, Xen physdev rules tolerated by the checker) · **Addresses:** threat-model T2, T3, T6 (risks R1, R2, R3, R11 in `RECON-2026-10-19.md`)
**Estimated effort:** ~3–4 h including tests · **Reversible:** yes (§6), no reboot required.
**Review:** v1 was adversarially reviewed by Codex (read-only). Accepted findings are folded in; see §8.

## 1. Goal

A guest must be able to "see an Internet" (DNS, HTTP/S, SMTP, …) but every packet it sends must end at **INetSim**, never at the real Internet, the home LAN, or dom0 services. **dom0 must also never be induced to send packets on a guest's behalf.** The design **fails closed** and stays closed while it is being re-applied.

## 2. Design

The deployed topology diagram (Mermaid) is in `containment-results-2026-10-19.md`. In summary: guest packets on `drakN` pass `raw` anti-spoofing (rpfilter) and a link-local drop (169.254.0.0/16, added 20 Oct: a real LAN never answers the cloud metadata address, INetSim did), then `nat` DNAT of all TCP/UDP/ICMP to INetSim at 10.99.0.2, then the `CHIMERA_GUARD` FORWARD chain (default DROP; only drakN → inetsim0 → 10.99.0.2 accepted). `CHIMERA_IN` allows guests only DHCP to dom0; `CHIMERA6` drops all IPv6; INetSim runs in netns `chimera-inet` with no default route.

The transit subnet moved from 10.13.255.0/30 (v1) to **10.99.0.0/30** because drakrun allows VM id 255, whose bridge network 10.13.255.0/24 would collide.

## 3. Exact changes

### 3.1 Package
```bash
sudo apt-get install --no-install-recommends inetsim     # Debian 12: 1.3.2+dfsg.1-1
systemctl list-unit-files | grep -i inetsim               # disable/mask any host-wide unit it ships (reported first)
```

### 3.2 `/usr/local/sbin/chimera-net-up` (new, root:root 0755)
All firewall state is applied in **one atomic `*-restore --noflush` transaction per address family**. Re-running it never exposes an empty chain, and an interrupted run leaves the previous rule set intact.
```bash
#!/bin/bash
# CHIMERA containment: INetSim netns + fail-closed guest firewall. Idempotent and atomic.
set -euo pipefail
NS=chimera-inet; H=inetsim0; P=inetsim-ns; HIP=10.99.0.1; NIP=10.99.0.2

# --- namespace + veth, IPv6 off on both ends
ip netns list | grep -qw "$NS" || ip netns add "$NS"
if ! ip link show "$H" &>/dev/null; then
  ip link add "$H" type veth peer name "$P"
  ip link set "$P" netns "$NS"
fi
sysctl -qw "net.ipv6.conf.$H.disable_ipv6=1"
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
ip addr replace "$HIP/30" dev "$H"
ip -n "$NS" addr replace "$NIP/30" dev "$P"
ip link set "$H" up
ip -n "$NS" link set lo up
ip -n "$NS" link set "$P" up
ip -n "$NS" route replace 10.13.0.0/16 via "$HIP"     # replies to guests; namespace has NO default route

# jump rules are (re)inserted at position 1 inside the same transaction
jump() {  # table chain target -> lines that delete an existing jump (if any) and insert it first
  if iptables -t "$1" -C "$2" -j "$3" 2>/dev/null; then echo "-D $2 -j $3"; fi
  echo "-I $2 1 -j $3"
}

iptables-restore --noflush <<EOF
*raw
:CHIMERA_RAW - [0:0]
-F CHIMERA_RAW
-A CHIMERA_RAW -i drak+ -s 0.0.0.0/32 -p udp --sport 68 --dport 67 -j RETURN
-A CHIMERA_RAW -i drak+ -d 169.254.0.0/16 -j DROP
-A CHIMERA_RAW -i drak+ -m rpfilter --invert -j DROP
-A CHIMERA_RAW -i $H ! -s $NIP/32 -j DROP
$(jump raw PREROUTING CHIMERA_RAW)
COMMIT
*nat
:CHIMERA_DNAT - [0:0]
-F CHIMERA_DNAT
-A CHIMERA_DNAT -i drak+ -p udp --sport 68 --dport 67 -j RETURN
-A CHIMERA_DNAT -i drak+ -p tcp  -j DNAT --to-destination $NIP
-A CHIMERA_DNAT -i drak+ -p udp  -j DNAT --to-destination $NIP
-A CHIMERA_DNAT -i drak+ -p icmp -j DNAT --to-destination $NIP
$(jump nat PREROUTING CHIMERA_DNAT)
COMMIT
*filter
:CHIMERA_GUARD - [0:0]
:CHIMERA_IN - [0:0]
-F CHIMERA_GUARD
-F CHIMERA_IN
-A CHIMERA_GUARD -i drak+ -o $H -d $NIP/32 -j ACCEPT
-A CHIMERA_GUARD -i $H -o drak+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A CHIMERA_GUARD -i drak+ -m limit --limit 6/min -j LOG --log-prefix "CHIMERA-EGRESS-DROP "
-A CHIMERA_GUARD -i drak+ -j DROP
-A CHIMERA_GUARD -o drak+ -j DROP
-A CHIMERA_GUARD -i $H -j DROP
-A CHIMERA_GUARD -o $H -j DROP
-A CHIMERA_IN -i $H -j DROP
-A CHIMERA_IN -i drak+ -p udp --sport 68 --dport 67 -j ACCEPT
-A CHIMERA_IN -i drak+ -j DROP
$(jump filter FORWARD CHIMERA_GUARD)
$(jump filter INPUT CHIMERA_IN)
COMMIT
EOF
iptables -P FORWARD DROP

jump6() { if ip6tables -C "$1" -j CHIMERA6 2>/dev/null; then echo "-D $1 -j CHIMERA6"; fi; echo "-I $1 1 -j CHIMERA6"; }
ip6tables-restore --noflush <<EOF
*filter
:CHIMERA6 - [0:0]
-F CHIMERA6
-A CHIMERA6 -i drak+ -j DROP
-A CHIMERA6 -o drak+ -j DROP
-A CHIMERA6 -i $H -j DROP
-A CHIMERA6 -o $H -j DROP
$(jump6 INPUT)
$(jump6 FORWARD)
COMMIT
EOF

echo 1 > /proc/sys/net/ipv4/ip_forward    # needed for DNAT; safe because FORWARD is default-DROP + guarded
/usr/local/sbin/chimera-net-check          # refuse to report success unless the invariants hold
```

### 3.3 `/usr/local/sbin/chimera-net-check` (new): invariant check, used by the up script, tests, and (M3) the worker units
Exits non-zero unless **all** of the following hold:
- `iptables -S FORWARD` line 2 is `-A FORWARD -j CHIMERA_GUARD`, and the same position-1 check passes for `INPUT/CHIMERA_IN`, `raw PREROUTING/CHIMERA_RAW` and `nat PREROUTING/CHIMERA_DNAT`;
- the FORWARD policy is DROP;
- each chain's rule count matches the expected count;
- `ip6tables` has `CHIMERA6` first in INPUT and FORWARD;
- `inetsim0` exists with IPv6 disabled;
- INetSim is listening on 10.99.0.2 inside the netns.

### 3.4 `/usr/local/sbin/chimera-net-down` (new, rollback)
**Refuses to run while any `vm-*` domain exists** (`xl list`); the operator must destroy guests first. It then removes all CHIMERA chains and jumps in a single restore transaction per family, restores the FORWARD policy to ACCEPT, deletes `inetsim0` and the netns, and sets `ip_forward=0`.

### 3.5 systemd units (new)
- `chimera-net.service`: `Type=oneshot`, `RemainAfterExit=yes`, `ExecStart=/usr/local/sbin/chimera-net-up`, `ExecStop=/usr/local/sbin/chimera-net-down`, `After=network-pre.target xen-init-dom0.service`, `WantedBy=multi-user.target`.
- `chimera-inetsim.service`: `Requires=`/`After=chimera-net.service`, `NetworkNamespacePath=/run/netns/chimera-inet`, plus sandboxing (the netns isolates the network, not the filesystem or IPC): `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateIPC=yes`, `PrivateDevices=yes`, `NoNewPrivileges=yes`, `ReadWritePaths=/var/log/chimera-inetsim /var/lib/inetsim`, `RestrictAddressFamilies=AF_INET AF_UNIX`, and a `CapabilityBoundingSet=` limited to what INetSim needs (`CAP_NET_BIND_SERVICE`, plus `CAP_SETUID CAP_SETGID` only if it insists on starting as root and dropping to its own user; checked after install, with the effective UID and capabilities recorded as evidence).
- **Before the first VM test:** every `drakrun vm-start` / analysis in the test procedure is preceded by `chimera-net-check`. In M3 the worker units get `Requires=chimera-net.service chimera-inetsim.service` and `ExecStartPre=/usr/local/sbin/chimera-net-check`.

### 3.6 `/etc/inetsim/chimera-inetsim.conf` (new; package default untouched)
```
service_bind_address 10.99.0.2
dns_default_ip       10.99.0.2
start_service dns
start_service http
start_service https
start_service smtp
start_service smtps
start_service pop3
start_service ftp
start_service ntp
start_service irc
start_service ident
start_service syslog
start_service dummy_tcp
start_service dummy_udp
```
(Directive names checked against the installed `inetsim.conf` before use. Unsupported ones are dropped and reported.)

### 3.7 `/etc/drakrun/config.toml` `[network]` (backup → `config.toml.bak.<timestamp>`)
```diff
-dns_server = "use-gateway-address"
-out_interface = "default"
+dns_server = "10.99.0.2"
+out_interface = "inetsim0"
 net_enable = true
```
drakrun then MASQUERADEs only towards `inetsim0`. INetSim sees 10.99.0.1 as the client, so per-guest attribution comes from the `drakN` PCAP, which keeps the original destination. Even if this config is reverted, the CHIMERA chains keep traffic off Wi-Fi.

### 3.8 `/etc/drakrun/cfg.template` (backup first; takes effect at the next restore because `vm-N.cfg` is regenerated each time, `drakrun/lib/vm.py:98`)
```diff
-vnclisten="0.0.0.0:{{ VM_ID }},websocket={{ VNC_PORT }}"
+vnclisten="127.0.0.1:{{ VM_ID }},websocket=127.0.0.1:{{ VNC_PORT }}"
```
(If qemu-xen rejects the host part of `websocket=`, fall back to `websocket={{ VNC_PORT }}` and confirm the binding with `ss -tlnp` in C7.)

### 3.9 System dnsmasq
```bash
sudo systemctl disable --now dnsmasq     # /etc/resolv.conf → 192.168.0.1 (router); nothing on dom0 uses it
```

## 4. Verification (immediately after applying; evidence saved)

Evidence: `/var/lib/chimera-evidence/containment-<date>/` holds `iptables-save`, `ip6tables-save`, counters before/after, a host `tcpdump` on Wi-Fi, drakrun's `dump.pcap`, INetSim logs, and transcripts.
Guest commands via `drakrun vm-start --vm-id 1` + `drakrun drakshell --vm-id 1`. **Benign only.** Spoof/TTL/fragment probes use `scapy` run in the guest's place from a *throwaway* netns attached to a test bridge `drak9`, so we don't need raw-socket tooling inside Windows.

| ID | Test | Pass criterion |
|---|---|---|
| C-1 | **Dry run before touching the host firewall:** run the §3.2 rule transactions inside a throwaway netns (`ip netns add chimera-dryrun; ip netns exec chimera-dryrun …`), re-run them 3×, `iptables-save` inside it, then delete the netns | Restores succeed; chain contents and positions are identical after each re-run |
| C0 | `chimera-net-check` | exit 0 |
| C1 | Guest `Resolve-DnsName example.com` | `10.99.0.2` |
| C2 | Guest `Invoke-WebRequest http://example.com` | INetSim default page |
| C3 | Guest TCP to 203.0.113.10:80 (TEST-NET-3) and 8.8.8.8:53 | INetSim answers; **0 packets** to those IPs on Wi-Fi |
| C4 | Guest TCP to LAN router 192.168.0.1:80 | INetSim answers; 0 packets to 192.168.0.1:80 on Wi-Fi |
| C5 | Guest → dom0 services on gateway IP (22, 5000, 6379) | Nothing reached on dom0 (Redis `CLIENT LIST` unchanged) |
| C6 | Guest IPv6 (link-local, all-nodes) | No reply; `CHIMERA6` counters increase |
| C7 | `ss -tlnp` with VM running | VNC + websocket on 127.0.0.1 only; nothing on `0.0.0.0:53` |
| C8 | Fail-closed: set `out_interface="default"`, **confirm via `iptables-save` that drakrun's Wi-Fi ACCEPT/MASQUERADE rules are active**, repeat C3 | Still 0 packets on Wi-Fi; config restored |
| C9 | Netns isolation **with a real route present**: temporarily add `default via 10.99.0.1` in the netns, then try 192.168.0.1 and 10.99.0.1:6379; remove the route | Both blocked by firewall (counters), not "no route" |
| C10 | Spoofing (from the `drak9` test netns): source 192.168.0.1 with TTL=1 towards any IP; source of another VM subnet; fragments; GRE/ESP protocol packets | `CHIMERA_RAW` drops them; **0 packets on Wi-Fi including ICMP Time Exceeded** |
| C11 | Re-apply robustness: continuous guest probe (C3 loop) while running `chimera-net-up` 5×, while killing it mid-run, and across `systemctl restart chimera-net` | 0 leaked packets; `chimera-net-check` passes after each |
| C12 | drakrun lifecycle: 3× restore/destroy, DHCP renew, drakshell, screenshots | All work; `dump.pcap` shows original destinations |
| C13 | INetSim process: effective UID, `CapEff`, mount view | Matches §3.5; no write access outside `ReadWritePaths` |

A failed test means stopping and reporting it, not loosening the test.

## 5. Risks of the change itself

| Risk | Likelihood | Mitigation |
|---|---|---|
| FORWARD policy DROP breaks other host routing (VPN, NM hotspot sharing) | Low (none observed) | Rollback; scoped to FORWARD |
| rpfilter drops legitimate guest traffic | Low | Guest source = 10.13.N.2 on `drakN`, which matches the route; C12 covers it |
| VM restore fails with the changed VNC string | Low | C7/C12; revert one line |
| INetSim requires root / directive names differ | Medium | Checked post-install (C13); config validated before start |
| Unix-socket/IPC exposure from the netns | Low after sandboxing | `PrivateIPC`, `ProtectSystem=strict`, `RestrictAddressFamilies` |

## 6. Rollback (≈3 min)
```bash
sudo xl list                                     # destroy any vm-* first: sudo xl destroy vm-1
sudo systemctl disable --now chimera-inetsim chimera-net    # chimera-net-down refuses while guests exist
sudo cp /etc/drakrun/config.toml.bak.<ts>  /etc/drakrun/config.toml
sudo cp /etc/drakrun/cfg.template.bak.<ts> /etc/drakrun/cfg.template
sudo systemctl enable --now dnsmasq              # only if the old behaviour is really wanted
sudo apt-get purge inetsim                       # optional
```

## 7. Not in this change
- Web UI on 127.0.0.1 and root-owned deployment: M3 systemd units.
- Guest-output caps and parser hardening (T4), evasion status bug: M3 code fixes.
- Guest hardening (SMBIOS, CPUID, MAC, devices, hidsim): M4, which needs a new snapshot.

## 8. Changes from v1 (Codex adversarial review, 2026-10-19)

| Finding | Severity | v2 change |
|---|---|---|
| Re-running v1 flushed live chains, so a guard-less window existed (and persisted if interrupted) | High | Atomic `*-restore --noflush` transactions; `chimera-net-check`; C11 |
| Spoofed source + TTL=1 makes dom0 emit ICMP to the LAN before FORWARD (`rp_filter=0` confirmed on this host) | High | `raw` table `CHIMERA_RAW` with `rpfilter`; C10 |
| No IPv6 cover on the INetSim veth; INPUT trusted ESTABLISHED from the netns | High / Medium | IPv6 disabled on both veth ends + `CHIMERA6`; `CHIMERA_IN` drops all namespace traffic; C9 with a real route |
| Guest INPUT protection depended on drakrun's rules | Medium | `CHIMERA_IN` allows only DHCP 68→67 from `drak+` |
| DHCP exception `--dport 67:68` too broad | Low | `--sport 68 --dport 67` |
| VM id 255 collides with the transit subnet | Medium | Transit moved to 10.99.0.0/30 |
| netns doesn't isolate filesystem/IPC | Medium | systemd sandboxing for INetSim; C13 |
| L2 bypass without br_netfilter | Info | Holds only with one vif per bridge (drakrun's design); documented |
