---
title: 4. Network containment
group: Build from scratch
---
# Build step 4: network containment with INetSim

Malware must believe it has the internet, and must never reach it. CHIMERA answers every guest connection with
**INetSim**, a simulator of common internet services (DNS, HTTP/HTTPS, SMTP, FTP and others), running in its own
network namespace, and puts a fail-closed firewall between the guests and everything else.

```diagram containment
```

## Design

- Each guest `vm-N` sits on its own bridge `drakN` (`10.13.N.1/24`); only the guest's `vif` ports are allowed on
  it.
- `CHIMERA_RAW` (raw table) drops spoofed sources with `rpfilter` and drops link-local destinations, including
  the cloud metadata address, before connection tracking.
- `CHIMERA_DNAT` (nat table) rewrites every guest TCP, UDP and ICMP packet to INetSim at `10.99.0.2`, so any IP
  and any port is answered by the simulator.
- `CHIMERA_GUARD` (FORWARD, policy DROP) accepts only traffic from `drak+` to `10.99.0.2` via `inetsim0`; anything
  else is logged and dropped. `CHIMERA_IN` lets guests reach dom0 for DHCP only. `CHIMERA6` drops all IPv6.
- INetSim runs in netns `chimera-inet` behind a veth pair (`inetsim0` 10.99.0.1 ↔ 10.99.0.2) with **no default
  route**, its services unprivileged and the unit sandboxed by systemd.
- Bridge netfilter is switched off, so `tcpdump` on `drakN` records the guest's **original** destinations, not the
  rewritten ones.

Every firewall change is one atomic `iptables-restore` transaction per address family, so re-running the setup
never leaves an empty guard chain, and the chain jumps are re-inserted at position 1 each time.

## Install

```bash
apt-get install --no-install-recommends inetsim
systemctl disable --now inetsim 2>/dev/null || true      # no host-wide INetSim
systemctl disable --now dnsmasq                          # guests get DNS from INetSim

cd /opt/chimera/src/scripts/chimera/containment
install -m 755 chimera-net-up chimera-net-down chimera-net-check /usr/local/sbin/
install -d /etc/inetsim && install -m 644 chimera-inetsim.conf /etc/inetsim/
install -m 644 chimera-net.service chimera-inetsim.service /etc/systemd/system/
cp -r inetsim-data/. /var/lib/inetsim/                   # extra HTTP fake files (Windows connectivity checks)
systemctl daemon-reload
systemctl enable --now chimera-net chimera-inetsim
```

Point drakrun at INetSim in `/etc/drakrun/config.toml`:

```toml
[network]
dns_server = "10.99.0.2"
out_interface = "inetsim0"
net_enable = true
```

Even if this section is later reverted, the CHIMERA chains keep guest traffic off the uplink.

Bind VNC to loopback in the guest template `/etc/drakrun/cfg.template` (it is regenerated into `vm-N.cfg` at
every restore):

```text
vnclisten="127.0.0.1:{{ VM_ID }},websocket=127.0.0.1:{{ VNC_PORT }}"
```

## Check

```bash
chimera-net-check --require-inetsim     # must pass; the worker units run it before starting
iptables -S CHIMERA_GUARD
ip netns exec chimera-inet ss -lntu      # INetSim's listening services
```

The repository's verification scripts (`windows_containment_test.py`, `hostile_guest_test.py`) run the tests
from inside a guest: DNS and HTTP answered by INetSim, external and LAN addresses answered by INetSim and never
seen on the uplink, dom0 services refused, IPv6 dropped, spoofed sources dropped, and the rules re-applied while
a guest is probing.

`chimera-net-down` removes everything CHIMERA added, and refuses to run while any `vm-*` domain exists.

Next: [guest images](build-guests.md).
