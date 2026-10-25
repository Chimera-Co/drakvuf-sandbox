# INetSim NCSI responses — 2026-10-19

Repo-only change for Debian INetSim 1.3.2; not deployed or tested in a running
namespace/Windows guest as part of this task. No network requests were made.
Offline verification invoked the installed `HTTP.pm` fake-file/status routines
with logging stubbed and the repo mappings/files: both returned 200, `text/plain`,
and the exact 22/14-byte bodies. A config comparison confirmed that all previous
active directives are unchanged and only the three directives below were added.

## Probe expectations and limits

| Probe | Expected success | Confidence / implementation |
|---|---|---|
| `http://www.msftconnecttest.com/connecttest.txt` | 200, exactly `Microsoft Connect Test` | High confidence from known Windows 10 NCSI defaults; implemented as 22 bytes, no newline/BOM. |
| `http://www.msftncsi.com/ncsi.txt` | 200, exactly `Microsoft NCSI` | High confidence for legacy Windows NCSI; implemented as 14 bytes, no newline/BOM. |
| A `dns.msftncsi.com` | `131.107.255.255` | High confidence for the NCSI DNS comparison; implemented with `dns_static`. |
| `http://edge-http.microsoft.com/captiveportal/generate_204` | 204, empty body | High confidence in the Chromium 204 success convention; the exact Edge endpoint comes from the supplied observation, not independently verified for this Edge build. **Not satisfied by stock INetSim configuration.** |

These expectations are from prior knowledge and the task's supplied endpoint,
not a fresh Microsoft documentation lookup (network use was forbidden). The
guest's effective registry/policy probe settings and Edge version were not read.

IPv6 stays deliberately blocked by `chimera-net-up`; IPv6 active probes will
fail. Successful IPv4 probes can provide IPv4 connectivity status, but this does
not simulate IPv6 Internet access or guarantee the icon changes under every
guest policy/cache state. Re-run guest probes after deployment to verify that.

## Exact directives and local source evidence

Added to `scripts/chimera/containment/chimera-inetsim.conf`:

```text
dns_static dns.msftncsi.com 131.107.255.255
http_static_fakefile /connecttest.txt ncsi-connecttest.txt text/plain
http_static_fakefile /ncsi.txt ncsi-legacy.txt text/plain
```

The fake files live in `inetsim-data/http/fakefiles/`, mirroring
`/var/lib/inetsim/http/fakefiles/` under the service's existing `--data-dir`.

Installed documentation/source inspected on this host:

- [Packaged config](/etc/inetsim/inetsim.conf:235), lines 235–245: `dns_static <fqdn hostname> <IP address>`;
  lines 354–364: `http_static_fakefile <path> <filename> <mime-type>` and
  `<data-dir>/http/fakefiles` layout. Also documented in
  `/usr/share/man/man5/inetsim.conf.5.gz` under additional DNS/HTTP(S) options.
- [Config parser](/usr/share/perl5/INetSim/Config.pm:751), lines 751–763
  and 863–879: actual directive parsing. `dns_static` also creates a reverse PTR
  mapping for `131.107.255.255`; that is an inherent side effect.
- [DNS implementation](/usr/share/perl5/INetSim/DNS.pm:308), lines 308–321:
  static host mappings win over the default IP. Other A lookups retain `10.99.0.2`.
- [HTTP fake-file handler](/usr/share/perl5/INetSim/HTTP.pm:840), lines 840–912:
  exact path lookup wins over extension/default selection, file bytes are read
  verbatim, and successful responses unconditionally use `set_response_status(200)`.
  The match is path-only, so these two paths change on any HTTP hostname.
  Other paths, HTTPS mappings, services and defaults remain unchanged.
- [Debian notes](/usr/share/doc/inetsim/README.Debian:1) say custom samples
  must be copied into `/var/lib/inetsim/` manually. The packaged `README.gz`
  §1.1 describes static-path fake mode and default/static DNS mappings.

The 204 reason phrase exists in `HTTP.pm:118`, but no per-path status directive
or successful fake-file route selects it. An empty fake file would still yield
200 and must not be claimed to pass the Edge check. For this change, Edge keeps
its existing default response. The least disruptive complete follow-up would be
a separately reviewed INetSim HTTP handler patch matching only HTTP GET with
Host `edge-http.microsoft.com` and path `/captiveportal/generate_204`, returning
204 with no body before normal fake-file dispatch. That patch is outside this
configuration-only change; Edge may still report a portal until it exists.

The static DNS IP does not bypass containment. In
[chimera-net-up](../../scripts/chimera/containment/chimera-net-up),
`CHIMERA_DNAT` matches guest `drak+` ingress TCP/UDP regardless of destination,
then DNATs to `10.99.0.2`, preserving the port. Thus guest HTTP to
`131.107.255.255:80` still reaches INetSim; conntrack reverses the translation
on replies. `dns.msftncsi.com` is the DNS comparison target, separate from the
HTTP hostnames, which still resolve to the default `10.99.0.2`. This is verified
by reading the repo rules, not by live packet testing.

## Deploy later (root shell on the host)

Run these exact commands as root; they copy only the new files into the existing
data directory and retain all packaged samples. They were **not run** here.

```sh
cd /home/shreyas/Documents/chimera/chimera-console
install -o root -g root -m 0644 scripts/chimera/containment/chimera-inetsim.conf /etc/inetsim/chimera-inetsim.conf
install -d -o root -g root -m 0755 /var/lib/inetsim/http/fakefiles
install -o root -g root -m 0644 scripts/chimera/containment/inetsim-data/http/fakefiles/ncsi-connecttest.txt /var/lib/inetsim/http/fakefiles/ncsi-connecttest.txt
install -o root -g root -m 0644 scripts/chimera/containment/inetsim-data/http/fakefiles/ncsi-legacy.txt /var/lib/inetsim/http/fakefiles/ncsi-legacy.txt
systemctl restart chimera-inetsim
```

## Host-side verification after deployment (root shell)

Explicit `--resolve` avoids dependence on the host resolver inside the netns;
DNS is tested separately against INetSim. `--noproxy '*'` bypasses proxy env vars.
The Python checks compare every body byte and the status, including absence of
trailing newlines. Run in Bash with `set -o pipefail` so curl failure is visible.

```sh
set -o pipefail
ip netns exec chimera-inet dig @10.99.0.2 dns.msftncsi.com A +short
# Expected: 131.107.255.255
ip netns exec chimera-inet dig @10.99.0.2 example.com A +short
# Expected: 10.99.0.2 (default unchanged)

ip netns exec chimera-inet curl --noproxy '*' --max-time 5 --fail --silent --show-error --resolve www.msftconnecttest.com:80:10.99.0.2 -w '\n%{http_code}' http://www.msftconnecttest.com/connecttest.txt | python3 -c 'import sys; assert sys.stdin.buffer.read() == b"Microsoft Connect Test\n200"; print("PASS: 200, exact 22-byte body")'
ip netns exec chimera-inet curl --noproxy '*' --max-time 5 --fail --silent --show-error --resolve www.msftncsi.com:80:10.99.0.2 -w '\n%{http_code}' http://www.msftncsi.com/ncsi.txt | python3 -c 'import sys; assert sys.stdin.buffer.read() == b"Microsoft NCSI\n200"; print("PASS: 200, exact 14-byte body")'
# Expected: the corresponding PASS line for each request.

ip netns exec chimera-inet curl --noproxy '*' --max-time 5 --silent --show-error --resolve edge-http.microsoft.com:80:10.99.0.2 -i http://edge-http.microsoft.com/captiveportal/generate_204
# Known limitation: HTTP/1.1 200 OK and existing INetSim HTML, NOT 204.
ip netns exec chimera-inet curl --noproxy '*' --max-time 5 --silent --show-error --resolve example.com:80:10.99.0.2 -i http://example.com/
# Expected: HTTP/1.1 200 OK and existing INetSim default HTML.
```

These commands do not exercise guest ingress DNAT: namespace-local traffic to
`131.107.255.255` has no default route and does not enter dom0's `drak+` rule.
A later guest HTTP request to that literal IP, plus packet/counter inspection,
is needed for runtime DNAT proof. Do not add a namespace route to test it.
