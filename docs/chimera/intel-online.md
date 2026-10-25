# Online threat intelligence

CHIMERA queries providers on the host in the `chimera-intel` background queue after
analysis. Guests never need internet. Only hashes (SHA256, SHA1, MD5), domains,
public IPs and URLs leave the host. There is no sample upload interface. The
sample file is never uploaded or opened by the lookup job. URLs can contain
sensitive paths and query strings: opt out at upload when necessary. VirusTotal
and other providers can retain queried hashes and other observables.

## Enable

Keep the existing offline bundle configured; online availability does not affect
its matching. Import a bundle with `drakrun intel import /path/to/bundle.tar.gz`.

Add to the existing `[intel]` section in config.toml:

```toml
online_enabled = true
online_default = true
keys_dir = "/etc/chimera/keys"
abusech_key_file = "/etc/chimera/abusech-auth-key"
cache_path = "/var/lib/drakrun/intel/online-cache.sqlite"
max_observables = 20
request_timeout_s = 10

[intel.providers]
virustotal = true
malwarebazaar = true
threatfox = true
urlhaus = true
otx = true
abuseipdb = true
greynoise = true
hashlookup = true
hybridanalysis = true
urlscan = true
```

All providers default enabled; online intel defaults disabled. The upload checkbox
uses `online_default` when enabled. Per-upload choice is stored with options;
a separate `online-options.json` preserves it across worker option normalization.
Run `drakrun intel-worker`, or install the supplied
`scripts/chimera/systemd/drakrun-intel-worker.service` with your deployment tooling
and enable/start `drakrun-intel-worker.service`. The service expects the existing
installation at `/opt/chimera/venv`; adjust that path for other installations.
The worker needs access to the keys, analysis artifacts and cache directory.

## On the CHIMERA host (25 Oct 2026)

`/etc/drakrun/config.toml` has `[intel] enabled = true`, `online_enabled = true`, `online_default = false`:
offline matching always runs (it is skipped quietly until a bundle is imported), and online lookups run only
when the upload ticks "Online threat intel" or someone presses "Run online lookup" on the report. The unit runs
as root with `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, only
`AF_UNIX`/`AF_INET`/`AF_INET6` sockets and a 1 GiB memory cap. Check providers with
`sudo /opt/chimera/venv/bin/drakrun intel providers` (add `--test` for one live request each).

Add a key (prompted, never echoed or kept in shell history):

```bash
read -rsp "VirusTotal key: " k && echo && printf '%s' "$k" | sudo tee /etc/chimera/keys/virustotal >/dev/null && unset k && sudo chmod 600 /etc/chimera/keys/virustotal
```

The file name is the provider id (`virustotal`, `otx`, `abuseipdb`, `greynoise`, `hybridanalysis`, `urlscan`);
abuse.ch providers use `/etc/chimera/abusech-auth-key`.

What is looked up: the sample's hashes, then observables from the **sample's own process tree** (DNS, HTTP,
TLS SNI, connections, files it dropped), then IOCs from memory dumps of that tree, then static strings. Activity
of other guest processes (Windows services, updates, telemetry) is never sent. Names that are not public
(`localhost`, `.local`, `.lan`, `.internal`, `.arpa`, ...), well-known background services (Microsoft/Windows
update and telemetry hosts, certificate and OCSP hosts, the INetSim fake internet) and string artefacts that only
look like hosts (version numbers such as `1.9.16.1`, one-letter domains, over-long label chains) are dropped
before any request. Only configured providers are called; a result counts as a match only when the provider
flags it malicious or suspicious.

VirusTotal results keep a detailed view: engine detections (flagged engines first), the popular threat label and
family names, crowdsourced YARA/Sigma/IDS hits, sandbox verdicts, first/last seen and file or network facts
(registrar, ASN, country, categories). They are shown as evidence beside the verdict, not as classifier features:
the models are trained from files and behaviour, and VirusTotal detections are kept for labelling and
evaluation.

Pacing: a lookup waits for its provider's interval (up to 20 s) instead of failing, and each provider gets a
fixed number of lookups per analysis, the sample's hashes first, then dynamic observables, then static ones.
The sample's SHA-1/MD5 are skipped when the SHA-256 is queried.

| Provider | Interval | Daily cap | Lookups per analysis |
| --- | --- | --- | --- |
| VirusTotal | 15 s | 450 | 6 |
| MalwareBazaar, ThreatFox, URLhaus | 2 s | 150 | 10 |
| GreyNoise | 2 s | 40 | 5 |
| urlscan | 2 s | 100 | 5 |
| Hybrid Analysis | 2 s | 500 | 3 |
| AbuseIPDB | 1 s | 900 | 10 |
| OTX, hashlookup | 1 s | 500 | 20 |

## Providers and credentials

| ID | Observables | Authentication |
| --- | --- | --- |
| virustotal | hashes, domain, IP, URL | x-apikey |
| malwarebazaar | hashes | Auth-Key |
| threatfox | hashes, domain, IP, URL | Auth-Key |
| urlhaus | SHA256, MD5, domain, IP, URL | Auth-Key |
| otx | hashes, domain, IP, URL | X-OTX-API-KEY |
| abuseipdb | IP | Key |
| greynoise | IP | key (optional) |
| hashlookup | SHA256 | none |
| hybridanalysis | hashes | api-key |
| urlscan | domain | API-Key (optional) |

Create the keys directory using `sudo install -d -m 700 /etc/chimera/keys`.
For each keyed provider replace `<id>` with its ID and run:

```bash
read -rsp 'key: ' k; printf '%s' "$k" | sudo tee /etc/chimera/keys/<id> >/dev/null; sudo chmod 600 /etc/chimera/keys/<id>; unset k
```

MalwareBazaar, ThreatFox and URLhaus share the existing abuse.ch key instead:

```bash
read -rsp 'key: ' k; printf '%s' "$k" | sudo tee /etc/chimera/abusech-auth-key >/dev/null; sudo chmod 600 /etc/chimera/abusech-auth-key; unset k
```

Keys are read at job time, stripped, and sent only in the documented header.
They are never logged or returned; provider echoes are rejected. API and CLI
inventory expose presence only. `drakrun intel providers` shows configuration;
`drakrun intel providers --test` queries the EICAR SHA256 for each configured,
enabled provider (IP/domain-only adapters return unsupported).

## Failure handling and limits

A TCP connection probe to the provider on port 443 has a 3-second timeout.
Requests have a maximum 10-second timeout, verified TLS, HTTPS-only endpoints,
no redirects, and a 2 MiB response cap. Each provider reports not configured,
offline, error (including timeout or bad key), rate limited, unsupported, or ran.
HTTP 401/403 are bad-key errors; 429 is rate limited. Nothing retries in a tight
loop. Failed lookups do not abort other providers or offline matching.

SQLite stores cached results (including not found) for 7 days for hashes and one
day for network observables. Cache hits require no network. SQLite transactions
reserve request slots across workers: VirusTotal is limited to one request per
15 seconds and 500/day; the other adapters conservatively use one per second and
500/day. A limit skips requests instead of blocking a worker. Your provider plan
may require lower limits; consult its terms before enabling. Reports list each
provider's status and counts; cached results count as available results.

`intel-online.json` uses schema `chimera-intel-online/1`, is written atomically
beside static.json, and is copied into portable report evidence. Refresh uses
`POST /api/intel/<id>/refresh`; disabled online intel returns 409. The frontend
polls every five seconds for up to three minutes. Jobs exceeding this window
continue on the worker. Private/reserved, loopback, link-local, multicast and
configured guest network addresses are excluded. Selection is deduplicated and
capped per type (20 by default), with sample hashes selected first.

## Assessment

Intel never becomes a classifier feature and never changes the classifier verdict.
The separate assessment applies these rules in order:

1. A MalwareBazaar or ThreatFox hash match means malicious, basis `known malware`,
   with family when available.
2. VirusTotal with at least 10 malicious engines means malicious. Three through
   nine means at least suspicious, preserving an already malicious classifier.
3. A CIRCL hashlookup known-good match means benign, basis `known software`,
   unless the classifier says malicious.
4. Otherwise retain the classifier label, basis `behaviour model`.

Assessment reasons explain differences. Online matches carry evidence IDs and IOC
sources `intel:<provider>`. No-match results never mean clean. Offline feeds remain
visible even when every online provider is unavailable.
