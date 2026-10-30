---
title: Threat intelligence
group: Concepts
---
# Threat intelligence

After an analysis, CHIMERA checks what it found (the sample's hashes, domains, IPs, URLs, TLS certificates and
JA3 fingerprints) against threat-intelligence sources. Intel is **report context**: it is not a classifier
feature and it never changes the verdict.

> A match attributes an observation to a feed; it does not prove the sample malicious. **No match is never a
> verdict of benign.** Strings found statically are not proof of use: every match says whether the indicator
> came from the sample hash, a static string or a dynamic observation (`observed_in`).

## Offline feeds

Dated local snapshots that analysis, reporting and import use without contacting anyone. The host builds a
bundle from the feed list in `scripts/chimera/intel/feeds.toml` and imports it into
`/var/lib/drakrun/intel/intel.db`:

| Feed | Indicators |
|---|---|
| MalwareBazaar (abuse.ch) | Malware sample hashes with family tags |
| URLhaus (abuse.ch) | Malware distribution URLs |
| ThreatFox (abuse.ch) | IOCs (domains, IPs, URLs) with malware families |
| Feodo Tracker (abuse.ch) | Botnet C2 IP addresses |
| SSLBL certificates and JA3 (abuse.ch) | Malicious TLS certificates and client fingerprints |
| MISP warninglist (public DNS resolvers) | Known-benign infrastructure, so a resolver address is not reported as a hit |

`chimera-intel-update.timer` refreshes the bundle daily on the host. A feed that fails keeps its previous data.
The abuse.ch Auth-Key lives in a root-only file and is substituted into export URLs only for the request itself,
never written to a log or manifest. For an air-gapped host the bundle can be built on a connected machine and
imported with `drakrun intel import bundle.tar.gz`.

## Maltrail attribution

The trails of [Maltrail](https://github.com/stamparm/maltrail), now kept in their own repository
([stamparm/trails](https://github.com/stamparm/trails)), map network indicators to malware families and **APT
groups**: one file per family under `malware/` (`apt_*` files are APT groups), plus `malicious/` and
`suspicious/` lists. `drakrun intel trails-sync` (every six hours through `chimera-trails-sync.timer`) fetches
the new commit, logs what changed and rebuilds an SQLite index (`/var/lib/drakrun/intel/trails.db`); it does not
run while an analysis VM exists. Trail content is under the Maltrail Trails Community Data License, so the
checkout and index stay on the host and are never published.

The `suspicious/` lists also contain bare top-level domains such as `.cc` or `.pw`. A domain that matches only
by such a TLD is shown as a weak "suspicious TLD only" note, never as a family or APT attribution, and strings
found only in the file (not contacted at run time) never match by TLD.

## Online lookups and VirusTotal

With `[intel] online_enabled = true` the host's `drakrun-intel-worker` queries providers in the background after
the analysis. **VirusTotal**, MalwareBazaar, ThreatFox and URLhaus are the usual set; AlienVault OTX, AbuseIPDB,
GreyNoise, CIRCL hashlookup, Hybrid Analysis and urlscan can be enabled under `[intel.providers]`. Each one is
paced to its public API limits.

- Only observables leave the host: hashes, domains, public IPs and URLs. **Samples are never uploaded**; there is
  no upload interface at all.
- Online lookups are opt-in per upload ("online intel"), with the default set by `online_default`. URLs can
  contain sensitive paths, so analysts can opt out.
- `hash_providers = ["virustotal"]` looks up the sample's own hash on every analysis, even without the opt-in;
  only the hash is sent.
- Results are cached (`cache_path`), each request has a timeout of at most 10 s, and at most `max_observables`
  indicators are sent per analysis. Providers can retain what they are asked about.

Guests never need the internet for any of this: lookups run on dom0, after the guest is gone.

## In the report

The threat-intel card shows offline matches, Maltrail families and APT groups, and the online results with the
time of the lookup. Every match carries evidence IDs pointing at the observation it came from, and the
indicators can be exported as `iocs.json` or `iocs.csv` from the CHIMERA report.
