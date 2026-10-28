# Maltrail attribution

The report attributes network indicators to malware families and APT groups with the trails of
[Maltrail](https://github.com/stamparm/maltrail). Since 2026 the trail content lives in its own repository,
[stamparm/trails](https://github.com/stamparm/trails): `malware/` (one file per family; `apt_*` files are APT
groups), `malicious/` and `suspicious/` (dynamic DNS, parking, sinkholes, TLDs and the like). `# Aliases:` lines
name other names of a family; each `# Reference:` block cites the source of the entries below it. On 28 Oct 2026
it held about 2.0 million indicators in 3,198 files, 342 of them APT groups.

## Licence

New trail content is under the Maltrail Trails Community Data License 1.0: internal defensive use and research
are free; other uses need written permission. CHIMERA keeps the data on the host: the checkout and the index are
never committed, bundled or published. Each sync records the SHA-256 of `LICENSE.md`; a change is logged as
`license_changed` and printed by `drakrun intel trails-sync`, and should be read before the next use.

## Sync (`drakrun intel trails-sync`)

`chimera-trails-sync.timer` runs `chimera-trails-sync.service` every six hours (upstream publishes about four
times a day). The service:

1. clones `https://github.com/stamparm/trails.git` shallow into `[intel] trails_checkout`
   (`/var/lib/chimera-intel/trails`), or fetches the new commit (depth 1, HTTPS only, no hooks);
2. logs what changed to `trails-changes.jsonl` next to the checkout: commit range, files changed, lines added
   and removed per file, and up to 25 indicators added to each APT trail;
3. resets the checkout to the new commit, drops the old one, and rebuilds the SQLite index at
   `[intel] trails_db_path` (`/var/lib/drakrun/intel/trails.db`, about 100 MB, about 30 s) into a new file
   that replaces the old one atomically.

The service does not run while an analysis VM (`vm-N`) exists: the rebuild takes about 30 s of dom0 CPU, which
would disturb timing measurements. Batches with real malware run with Wi-Fi off, so the fetch fails then and
the last index stays in use. Attribution is off until `trails_db_path` is set.

## What is indexed

Domains (a trail matches the domain and its subdomains), IPs, `IP:port` pairs (an `IP:port` observation also
matches a trail on its IP), CIDR ranges, `host/path` URLs, host-less request paths (`/gate.php`; a trail ending
in the query, such as `/check.php?id=`, matches requests whose query starts with it) and TLDs (`.onion`).
Regular-expression trails and malformed lines are counted as skipped, not indexed.

## Matching and presentation

The intel stage matches the network indicators produced by the sample's own process tree, traffic no process
can be tied to, and the URLs, domains and IPs in the file's strings. Traffic of other guest processes is left
out. Matches go to `intel-attribution.json` (hashed, with an evidence ID per match), to the IOC export with
`source = "maltrail:<category>/<file>.txt"`, and to the report card's "Maltrail attribution" table (family,
APT, aliases, indicators, where observed, references). Malware and malicious families also become claims
("… is listed in Maltrail's lazarus trail (APT group)") of kind `inferred` and are listed in
`assessment.attribution` and the assessment text. Suspicious trails are shown but do not name a family.

Attribution never changes the label: a listed indicator ties the run to a family, but shared hosting, sinkholes
and reused infrastructure can make that wrong, and INetSim answers every DNS query, so a contacted domain shows
what the sample tried, not what a real server returned.
