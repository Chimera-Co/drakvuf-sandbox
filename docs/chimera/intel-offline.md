# Offline threat intelligence

CHIMERA correlates observations with dated local snapshots. Analysis, reporting,
import and status do not contact providers, resolve domains or visit indicators.
Only the separately invoked connected-host builder has HTTP code. Intel is report
context, excluded from classifier features and report completeness.

A match attributes an observation to a feed; it does not prove maliciousness.
Shared infrastructure, false positives and old records need analyst review. **No
match in the offline feeds is not a verdict of benign.** Static strings are not
proof of use. `observed_in` distinguishes sample hashes, static strings and dynamic
observations. Dynamic correlation covers the report's network observations,
including records without process attribution; inspect the underlying report
before attributing a connection to the sample.

## Air-gap workflow

1. On a separate connected update host with the package installed, review the
   provider terms and `scripts/chimera/intel/feeds.toml`. Store the operator's
   abuse.ch Auth-Key in a restricted file outside the repository. Do not put a key
   in a shell argument, environment variable, feed list or unit file. Since 2026
   abuse.ch serves its exports only at `https://<service>-api.abuse.ch/v2/files/exports/<key>/...`,
   so `feeds.toml` holds the placeholder `{auth_key}`: the builder substitutes the
   key (which must match `[A-Za-z0-9_-]{16,128}`) only for the request itself, only
   on `*.abuse.ch`, and never writes the resulting URL to a manifest or log.
2. Build a daily snapshot (weekly is possible with longer reviewed expiry limits):

   ```sh
   python scripts/chimera/intel/build_bundle.py \
     --feeds scripts/chimera/intel/feeds.toml \
     --output /srv/chimera-intel/bundles \
     --abusech-key-file /srv/chimera-intel/auth-key \
     --previous /srv/chimera-intel/bundles/chimera-intel-20261024T0200Z.tar.gz
   ```

   Omit `--previous` on the first run. Select the last trusted bundle on subsequent
   runs. A failed feed retains its previous normalized data and original expiry,
   with `failure` in its manifest entry. A failure without previous data appears
   in the manifest's `failures` list. Exit status is nonzero when all feeds fail;
   retained data can still be transferred after reviewing that failure. A 304
   retains the original acquisition date and expiry rather than claiming a new
   observation. No retries occur. Each feed makes at most one GET, with a 60-second
   timeout, verified TLS, conditional headers when known, and a 200 MiB default
   response cap (`--max-feed-bytes`, or per-feed `max_bytes`). Redirects are refused,
   including same-host redirects. Review endpoints that require redirects or
   account-specific export access before deployment. Live endpoint compatibility
   has not been verified in the offline development environment.
3. Transfer the dated `.tar.gz` **and** `.tar.gz.sha256` using approved removable
   media. Keep provider data and bundles out of this public repository. The checksum
   detects corruption; it is not a signature or proof of trusted origin. Authenticate
   the media/bundle through your deployment's trusted transfer procedure.
4. On the sandbox, configure:

   ```toml
   [intel]
   enabled = true
   db_path = "/var/lib/drakrun/intel/intel.db"
   max_bundle_bytes = 209715200
   ```

   Then run:

   ```sh
   drakrun intel import /media/update/chimera-intel-20261025T0200Z.tar.gz
   drakrun intel status
   ```

   Import verifies the optional adjacent checksum, schema, normalized-file digests,
   counts and typed records; rejects nonregular, duplicate, nested/traversal and
   oversized archive members; and creates a separate SQLite database before atomic
   replacement. The import cap covers total uncompressed members and compressed
   input, not only a single feed. A failed import leaves the previous database in
   place. The database retains the last three imported manifests. Temporary databases
   start with mode 0600. Run import as the account used by the readers, or have the
   authorized host operator establish the required group permissions after each
   import. Verify worker and web read access before enabling intel.

The example service and timer in `scripts/chimera/intel/` run as an unprivileged
`chimera-intel` account on the **connected update host only**. They are templates,
not installed by this work. Provision that account, checkout/virtual environment,
restricted key file and output directory separately. Adapt `ExecStart` to include
`--previous` pointing to the last successful snapshot if retention is wanted.
The timer uses `OnCalendar=daily`, `RandomizedDelaySec=1h` and `Persistent=true`.
For weekly updates use `OnCalendar=weekly` and explicitly review `max_age_days`;
the two-day Feodo expiry will otherwise correctly show stale between updates.

## On the CHIMERA host (25 Oct 2026)

The host has internet and builds its own bundle every day: `chimera-intel-update.timer` (02:30 plus up to 30
minutes' random delay, `Persistent`) runs `scripts/chimera/intel/update-host.sh`, which builds a bundle from
`/opt/chimera/src` with the previous one as `--previous`, imports the newest and deletes bundles older than 14
days. The service is hardened like the other CHIMERA units. The `chimera-intel-build.*` units remain for a
separate air-gapped update host.

A finished analysis can be matched again against the current bundle with **Re-check offline feeds** on the
report (`POST /api/intel/<id>/recheck`, queued on the intel worker); it rebuilds the report and the Threat intel
card.

## Feed catalog and supported formats

The committed catalog contains metadata and URLs only, never feed contents.
All endpoints and rights require operator review on the connected host.

| Feed | Format / indicators | Expiry | License / terms note |
| --- | --- | --- | --- |
| MalwareBazaar | CSV; SHA256, MD5, SHA1 | 7 days | abuse.ch terms; authenticated access |
| URLhaus | CSV; URLs | 7 days | abuse.ch terms; authenticated access |
| ThreatFox | JSON export; typed hashes, domains, URLs, IPs and IP:port | 7 days | abuse.ch terms; authenticated access; export scope may omit older records |
| Feodo Tracker | IP blocklist JSON; IP and IP:port | 2 days | Review provider feed and redistribution terms |
| SSLBL certificates | CSV; certificate SHA1 | 7 days | Review provider feed and redistribution terms |
| SSLBL JA3 | CSV; JA3 MD5 | 7 days | Review provider feed and redistribution terms |
| MISP warninglist | Warninglist JSON; benign domain/IP suppression | 30 days | Review upstream list-specific license and provenance |
| Operator text feed | One indicator per line, `format = "text"`, one declared `indicator_types` entry | Operator defined | Must supply license/terms note and source URL |

abuse.ch terms restrict use to permitted not-for-profit activity, prohibit
high-volume harvesting, and prohibit training or improving models with the data
without written permission. Commercial use and redistribution may require separate
permission or subscription. Authentication does not grant unrestricted use.
Do not train the classifier with feed labels/content. MISP warninglist inclusion
is not a blanket redistribution license. Feed `license` notes travel with the bundle
and report provenance; retain them when sharing a report.

The parser consumes CSV/JSON/text exports, not sample files or sample-download
endpoints. Unsupported formats fail without following linked resources. Auth-Key
is sent only in the `Auth-Key` header to an explicitly configured abuse.ch host;
missing credentials fail that feed. The builder does not log exception bodies or
response contents and rejects output containing the supplied key. URLs with
userinfo, query strings or fragments are refused by the HTTP fetcher to prevent
credential-bearing source URLs. Raw response SHA256 is retained for acquisition
provenance; the raw download is not bundled. `normalized_sha256` verifies each
JSONL file's bytes on import.

## Matching and presentation

Hashes are lowercase and length checked. Domains use IDNA, lowercase and remove
terminal dots. URL scheme and host are normalized; path, query and fragment case
are preserved. IPv4/IPv6 use `ipaddress`; IPv6 endpoints use `[address]:port`.
IP and IP:port remain different keys. Domain matching is exact unless an individual
feed explicitly declares `match_subdomains = true`; that rule matches only parent
labels, never substrings. Warninglists suppress network matches on exact hosts/IPs
(and parent domains only when explicitly enabled). Hash matches are never
suppressed. Suppressed entries retain their feed and allowlist names.

The intel stage reads hashes and static IOCs from `static.json` (or the static
snapshot in `features.json`), metadata/report sample hashes, DNS, HTTP, connection
endpoints and available TLS SNI/JA3/certificate hashes. It never adds feed facts to
features. Matches and suppressed lists are each capped at 500; checked counts
continue over all unique observations per origin. Feed expiry is evaluated when
the report snapshot is built. Old reports retain their original freshness state;
import does not rewrite previous analyses.

Status is `unavailable` when disabled, missing or unreadable, `stale` when every
feed is expired, and `ok` otherwise, including zero matches. Mixed freshness is
shown per feed. Partial feed acquisition failures remain visible in feed metadata.
Every match has an evidence reference into the hashed `intel-evidence.json`
artifact and appears in the IOC export with `source = "intel:<feed>"`.
`GET /api/intel/<task_uid>` serves the saved report stage, returning 404 before a
report exists. The analysis card displays freshness, observation source, family,
tags, dates and plain-text references with copy buttons. It never follows a
reference, previews it or resolves an indicator. Standalone legacy embedded pages
without a supplied intel snapshot show missing feeds and make no intel requests.

## Verification boundary

Unit tests create small synthetic feeds in temporary directories and prohibit
socket use. HTTP behavior is tested with in-memory response doubles. No live feeds,
keys, malware samples, VMs, services or privileged paths were used.

The authorized host operator still needs to check actual provider access and
current terms on the update host; schedule/user/path permissions; trusted media
transfer; database import and worker/web read permissions at the configured
production path; and intel rendering for an existing authorized analysis. No
installation, service restart, deployment or analysis execution is included here.
