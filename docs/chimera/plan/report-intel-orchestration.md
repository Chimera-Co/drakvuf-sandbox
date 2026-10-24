# CHIMERA: threat intelligence, reporting and orchestration

Research date: 25 October 2026. Audience: Group 3; delivery deadline: 31 October 2026.

Scope: source audit and public documentation only. No repository modifications, authenticated requests, sample transfers, service operations or guest execution. Host capacities and deadline are supplied project constraints, not measured here. Proposed behavior is explicitly labelled **Design**; it is not an implementation claim.

Evidence notation: **[V]** primary public source read during this audit; **[S]** secondary source; **[K]** background not re-verified. Repository statements use `path:line`; citations describe this checkout, not necessarily the installed deployment. No secondary product claims are needed below. An unavailable or undocumented quota is recorded as unknown rather than guessed.

## Decision

By 31 October, prioritize truthful partial-result reporting, a host-wide dynamic execution gate, explicit analysis modes, an offline intel adapter, and a complete printable HTML snapshot. Keep online enrichment disabled unless the operator separately establishes permitted access. Do not deploy IntelOwl or MISP on dom0 for this deadline. Never send sample bytes, report files, extracted strings, URLs or network indicators to an enrichment service.

Read alongside the existing project documents: `docs/chimera/ecosystem-and-market.md:1`, `docs/chimera/static-analysis.md:1`, `docs/chimera/classifier-interface.md:1`, `docs/chimera/threat-model.md:1`. They were read first. Source inspection below supersedes older implementation-status prose: for example, per-VM locking and postprocess outcome recording now exist (`drakrun/analyzer/run_tools.py:211`; `drakrun/analyzer/postprocessing/postprocess.py:44`).

## 1. Threat intelligence

### 1.1 VirusTotal v3: lookup is not upload, but is not private

| Operation | Verified interface and meaning | CHIMERA decision |
|---|---|---|
| File lookup | **[V]** `GET /api/v3/files/{id}`, where ID accepts SHA-256, SHA-1 or MD5; requires `x-apikey`. [File report](https://docs.virustotal.com/reference/file-info) | Permit SHA-256 only in an explicitly enabled adapter. |
| URL lookup | **[V]** `GET /api/v3/urls/{id}` returns an existing URL object; accepts the URL identifier or unpadded base64 URL representation. [URL report](https://docs.virustotal.com/reference/url-info) | Exclude. Encoding is not confidentiality; this is not a file-hash lookup. |
| IP lookup | **[V]** `GET /api/v3/ip_addresses/{ip}` returns an IP object. The page warns that queried IOCs are scanned and added to the dataset, accessible to the community. [IP report](https://docs.virustotal.com/reference/ip-info) | Exclude, including public-looking addresses extracted from a private run. |
| Domain lookup | **[V]** `GET /api/v3/domains/{domain}`; the same dataset-inclusion warning appears here. [Domain report](https://docs.virustotal.com/reference/domain-info) | Exclude. Never resolve extracted domains for enrichment. |

**[V]** File objects expose attributes such as last-analysis date, engine results/statistics and first-submission date; some attributes are premium-only. A hash lookup retrieves information about a previously known object. [File object](https://docs.virustotal.com/reference/files)

**Design interpretation:** transmitting only a digest does not transmit the file or cause CHIMERA to upload it. It nevertheless discloses interest in that exact digest, together with request timing and network/account context. Do not describe it as anonymous or confidential. A missing record means “not found”, never “benign”. Lookup failure must never trigger upload, rescan or another provider's sample-download endpoint.

**[V]** VirusTotal describes submission results being shared with examining partners and acknowledges false positives. [How it works](https://docs.virustotal.com/docs/how-it-works) **[V]** Its current privacy notice also describes collection of operational usage information and IP addresses. [SecOps privacy notice](https://cloud.google.com/terms/secops/privacy-notice)

**[V]** Public API: 4 requests/minute and 500/day; no commercial products/services, no business workflows that do not contribute new files, and no multiple accounts to bypass quotas. Premium quotas depend on the licensed service tier; the reference gives no universal numeric premium allowance or public fixed price. [Public versus Premium](https://docs.virustotal.com/reference/public-vs-premium-api) **[V]** The vendor's public/private comparison lists academic/non-commercial use for public access and paid, usage-dependent quotation for private access. [Comparison](https://docs.virustotal.com/docs/difference-public-private)

**Design:** academic project status is not a blanket permission for future commercial deployment. Document intended use before enabling an existing operator-owned key. Do not upload files to satisfy a contribution condition. With this task's no-account/no-key rule, live API access was neither attempted nor validated.

### 1.2 abuse.ch providers: current authentication and quota uncertainty

| Provider | Verified public capability | Limits / access / fit |
|---|---|---|
| MalwareBazaar | **[V]** `POST https://mb-api.abuse.ch/api/v1/`, form `query=get_info&hash=<digest>`; documentation accepts SHA-256/MD5/SHA-1 and returns metadata including first/last seen, tags and optional signature. `Auth-Key` header required. [API](https://bazaar.abuse.ch/api/) | **[V]** List queries such as tags/signatures have default 100, maximum 1,000 results: these are response-size caps, not requests/minute. The page separately mentions a daily file-download limit. A fixed metadata-query rate and a fixed 72-hour lockout were not found in the public page read. [API limits context](https://bazaar.abuse.ch/api/) |
| URLhaus | **[V]** Authenticated API queries URL, host and payload information; payload lookup accepts file hashes. Do not use the separately documented payload download routes. [Lookup API](https://urlhaus-api.abuse.ch/) | **[V]** Community dumps are generated every five minutes and must not be fetched more frequently. An Auth-Key is required; export URLs may contain it. [Community API](https://urlhaus.abuse.ch/api/) No universal lookup requests/minute verified. Hash-to-payload metadata fits online mode; network IOC matching fits local snapshots. |
| ThreatFox | **[V]** Auth-Key required; supports IOC search and hash-based association search. Recent-IOC query accepts 1–7 days, default 3. IOCs older than six months are omitted from API/export since 1 May 2025, though retained in the UI. [Community API](https://threatfox.abuse.ch/api/) | No numeric query-rate entitlement verified. A seven-day response window is not a request quota. Use hash-associated results only online; retain expiry/source times in offline matches. |
| YARAify / hunting | **[V]** Auth-Key required; `lookup_hash` retrieves existing results. API also supports YARA rule queries/deployment and scans; file scanning defaults to sharing submitted files. [API](https://yaraify.abuse.ch/api/) | No numeric request-rate quota verified on that API page. Use existing hash results only, if enabled later. Do not deploy hunting rules, rescan files, unpack remotely or submit files. Local pinned YARA rules are the deadline choice. |

**[V]** The abuse.ch terms, updated 21 October 2026, allow authenticated not-for-profit use subject to query/export limits, allow access restriction for excessive use, and say commercial use of MalwareBazaar/URLhaus/ThreatFox may require subscription. They prohibit high-volume harvesting and restrict use of data to train or improve models without written permission. The terms separately describe YARAify as a CC0 exception without limitations, while its API page still requires authentication and has a generic commercial notice. [Terms](https://abuse.ch/terms-of-use/)

**Design:** treat those YARAify pages as requiring a terms review before deployment, not as permission for unbounded calls. Do not train the classifier on provider-derived labels/content without checking rights. Keep provider results as report context outside classifier features for this sprint. A provider's data must retain its source and redistribution restrictions in exports.

**72-hour warning:** the supplied project warning is operational evidence from the task, not a verified provider guarantee. Neither a global safe query rate nor an exact 72-hour reset was established. Do not turn it into “the API permits X requests”. Proposed defensive policy: on a ban/restriction indication, persist a 72-hour minimum cooldown and require operator review; honor any longer advertised retry interval. Never test the threshold, rotate identities or retry through another endpoint.

**Privacy design:** each live hash query reveals the digest and query context to its provider. Returned URLs may lead to malicious content: render them as text and provider-record references only; do not fetch, preview, expand or follow them automatically. Auth-Key-in-path export URLs must be redacted from logs, metadata and HTML. Offline snapshots avoid per-analysis disclosure but still carry licensing and provenance obligations.

### 1.3 Offline trails, MISP and exchange formats

**[V]** Maltrail matches network observables against trails, including domains, URLs, IPs, IP:port and User-Agent values. Current documentation separates the trail content from the engine. [Maltrail README](https://github.com/stamparm/maltrail) **[V]** Current trail-content licensing permits internal defense and bona fide research/education, while incorporation into third-party products/services or redistributed feeds requires separate permission; previously MIT-published material retains MIT terms. [Trail data license](https://github.com/stamparm/trails/blob/main/LICENSE.md)

**Design:** import a reviewed, dated text snapshot into a local SQLite exact-match index; store snapshot digest, acquisition date, license, source reference and indicator type. Do not assume the engine's license covers the data. No Maltrail daemon or live capture installation is needed. Match parsed CHIMERA observations offline, without visiting any indicator. Normalize domain case and terminal dots; keep URL path/query case; match IP and IP:port separately. Domain suffix matching must be an explicit rule, not an accidental substring match. Shared infrastructure and stale trails remain weak evidence. Do not commit or redistribute the snapshot with this public repository.

**[V]** MISP supports native event, CSV and free-text feeds from URLs or local files, and offers cache/correlate without importing events. [Feeds](https://www.misp-project.org/feeds/) **[V]** Its features include REST/restSearch, MISP JSON, CSV, STIX import/export and sharing/distribution controls. [Features](https://misp-project.org/features/)

**Design:** accept an operator-provided MISP JSON or CSV export as another local snapshot, preserving event UUID, attribute UUID, timestamps, tags, distribution/markings and source. No MISP server is needed for the demo. Source-feed authentication, quotas and licenses remain provider-specific; “listed by MISP” is not a blanket right to redistribute. Reject unknown formats rather than recursively fetching linked resources. Future remote MISP access needs its own credentials and sharing policy; not exercised here.

**[V]** STIX 2.1 represents observables, indicators, observed-data, relationships and bundles; TAXII 2.1 defines a REST exchange protocol with API roots and collections. Neither defines a universal provider subscription, API quota or data-redistribution license. [STIX standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), [TAXII standard](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)

**Design:** export a local STIX bundle; defer a TAXII server/client. A bundle is not proof of indicator validity and does not grant sharing rights. Preserve markings and source references; never turn an arbitrary string extracted from a file into a confident detection indicator.

### 1.4 IntelOwl: valuable later, reject dom0 deployment this week

**[V]** IntelOwl aggregates file/observable enrichment through an API and plugins including analyzers, connectors, pivots and playbooks. [README](https://github.com/intelowlproject/IntelOwl) **[V]** Its installation documentation recommends a dedicated basic deployment with 2 CPUs, 4 GB RAM and 20 GB disk; its Compose deployment includes application/database/Redis/web components. These are recommendations, not measured CHIMERA consumption. [Installation](https://intelowlproject.github.io/docs/IntelOwl/installation/)

**Design judgment:** 4 GB recommended RAM against a 6 GiB dom0 already hosting the web stack, postprocessors and a static container budget is too much operational scope six days before delivery. Deploy no additional orchestrator. A small RQ intel worker reuses existing infrastructure. Future IntelOwl belongs on a separate host with only explicitly permitted observable analyzers enabled; disable file submission, retrieval, automatic pivots and connectors. Its integration does not remove upstream service quotas or license obligations.

### 1.5 Design: bounded `intel` stage

These are proposed local defaults, **not provider entitlements**.

| Setting | Proposed behavior |
|---|---|
| Policy | `intel_mode=offline` default; `off`, `offline`, `online_hash` only. Per-analysis selection is persisted at submission and overrides global online enablement. Global policy may prohibit online; it must never force it. |
| Offline | Read approved snapshots and, where sharing policy permits, prior cached responses. No network fallback, DNS or update during analysis. Distinguish `origin=offline_feed` from `origin=prior_online_cache`. |
| Online | Optional `chimera-intel` queue. Only sample SHA-256 from trusted server hashing; no filesystem path or sample content passed to worker. Offline matching can still run locally. Missing credentials becomes `unavailable`, not anonymous probing. |
| Providers | Adapter allowlist of exact host, path, method and query selector. Permit only metadata lookup. Some read-only APIs use POST; do not confuse HTTP verb with sample upload. Deny multipart/file parameters and all download/rescan/submit routes. |
| Cache | Local SQLite; key `(provider, operation, normalized_sha256, adapter_version)`. Positive hash TTL 7 days; negative TTL 24 h. Preserve immutable analysis snapshot even when shared cache refreshes. |
| Offline freshness | Manifest includes generated/fetched time and expiry. Display stale data explicitly; expired network indicators do not silently remain current. TTLs are local policy, separately configurable per feed. |
| VT throttle | Shared persistent rolling limiter: one request per 16 seconds, maximum 450/day UTC as a conservative local cap; count every attempt, including errors. Never exceed a lower account quota. |
| abuse.ch throttle | Start disabled; proposed shared cap across enabled adapters: one request per 60 seconds, 50/day, pending confirmed access conditions. This does not claim the provider will accept that volume. |
| Deduplication | Single in-flight `(provider, hash)` request across analyses; one response can satisfy multiple opted-in jobs. No eager cross-provider fan-out. |
| Failure | On 429, respect `Retry-After`, stop current work and persist provider cooldown. On 401/403/restriction, disable provider pending review. Timeout/5xx: one delayed retry with jitter at most; never retry inside report rendering. |
| Bounds | 5 s connect / 10 s response budget, 1 MiB JSON response cap, no redirects, normal TLS validation, schema/type checks, bounded strings and lists. 30 s stage deadline; unfinished providers are reported as deferred/unavailable. |
| Separation | Worker has no sample mount, no Xen permissions and no access to management secrets. Egress allows only configured TI endpoints; never relax guest containment or static-container `--network none`. |
| Retention | Restrict local cache to operator; retain minimum normalized facts and permitted source references, not unrestricted provider corpus copies. Credential values never enter cache/export. |

**Design result record:** provider, operation, query SHA-256, status (`hit`, `not_found`, `disabled`, `rate_limited`, `unavailable`, `stale`), checked-at, provider-data-at, expires-at, cache-hit, source-record URL, source/license/marking, normalized facts and warnings. Store provider labels as attributed assertions. A successful HTTP response containing `hash_not_found` is not a positive match; authentication/transport errors are not negative cache entries.

**Presentation:** “VirusTotal: N engines marked malicious of M completed applicable verdicts; last scan DATE; retrieved DATE.” Show harmless, suspicious, undetected, unsupported/error/timeouts separately when present. No universal maliciousness threshold, no fabricated denominator, no “N% probability”. If the denominator cannot be computed consistently, show category counts alone. Keep classifier score, static rule score, local observations and external reputation in separate cards. A not-found hash or zero detections cannot override observed harmful behavior. Disagreement is report content, not something to hide by averaging.

**Acceptance fixtures:** repeated digest uses cache once; opt-out produces zero requests; URL-looking digest rejected; no sample/download route reachable; concurrent requests share rate state; 429 persists across restart; negative lookup expires; malformed/oversize JSON fails closed; stale offline match is visibly stale. All use synthetic identifiers and local mocked responses.

## 2. Reporting audit and proposed final report

### 2.1 What exists today

- **[V]** Upstream v0.21 explicitly added offline HTML analysis reports. [Release](https://github.com/CERT-Polska/drakvuf-sandbox/releases/tag/v0.21.0)
- Process tree is built from `procmon.log`; report process entries include seqid, PID, parent seqid, command arguments and start/exit times (`drakrun/analyzer/postprocessing/plugins/build_process_tree.py:10`). Seqid is the report-local identity to use instead of PID alone.
- Postprocessors run in declared order: split logs, tree/capa/dumps and protocol/file/TTP extractors, Linux behavior, TLS, optional Karton, `generate_report`, classifier, HTML, then index logs (`drakrun/analyzer/postprocessing/plugins/__init__.py:24`). OS-specific plugins are skipped for the other guest (`drakrun/analyzer/postprocessing/postprocess.py:13`).
- TTP report entries carry rule name, `att&ck` data and resolved process seqids (`drakrun/analyzer/postprocessing/plugins/get_ttps_info.py:7`). Socket summaries include connection endpoints and DNS names with process seqids (`drakrun/analyzer/postprocessing/plugins/get_socket_info.py:40`). These are useful IOC inputs, not an already standardized IOC export.
- `report.json` merges metadata, startup/injection information and accumulated report sections (`drakrun/analyzer/postprocessing/plugins/generate_report.py:46`). The classifier writes separate `features.json` and `classification.json` and updates metadata afterward (`drakrun/analyzer/postprocessing/plugins/classify_sample.py:25`). Consequently `report.json.info` can predate classification and final completion metadata.
- HTML embeds metadata plus extra metadata, `report.json`, optional process tree and screenshots in a frontend template (`drakrun/analyzer/postprocessing/plugins/generate_html_report.py:20`). It does not embed `static.json`, `features.json` or `classification.json` as independent offline resources there.
- The UI has summary, process information and screenshots, with live-only general logs/static/files tabs (`drakrun/web/frontend/src/AnalysisReport.jsx:247`). The verdict card is explicitly hidden offline (`drakrun/web/frontend/src/AnalysisReport.jsx:349`). Merely adding static/classifier data to metadata will not display those offline sections.
- The verdict/static components fetch once; 404 conflates not-ready with absent/disabled. Verdicts show combined score, optional family, model and component explanations (`drakrun/web/frontend/src/AnalysisVerdict.jsx:19`; `:78`; `:144`). Add lifecycle-aware polling or final-snapshot reads rather than interpreting every 404 as “pending”.
- Postprocess failures/skips are now recorded in metadata, but only after the plugin loop (`drakrun/analyzer/postprocessing/postprocess.py:44`). The HTML plugin therefore runs before the final complete outcome map is attached. `generates=["report.html"]` also prevents ordinary regeneration while that file exists (`drakrun/analyzer/postprocessing/plugins/__init__.py:109`; `drakrun/analyzer/postprocessing/postprocess.py:35`).

**Audit security finding:** raw `json.dumps(offline_files)` is inserted directly in executable script context (`drakrun/analyzer/postprocessing/plugins/generate_html_report.py:46`). A guest-controlled string containing a closing script tag can cross that context unless separately escaped. Treat as a source-level injection risk requiring a synthetic regression test, not a claim of a demonstrated exploit here. Prefer a script-free escaped report; if JSON is embedded in HTML, escape `<`, `>`, `&` and script-sensitive separators and parse it safely. React text escaping alone does not protect the initial HTML parse.

### 2.2 Design: one canonical snapshot, three renderings

Keep existing `report.json` and endpoints compatible. Add `chimera-report.json` with schema marker `chimera-report/1`; HTML and PDF derive from the same completed revision. A coordinator, not the HTML plugin mid-loop, writes the final snapshot after requested stages settle or reach their deadline. Write temporary files and atomically replace. Late enrichment produces revision 2 with a new digest and timestamp; do not silently mutate a previously downloaded report.

Recommended ordering, consistent in JSON view, HTML and PDF:

1. **Identity and outcome:** analysis UUID, report revision/time, sample SHA-256/size/type; requested mode; overall completeness; short evidence-backed assessment; conspicuous stub-model or missing-stage warning.
2. **Execution and coverage:** requested/actual stages; start/end/duration; guest/platform, image/config/tool/rule/model versions; requested plugins, observed/missing telemetry, injection result, timeout/stall and network policy.
3. **Key findings and correlation:** claim text, severity, observed/inferred/external category, confidence rationale, process/time scope, and evidence IDs. Conflicts appear explicitly.
4. **Static analysis:** type/architecture, hashes, signatures, entropy/packing indicators, imports, local YARA/capa, extracted strings/IOCs and parser limitations. Distinguish potential capability from execution.
5. **Dynamic behavior:** sample-rooted process tree, timeline, files/registry, DNS/connections/HTTP/TLS, screenshots and observed attempts versus confirmed outcomes. Label background/unattributed events separately.
6. **Classifier:** label/score/model/version, components, explanations, input coverage and feature snapshot digest. Never describe an uncalibrated score as probability.
7. **Threat intelligence:** source attribution, exact query, acquisition/provider times, hit/miss/failure, cache/offline status, restrictions and disagreement.
8. **ATT&CK table:** technique/subtechnique ID and name, tactic when sourced, platform, rule/version, observed vs capability-only, process/time, evidence IDs and confidence rationale.
9. **IOCs and exports:** normalized values, type, observed/static/external origin, process/time attribution, source, confidence, markings and suppression reason.
10. **Limitations and evidence manifest:** prominent summary also near the top; artifact inventory with relative paths, byte sizes and SHA-256, truncation/redaction notes and unavailable evidence.

**Design evidence semantics:** an evidence ID resolves to a manifest artifact plus JSON Pointer, log line/event number or PCAP frame selector. Store original file digest and encoding; for compressed logs name the compressed artifact and uncompressed event selector. Add process seqid and UTC/time-offset provenance where available. Artifact links use local allowed paths or stable API IDs; never arbitrary guest-supplied paths. A manifest is an integrity check against later changes, not proof that guest-generated content was truthful.

### 2.3 Design: JSON Schema core for `chimera-report/1`

This compact Draft 2020-12 schema specifies the common envelope and evidence-bearing claims. Stage payloads deliberately remain versioned existing documents; adapters must also validate `chimera-static/1`, `chimera-features/1`, `chimera-verdict/1` or the declared producer schema. A marker alone does not validate nested content. Extension detail records such as IOC/ATT&CK rows are constrained by the normative rules immediately below.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "chimera-report/1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "analysis_id", "revision", "generated_at", "mode", "status", "sample", "stages", "assessment", "claims", "evidence", "attack", "iocs", "limitations", "provenance"],
  "properties": {
    "schema": {"const": "chimera-report/1"},
    "analysis_id": {"type": "string", "format": "uuid"},
    "revision": {"type": "integer", "minimum": 1},
    "generated_at": {"type": "string", "format": "date-time"},
    "mode": {"enum": ["static-only", "dynamic-only", "combined"]},
    "status": {"enum": ["complete", "partial", "failed"]},
    "sample": {
      "type": "object", "additionalProperties": false,
      "required": ["sha256", "size_bytes", "display_name"],
      "properties": {
        "sha256": {"$ref": "#/$defs/digest"},
        "size_bytes": {"type": "integer", "minimum": 0},
        "display_name": {"type": "string", "maxLength": 255},
        "file_type": {"type": ["string", "null"]}
      }
    },
    "stages": {
      "type": "object", "additionalProperties": false,
      "required": ["static", "dynamic", "classifier", "intel"],
      "properties": {
        "static": {"$ref": "#/$defs/stage"},
        "dynamic": {"$ref": "#/$defs/stage"},
        "classifier": {"$ref": "#/$defs/stage"},
        "intel": {"$ref": "#/$defs/stage"}
      }
    },
    "assessment": {"$ref": "#/$defs/claim"},
    "claims": {"type": "array", "items": {"$ref": "#/$defs/claim"}},
    "evidence": {"type": "array", "items": {"$ref": "#/$defs/evidence"}},
    "attack": {"type": "array", "items": {"type": "object"}},
    "iocs": {"type": "array", "items": {"type": "object"}},
    "limitations": {"type": "array", "items": {"type": "string"}},
    "provenance": {"type": "object"}
  },
  "$defs": {
    "digest": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    "refs": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
    "stage": {
      "type": "object", "additionalProperties": false,
      "required": ["status", "reason", "producer", "payload", "evidence_ids"],
      "properties": {
        "status": {"enum": ["ok", "partial", "failed", "timeout", "disabled", "skipped", "unavailable"]},
        "reason": {"type": ["string", "null"]},
        "producer": {"type": "object"},
        "payload": {"type": ["object", "null"]},
        "evidence_ids": {"$ref": "#/$defs/refs"},
        "started_at": {"type": ["string", "null"], "format": "date-time"},
        "finished_at": {"type": ["string", "null"], "format": "date-time"}
      }
    },
    "claim": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "text", "kind", "confidence", "evidence_ids"],
      "properties": {
        "id": {"type": "string"},
        "text": {"type": "string", "maxLength": 4000},
        "kind": {"enum": ["observed", "inferred", "external", "coverage"]},
        "confidence": {"enum": ["high", "medium", "low", "unknown"]},
        "evidence_ids": {"$ref": "#/$defs/refs"},
        "rationale": {"type": "string"},
        "process_seqid": {"type": ["integer", "null"]}
      }
    },
    "evidence": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "artifact", "sha256", "selector", "producer"],
      "properties": {
        "id": {"type": "string"},
        "artifact": {"type": "string"},
        "sha256": {"$ref": "#/$defs/digest"},
        "selector": {"type": "string"},
        "producer": {"type": "string"},
        "size_bytes": {"type": "integer", "minimum": 0},
        "observed_at": {"type": ["string", "null"], "format": "date-time"}
      }
    }
  }
}
```

Normative adapter/finalizer checks beyond that envelope:

- Every referenced ID exists; IDs are unique; non-coverage claims require at least one evidence link. Coverage claims point to stage outcomes where available. References must not escape the analysis directory or name samples, credentials or secret-bearing logs for public export.
- Every ATT&CK row requires `technique_id`, `name`, `basis` (`observed`/`capability`), `rule`, `rule_version`, `process_seqids`, `evidence_ids`, and `confidence`; unknown name/version is explicit null, not invented. Pin ATT&CK vocabulary/version in provenance. A rule match is not proof every mapped action occurred.
- Every IOC requires `id`, `type`, `value`, `origin`, `first_seen`, `last_seen`, `process_seqids`, `evidence_ids`, `confidence`, `markings`, `exportable`, and `suppression_reason`. Use null times when unknown. Do not reuse provider first-seen as this run's observation time.
- Provenance requires report-generator version, code revision, stage tool/rule/model versions, environment/network mode, and a manifest of exported artifacts. Unknown runtime versions remain unknown until the installed host is checked.
- Format assertions must be enabled in the validator. Reject NaN/infinity, absolute/traversal paths, unknown enum values, dangling references and inconsistent requested-stage statuses. Bound payloads/rows/text before rendering.

### 2.4 Correlation without inventing certainty

**Design examples, not observed sample findings:**

| Inputs | Allowed statement | Evidence / caution |
|---|---|---|
| Static suspicious import + attributed API event | “Import suggests injection capability; sample process called this API.” | Static JSON Pointer + apimon event + process seqid; call alone does not prove successful injection. |
| Static URL + attributed DNS/HTTP | “The file contains this URL; this process requested its hostname.” | Preserve exact string separately from normalized IOC and dynamic event; do not infer successful C2. |
| Capa match + mapped technique | “Rule R maps this evidence to technique T; basis: capability/observed.” | Keep rule version, event/dump scope and process association; do not silently upgrade static capability to behavior. |
| Classifier malicious + external family label | “Model M scored X; provider P labels this exact hash F.” | Two attributed assertions, not independent ground truth or automatic family confirmation. |
| Static concern + little dynamic activity | “Static indicators present; limited behavior observed in this environment/time window.” | Show injection/telemetry completeness before suggesting evasion. |

Current classifier feature extraction reports telemetry completeness and scoped network/TTP data (`drakrun/analyzer/classifier/features.py:237`; `:384`; `:431`). Preserve its observed-data scope; do not feed third-party reputation into the same model this week. Record whether a component was unavailable instead of substituting all-zero behavior. An empty registry feature on Linux is unsupported coverage, not evidence of benignness (existing interface description: `docs/chimera/classifier-interface.md:120`).

**Limitations block template:** requested versus observed plugins; guest OS/image and analysis duration; launch success; hard timeout/stall/early exit; static parser failures/truncation; unsupported formats; classifier stub/version/input coverage; network disabled/simulated and whether connections are attempts; background traffic attribution; missing/expired/offline TI; no provider match is not a clean bill; no exhaustive anti-evasion claim. Report absence as “not observed under these conditions”.

### 2.5 IOC export design

- **JSON:** preserve typed IOC rows, evidence IDs and provenance; normalized value plus raw value only where sharing policy permits. Default export excludes local/private addresses, simulator addresses, private paths/usernames, email addresses, secret-bearing URL parameters and background-only observations. Keep an explicit suppression summary.
- **CSV:** columns `type,value,origin,first_seen,last_seen,process_seqids,confidence,evidence_ids,source,markings`. Quote correctly and neutralize spreadsheet formulas beginning `=`, `+`, `-`, `@`, tab or carriage return in every user-controlled field. JSON retains the unmodified canonical value; CSV is a safe presentation export.
- **STIX:** **[V]** STIX distinguishes cyber-observable objects from Indicator patterns and supports Observed Data references, timestamps, markings and external references. [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) **Design:** emit file/domain-name/ipv4-addr/ipv6-addr/url observables plus Observed Data for actual run observations; include Report/Note context as appropriate. Static extraction becomes contextual data, not a fabricated network sighting. Emit Indicator objects only for deliberately curated detection assertions, with valid patterns, `pattern_type`, `valid_from`, producer and markings. Validate IDs, required properties, escaping and object references with synthetic fixtures; bundle creation never publishes it.

### 2.6 HTML and PDF on this host

| Route | Verified capability | Recommendation / practical limit |
|---|---|---|
| Existing browser, print to PDF | **[V]** Browser print styling supports `@media print`, `@page` and print events. [MDN](https://developer.mozilla.org/en-US/docs/Web/CSS/Guides/Media_queries/Printing) | Deadline route: generate a standalone escaped HTML summary with all sections expanded, local fonts/images and no network loads; operator uses Print → Save as PDF. No additional renderer daemon. Actual installed browser/PDF destination was not checked. |
| WeasyPrint | **[V]** Current installation docs require Python plus Pango and other dependencies and provide HTML-to-PDF use. [First steps](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html) | Future optional deterministic server export from script-free HTML. Do not assume `pip install` alone suffices or that the React app will render. Run unprivileged, deny network/file fetching outside an asset allowlist, and cap memory/time. No install attempted. |

**Design:** print is a dedicated document view, not whichever interactive tab is selected. Expand tables/tree, wrap hashes/commands, repeat headings, preserve evidence IDs as text, include page breaks and grayscale-readable severity labels. Show report digest/revision in the footer. A large screenshot set should be capped with links to the evidence manifest. Inspect one complete and one partial synthetic report in PDF; check long paths, missing data, pagination and Unicode. Keep PDF generation away from the VM worker's critical path. Automated Chromium/Playwright installation is unnecessary for this deadline.

## 3. Orchestration: current source behavior

### 3.1 Submission through completion

1. `POST /api/upload` creates a UUID, takes timeout/default, original name, guest OS, startup and plugin options; saves the upload, chmods `0400`, and evaluates file metadata (`drakrun/web/api.py:62`, `:80`). There is no analysis-mode or intel-mode field in `UploadFileForm` today (`drakrun/web/schema.py:14`).
2. Static staging is attempted immediately, before the original can be moved to optional S3; exceptions are logged and do not fail the upload (`drakrun/web/api.py:90`). If enabled, `stage_and_enqueue` copies a separately staged input and queues job `static-<UUID>` on **`chimera-static`** (`drakrun/analyzer/static/worker.py:41`). Root staging uses `0440` root/container-group ownership (`drakrun/analyzer/static/sandbox.py:66`).
3. The API optionally uploads the sample to configured S3 and deletes the local upload, or retains its local path. It constructs `AnalysisOptions`, applies network/screenshot/startup/archive choices and **always calls `enqueue_analysis`** (`drakrun/web/api.py:99`, `:109`, `:144`). S3 is a separate optional transfer path: a no-external-upload policy must explicitly keep it disabled, not merely disable TI uploads.
4. Windows queues to **`drakrun-analysis`**; Linux to **`drakrun-analysis-linux`**. The RQ job ID is the analysis UUID; meta contains options/file metadata (`drakrun/analyzer/worker.py:27`, `:212`, `:220`). The API returns `task_uid` and trims old finished/failed RQ entries beyond the list cap of 100 (`drakrun/web/api.py:54`, `:155`; `drakrun/analyzer/worker.py:271`). This is not disk-artifact retention.
5. A worker is bound to a VM ID. Its OS is CLI/config-selected; `any` consumes both queues, otherwise only its OS queue, with a mismatch rejection in the job (`drakrun/analyzer/worker.py:83`, `:191`). Parallel systemd drop-ins are explicitly examples binding VM 1 to Windows and VM 2 to Linux (`scripts/chimera/systemd/parallel/drakrun-worker@1.service.d/guest-os.conf:1`; corresponding `@2` file `:1`). Their presence is not evidence they are installed.
6. The job creates its analysis directory/log handler, initial metadata and substatus callback, retrieves optional S3 input, then dispatches Windows or Linux analyzer (`drakrun/analyzer/worker.py:107`, `:123`, `:144`, `:153`). Windows copies/injects the selected file/command and runs DRAKVUF with capture/screenshots (`drakrun/analyzer/analyzer.py:293`, `:376`, `:388`). Linux uses its agent for readiness/upload/launch, verifies uploaded SHA-256, then closes the agent during sample execution (`drakrun/analyzer/linux_analyzer.py:188`, `:201`, `:238`). Describe monitoring as VMI with platform preparation/launch helpers; do not imply the Linux path has no guest helper.
7. Both paths use `run_vm`: exclusive per-VM nonblocking flock; normal restore destroys a stale domain, waits for memory admission, restores inside cleanup protection, yields for execution and destroys in `finally` (`drakrun/analyzer/run_tools.py:211`, `:231`). `no_restore` instead yields an already running VM and does not take the normal destroy branch (`:239`).
8. Memory admission serializes **check plus restore**, checks Xen free memory against guest memory plus configured margin, and releases its host lock after restore (`drakrun/lib/memory_admission.py:28`; `drakrun/analyzer/run_tools.py:251`). Defaults: wait 1,800 s, poll 5 s, margin 192 MB (`drakrun/lib/config.py:40`). It does not limit all running VMs to one.
9. After execution/VM context exit, telemetry is summarized, made visible to classification, postprocessing runs, and telemetry is summarized again after artifact transformations (`drakrun/analyzer/analyzer.py:428`; `drakrun/analyzer/linux_analyzer.py:272`).
10. Static job runs its container, always attempts staged-input cleanup, adds job timing, atomically writes `static.json`, removes temporary output, and returns a small summary (`drakrun/analyzer/static/worker.py:52`). The container has no network, read-only root, dropped capabilities, resource and mount controls (`drakrun/analyzer/static/sandbox.py:37`).
11. Classifier postprocess follows JSON report generation. If static is enabled, it waits up to `static.wait_s` for `static.json`, then writes features and invokes the configured model (`drakrun/analyzer/postprocessing/plugins/classify_sample.py:10`). This is a bounded wait, **not an RQ dependency or durable join**. If static arrives later, no automatic reclassification is shown there.
12. Worker catches analyzer `BaseException`, marks failure and rethrows. Its `finally` writes final metadata/time, removes input and optionally uploads artifacts to S3 (`drakrun/analyzer/worker.py:153`). This protects ordinary exceptions; hard process death can bypass it. Setup/download failures before that try are another gap (`:144`).
13. API status uses live RQ meta for nonterminal jobs, otherwise on-disk/S3 metadata; missing final metadata can return 404 (`drakrun/web/api.py:207`). Static has a separate local file endpoint returning 404 until available; report/classification/features/HTML endpoints are separate (`:356`, `:367`, `:377`, `:389`, `:442`). Static reports stay local even in S3 mode (`:384`).

### 3.2 Timeouts and failures: what “finished” does not mean

| Mechanism | Source behavior |
|---|---|
| Requested runtime | Uses supplied timeout or configured default (`drakrun/web/api.py:67`); no universal installed runtime value was read. |
| Dynamic RQ budget | `options.timeout + options.job_timeout_leeway + ceil(config.worker.memory_admission_timeout)`; default leeway 600 s (`drakrun/analyzer/worker.py:238`; `drakrun/lib/config.py:52`). |
| DRAKVUF hard wait | Runtime plus 30 s; terminate then wait 10 s; return code/hard-timeout retained (`drakrun/analyzer/analyzer.py:410`; `drakrun/analyzer/linux_analyzer.py:258`). |
| Static job | RQ budget `timeout_s + 120`; result TTL 24 h (`drakrun/analyzer/static/worker.py:48`). Container uses timeout plus grace, then kill/remove; absent engine or bad output becomes an error document (`drakrun/analyzer/static/sandbox.py:97`). Default timeout 90 s, 2,048 MB, 1 CPU (`drakrun/lib/config.py:104`). |
| Classifier | Default 60 s, static wait default 120 s (`drakrun/lib/config.py:98`, `:118`). Timeout kills model process group; bad/invalid model results become unknown (`drakrun/analyzer/classifier/runner.py:89`, `:121`). Missing model falls back to a labelled stub (`:93`). |
| Postprocessing | Requirements/existing outputs/OS/disabled classifier cause skips; exceptions are logged and processing continues, with outcomes recorded (`drakrun/analyzer/postprocessing/postprocess.py:25`, `:44`). Thus finished RQ status is not complete evidence. |
| Static queue failure | Upload can still succeed; a failed static RQ job may leave no final JSON, causing classifier wait and API 404. The static worker's input cleanup covers job execution but not all enqueue/kill failure cases (`drakrun/web/api.py:92`; `drakrun/analyzer/static/worker.py:41`, `:52`). |

No explicit retry/backoff policy is passed to either enqueue call (`drakrun/analyzer/worker.py:230`; `drakrun/analyzer/static/worker.py:48`). Do not interpret systemd process restart as retrying or completing the failed analysis.

Systemd templates: analysis workers require containment/INetSim/Redis, run a preflight and run as root; restart on failure after 10 s (`scripts/chimera/systemd/drakrun-worker@.service:5`). Static requires Redis, runs separately, has `NoNewPrivileges`, `MemoryMax=3G` and no VM-containment dependency (`scripts/chimera/systemd/drakrun-static-worker.service:4`, `:18`). Web template binds loopback and restarts after 5 s (`scripts/chimera/systemd/drakrun-web.service:11`). These are repository templates; actual enabled units, overrides and cgroup behavior remain unverified.

### 3.3 Design: three explicit analysis modes

| Mode | Requested stages | VM behavior | Classification |
|---|---|---|---|
| `static-only` | Metadata/hash + static; intel per separate policy | Never queue dynamic; never restore/connect to a VM or require guest preflight | Static-capable model only; otherwise unknown/unsupported, never feed zero dynamic features to a dynamic model. |
| `dynamic-only` | Metadata/hash + dynamic; intel per policy | Queue only selected OS; no static staging | Dynamic-capable model; skip static wait regardless of global static setting. |
| `combined` (default) | Static and dynamic plus finalization; intel per policy | One selected guest, not both OSes | Combine only available supported components; preserve partial-failure reasons. |

**API changes:** add enum `mode` default `combined`, enum `intel_mode` default `offline`, and persisted requested/effective stage configuration. Validate before storing/staging. Explicit static-only when static is unavailable returns a clear configuration error; combined may proceed as partial only with that policy displayed. Reject nonsensical static-only execution fields rather than silently using them. Keep guest fields optional for static-only. Clamp runtime/input size through a documented local policy.

**Job model:** create a durable parent analysis record before child enqueues; child IDs `static-UUID`, `dynamic-UUID`, `intel-UUID`, `finalize-UUID`. The parent UUID remains the public ID, not an implicit dynamic job. Track per-stage queued/running/terminal states independently from final report status. Persist requested stages and deadlines atomically; reconcile any partially enqueued submission. Existing list/status endpoints must include static-only parents, which current dynamic-queue enumeration cannot do (`drakrun/analyzer/worker.py:248`).

**Join/finalization:** short, idempotent coordinator checks terminal stage records, not a long VM-worker polling loop. It accepts successful and failed children; it must not depend solely on a success-only RQ dependency. When required stages settle, or their queue/runtime deadline expires, validate available outputs, run a compatible classifier, finalize and render. Stage result identity/hash must match parent. Guard classification/finalization by `(analysis_id, input_revision)` so retries do not duplicate work. Optional intel has its own bounded deadline and cannot hold the VM or prevent base report availability.

**Status semantics:** report `complete` means every requested core analysis stage succeeded with sufficient declared coverage; `partial` means useful evidence exists but requested coverage failed/timed out; `failed` means no usable core analysis result. Optional intel or classifier failure is visible separately and cannot erase static/dynamic evidence. A disabled stage is not pending. UI banner lists missing components even if optional failure does not downgrade core completeness. Preserve existing raw RQ status for diagnostics.

**UI changes:** mode selector beside submit; guest/startup/plugin controls only for modes that execute; independent intel selector with “hash lookup discloses hash to provider”. Show phase badges and queue/admission wait, partial-result banner, component verdicts and print/export actions. Poll only nonterminal stages. Offline reader uses the canonical embedded snapshot with no HTTP requests. Static-only views must not render a fake empty process tree as a successful dynamic run.

### 3.4 Design: partial-failure matrix

| Failure | Required outcome |
|---|---|
| Static enqueue/container fails, dynamic succeeds | Preserve dynamic result; combined is partial; no static wait after terminal failure; classifier explicitly lacks static input. |
| Restore/injection/DRAKVUF fails, static succeeds | Preserve static result; combined partial; dynamic evidence incomplete; do not label lack of behavior benign. |
| Static-only container fails | Failed core result with error/manifest, not “VM queued”; still retain trusted sample identity. |
| Classifier crashes/stub/missing compatible model | Unknown classifier with explicit reason/stub label; retain observations and source report. |
| Intel absent/off/rate limited | Source status and timestamp; no auto-upload, retry storm or “clean”. |
| HTML/PDF renderer fails | JSON remains downloadable; rendering failure separate; retry only rendering, never rerun the sample. |
| Worker hard-killed or Redis record expires | Reconciler marks interrupted/unknown from durable stage records, retains artifacts and refuses automatic VM reuse until cleanup is confirmed. |
| Late static/intel response | New explicit report revision; previous export remains reproducible; never silently change its assessment. |

### 3.5 Design: enforce one dynamic run across the host

Current per-VM flock prevents simultaneous users of the **same** VM; memory admission serializes restores, then releases (`drakrun/analyzer/run_tools.py:211`, `:251`). Two OS-bound workers can therefore overlap execution if memory is sufficient. RAM pressure is not a concurrency control.

Add a host-wide `dynamic-slot.lock` held **before restore through confirmed teardown**, shared by Windows, Linux and evasion execution paths. Keep per-VM lock and memory admission. Fixed acquisition order everywhere: global slot → per-VM → memory-admission/restore; release in reverse order. Use bounded nonblocking acquisition with explicit “waiting for dynamic slot”, not a failed result merely because another job is running. Include slot-wait budget in job timeout; avoid counting the same wait twice when calculating the total.

File locking suits this single host and releases on process death, but that alone is insufficient: a killed worker can leave a live domain after releasing its lock. New slot holder must validate/reconcile managed domains before admitting another run; if safe cleanup cannot be confirmed, mark slot blocked and require operator recovery. Hold the gate for `no_restore` too, or disable that option in ordinary submission. Ensure evasion helpers and direct management entry points use the same gate; no nested second acquisition in the same launch chain. Static/intel/finalization need no dynamic slot.

**Acceptance:** two process-level synthetic jobs for different VM IDs must never overlap their simulated execution/teardown intervals; analysis versus evasion must also serialize. Inject restore/destroy errors and process death: release locks, preserve failed state, and block the next simulated restore until stale-domain reconciliation succeeds. No real VM is required for these unit fixtures.

## 4. Ranked delivery plan

### Do by 31 October: small, testable increments

1. **Truthful final status and printable snapshot first.** Collect current static/classification/postprocess/telemetry data after completion; render escaped standalone HTML and JSON, including partial failures. Tests: offline output contains static + model + failures, makes zero fetches, and safely renders a synthetic closing-script string. Manually inspect browser PDF pagination on synthetic complete/partial reports.
2. **Host-wide dynamic gate.** Extend existing lifecycle lock coverage as above, including evasion and interrupted-run handling. Tests: two OS jobs never overlap; restore/teardown failure cannot admit a second run. Runtime confirmation requires the authorized host operator.
3. **Modes with durable parent status.** Add API enum and route static-only without dynamic enqueue; dynamic-only avoids static and waiting; combined preserves current default. Tests: enqueue spy matrix, static-only list/status, unsupported-model handling and both partial-failure directions. Keep UI changes limited to selector, field visibility and stage banners.
4. **Offline intel + cache/status contract.** One local synthetic feed adapter, opt-out, stale/unknown states, trusted SHA-256 and provenance. Tests: normalization, false suffix matches, expiry and zero network. This is sufficient for the demo's TI claim if described as offline correlation.
5. **IOC JSON/CSV plus evidence manifest.** Test stable values, suppression and CSV formula escaping. Add STIX bundle only if core tests and demo are stable; otherwise explicitly label it future work. Do not claim an export exists until validated.
6. **Optional online hash adapter only after access conditions are resolved.** Implement one provider, persistent limiter/circuit breaker and mocked tests. No new accounts or keys as part of this audit. If access remains unresolved, ship disabled and demonstrate recorded synthetic responses labelled as fixtures; never present them as live results.

Proposed implementation regression command from repository instructions: `cd test && PYTHONPATH=.. ../.venv/bin/python -m pytest -q unit`. Run after implementation changes, plus frontend tests for altered views. This audit made no code changes and did not run that suite. No graph update is needed because code was not modified.

### Future work

- Separate-host IntelOwl/MISP, licensed online enrichment and selective TAXII exchange; no automatic external publication.
- Complete machine-enforced schemas for nested ATT&CK/IOC/provenance records, validated STIX export and reproducible automatic PDF rendering.
- Durable stage reconciliation, queue deadlines/cancellation, resource admission covering static/capa/classification CPU/RAM, input/output quotas and retention cleanup.
- Better event-level attribution and technique mapping, calibrated model scores and explicit model support for missing modalities; independently reviewed labels and terms-compliant datasets.
- Full report artifact signing, environment/image/config attestation and tracked redaction profiles for private versus public reports.

## 5. Verification boundary and handoff

Completed: graph query first; four required project documents read; queue/worker/lifecycle/static/classifier/postprocess/frontend/systemd source audited; primary public documentation read; deliverable written outside the repository. `rg` was unavailable, so file search used `find`/`grep`. Graph query located its graph successfully. Repository status was clean when checked during the audit.

Not performed: code implementation, unit/frontend tests, browser/PDF rendering, provider API calls, quota/ban experiments, authenticated feeds, resource benchmarks, deployments or runtime analysis. No samples or binaries were downloaded/opened/executed, and no content was uploaded.

Authorized host operator still needs to verify: installed revision matches audited source; active units/OS bindings and no bypassing worker; actual global-slot deployment and stale-domain recovery after interruption; effective runtime/postprocess timeout budgets; static-container/cgroup memory against dom0 headroom; containment preflight and S3 disabled under no-upload policy; model/rules/image versions; report escaping/offline completeness; existing browser PDF output. Provider access/terms and the reported 72-hour restriction need administrative confirmation, not root experiments.

Files changed during the audit: this document only; no source files changed. Checks: 369 lines, embedded schema parses as JSON, cited line bounds checked, repository status clean. Full JSON Schema meta-validation was unavailable because the local Python lacks jsonschema; runtime and code tests not run. Anything not done or verified is listed immediately above.
