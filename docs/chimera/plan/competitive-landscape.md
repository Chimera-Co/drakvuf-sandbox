# Malware-analysis platforms: competitive landscape for CHIMERA

Research date: **25 October 2026**. Audience: Group 3; delivery deadline: **31 October 2026**.

## Reading this comparison

- **[V]** means a primary source was read during this research. Vendor promises are verified *as promises*, not independently validated performance. Source links accompany external facts, including matrix cells through reference links.
- **[S]** means a secondary source; **[K]** means background knowledge not re-verified. Neither is needed to establish the principal findings below.
- **Unknown / U** means not established from the sources read, not that the capability is absent. **N/V** means no implementation verified in the inspected CHIMERA paths. **Conditional / C** means dependent on configuration, engine, entitlement, rules, or guest image.
- Repository evidence uses `path:line`, relative to `chimera-console`. It establishes implementation or a documented historical result, not the current privileged host state. No deployment, sample execution, uploads, accounts, authenticated APIs, or binary downloads were used.
- Scope matters: an input being accepted or identified does not prove it can be detonated. PCAP visibility does not prove TLS plaintext recovery. Memory inspection, process dumps, and a whole-VM memory dump are different capabilities.
- Scores across vendors are not interchangeable probabilities. Recommendations and effort estimates below are this audit's judgments, not vendor claims.

**Recommendation:** keep the final demonstration focused on an explainable local workflow: static evidence, VMI-observed behavior, a qualified combined verdict, downloadable evidence, and reproducible evasion measurements. Spend the remaining days making that chain visible and reliable rather than adding operating systems or external feeds.

## 1. Platform profiles

### CERT-Polska DRAKVUF Sandbox: upstream baseline

1. **Modes and coverage.** [V] Primarily Windows behavioral analysis; the vendor distinguishes Windows-focused Sandbox from the underlying DRAKVUF engine's Windows/Linux capabilities. Do not attribute engine Linux support automatically to upstream drakrun. [CERT documentation][D1]
2. **Static features.** [V] Upstream includes capa processing of dumps and TTP reporting; this is not the same as CHIMERA's new original-file PE/ELF/PDF analyzer. [Upstream source][D3] Original-file FLOSS, similarity hashing, comprehensive format parsers and configuration extraction: unknown in this audit.
3. **Dynamic features.** [V] Monitoring uses VMI from dom0 without installing a monitoring agent. Reports expose PCAP, TLS keys and memory dumps; supported TLS-key extraction is not a guarantee for every TLS implementation. Screenshots and searchable per-process logs are documented. [CERT documentation][D1] [V] Live guest interaction is supported by the upstream frontend. [Frontend][D4]
4. **Verdict.** Unknown: a universal maliciousness scale or calibrated confidence was not verified. TTP/capability evidence should not be relabeled as a calibrated verdict.
5. **Reports.** [V] v0.21.0 includes offline HTML reports, raw analysis-file downloads and experimental Karton integration. [Release notes][D2] PDF/STIX/MISP exporters: unknown.
6. **Intelligence/privacy.** [V] The distribution is locally deployable; it need not be treated as a public sample-upload service. Experimental Karton is a pipeline integration, not proof of comprehensive reputation feeds. [Repository][D5], [release][D2] Exact external egress depends on deployment.
7. **UI worth copying.** [V] v0.21.0 collapses advanced upload options, and permits working-directory selection and shellexec/runas. [Release][D2] Recommendation: preserve these inherited affordances and identify which additions are Group 3's work.
8. **Source/licence.** [V] Source available and self-hostable. The actual licence says **GPL v2 with additional clarifications/exceptions** and separately calls out DRAKVUF's licence; “plain GPL” is incomplete. [Licence][D6]

**What changed since v0.21.0?** [V] The unauthenticated GitHub comparison `v0.21.0...master` returned HTTP 200, `status: identical`, `ahead_by: 0`, `total_commits: 0` during this audit. Thus no post-v0.21.0 default-branch code delta was found; this does not rule out work in PRs, branches or the separate DRAKVUF engine. [Comparison API][D7] [V] The releases page identifies v0.21.0 at `7c328ab`, dated 19 August, with the features above plus network-removal hooks and a 64-bit .NET profile improvement. These are **in** v0.21.0, not later changes. [Releases][D2]

### CAPE Sandbox / CAPEv2

1. **Modes/coverage.** [V] Automated detonation with static and dynamic configuration extraction; README coverage explicitly includes Windows 10 and Windows 11 23H2. Its baseline is Windows API-hook instrumentation. [README][C1] [V] File and URL submissions are supported. [Submission docs][C2] Complete current extension/OS matrix: not verified; avoid borrowing every capability of older Cuckoo releases.
2. **Static.** [V] YARA on unpacked payloads and static/dynamic family configuration extraction are core strengths. [README][C1] [V] Optional FLOSS integration extracts ordinary, stack, tight-loop and decoded strings when dependencies/configuration permit. [FLOSS implementation][C3] capa and similarity-hash coverage: unknown here.
3. **Dynamic.** [V] API hooks plus a programmable debugger support unpacking, instruction tracing and anti-sandbox countermeasures; interactive desktop and system memory dumps are listed. This is not agentless VMI. [README][C1] [V] TLS processing can create a Wireshark-compatible secrets file from monitor/PCAP data. [TLS processor][C4] Universal TLS decryption is not established.
4. **Verdict.** [V] Behavioral/network signatures and YARA contribute to classification. [README][C1] Exact current aggregate score range, confidence calibration and thresholds: unknown; do not import a remembered Cuckoo 2 scale.
5. **Reports.** [V] Documented artifacts include JSON, HTML, MAEC XML, PCAP, screenshots, dropped files and optional `memory.dmp`. [Results][C5] [V] ATT&CK report generation exists when TTP data and its dependency are available. [MITRE reporter][C6] Native PDF/STIX/MISP exports: not verified.
6. **Intelligence/privacy.** [V] Self-hosting is possible. [Repository][C7] Recommendation: audit configured integrations before claiming no sample egress; the existence of a local deployment alone does not establish its configuration. Specific hash/IP feeds and upload policies remain unknown here.
7. **UI.** [V] Submission options include instrumentation and API-log limits. [Submission docs][C2] Recommendation: copy an explicit “analysis options” summary and a prominent configuration/payload section, rather than CAPE's full tuning surface.
8. **Source/licence.** [V] Public source, self-hostable; repository licence text specifies GPL v3. [Repository][C7], [licence][C8]

### Cuckoo 3 — cert-ee/cuckoo3

1. **Modes/coverage.** [V] Files and links; current README says Linux/Ubuntu host with Python 3.10 and **Windows sandboxes**, and warns it is not production ready. This is the cert-ee project, not Cuckoo 2. [README][K1]
2. **Static.** [V] Preprocessing dispatches PE and Office handlers; PE analysis includes certificate metadata and imphash. [Static dispatch][K2], [PE parser][K3] [V] Static YARA rules are loaded from configured rule directories and converted into signatures. [YARA processor][K4] FLOSS/capa and other similarity hashes: unknown.
3. **Dynamic.** [V] Installation requires monitor and stager components to gather behavioral data. This establishes guest instrumentation, not VMI; precise hook/driver internals were not verified. [Installation][K5] [V] Network-routing documentation exists but explicitly warns that it is inherited and unverified. [Routing][K6] TLS recovery, whole-memory dump support, anti-evasion guarantees and interactive control: unknown in this audit.
4. **Verdict.** [V] A signature tracker score and minimum reporting-score gate are present. Exact score scale/calibration: unknown. [MISP implementation][K7]
5. **Reports.** [V] MISP reporter can include signature descriptions, ATT&CK techniques, IPs, domains, URLs and sample hashes. Optional sample attachment and publishing are configuration choices. [MISP reporter][K7] Other export formats, PDF and PCAP download UX: unknown.
6. **Intelligence/privacy.** [V] Local installation and configurable MISP integration are available. [Installation][K5], [reporter][K7] No-upload operation is a configuration property: disable sample attachment/external connectors. Hash-only reputation providers were not individually verified.
7. **UI.** [V] Public dashboard is reachable but returned only a statistics-loading shell; official web-UI documentation says it is in progress. [Dashboard][K8], [UI docs][K9] No detailed UI claims are inferred from that shell. Recommendation: use only an actually loaded report for future visual comparisons.
8. **Source/licence.** [V] Open source and self-hostable, **EUPL 1.2**, not the older Cuckoo GPL label. [README][K1], [licence][K10]

### ANY.RUN

1. **Modes/coverage.** [V] Interactive files/websites; current feature page advertises Windows 7/10/11/Server, macOS, Ubuntu/Debian Linux and Android. These are vendor-listed offerings, not a claim of identical coverage on every plan. [Features][A1]
2. **Static.** [V] The public report inspected has a Static information section and SSDEEP metadata. [Example][A2] Complete parser inventory, YARA/capa/FLOSS availability, packer/unpacking coverage and TLSH: unknown here.
3. **Dynamic.** [V] Browser-based VM interaction, real-time observation and automated interactivity are advertised. [Features][A1] [V] The inspected report records MITM proxy, Fakenet, network, Tor and “Heavy Evasion” options, including whether each was enabled. [Example][A2] Exact instrumentation placement (agent, kernel driver, VMI) is unknown; do not label it from general reputation. Memory-dump scope is also unverified.
4. **Verdict.** [V] The inspected report says “Malicious activity”; the vendor guide also defines “No threats detected.” Numeric probability/confidence: unknown. [Example][A2], [guide][A3]
5. **Reports.** [V] Features advertise HTML, JSON summary, ZIP and process-graph downloads plus STIX/MISP integration. [Features][A1] [V] Public reports support search by domain, IP and ATT&CK technique. [Reports page][A4] PDF is not independently verified as a native export.
6. **Intelligence/privacy.** [V] Threat-intelligence context and plan-dependent analysis privacy are offered. [Features][A1], [plans][A5] Private cloud analysis still involves sending data to the provider; no offline/no-upload deployment was verified.
7. **UI.** [V] Example sections include General, Behavior, MalConf, Static, Video, Screenshots, system events and Network. [Example][A2] Recommendation: copy the visible run configuration and process-to-event navigation; distinguish user intervention from automatic behavior.
8. **Source/licence.** [V] Commercial subscription service. [Plans][A5] Platform source licence and self-hostable engine: not verified; public client integrations do not establish an open engine.

### Hybrid Analysis / CrowdStrike Falcon Sandbox

1. **Modes/coverage.** [V] File/URL submissions; PE, Office/PDF, scripts, ELF/APK and archives listed. Native OS/environment parity is unknown. [FAQ][H1]
2. **Static.** [V] PE/document parsing, YARA, entropy, imphash/authentihash. capa/FLOSS: unknown. [FAQ][H1]
3. **Dynamic.** [V] Runtime plus memory-dump analysis; action scripts. Instrumentation placement and TLS capture: unknown. [FAQ][H1]
4. **Verdict.** [V] Vendor listing shows `/100` and “ambiguous”; calibration unknown. Only indexed listing text was readable. [Listing][H2]
5. **Reports.** [V] Private/standalone: offline HTML, JSON/XML, MAEC, OpenIOC, MISP XML; public availability differs. PDF/STIX: unknown. [FAQ][H1]
6. **Privacy/intelligence.** [V] Standalone can operate without outgoing connectivity. Public confidentiality, retention and feeds: unknown. [FAQ][H1]
7. **UI.** [V] Search pivots include domains, families, fuzzy hashes and artifacts. [FAQ][H1] Recommendation: copy evidence pivots.
8. **Licence.** [V] Licensable standalone package; open engine not established. Current packaging needs confirmation. [FAQ][H1]

### VirusTotal — file report, Behavior, sandboxes and Code Insight

1. **Modes/coverage.** [V] Aggregates static/dynamic results rather than representing one sandbox. In-house engines list Windows, Linux, macOS and Android with per-engine format/feature tables; CAPE Linux includes ELF/scripts/JAR/DEB/wheels. [Sandbox tables][V1] URL analysis is separately documented. [Private scanning][V2]
2. **Static.** [V] Details include type, hashes/similarity hashes, signatures, packer/compiler and format dissection; YARA and configuration extraction are available within documented scanning workflows. [Private scanning][V2] [V] A CAPA entry appears in engine tables. [Sandbox tables][V1] Exact FLOSS use is unknown.
3. **Dynamic.** [V] Instrumentation varies: e.g. Box Of Apples hooks syscalls; other engines have different implementations. PCAP, dumps, screenshots, event logs and ATT&CK support vary by engine. [Tables][V1] A unified VMI/driver claim would be wrong. Universal TLS decryption and uniform anti-evasion guarantees: unknown.
4. **Verdict.** [V] File objects expose multiple engine results and aggregate analysis statistics; sandbox results are separate. Sandbox summaries separately carry normalized labels and a provider confidence field 0–100; an engine detection fraction is not a calibrated probability. [File schema][V3] [V] Behavior objects include sandbox-specific verdict data and highlighted calls. [Behavior schema][V4] Recommendation: keep disagreement visible.
5. **Reports.** [V] Behavior schema covers processes, files, registry, network, IDS and presence flags for HTML/PCAP/memory/EVTX artifacts; availability is explicit, not universal. [Behavior schema][V4] [V] Web report tabs separate Detection, Details, Relations and Behavior, with ATT&CK and IOC enrichment. [Private scanning][V2] JSON API exists; general PDF/STIX/MISP export entitlement was not established. [File API][V5]
6. **Intelligence/privacy.** [V] Hash-based report retrieval needs no file upload, although the API requires a key. [File API][V5] [V] Paid Private Scanning keeps submissions out of the main shared corpus and excludes multi-antivirus partner verdicts; it remains an upload to VirusTotal infrastructure. [Private scanning][V2] Hash lookup still discloses the queried hash.
7. **UI.** Recommendation: copy separation of evidence sources and per-engine availability; retain simple drill-down from a suspicious behavior to its originating sandbox rather than merging all evidence into one unexplained score.
8. **Source/licence.** [V] Hosted service with paid private-scanning entitlement. [Private scanning][V2] No open/self-hostable VirusTotal analysis engine was established.

**Code Insight is separate from detonation.** [V] Vendor describes automated code explanations; supported file documentation lists scripts/source and Office/archive-contained scripts with a **1 MB script limit**. It is not proof that every native executable is decompiled or understood. [Introduction][V6], [supported types][V7] Recommendation: for this deadline, use deterministic evidence text rather than reproducing this feature; explanations require provenance and can be wrong.

### Intezer Analyze

1. **Modes/coverage.** [V] Intezer's current platform material describes static, sandbox, memory and URL evidence processing and recursive unpacking. This is broader platform documentation; do not assume every feature is included in the historical standalone Analyze plan. [Investigation workflow][I1], [current platform][I2] [V] Its ELF tutorial demonstrates Analyze code reuse against Linux Rekoobe. [Tutorial][I3] Complete current OS/file matrix: unknown.
2. **Static.** [V] Central distinction is correlation of reused code with known malicious/trusted code, plus recursive artifact unpacking. [Workflow][I1] Parser/YARA/capa/FLOSS and named similarity-hash inventory: unknown. Code reuse is not synonymous with fuzzy hashing.
3. **Dynamic.** [V] Sandboxing and memory analysis are claimed. [Current platform][I2] Exact agent/driver/VMI method, TLS capture, memory-dump export, interactivity and anti-evasion mechanisms: unknown.
4. **Verdict.** [V] Workflow produces verdict, family/actor/vendor classification and risk; ELF example explicitly shows a malicious verdict and Rekoobe attribution based on code reuse. [Workflow][I1], [tutorial][I3] Numeric confidence/range/calibration: unknown.
5. **Reports.** [V] Workflow describes sandbox reports, URL screenshots and extracted script content. [Workflow][I1] Current Analyze ATT&CK mapping and JSON/PDF/STIX/MISP/PCAP export entitlement: unknown, not inferred from unrelated integrations.
6. **Intelligence/privacy.** [V] Correlation uses vendor and organizational artifact databases. [Workflow][I1] Exact current Analyze privacy, retention, no-upload lookup and private-deployment terms: unknown. Do not treat older community/enterprise announcements as current terms.
7. **UI.** Recommendation: copy side-by-side malicious/trusted/unknown evidence provenance and an explicit explanation of family attribution. Present a “why” trail; code-sharing alone should not become an unexplained accusation.
8. **Source/licence.** [V] Current platform calls its models proprietary. [Current platform][I2] No open engine/self-hostable Analyze distribution was verified. Commercial packaging has evolved; a public product label does not establish current standalone availability.

### IntelOwl

1. **Modes/coverage.** [V] File/observable orchestration, not one native detonation engine. [Usage][O1]
2. **Static.** [V] Plugins include pefile, Doc_Info, YARA, capa, FLOSS, strings and emulation. Hash/unpacking coverage varies. [Usage][O1]
3. **Dynamic.** [V] External sandbox plugins; instrumentation/TLS/dumps/interactivity depend on providers. Emulation is distinct from VM detonation. [Usage][O1]
4. **Verdict.** [V] Normalized DataModels and evaluations; universal calibrated score unknown. [Usage][O1]
5. **Reports.** [V] Results, visualizers, pivots and connectors including MISP. PDF/STIX/PCAP entitlement unknown. [Usage][O1] [V] Local MISP installation is documented. [Installation][O2]
6. **Privacy/intelligence.** [V] Local/remote analyzers coexist; some reputation plugins upload unknown files under TLP CLEAR. Local-only operation requires explicit configuration. [Usage][O1]
7. **UI.** Recommendation: copy tool statuses, provenance and observable pivots; defer deploying the whole stack.
8. **Source/licence.** [V] AGPL-3.0, self-hostable. [Repository][O3], [installation][O2]

### Recorded Future Triage / Recorded Future Sandbox

1. **Modes/coverage.** [V] Static then behavioral stages; formats include PE/MSI, Office/PDF/scripts, macOS applications/Mach-O, Android APK/DEX and multi-architecture Linux ELF/shell. Archives are unpacked statically; selected children can be detonated. SVG is static-only. [Analysis stages][T1], [filetypes][T2]
2. **Static.** [V] YARA, heuristics, container/archive extraction and family-specific configuration extraction. [Analysis][T1] [V] The inspected report shows SSDEEP/TLSH. [Example][T3] capa/FLOSS and full parser inventory: unknown.
3. **Dynamic.** [V] Collects registry/files/network/memory artifacts; Live Monitor supports interaction. [Analysis][T1], [live monitor][T4] [V] Dynamic-report documentation describes process trees, DNS/HTTP/TLS flows, signatures and configurations. [Recorded Future API docs][T5] Exact VMI/agent/driver placement and universal TLS plaintext support: unknown. Do not transfer old Hatching architecture claims without verification.
4. **Verdict.** [V] **1–10** in the scoring guide, signature-driven: 10 known bad, 8–9 likely malicious, 5–7 suspicious, 2–4 likely benign, 1 no potentially malicious behavior observed; N/A for incomplete/error. It explicitly advises reading triggered signatures. [Scoring][T6] This is not a percentage confidence. The newer API reference calls the field 0–10; retain raw values and do not silently normalize the documentation discrepancy. [API][T5]
5. **Reports.** [V] JSON dynamic schema includes processes, signatures, network, dumps/extracts and errors. [Schema][T7] [V] Inspected report has static/task tabs, ATT&CK and print-to-PDF control. [Example][T3] [V] PCAP/PCAPNG retrieval is documented; actual access needs service privileges. [API docs][T5] STIX/MISP export entitlement: unknown here.
6. **Intelligence/privacy.** [V] Public Tria.ge submissions are visible and cannot be deleted; enterprise submissions are private by default and permission-controlled. [FAQ][T8] Private analysis still uploads to the service. Specific external reputation providers/feeds: unknown.
7. **UI.** [V] Example compares Windows 10/11 tasks and separates overview/static/behavioral results. [Example][T3] Recommendation: copy explicit task/run provenance and error states before attempting multi-VM execution.
8. **Source/licence.** [V] Documentation distinguishes public cloud and private/enterprise endpoints. [API home][T9] No open analysis-engine licence or self-hostable engine was verified; an open client library would not establish either.

### Joe Sandbox — brief

1. **Modes/coverage.** [V] Cloud product describes file/URL analysis on Windows/macOS/Linux. [Product][J1] Do not infer current mobile availability from historical feature sheets.
2. **Static.** [V] Product combines static/dynamic analysis and reports strings, domains and file structures. [Product][J1] [V] Inspected report exposes YARA, Suricata and static sections; capa/FLOSS and similarity-hash inventory remain unknown. [Example][J2]
3. **Dynamic.** [V] Optional custom Intel-hardware hypervisor inspection captures syscalls, kernel/user calls and instruction/memory access; vendor markets stealth on VMs and physical systems. It is not Xen-based. [Hypervisor product][J3] [V] Example explicitly says hypervisor inspection **false**: do not attribute the optional feature to every run. [Example][J2] TLS-decryption completeness and default kernel-driver architecture: unknown.
4. **Verdict/report.** [V] Example gives **0–100** score, CLEAN label, signatures, ATT&CK, process tree/behavior graph, network and static views; export menu includes PDF/JSON/STIX/MISP/PCAP/dumps. Menu presence does not establish anonymous download entitlement. [Example][J2]
5. **Privacy/intelligence/licence.** [V] Commercial Cloud Basic/Pro offerings and integrations are documented. [Product][J1] Exact private retention, no-upload deployment, feeds and self-hosting terms were not verified. No open engine licence established.
6. **UI lesson.** Recommendation: use navigable sections and process context, but avoid reproducing the report's complexity. Make analysis mode and inspection backend visible on every report.

## 2. CHIMERA: current implementation evidence

These findings supersede stale “not started” entries in the 19 October ecosystem table (`docs/chimera/ecosystem-and-market.md:54`). They do not certify the live deployment.

| Area | Honest CHIMERA finding | Repository evidence |
|---|---|---|
| Core dynamic backend | Xen/DRAKVUF VMI; inherited upstream behavior/report pipeline must be credited | `docs/chimera/ecosystem-and-market.md:14`; `drakrun/analyzer/run_tools.py:145` |
| Guest coverage | Windows 10 and Debian 12 Linux paths; Linux ELF dispatch and shared console | `docs/chimera/linux-sandbox.md:3`; `drakrun/analyzer/linux_analyzer.py:1` |
| Agentless caveat | Linux uses an in-guest serial Python control/execution helper. VMI telemetry does not make every component agentless | `docs/chimera/linux-sandbox.md:34` |
| Static/combined mode | Static starts beside dynamic upload; no separate static-only submission route verified in reviewed upload flow | `drakrun/web/api.py:90`; `docs/chimera/static-analysis.md:3` |
| Format coverage | Broad magic/type identification; deep parser plugins PE, ELF, PDF. Identifying Office/APK/Mach-O is not detonation/parser parity | `docs/chimera/static-analysis.md:19`; `static_analyzer/chimera_static/analyze.py:42` |
| Strings/IOC/hashes | ASCII/UTF-16, entropy, IOC extraction; MD5/SHA-1/SHA-256, ssdeep/TLSH and PE imphash documented | `docs/chimera/static-analysis.md:20`; `static_analyzer/chimera_static/analyze.py:73` |
| YARA caveat | Matching implementation exists, but checked-in rules directory has only instructions, not an operative ruleset. Built image contents unknown | `static_analyzer/chimera_static/analyze.py:82`; `static_analyzer/rules/README.txt:1` |
| capa/unpacking | Existing capa on dumps; packer indications/embedded-file recognition are not CAPE-style general dynamic unpacking/config extraction | `drakrun/analyzer/postprocessing/plugins/capa_plugin/capa_processor.py:1`; `docs/chimera/static-analysis.md:21` |
| Static isolation | Podman command applies no network, read-only root, dropped capabilities, unprivileged UID, PID/memory/CPU/time limits | `drakrun/analyzer/static/sandbox.py:37` |
| Static verdict | Rule score 0–100; clean/low/medium/high; separate from maliciousness probability | `static_analyzer/chimera_static/analyze.py:14`; `docs/chimera/static-analysis.md:26` |
| Classifier output | malicious/suspicious/benign/unknown, 0–1, family/model/version/explanation and optional component verdicts; disabled/missing/model failure is not “benign” | `docs/chimera/classifier-interface.md:11`; `docs/chimera/classifier-interface.md:39`; `docs/chimera/classifier-interface.md:50` |
| Actual fusion semantics | Deployed-model source describes threshold-centered log-odds fusion: combined 0.5 is at malicious threshold. Do not call this calibrated confidence | `classifier/chimera_clf/deploy_model.py:8` |
| Linux classifier limitation | Dynamic model returns unknown for Linux because it knows Windows behavior. Static component may still contribute | `classifier/chimera_clf/deploy_model.py:83` |
| Process attribution | Features scope to sample subtree; Linux creation count/registry/HTTP/TTP coverage has explicit limitations | `docs/chimera/classifier-interface.md:92`; `docs/chimera/classifier-interface.md:120` |
| Network | PCAP plus attributed DNS/socket data; INetSim responses mean attempts do not prove real C2 success | `docs/chimera/classifier-interface.md:107`; `docs/chimera/classifier-interface.md:117` |
| TLS/memory | Windows report provides conditional TLS key and memory-dump downloads; not established as Linux parity or all TLS stacks | `drakrun/web/frontend/src/AnalysisReport.jsx:365`; `drakrun/analyzer/postprocessing/plugins/generate_wireshark_key_file.py:26` |
| ATT&CK | capa TTPs include ATT&CK and process seqids; Linux classifier features explicitly lack a TTP producer | `drakrun/analyzer/postprocessing/plugins/get_ttps_info.py:7`; `docs/chimera/classifier-interface.md:127` |
| Reports/UI | JSON, process tree, filtered process logs, static tab, combined verdict/components, screenshots, raw artifacts and offline HTML path | `drakrun/analyzer/postprocessing/plugins/generate_report.py:46`; `drakrun/web/frontend/src/AnalysisReport.jsx:17`; `drakrun/web/frontend/src/AnalysisVerdict.jsx:52` |
| Live progress | Status polling once per second and estimated remaining execution time; live VNC documented for both guests | `drakrun/web/frontend/src/AnalysisView.jsx:18`; `docs/chimera/linux-sandbox.md:40` |
| Offline report gap | HTML generator embeds metadata/report/process tree/screenshots, not standalone static/classification JSON; UI hides VerdictCard offline | `drakrun/analyzer/postprocessing/plugins/generate_html_report.py:20`; `drakrun/web/frontend/src/AnalysisReport.jsx:349` |
| Late-result UX gap | Optional static/classification fetch is once per mount; 404 becomes missing with no retry in that hook | `drakrun/web/frontend/src/AnalysisVerdict.jsx:19` |
| Reputation/export gaps | External hash/IP/URL reputation and PDF/STIX/MISP exporters not verified in reviewed report/static paths; optional Karton is distinct | `drakrun/analyzer/postprocessing/plugins/generate_report.py:46`; `drakrun/analyzer/postprocessing/plugins/karton_integration.py:1` |
| Privacy/containment | Local report/sample path; documented fail-closed INetSim guard and worker preflight. Privileged state not rechecked | `docs/chimera/threat-model.md:62`; `drakrun/analyzer/static/sandbox.py:45` |
| Licence | Inherited GPL v2 with additional clarifications/exceptions, separate engine terms; local source/self-hosting | `LICENSE:12`; `LICENSE:4` |

## 3. Comparison matrix

Cells marked **[V]** link to primary sources read now. CHIMERA cells use **R1–R8**, expanded immediately below; “U” is deliberately not a negative claim. Commercial capabilities may require an entitlement. Width is intentional to keep all requested platforms together.

| Capability | DRAKVUF SB | CAPEv2 | Cuckoo 3 | ANY.RUN | HA/Falcon | VirusTotal | Intezer | IntelOwl | Triage | Joe | CHIMERA |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Static + dynamic | Dump/static [V][D3] | Yes [V][C1] | Yes [V][K2] | Yes [V][A2] | Yes [V][H1] | Multi-engine [V][V1] | Yes [V][I2] | Plugins [V][O1] | Yes [V][T1] | Yes [V][J1] | Yes R1 |
| URL input | U | Yes [V][C2] | Yes [V][K1] | Yes [V][A1] | Yes [V][H1] | Yes [V][V2] | Yes [V][I1] | Observable [V][O1] | Yes [V][T8] | Yes [V][J1] | N/V R1 |
| Windows dynamic | Yes [V][D1] | Yes [V][C1] | Yes [V][K1] | Yes [V][A1] | PE listed [V][H1] | Yes [V][V1] | Full matrix U | Provider [V][O1] | Yes [V][T3] | Yes [V][J1] | Yes R2 |
| Linux dynamic | Engine ≠ SB [V][D1] | Full matrix U | Not current README [V][K1] | Yes [V][A1] | ELF listed [V][H1] | Yes [V][V1] | ELF example [V][I3] | Provider [V][O1] | Yes [V][T2] | Yes [V][J1] | Debian ELF R2 |
| macOS / Android | U | U | Windows only [V][K1] | Both listed [V][A1] | APK listed [V][H1] | Both [V][V1] | U | Provider [V][O1] | Both listed [V][T2] | macOS [V][J1] | N/V R2 |
| Monitoring method | VMI [V][D1] | Hooks/debugger [V][C1] | Monitor/stager [V][K5] | U | U | Varies [V][V1] | U | Provider [V][O1] | U | Optional hypervisor [V][J3] | VMI + control helper R2 |
| Deep static parsers | U | Config extraction [V][C1] | PE/Office [V][K2] | Static tab [V][A2] | PE/docs [V][H1] | Multi-format [V][V2] | Inventory U | Plugins [V][O1] | Format-specific [V][T1] | Static [V][J1] | PE/ELF/PDF R1 |
| YARA | U | Payloads [V][C1] | Configured [V][K4] | U | Yes [V][H1] | Yes [V][V2] | U | Plugin [V][O1] | Yes [V][T1] | Yes [V][J2] | Matcher; rules gap R1 |
| capa | Dumps [V][D3] | U | U | U | U | Listed [V][V1] | U | Plugin [V][O1] | U | U | Dumps R3 |
| FLOSS | U | Optional [V][C3] | U | U | U | U | U | Plugin [V][O1] | U | U | N/V; ordinary strings R1 |
| Similarity fingerprints | U | U | imphash [V][K3] | SSDEEP [V][A2] | imphash/authentihash [V][H1] | Yes [V][V2] | Code reuse [V][I1] | Plugin-specific [V][O1] | SSDEEP/TLSH [V][T3] | U | ssdeep/TLSH/imphash R1 |
| Config extraction/unpacking | U | Core strength [V][C1] | U | MalConf tab [V][A2] | Embedded files [V][H1] | Config plugins [V][V1] | Recursive [V][I1] | Plugin-specific [V][O1] | Family-specific [V][T1] | Config section [V][J2] | Embedded recognition R1 |
| Live interaction | Yes [V][D4] | Yes [V][C1] | U | Core [V][A1] | Action scripts [V][H1] | C [V][V2] | U | Provider | Yes [V][T4] | U | noVNC R2 |
| Network capture | PCAP [V][D1] | PCAP [V][C5] | U | Network view [V][A2] | U | C/PCAP [V][V4] | U | Provider | PCAP API [V][T5] | PCAP menu [V][J2] | PCAP R4 |
| TLS plaintext/keys | C/keys [V][D1] | C/secrets [V][C4] | U | MITM option [V][A2] | U | Engine-specific U | U | Provider | TLS flows ≠ decrypt [V][T5] | HTTPS view ≠ decrypt [V][J2] | C/Windows keys R4 |
| Memory evidence | Dumps [V][D1] | Full dump C [V][C5] | U | U | Dump analysis [V][H1] | C [V][V4] | Analysis [V][I2] | Provider | Dumps [V][T1] | Dump menu [V][J2] | C/dumps R4 |
| Verdict scale | U | Scale U | Score, scale U [V][K7] | Labels [V][A3] | /100 [V][H2] | Engine results [V][V3] | Label/risk [V][I1] | Per-tool | 1–10 [V][T6] | 0–100 [V][J2] | Rule 0–100; fusion 0–1 R5 |
| Explanatory evidence | TTPs [V][D3] | Signatures [V][C1] | Signatures [V][K7] | Behavior [V][A2] | Indicators [V][H1] | Behavior [V][V4] | Reuse [V][I3] | Per-tool [V][O1] | Signatures [V][T6] | Signatures [V][J2] | Findings/components R5 |
| ATT&CK / IOCs | TTPs [V][D3] | C/ATT&CK [V][C6] | MISP TTP/IOC [V][K7] | Search [V][A4] | IOC [V][H1] | Both [V][V2] | Mapping U | Tool/connector [V][O1] | Both [V][T5] | Both [V][J2] | Windows TTP + static IOC R3 |
| JSON / HTML | HTML [V][D2] | Both [V][C5] | MISP integration [V][K7] | Both [V][A1] | C/both [V][H1] | JSON + C/HTML [V][V4] | U | JSON/tool [V][O1] | JSON [V][T7] | Both [V][J1] | Both, offline gap R6 |
| PDF | U | U | U | U | U | U | U | U | Print [V][T3] | Yes [V][J1] | N/V R6 |
| STIX / MISP | U | U | MISP [V][K7] | Both [V][A1] | MISP XML [V][H1] | U | U | MISP connector [V][O1] | U | Both menus [V][J2] | N/V R6 |
| Reputation/enrichment | Karton ≠ feed [V][D2] | U | MISP [V][K7] | TI [V][A1] | Specific feeds U | IOC enrichment [V][V2] | Code databases [V][I1] | Core purpose [V][O1] | Specific feeds U | Specific feeds U | N/V R7 |
| Local/no sample upload | Local [V][D5] | Local [V][C7] | Configurable [V][K5] | U | Standalone [V][H1] | Hash lookup [V][V5] | U | Local tools C [V][O1] | Private ≠ local [V][T8] | U | Local design R7 |
| Private hosted analysis | Deployment-specific | Deployment-specific | Deployment-specific | Plan C [V][A5] | Exact terms U | Paid [V][V2] | Current terms U | Self-host policy | Enterprise [V][T8] | Terms U | Local operator R7 |
| Source/self-host licence | GPL2 + terms [V][D6] | GPL3 [V][C8] | EUPL1.2 [V][K10] | Commercial [V][A5] | Licensed standalone [V][H1] | Hosted [V][V2] | Proprietary [V][I2] | AGPL3 [V][O3] | Open engine U | Commercial [V][J1] | Inherited terms R8 |

CHIMERA matrix references:

- **R1:** `docs/chimera/static-analysis.md:19`; `static_analyzer/chimera_static/analyze.py:73`; `static_analyzer/rules/README.txt:1`; `drakrun/web/api.py:90`.
- **R2:** `docs/chimera/linux-sandbox.md:3`, `:34`, `:40`; `docs/chimera/threat-model.md:3`.
- **R3:** `drakrun/analyzer/postprocessing/plugins/capa_plugin/capa_processor.py:1`; `drakrun/analyzer/postprocessing/plugins/get_ttps_info.py:7`; `docs/chimera/classifier-interface.md:127`.
- **R4:** `drakrun/web/frontend/src/AnalysisReport.jsx:356`; `drakrun/analyzer/postprocessing/plugins/generate_wireshark_key_file.py:26`; `docs/chimera/classifier-interface.md:107`.
- **R5:** `docs/chimera/classifier-interface.md:39`; `classifier/chimera_clf/deploy_model.py:8`; `static_analyzer/chimera_static/analyze.py:19`; `drakrun/web/frontend/src/AnalysisVerdict.jsx:52`.
- **R6:** `drakrun/analyzer/postprocessing/plugins/generate_report.py:46`; `drakrun/analyzer/postprocessing/plugins/generate_html_report.py:20`; `drakrun/web/frontend/src/AnalysisReport.jsx:349`. Export “N/V” is limited to these inspected paths.
- **R7:** `docs/chimera/threat-model.md:62`; `drakrun/analyzer/static/sandbox.py:37`; `drakrun/analyzer/postprocessing/plugins/karton_integration.py:1`. Reputation “N/V” is limited to the reviewed analyzer/report paths.
- **R8:** `LICENSE:4`; `LICENSE:12`.

## 4. Where CHIMERA is genuinely different

### A defensible contribution, not a unique invention of VMI

CHIMERA combines inherited VMI telemetry with its own evasion verification, hardened guest profiles, Linux pipeline integration and isolated static/combined reporting. Attribute the first to upstream; present the integration and measured experiments as the contribution. Repository basis: `docs/chimera/ecosystem-and-market.md:52`; `docs/chimera/linux-sandbox.md:13`; `docs/chimera/hardening-design.md:53`; `drakrun/analyzer/static/sandbox.py:37`.

[V] VMI is already upstream's defining design, and Joe markets optional hypervisor inspection. Therefore “the only agentless sandbox” or “VMI is our invention” would be indefensible. [CERT][D1], [Joe hypervisor][J3] The more precise wording is: **“Local malware analysis using DRAKVUF VMI, extended with reproducible environment checks, measured guest hardening and explainable static/dynamic evidence.”** Linux control-helper presence must be disclosed (`docs/chimera/linux-sandbox.md:34`).

### Measured evasion resistance with remaining detections

The hardening document records repeated attached-DRAKVUF arms, CPUID/user-input changes, firmware work and guest realism. H3b records zero PERDEDOR detections while al-khaser still detects 20 checks; later clock correction reintroduces a timing-related detection and changes duration. These are **documented results**, not freshly reproduced measurements (`docs/chimera/hardening-design.md:53`, `:63`, `:173`, `:189`).

This gives Group 3 a stronger research story than a vague “anti-evasion” checkbox: show which checks changed, the instrumentation state, repetitions, residuals and configuration. It does **not** demonstrate universal stealth, superiority against commercial services, or that malicious programs will execute more fully. The document itself warns about teaching to PERDEDOR's thresholds and timing/device residuals (`docs/chimera/hardening-design.md:49`). No competitor-wide absence of similar internal validation was established.

### Local evidence custody and constrained resources

Static isolation has an explicit networkless parser boundary; network simulation and worker preflight are documented, supporting a local workflow without submitting sample bytes to a provider (`drakrun/analyzer/static/sandbox.py:37`; `docs/chimera/threat-model.md:62`). That is valuable for the demo but not unique: [V] CAPE is self-hostable, Falcon has an autonomous standalone package, and IntelOwl supports local tools. [CAPE][C7], [Falcon][H1], [IntelOwl][O1]

The six-day scope should assume the user's stated 16 GiB host and one dynamic run at a time. Do not present throughput or simultaneous Windows/Linux analysis as a differentiator. Repository resource admission/deployment reliability still needs owner confirmation; this audit did not start guests.

### Transparent fusion with a critical score caveat

Component labels, model versions, reasons and unknown/error states are implemented (`docs/chimera/classifier-interface.md:54`). They are useful demonstration assets. However the deployed fusion is threshold-centered, not a calibrated probability; Linux dynamic inference is explicitly unknown (`classifier/chimera_clf/deploy_model.py:8`, `:83`). Show those limitations on screen. Do not turn “0.91” into “91% certainty” or imply an ELF static verdict proves Linux behavioral model coverage.

## 5. Gaps that matter for a final-year demo

Effort estimates: **S** ≤ half a developer day; **M** roughly 1–2 days; **L** ≥3 days or involves substantial runtime/model/architecture risk. Estimates assume one developer familiar with the code; they are not additive commitments. “By 31 Oct” is feasibility, not authorization to implement or deploy.

### Do by 31 October, in this order

| Priority | Gap and concrete acceptance condition | Effort | Feasible? | Evidence / reason |
|---|---|---|---|---|
| P0 | **Score and coverage wording:** display “rule severity 0–100,” “combined decision score 0–1,” model/version, Windows-only dynamic model limitation, and unknown/error independently of benign | S | Yes | Fusion threshold semantics and Linux unknown: `classifier/chimera_clf/deploy_model.py:8`, `:83`; UI currently says combined score: `drakrun/web/frontend/src/AnalysisVerdict.jsx:104` |
| P0 | **Late static/classifier results:** retry pending/404 results with a bounded interval; stop on terminal completion/error, show explicit unavailable state. Acceptance: opening a report before static completion eventually updates without reload | S | Yes | Current hook fetches once and converts 404 to missing: `drakrun/web/frontend/src/AnalysisVerdict.jsx:19` |
| P0 | **Portable report parity:** embed static/classification data into offline output and render it offline; acceptance: one exported report opened without network contains both component evidence and error states | M | Yes if tightly scoped | HTML currently embeds a fixed file set; verdict is hidden offline: `drakrun/analyzer/postprocessing/plugins/generate_html_report.py:20`; `drakrun/web/frontend/src/AnalysisReport.jsx:349` |
| P0 | **Verify operating state before presentation:** owner checks model identity, static-worker/rules image, containment preflight and guest snapshot/profile versions. Produce a small runtime checklist with observed output, never expose secrets | S audit + owner runtime | Yes; owner required | Defaults/model fallback documented: `docs/chimera/classifier-interface.md:11`; static opt-in: `docs/chimera/static-analysis.md:55`; containment: `docs/chimera/threat-model.md:64` |
| P1 | **Honest YARA state:** show loaded-rule count/version or “no rules installed”; use an innocuous custom string fixture to demonstrate plumbing if desired. Do not advertise a bundled detection corpus without confirming it | S | Yes | Checked-in directory only supplies placement instructions: `static_analyzer/rules/README.txt:1`; matcher: `static_analyzer/chimera_static/analyze.py:82` |
| P1 | **Evidence-first summary:** top findings → process/event or static finding; separate attempted network contact under INetSim from successful external communication; display incomplete telemetry near verdict | M | Yes, narrow scope | Features include run completeness and attributed attempts: `docs/chimera/classifier-interface.md:98`, `:117`; findings contain source/evidence: `static_analyzer/chimera_static/analyze.py:26` |
| P1 | **Evasion comparison slide:** pin arms, tool versions/check IDs, repetitions and instrumentation; include remaining detections and the clock caveat. Acceptance: each result is traceable to a documented arm, no “undetectable” headline | S | Yes, from existing documented evidence | `docs/chimera/hardening-design.md:53`, `:173`, `:189`. Raw privileged evidence remains owner-verified |
| P2 | **Submission expectation text:** list what each OS can execute, what only gets generic static analysis, timeout, local storage and simulated-network policy. Keep advanced options collapsed | S | Yes | Identification/parser distinction: `docs/chimera/static-analysis.md:19`; Linux path: `docs/chimera/linux-sandbox.md:3`; [V] upstream already has collapsed options [release][D2] |
| P2 | **Side-by-side report rubric:** demonstrate the same questions across existing public reports and CHIMERA's authorized local results; compare evidence navigation, not detection rates | S | Yes | Recommendations and report URLs below; no upload needed |

Suggested allocation: 25–26 Oct score/late-result/YARA-state work; 27–28 Oct offline parity and evidence navigation; 29 Oct owner validation; 30 Oct report/demo rehearsal; 31 Oct contingency. Prefer removing a stretch item over destabilizing guest images or changing hypervisor versions. No work in this table was implemented during this audit.

### Future work / defer beyond the deadline

| Gap | Effort | By 31 Oct? | Concrete future boundary |
|---|---|---|---|
| Full timeline/search across processes, files and network | M–L | Defer full implementation | Existing per-process log filtering is useful; normalize timestamps and event provenance before adding a cross-source timeline (`drakrun/web/frontend/src/AnalysisReport.jsx:89`) |
| Static-only submission and report route | M | Stretch only, not on critical path | Avoid reserving a VM for unsupported formats; current upload starts both paths (`drakrun/web/api.py:90`) |
| Deep Office/script/LNK/archive analysis and safe recursive extraction | L | No | Currently listed as next plugins, not completed parser coverage (`docs/chimera/static-analysis.md:27`) |
| General unpacking and family configuration extraction | L | No | Treat packer/embedded recognition as evidence, not automatic payload recovery (`docs/chimera/static-analysis.md:21`) |
| FLOSS or broader original-file capa | M–L | Defer | New dependencies/resource budgets need validation; current static layer has ordinary strings, while capa is in dump postprocessing (`docs/chimera/static-analysis.md:20`; `drakrun/analyzer/postprocessing/plugins/capa_plugin/capa_processor.py:1`) |
| Reputation feeds / IntelOwl integration | M–L | No | First design hash-only lookup and explicit remote-consent/egress policy; keep demo local. N/V in reviewed analyzer/report paths (`drakrun/analyzer/postprocessing/plugins/generate_report.py:46`) |
| STIX/MISP and native PDF | M | Defer | Finish complete offline HTML/JSON first; validate schemas before claiming standards compliance (current generator: `drakrun/analyzer/postprocessing/plugins/generate_html_report.py:20`) |
| Linux behavioral model, cross-platform calibration and evaluation | L | No | Requires representative labeled data and validation, not a renamed Windows model (`classifier/chimera_clf/deploy_model.py:83`) |
| More OSes / simultaneous VM throughput / hardware stealth changes | L | No | Keep resource-constrained single-run operation stable; do not extrapolate documented evasion tests to new configurations (`docs/chimera/hardening-design.md:49`) |

## 6. Public reports for side-by-side review

Only open the **report pages**. Do not click sample, dropped-file, unpacked-payload or memory-dump download links. URLs inside a report's evidence are observations, not browsing destinations. No report was submitted or rescanned during research.

| Platform / public URL | What to inspect | Access verification |
|---|---|---|
| [ANY.RUN HTML report](https://any.run/report/baac0199b45076f30e89db5529d30a2914de53dd86bcade322143425fca20605/1518fbbb-e3fd-4c7b-af47-396fd8da99b3) | [V] Run configuration, verdict, static/behavior/network sections, user-intervention caveat | Readable primary report text now; dynamic task linked separately. This is a URL-analysis example, not a matched-file detection benchmark [report][A2] |
| [Triage overview](https://tria.ge/260317-rsg7aaev7x) | [V] Task-specific Windows versions, score 7/10, signatures, ATT&CK and fingerprints | Overview read now; direct static-tab fetch timed out. Use overview first [report][T3] |
| [Joe Linux report](https://www.joesandbox.com/analysis/1811800/0/html) | [V] Process tree, chronological behavior, score 2/100/CLEAN, failed network output, export menu and explicit inspection mode | Readable primary report now. Particularly useful for showing that interesting commands do not by themselves prove successful compromise [report][J2] |
| [VirusTotal file report for the Triage hash](https://www.virustotal.com/gui/file/72d15860160c5143fb82589f8a70c5a8653bcf7e43322f3943661597a7fde432) | Compare Detection/Details/Behavior if a report already exists; **candidate URL only** | Hash comes from inspected Triage report [V][T3]; this VirusTotal page's existence/content was not verified. Do not upload or reanalyze if absent |

Additional discovery entry points, **not verified individual report examples**: [V] [CAPE demo link in its README][C1], [Cuckoo 3 public dashboard][K8], and [ANY.RUN report index][A4]. Hybrid Analysis's public listing direct request failed; no individual HA report is certified here. An unauthenticated standalone Intezer report was not established. Do not create accounts merely to fill the comparison.

Use this rubric (recommendation): Can a reviewer identify the input, OS/image, start/duration and network mode? Distinguish static findings from observed behavior? Trace the verdict to concrete evidence? Identify the responsible process? See ATT&CK/IOC provenance? Recognize incomplete analysis? Preserve the full report offline? Score each 0=absent, 1=partial, 2=clear, and compare report usability only. A different sample, timeout, OS, network or intervention invalidates a detection-quality comparison.

## 7. Verification limits and owner follow-up

- Repository source and docs were inspected read-only after `graphify query`. The earlier ecosystem document was read as historical context; newer implementation docs and code govern this audit's CHIMERA column.
- No unit tests were run: no code changed, and this was research only. No `graphify update` was run because no repository code changed.
- Exact **root checks still required**: active Xen/DRAKVUF/drakrun builds and guest images/profiles; selected hardening arm; `cpuidmon`/`hidsim` runtime activation; containment preflight and fail-closed state for each guest; static worker/image and loaded rules; deployed model/version versus stub and timeout/error behavior; current end-to-end reports including TLS/dump availability; and raw evidence behind hardening/Linux historical results. Those files/services/guests were not accessed here.
- Commercial service internals, present-day entitlements, retention and exact export availability are unknown where noted. No prices or vendor performance numbers are asserted. The matrix is an evidence map, not a laboratory ranking.

## Sources read during this audit

Reference links below resolve every source shorthand used above. Dates/limits belong to the pages read, not guaranteed future product behavior.

[D1]: https://wiedza.cert.pl/systemy-cert-polska/narzedzia-oss/drakvuf-sandbox/
[D2]: https://github.com/CERT-Polska/drakvuf-sandbox/releases
[D3]: https://raw.githubusercontent.com/CERT-Polska/drakvuf-sandbox/master/drakrun/analyzer/postprocessing/plugins/capa_plugin/capa_processor.py
[D4]: https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/drakrun/web/frontend/src/AnalysisLiveInteraction.jsx
[D5]: https://github.com/CERT-Polska/drakvuf-sandbox
[D6]: https://raw.githubusercontent.com/CERT-Polska/drakvuf-sandbox/master/LICENSE
[D7]: https://api.github.com/repos/CERT-Polska/drakvuf-sandbox/compare/v0.21.0...master
[C1]: https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/README.md
[C2]: https://capev2.readthedocs.io/en/latest/usage/submit.html
[C3]: https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/lib/cuckoo/common/integrations/floss.py
[C4]: https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/modules/processing/dumptls.py
[C5]: https://capev2.readthedocs.io/en/latest/usage/results.html
[C6]: https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/modules/reporting/mitre.py
[C7]: https://github.com/kevoreilly/CAPEv2
[C8]: https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/LICENSE
[K1]: https://github.com/cert-ee/cuckoo3/blob/main/README.md?plain=1
[K2]: https://raw.githubusercontent.com/cert-ee/cuckoo3/main/processing/cuckoo/processing/pre/static.py
[K3]: https://raw.githubusercontent.com/cert-ee/cuckoo3/main/processing/cuckoo/processing/static/pe.py
[K4]: https://raw.githubusercontent.com/cert-ee/cuckoo3/main/processing/cuckoo/processing/pre/yara.py
[K5]: https://cuckoo-hatch.cert.ee/static/docs/installing/cuckoo/
[K6]: https://cuckoo-hatch.cert.ee/static/docs/configuring/routing/
[K7]: https://raw.githubusercontent.com/cert-ee/cuckoo3/main/processing/cuckoo/processing/reporting/misp.py
[K8]: https://cuckoo-hatch.cert.ee/
[K9]: https://cuckoo-hatch.cert.ee/static/docs/using/web-ui/
[K10]: https://github.com/cert-ee/cuckoo3/blob/main/LICENSE
[A1]: https://any.run/features/
[A2]: https://any.run/report/baac0199b45076f30e89db5529d30a2914de53dd86bcade322143425fca20605/1518fbbb-e3fd-4c7b-af47-396fd8da99b3
[A3]: https://any.run/cybersecurity-blog/how-to-use-anyrun/
[A4]: https://any.run/malware-reports/
[A5]: https://any.run/plans/
[H1]: https://www.hybrid-analysis.com/faq
[H2]: https://www.hybrid-analysis.com/submissions/sandbox/files
[V1]: https://docs.virustotal.com/docs/in-house-sandboxes
[V2]: https://docs.virustotal.com/docs/private-scanning
[V3]: https://docs.virustotal.com/reference/files
[V4]: https://docs.virustotal.com/reference/file-behaviour-summary
[V5]: https://docs.virustotal.com/reference/file-info
[V6]: https://blog.virustotal.com/2023/04/introducing-virustotal-code-insight.html
[V7]: https://docs.virustotal.com/docs/codeinsight-supported-files
[I1]: https://intezer.com/blog/how-does-intezer-investigate-alerts
[I2]: https://intezer.com/blog/how-intezer-works
[I3]: https://research.intezer.com/docs/elf-malware/part2/
[O1]: https://intelowlproject.github.io/docs/IntelOwl/usage/
[O2]: https://intelowlproject.github.io/docs/IntelOwl/installation/
[O3]: https://github.com/intelowlproject/IntelOwl
[T1]: https://tria.ge/docs/analysis/
[T2]: https://tria.ge/docs/cloud-api/filetypes/
[T3]: https://tria.ge/260317-rsg7aaev7x
[T4]: https://tria.ge/docs/live-monitor/
[T5]: https://docs.recordedfuture.com/reference/sandbox-get-dynamic-report
[T6]: https://tria.ge/docs/scoring/
[T7]: https://tria.ge/docs/cloud-api/dynamic-report/
[T8]: https://tria.ge/docs/faq/
[T9]: https://tria.ge/docs/
[J1]: https://www.joesecurity.org/joe-sandbox-cloud
[J2]: https://www.joesandbox.com/analysis/1811800/0/html
[J3]: https://www.joesecurity.org/joe-sandbox-hypervisor
