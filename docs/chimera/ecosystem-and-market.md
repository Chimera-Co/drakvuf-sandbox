# CHIMERA — Ecosystem, Our Delta, and Market Position

**Date:** 2026-10-19 · **Evidence labels:** **[V]** verified this session (command/file/primary page) · **[S]** secondary source (listicle, third-party) · **[K]** general background knowledge, not re-verified. Treat [S]/[K] as leads, not facts for the report.

---

## 1. The stack we stand on (verified from this repo and host)

```
 ┌──────────────────────────── CHIMERA (our fork: Chimera-Co/drakvuf-sandbox) ───────────────────────────┐
 │  React 19 UI (rebranded) · Flask API · evasion API/UI · scoring · PERDEDOR + al-khaser adapters          │
 ├───────────────────────── drakrun = CERT-Polska drakvuf-sandbox v0.21.0 (upstream HEAD 7c328ab) ─────────┤
 │ RQ queue (Redis) · VM lifecycle (xl) · per-VM bridge/dnsmasq/iptables · injector · drakshell (guest helper) │
 │ screenshotter (asyncvnc + Perception) · postprocess: process tree, TTPs, HTTP/socket info, capa, TLS keys  │
 │ profiles: drakpdb (PDB → JSON) · optional S3 (boto3) · experimental Karton plugin (karton-core)             │
 ├──────────────────────────── DRAKVUF v1.1-da982ab (tklengyel/drakvuf, built from /opt/drakvuf) ─────────────┤
 │ 36 plugins compiled in, incl. apimon procmon filetracer socketmon tlsmon memdump regmon syscalls           │
 │ hidsim hidevm cpuidmon envmon wmimon fileextractor  (+ Linux: ebpfmon ptracemon unixsocketmon)             │
 ├──────────── LibVMI df8547f · Volatility3 + dwarf2json (profiles) — DRAKVUF submodules ─────────────────────┤
 ├──────────── Xen 4.19.2 (host, built 2 Sep)  ⚠ DRAKVUF's own submodule pins Xen RELEASE-4.20.1 ──────────────┤
 │ qemu-xen 8.0.5 device model · hvmloader (SMBIOS/ACPI defaults "Xen")                                       │
 └────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Component | Upstream | Pinned/installed | Role in CHIMERA | Notes |
|---|---|---|---|---|
| **drakvuf-sandbox** | CERT-Polska | v0.21.0 (19 Aug 2026), fork base = upstream HEAD **[V]** | Whole pipeline: queue, VM lifecycle, networking, injection, postprocessing, web | v0.19 was a full rewrite (Karton → RQ, local FS storage, new web UI); v0.21 added offline HTML reports, shellexec/runas, network hook scripts, inter-VM traffic drop, experimental Karton plugin **[V]** ([releases](https://github.com/CERT-Polska/drakvuf-sandbox/releases)) |
| **DRAKVUF** | tklengyel/drakvuf | installed `da982ab` (6 Aug 2026); repo submodule pins `f619440` (Nov 2025); upstream head `b2f64d8` (30 Sep 2026) **[V]** | VMI engine, all telemetry | Upstream fixed 3 `hidevm` bugs and added Win11 WMI spoofing on 30 Sep (#1881/#1882), after our build **[V]** |
| **LibVMI** | libvmi/libvmi | `df8547f` (`libvmi.so.0.0.15`) **[V]** | Memory introspection library under DRAKVUF | |
| **Xen** | xen-project | host 4.19.2; DRAKVUF tests against 4.20.1 **[V]** | Hypervisor, altp2m | Version skew works historically but is untested by upstream DRAKVUF CI |
| **Volatility3 + dwarf2json** | volatilityfoundation; tklengyel fork | DRAKVUF submodules **[V]** | Kernel JSON profiles (needed for **Linux** guests) | |
| **drakpdb** | CERT-Polska | 0.2.3 **[V]** | Windows PDB → DRAKVUF JSON profiles | |
| **flare-capa + capa-rules** | Mandiant | 7.4.0 + submodule **[V]** | Capability detection on process dumps (postprocess) | Our "static analysis" is already partly here |
| **karton-core** | CERT-Polska | ≥5.9 **[V]** | Optional distributed pipeline integration | Part of CERT-Polska's karton/MWDB ecosystem **[K]** |
| **RQ + Redis** | rq | 2.9.0 **[V]** | Job queue | One worker per VM |
| **Flask / flask-openapi3 / rq-dashboard** | | 3.0.3 / 4.1.0 / 0.8.7 **[V]** | API, OpenAPI docs, `/rq` | No auth (threat model T6) |
| **asyncvnc, Perception, OpenCV, Pillow** | | **[V]** | Screenshots + de-duplication | |
| **boto3** | AWS | **[V]** | Optional S3/MinIO storage | Not used in our deployment |
| **noVNC, React 19, Bootstrap 5, recharts** | | **[V]** | Live interaction, UI, charts | |
| **PERDEDOR** | clustercoder/perdedor (team) | `df17319` **[V]** | Environment-verification agents (Win PS7, Linux py/C, Android adb) | 45 tests pass **[V]** |
| **al-khaser** | LordNoteworthy (external binary) | `al-khaser_x64.exe` in `alkhaser-provisioning/` **[V]** | Independent anti-VM test suite | Most checks errored on Xen runs **[V]** |
| **INetSim** | inetsim.org | Debian 1.3.2 available, not installed **[V]** | Fake Internet (planned) | |

The broader CERT-Polska ecosystem (karton for pipelines, MWDB for sample storage, malduck for config extraction, mquery for YARA search) is relevant as future integration, not for 31 Oct **[K]**.

## 2. What CHIMERA has actually added on top of upstream (verified diff `7c328ab..sprint/final`)

| Area | Added by us | Status |
|---|---|---|
| Branding/UI | CHIMERA theme, intro page, assets (`01d3677`, `86c1cc3`) | Done (UI only) |
| Evasion verification subsystem | `drakrun/evasion/*` (sandbox registry, guest runner, PERDEDOR + al-khaser verifiers, scoring, HTML/JSON report, storage), `web/evasion_api.py`, 8 React views, CLI `evasion-worker`, `evasion-smoke-test` (`92c6a3e`, `9b7d5e1`) | Implemented; 197 unit tests; runtime results unreliable (al-khaser errors, status bug, not run under DRAKVUF) |
| Analysis core, networking, VM config, hardening | **Nothing**: upstream code and upstream default `cfg.template` | Containment + hardening are the main open work |
| Linux / Android detonation | Nothing | Not started |

**Honest framing for the report:** CHIMERA = *upstream DRAKVUF Sandbox* (credited) + *our evasion-verification and scoring layer* + *(to do) containment, Xen guest hardening and its measured effect*. The novelty must come from the second and third parts and their evaluation, not from the pipeline we inherited.

## 3. Remaining work (aligned with the approved plan)

| # | Item | Why it matters for the claim |
|---|---|---|
| M2 | INetSim + fail-closed firewall (proposal ready) | Without it, no real malware run is defensible |
| M3 | Restore reliability, status bug, per-VM lock, output caps, root-owned deployment + systemd units | "Automated platform" claim needs ≥9/10 reliable runs |
| M4 | Xen hardening profile: `smbios=`, `cpuid hypervisor=0`, `viridian=0`, `xen_platform_pci=0`, non-Xen MAC, realistic vCPU/RAM, devices trimmed, **+ DRAKVUF `hidsim`** (and `hidevm` if we rebuild DRAKVUF ≥ `b2f64d8`) | The research result: baseline vs hardened, **measured while DRAKVUF is active** |
| M5 | Small authorised malware set | Answers the review-2 panel ("no real malware run") |
| S1 | Linux via DRAKVUF-direct (procmon/syscalls/filetracer + dwarf2json) | Promised deliverable; time-boxed |
| M6/M7 | Metrics, report, demo | |

## 4. Market and research landscape

### 4.1 Comparison

| System | Monitoring | Hypervisor | Guest OS | Evasion stance | Open source / on-prem | Evidence |
|---|---|---|---|---|---|---|
| **CHIMERA (target)** | Agentless VMI (DRAKVUF) + optional in-guest verification run | Xen | Windows (Linux stretch) | Hardening + **built-in measurable self-verification** (PERDEDOR/al-khaser) + hidsim | Yes / yes | this repo |
| **DRAKVUF Sandbox** (upstream) | Agentless VMI | Xen | Windows 7/10 | Agentless by design; no built-in hardening profile or verification | Yes / yes | **[V]** docs `getting_started.rst:13` |
| **CAPEv2** | In-guest monitor (API hooking DLL) + agent | KVM typical | Windows (+ Linux partial) | Anti-VM hardening via guides/patches; a 2022 thesis found several evasion techniques and a monitor bug | Yes / yes | **[S]** ([CTU thesis](https://dspace.cvut.cz/handle/10467/101360?show=full)) |
| **Cuckoo 2.x / Cuckoo3** | In-guest agent | VirtualBox/KVM | Windows, Linux | Detectable in-guest agent; 2.x reported dormant | Yes | **[S]**; Cuckoo3 status unverified |
| **VMRay** | Agentless, hypervisor-based | Proprietary | Windows, macOS, Linux | Positioned as best-in-class evasion resistance | No (commercial) | **[S]** ([cybersecuritynews](https://cybersecuritynews.com/best-malware-analysis-tools/)) |
| **Joe Sandbox** | Hybrid | Multiple | Win, macOS, Linux, Android, iOS | Breadth of platforms | Commercial (on-prem option) | **[S]** |
| **ANY.RUN** | In-guest, interactive | Cloud | Windows, Linux, Android | Human interaction defeats some reverse-Turing checks | Commercial cloud | **[S]** |
| **Hatching Triage** | Mixed | Cloud | Multi | High-volume | Commercial | **[S]** |
| **MS-360 (C-DAC/ISEA)** | Aggregator: e-Samarthak (static PE), MobSF (APK), **Cuckoo** (dynamic) | — | Windows, Android (APK), URL, PCAP | No evasion claim seen | Government service, not open | user's lecture notes + `ms360_asset/images` (v4.0 UI) |

Key literature already in `Chimera-docs/Research_Papers`: Ether (2008, hardware-virtualisation transparency), BareCloud (2014, bare-metal comparison for evasive malware), Afianian (2019 taxonomy we use), Melvin (2019, DRAKVUF vs Cuckoo), Spotless Sandboxes (2017, wear-and-tear artefacts, which match PERDEDOR's "aged files / installed programs" detections), Nappa (2021, timing side channels, which is our RDTSC limitation), Sui (2026, AI-environment realism gaps). Also **Gruber & Freiling (2022), "Fighting Evasive Malware: …VMI-Based Human Interaction Simulator"**, the peer-reviewed basis of DRAKVUF `hidsim` **[V]** ([GI DL](https://dl.gi.de/items/f6dd1ed9-db6f-4555-bab4-5bf103c3e5c3/full), [CERT.pl post](https://cert.pl/en/posts/2021/08/hid-simulation-for-drakvuf/)). Add it to the paper's references.

### 4.2 Are we on the right track?

**Yes on architecture, but the claim has to be narrowed and proven.**

1. **Agentless VMI is the right bet for evasion resistance.** It is the approach of the commercial leader positioned on evasion (VMRay) and a long academic line (Ether → DRAKVUF). In-guest-agent sandboxes (Cuckoo, CAPE, MS-360's Cuckoo engine) carry a detectable agent by design.
2. **But agentless isn't invisible.** On our Xen guest today, SMBIOS/ACPI/PCI/MAC all say "Xen" [V]. The defensible contribution is: *a reproducible verification gate + a hardening profile + measured before/after under live instrumentation*, with honest residuals (Xen CPUID leaf 0x40000000 cannot be hidden, timing).
3. **Upstream is healthy** (v0.21.0 Aug 2026; DRAKVUF commits through 30 Sep 2026) [V], so building on it is sound. Avoid deep forks of the core: use the hook points (network hook scripts, config, plugins).
4. **Where we lose to the market** (state these as limitations/future work, don't chase them now): Linux/macOS/Android breadth (Joe, ANY.RUN, MS-360 APK), config extraction (CAPE), interactive analysis (drakvuf-sandbox's noVNC live view already partly covers this), threat intel and URL/PCAP analysis (MS-360).
5. **Where we can credibly win:** (a) agentless + hardened + **self-verifying** before each run; (b) fully local/offline (no sample upload); (c) evidence-backed evasion metrics, which none of the open alternatives ship as a feature.

### 4.3 Answers to the open questions in Context.md

| Question | Recommendation |
|---|---|
| Offer in-guest / out-of-guest / hybrid monitoring choice? | **No for 31 Oct.** Out-of-guest is the thesis. An in-guest agent would reintroduce the artefacts we're removing. Mention hybrid as future work. |
| Separate static / dynamic / combined analysis modes? | **Optional, small.** A "static-only" report (hashes, file type, PE headers, capa) needs no VM. Only if time remains after M6. |
| PERDEDOR + al-khaser integration? | **Yes, already built.** Fix it and run it *through the analysis path with DRAKVUF active*. |
| Threat-intel integration? | **Offline hash lookup only, optional.** Never upload samples (privacy/offline claim). |
| Auto-hardening "suggester/doer"? | **Suggester only, stretch:** map each failed PERDEDOR check to the `xl.cfg` knob that fixes it. No auto-apply. |
| MS-360 study? | One comparison slide (this table), positioned as breadth (MS-360) versus evasion depth (CHIMERA). |

## 5. Risks discovered in this research

- **DRAKVUF/Xen version skew** (installed Xen 4.19.2 vs DRAKVUF's 4.20.1 pin): don't upgrade either before 31 Oct unless a blocker forces it. Record versions in every analysis.
- **`hidevm` on our build** predates upstream fixes: test it before relying on it, or rebuild DRAKVUF at ≥ `b2f64d8` (≈1 h build plus regression run). This is a decision for M4.
- **Market-claim hygiene:** listicle sources [S] must not be cited as evidence in the report. Use vendor docs or papers, or omit.
