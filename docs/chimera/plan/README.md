# CHIMERA planning package (25 Oct 2026)

Research, audit and plan for the last six days before the 31 Oct presentation. Start with **`roadmap.md`**.
Every claim about this repository cites `path:line`; external claims carry a source URL and a label: **[V]**
verified from a primary source, **[S]** secondary, **[K]** background knowledge not re-verified.

## Documents

| Document | What it answers |
|---|---|
| [`roadmap.md`](roadmap.md) | What we build by 31 Oct, in what order, with an acceptance test each; what we leave for later |
| [`current-state.md`](current-state.md) | What is deployed and working today, test results, data, and the defects this audit found |
| [`ms360-study.md`](ms360-study.md) | MS 360 (Malware Shodhak 360) from the team's screenshots and recordings and its public page: engines, reports, gaps. Background only: the team has no MS 360 access, so it is not a benchmark comparator |
| [`competitive-landscape.md`](competitive-landscape.md) | CERT-PL DRAKVUF Sandbox, CAPE, Cuckoo 3, ANY.RUN, Hybrid Analysis, VirusTotal, Intezer, IntelOwl, Triage, Joe Sandbox; comparison matrix with CHIMERA |
| [`static-engine-design.md`](static-engine-design.md) | Static analyzer audit, tool and YARA ruleset choices (with licences), `chimera-static/2` evidence schema |
| [`classifier-audit.md`](classifier-audit.md) | Data, leakage, the zero-call defect (fixed), score semantics, calibration limits, evaluation protocol |
| [`report-intel-orchestration.md`](report-intel-orchestration.md) | Threat-intelligence design (hash-only, offline-first), `chimera-report/1` report schema, queue flow, analysis modes |
| [`architecture.md`](architecture.md) | Components, data flow, trust boundaries and artifacts as they are today, and the deltas after the roadmap |
| [`hardening-roadmap.md`](hardening-roadmap.md) | Measured evasion results, remaining detections and their causes, future VMI and PERDEDOR work, what never to do |
| [`benchmark-plan.md`](benchmark-plan.md) | A fair, pre-registered comparison of CHIMERA with CAPE (Cuckoo's maintained successor) on the same files under matched settings, and with reports public sandboxes (Triage, ANY.RUN) already published for the same hashes; metrics, statistics, runbook |
| [`testing-strategy.md`](testing-strategy.md) | Test inventory, gaps, contract and security tests, operator smoke tests, freeze checklist |
| [`bibliography.md`](bibliography.md) | All 180 external sources cited above |
| [`evidence/`](evidence/) | Reproducible probe behind the classifier findings and its output |

## Key findings

1. **The core is in place and measured:** Windows and Linux dynamic analysis under DRAKVUF, hardened Windows guest
   (PERDEDOR 100.0, al-khaser 20–21), containment tests passed, classifier and static analysis integrated, 613 unit
   tests green. Two DRAKVUF fixes from this project were merged upstream on 24 Oct.
2. **The classifier said "benign" on runs it could not judge.** Fixed and deployed on 25 Oct (`4696288`); the cause
   also sits in training data (empty benign runs) and needs a change at the next retraining.
3. **Four more honesty defects** remain: an unescaped offline report, static errors logged as success, a static
   fallback that votes benign on files it could not parse, and no YARA rules. All are small and come first.
4. **MS 360 has breadth (APK, URL, PCAP) but separate engines with separate scores and no combined verdict;** its
   dynamic engine is Cuckoo 2.0.7 for `.exe`/`.dll`. CHIMERA's case is depth: VMI monitoring from outside the guest on
   Windows and Linux (Linux uses a small in-guest helper only to launch the sample), measured anti-evasion, and one
   explained verdict across static and dynamic evidence.
5. **The most valuable new feature is one combined, printable report** that links every claim to its evidence,
   followed by analysis modes (static-only, dynamic-only, combined).
6. **Scores are decision scores, not probabilities.** There is not enough CHIMERA malware data to calibrate; the
   evaluation must report abstentions and small-n confidence intervals.

## Decisions needed from the owner

- Approve the roadmap order (P0 before P1, freeze 29 Oct 20:00).
- M5 Stage 1 start, once approved.
- Linux control samples; visibility of the benign dataset repository; whether this package (it discusses MS 360)
  goes to the public repository or stays private.
