# CHIMERA testing strategy — 25–31 October 2026

Research/audit deliverable; proposed additions below are not implemented. Prioritize trustworthy reports, containment and a reproducible demo over new feature breadth. Repository claims cite `path:line`. External product claims, where used, carry [V]/[S]/[K] and a source URL; no external testing service is needed.

## 1. What was run

From the repository root, ran exactly:

```sh
.venv/bin/python -m pytest -q test/unit --confcutdir=test/unit -p no:cacheprovider
```

Final count verbatim:

```text
613 passed in 13.09s
```

The suite does not establish live Xen, firewall, container or classifier-model correctness. `test/unit/conftest.py:1` describes offline fixtures/config isolation. No VM/service/analysis/container was started for this audit; no binaries or malware samples were downloaded, opened or executed. Other suites below were surveyed, not run. No source edits were made. Initial git status showed untracked `docs/chimera/plan/`; preserve it.

## 2. Existing coverage and gaps

| Surface | Existing tests/evidence | Interpretation / next check |
|---|---|---|
| Offline backend `test/unit/` | Parser/adapter, scoring, report/API, guest runner, lifecycle, memory admission/CPU pinning, queue/OS dispatch, Linux postprocessing/dumps, TLS, classifier/static and M5 tests. Representative fixtures: `test/unit/conftest.py:39`; static fake engine: `test/unit/test_static.py:20`; report tests: `test/unit/test_report_generation.py:35`. | 613 passed in this command. Fakes prove decisions and artifact transformations, not actual hypervisor/container enforcement. Keep additions beside existing tests in `test/unit/`. |
| Classifier adapter | Synthetic source reports test schema shape, subtree/window filtering, repeats, aliases and hook allowlist (`classifier/tests/test_cape_adapter.py:24`, `:33`). | Shape equality alone is not full semantic validation or classifier accuracy. Add malformed and ambiguous-root cases. |
| Classifier packaging | Runner/features/PCAP/hooks/deploy synchronization and vendored feature extractor equality (`classifier/tests/test_in_sync.py:20`, `:39`, `:47`). | Run in classifier's intended environment; record import skips as missing coverage. Do not refresh deploy artifacts merely to hide drift. |
| Classifier deployed model | Runner verdict, unknown on unsupported/empty input, static/dynamic fusion, malformed static input (`classifier/tests/test_deploy.py:26`, `:64`, `:73`, `:107`). | Entire module skips if deployed model absent (`:19`). A green skipped module is not a tested model; capture model hash and package versions. |
| Static analyzer | PE/ELF features, crafted PDF/script bytes, mismatched extensions, IOCs, malformed bytes, symlink/directory refusal, file modes and CLI exits (`static_analyzer/tests/test_analyzer.py:38`, `:57`, `:101`, `:108`, `:118`, `:127`). | Requires analyzer dependencies unavailable in ordinary dev venv per task context. Not attempted here; do not invent a failure transcript/count. Fixtures are referenced by source only in this audit. |
| Frontend | Seven test files: `AnalysisVerdict.test.jsx`, `EvasionReport.test.jsx`, `EvasionCheckTable.test.jsx`, `EvasionToolOptions.test.jsx`, `SandboxEvasion.test.jsx`, `evasionStatus.test.js`, `formatUtils.test.js`, under `drakrun/web/frontend/src/`. Verdict loading/error/components: `AnalysisVerdict.test.jsx:11`; OS/tool submission: `SandboxEvasion.test.jsx:106`; incomplete report: `EvasionReport.test.jsx:87`. | Run `npm test` in frontend (script: `drakrun/web/frontend/package.json:11`); not run here. Add malicious-string DOM checks and saved report rendering. Unit component mocks do not cover live routing/API/export. |
| Container integration | `scripts/chimera/e2e_classifier_static.py:7` checks network/filesystem/sample execution/fork/resource isolation, real static job and classify postprocess. Uses temporary folders, not a queue/VM path (`:16`). | Operator with production container image and known harmless input only. It includes attempted execution of its supplied file (`:54`): **never provide malware**, even to a supposed denial test. This is not a full web→RQ→VM test. |
| Windows integration/reliability | Benign API→RQ→VM series (`scripts/chimera/bench/benign_series.py:93`); harmless behavioural positive control (`scripts/chimera/bench/behaviour-probe/probe.c:2`); attached evasion scans (`scripts/chimera/bench/m4/scan.sh:2`). | Historical 10/10 BGInfo result is tied to old commit/image/window (`docs/chimera/benign-series-2026-10-19.md:3`, `:18`); repeat on demo deployment if changed. |
| Linux integration | `scripts/chimera/linux/bench/run_linux.py:23`, `check_probe.py:31`; source probes `probe.c:1`, `probe_ext.c:1`. | Checker prints 16 booleans and aggregate `ok` (`check_probe.py:53`); require parsed `ok=true`, not merely exit code zero. |
| Containment | Windows/Linux guest tests referenced at `docs/chimera/linux-sandbox.md:235`; host C-1…C13 historical results at `docs/chimera/containment-results-2026-10-19.md:38`. | Guest scripts alone do not rerun host fault-injection tests C8–C13. L1/L2/link-local tests are additional, not replacements. Root operator must reproduce relevant evidence. |
| M5 evaluation | Label/statistics/scheduling tests in `test/unit/test_m5_eval.py`; implementation `scripts/chimera/bench/m5_eval.py:194`, `:279`, `:289`. | Freeze tie-as-observed aggregation, scoped attribution and incomplete-run exclusions; distinguish test/control/family denominators. Never run acquisition or live evaluation as a unit test. |

No coverage percentage was measured. File inventory and passing tests do not demonstrate every branch is tested. The report below distinguishes existing checks from proposed regression cases.

## 3. Static tests without weakening production

`static_analyzer/Containerfile:7` builds wheels with compilers; runtime starts separately at `:16`, installs libmagic at `:23`, removes packaging tools at `:30`, and runs uid 65534 at `:35`. Keep these boundaries. Runtime flags and worker staging are documented at `docs/chimera/static-analysis.md:29`, `:64`; fake-engine tests cannot prove enforcement.

Preferred by 27 October: add a **separate test target**, built from a dependency-complete stage before packaging tools are removed. Install pytest only in that target; copy test sources and harmless fixtures with the same package versions as runtime. Explicitly preserve fixture layout: PE fixture is `REPO/test/test.exe`, outside the current `static_analyzer` build context, while ELF fixture is under analyzer tests (`static_analyzer/tests/test_analyzer.py:17`). Use a reviewed repository-root test build context or staged harmless fixture directory; exclude private evidence, samples and secrets. Do not make the final runtime inherit the pytest/compilers test stage.

Test target must contain libmagic, all analyzer requirements and installed analyzer package; run tests as non-root with writable temporary output, no external network, and read-only fixture mounts. The CLI test uses `python -I` (`static_analyzer/tests/test_analyzer.py:130`), so install the package rather than relying on PYTHONPATH. Building dependencies is an operator/CI preparation step; execution of tests must not require network or fetch specimens.

Alternative: isolated analyzer test venv outside the deployment venv, using the documented Python 3.11 setup (`docs/chimera/static-analysis.md:68`), analyzer requirements, pytest, editable package and required system libmagic already provisioned. Do not add sklearn/thrember dependencies to the orchestration venv merely to make discovery pass. Use approved cached dependencies where possible; record lock/package versions. No environment was created here.

Proposed commands after environment preparation:

```sh
# Separate prepared analyzer environment, from static_analyzer/
/path/to/static-test-venv/bin/python -m pytest -q tests -p no:cacheprovider
# Classifier's prepared dependency environment, from classifier/
/path/to/classifier-test-venv/bin/python -m pytest -q tests -p no:cacheprovider
# Frontend, existing installed dependencies, from drakrun/web/frontend/
npm test
npm run build
```

Record executed/passed/failed/skipped counts separately for each. Missing deploy model or optional dependency is a release-evidence gap, not a reason to weaken tests. Do not run the whole repository recursively: inherited integration conftests and dependency environments have different preconditions. The requested `--confcutdir=test/unit` explicitly isolates today's offline suite.

## 4. By 31 October: contract tests (P0)

Owner: backend/classifier/static maintainers together; one short fixture per success, incomplete and failure state, plus boundary cases. Validate producer output and consumer behaviour, including API/UI representation, rather than merely comparing key names. Existing contracts: `docs/chimera/classifier-interface.md:50`, `:72`, `:85`, `:90`; `docs/chimera/static-analysis.md:5`.

| Contract | Proposed assertions and negative cases | Evidence that must stay consistent |
|---|---|---|
| `chimera-static/1` | Correct schema/hash/format; numeric score bounds, recognized level; typed findings/errors; model vectors have supported dimensions and finite numbers. Reject wrong schema, oversized JSON, symlink, directory, malformed/truncated output; timeout yields explicit error. Test optional ML block absent and per-format nonapplicable fields. | Static artifact, features.static, static API and UI show same identity/status. Define minimal error envelope separately from success envelope; do not require every success field on errors. |
| `chimera-verdict/1` | Exact allowed labels; score finite 0..1 and never boolean; bounded explanation; component name/count/weight rules; invalid component makes unknown; extra fields handled per documented drop policy. Test runner timeout/exception/invalid JSON/missing model and valid absent optional score. | classification.json, metadata.classification, API, UI and offline report agree; unknown never displayed as benign. Distinguish suspicious from unknown in native output. |
| `chimera-features/1` | Sample SHA/OS/window match metadata; only injected root+descendants; PID reuse/duplicate names not merged; capped lists and first-2000 sequence semantics; unrelated activity excluded. Missing/corrupt process tree must not silently create reassuring empty input. | Windows API and Linux syscall semantics remain separate; DNS attribution requires evidence. Include a background DNS fixture and a subtree UDP/PCAP join fixture. Linux empty registry is expected, not evidence of failure. |
| Cross-stage ordering | Static finishes before/after dynamic, static never arrives, RQ delay, classifier disabled, model absent, classification timeout; bounded wait and correct partial-result rendering. | Final job state, postprocess failure state and artifact completeness remain distinct. A finished RQ task alone does not imply complete telemetry. |

Use only synthetic JSON/logs and existing harmless fixtures; no live sample needed. Add contracts next to `test/unit/test_static.py`, `test_classifier.py`, `test_classifier_api.py` and Linux/telemetry tests; classifier-specific semantic checks next to existing classifier tests. Reuse existing models/validators where present; do not invent a new public schema revision during freeze.

## 5. By 31 October: report goldens and security regressions (P0)

Create a small reviewed golden set: Windows benign complete; Linux benign complete; partial telemetry; static timeout; unknown classifier; combined verdict with differing components; incomplete evasion scan. Freeze synthetic input JSON and expected normalized JSON + offline HTML semantic assertions. Mask only unstable IDs/timestamps/temporary paths; keep sample hashes, labels, reasons, error text and process attribution. HTML checks must assert user-visible headings, values, artifact links and escaping, not only byte snapshots. Reviewer approves meaningful changes; never regenerate goldens blindly to clear failures.

Threat basis: hostile guest output is untrusted (`docs/chimera/threat-model.md:6`, `:73`); historical escaping/inventory gaps at `:75` are audit leads, not a claim they remain unfixed. Inspect current code and add failing regressions before any fix.

| Priority / proposed regression | Acceptance |
|---|---|
| P0 HTML escaping | Place `<img src=x onerror=...>`, `</script>`, quotes, ampersands and Unicode in process names, paths, domains, tool summary/weighted score and classifier explanations. Check portal DOM, evasion native HTML and offline export: text is visible; no injected elements/handlers/script execution. Test URL-bearing fields against `javascript:`/unsafe schemes. Local browser interception prevents external requests. |
| P0 path traversal and symlinks | Attempt `../`, encoded traversal, absolute paths, backslashes, archive entry escapes, symlinked output and cross-analysis IDs. Assert rejection/no read or write outside a temporary fixture root. Use a harmless sentinel file, never real credentials or protected paths. Include artifact download and ZIP member paths. |
| P0 caps/denial of service | Over-limit guest stdout/report/static JSON, long strings, malformed JSON, unexpected check inventory, duplicate/omitted check IDs, tool nonzero exit and parser timeout. Explicit incomplete/unknown states; no clean/high-confidence manufactured score. Existing report-size test: `test/unit/test_report_generation.py:35`. |
| P0 command/process boundaries | Quotes/metacharacters in launch names and arguments cannot change the invoked host command; fake subprocesses assert argv. Cancellation/timeouts clean up child process and temporary staged data. |
| P0 lifecycle/queue | Restore and postprocess failures release locks; analysis/evasion cannot share slot; OS mismatch refused; admission failure explicit; static job lag cannot hold forever. Existing suites named in inventory should be extended only for missing scenarios. |
| P1 isolated container enforcement | Production image/flags: no network/DNS, no root write, immutable harmless input, noexec temporary mount, no fork after hardening, bounded memory/time, uid and capabilities. Actual operator check; fake argv tests are necessary but insufficient. |

If any report renderer executes injected content, any artifact endpoint escapes its analysis root, or containment fails, treat it as demo-blocking. Add no public remote access to work around localhost limitations.

## 6. Operator-only VM smoke and containment

These require privileged deployment/guest/network access and remain **unverified in this audit**. No sudo, Xen, firewall, service management or analysis commands were run. Operator uses the existing documented procedures, capturing sanitized evidence outside the public repo.

1. Record deployed commit, model hash, image/snapshot identity, profile match, config/plugin hash, container image digest and clock state. Do not copy install.json or credentials into evidence. Pause competing work through the established operator procedure; one dynamic analysis at a time.
2. Reproduce C-1, C0, C1–C13 from `docs/chimera/containment-results-2026-10-19.md:38`: rule idempotence/guard restoration; net-check; DNS/HTTP redirection; literal external and LAN destinations; dom0 services; IPv6; loopback listeners; fail-closed despite upstream masquerade; namespace pivot denial; spoofing/protocol/fragment cases; apply/restart interruption; three restore/DHCP/drakshell cycles; INetSim privilege/filesystem constraints. Retain counters, captures and explicit per-ID outcomes. C-1 is a distinct label, not a typo for C1.
3. Run the Windows and Linux guest containment companions plus L1/L2/link-local metadata tests (`docs/chimera/linux-sandbox.md:54`, `:240`). These do not cover the entire host fault-injection matrix. Full checks after relevant networking changes; same-boot net-check before each batch. Stop on suspect egress and follow `docs/chimera/threat-model.md:130`.
4. Linux benign probe through upload→RQ→worker→report: run the existing checker and **parse its JSON**; require all 16 checks true and `ok=true`. `check_probe.py:35` checks presence of an upload hash, not equality: additionally compare actual submitted and guest-received SHA-256. Save tree, report, telemetry and attribution evidence.
5. Windows harmless positive probe: require child, written batch path, Run-value attempt, DNS/HTTP intent and correct subtree. BGInfo or another frozen benign control: ten sequential production-path attempts, complete telemetry, zero unexplained teardown leftovers, no hidden retries. Save all failures; historical 10/10 is not today's result.
6. Run harmless static/classifier container check; then a real benign web→RQ→VM case with concurrent static analysis and valid final contract artifacts. Confirm portal and offline report agree. Record unsupported classifier inputs as unknown where intended.
7. Linux dump/TLS claims need explicit fresh validation: process-exit and timeout cores, hash/attribution and cleanup; accepting TLS client shows request contents, rejecting client only metadata/error. Documentation includes later “live test needed”/known-gap notes (`docs/chimera/linux-sandbox.md:173`, `:196`); do not resolve these by quoting earlier success text. Missing support must be disclosed or removed from demo claims.

## 7. Six-day priority schedule and freeze

| Date | Work / owner | Exit gate |
|---|---|---|
| 25 Oct | Backend maintainer records offline baseline; team assigns root operator, classifier/static owners and two report scorers | Baseline transcript and known gaps attached; this audit's 613-pass result available |
| 26 Oct | Backend/frontend owners add targeted escaping/traversal/contract regressions and fix demonstrated blockers | P0 cases pass; no scope expansion; review security fixes |
| 27 Oct | Static/classifier owners run separate environments and model/package parity; frontend owner runs tests/build; operator validates smoke/containment | No unreviewed failures/skips affecting demo; model/image/config hashes frozen; benchmark preregistered |
| 28 Oct | Benchmark lead/operator execute benchmark plan; collect exact artifacts and deviations | No model/image tuning on benchmark outcomes; safety failure stops batch |
| 29 Oct | Complete data capture, ten-run reliability if changed, blind report preparation; fix only blockers | Repeat affected checks after each fix; separate pre/post-fix data |
| 30 Oct | Two scorers finish; team verifies release evidence and rehearses; freeze by 18:00 local | Signed freeze checklist; exported fallback artifacts/recording |
| 31 Oct | Operator performs short same-boot safety/benign smoke before demo | No dependency/OS/hypervisor upgrades; use frozen fallback if live checks fail |

Freeze checklist:

- [ ] Offline unit suite passes on candidate commit; exact command/count/time retained.
- [ ] Classifier tests run with intended model present; synchronization passes; every skip explained.
- [ ] Static analyzer tests pass in prepared environment; image isolation checked separately.
- [ ] Frontend tests and both portal/embedded-report builds pass; report escaping goldens reviewed.
- [ ] Contract artifacts/API/UI/offline report agree on identity, labels, components and partial states.
- [ ] Root operator signs current containment and Linux 16/16 records; Windows probe and teardown checks pass.
- [ ] Benchmark dataset immutable; failures/abstentions/exclusions retained; no test/train contamination concealed.
- [ ] Freeze commit, deploy/model/image/config hashes and rollback identities recorded without secrets; no new features after freeze.
- [ ] Demonstration uses approved inputs, serial scheduling, known time budget; fallback report/recording opens locally.
- [ ] Public deliverables contain no samples, protected evidence, credentials, personal data or internal feedback.

Future work: broader independent family-disjoint classifier evaluation, calibrated abstention, parser fuzzing in dedicated isolation, automated privileged containment lab, full browser journey coverage and reproducible dependency/image locks. Defer new OS/multi-slot functionality; one dynamic slot meets this deadline.

## Audit closeout

Files created: `benchmark-plan.md` and this document; no source changes. Tests run: requested offline suite, **613 passed in 13.09s**. Not run: classifier/static/frontend suites, builds, container checks, benchmark analyses and all privileged VM/containment checks listed above. Root evidence and deployed configuration were not read. No graph update is required because no code was modified.
