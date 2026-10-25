# Benign Reliability Series — 2026-10-19

**What:** 10 sequential analyses of a benign, Microsoft-signed sample (Sysinternals BGInfo 4.33, SHA-256 `ee2c4850e62277e5efded460afd708af22007ef5f2c2c9dae7a699fc3de346d0`) submitted through the **real path**: web API (`127.0.0.1:5000`) → Redis/RQ → `drakrun-worker@1` (root-owned deployment `/opt/chimera`, commit `4944a32`) → Xen/DRAKVUF → postprocessing.
**Conditions:** containment active (`chimera-net-check --require-inetsim` OK before start), arm A0 (current Windows 10 snapshot, 2 vCPU / 4 GiB), default plugin set, analysis timeout 120 s, one VM, runs strictly sequential.
**Runner:** `scripts/chimera/bench/benign_series.py`. **Evidence:** `/var/lib/chimera-evidence/benign-series-2026-10-19/` (`summary.csv`, `run-NN.json`).

## Results (n = 10)

| Metric | Mean | SD | Min | Max |
|---|---|---|---|---|
| Submit → done (s) | 153.0 | 4.0 | 148.2 | 162.2 |
| Queue wait (s) | 0.01 | — | 0.01 | 0.03 |
| VM start → sample executing (s) | 17.0 | 1.0 | 15.8 | 18.5 |
| Execution window (s) | 135.1 | 3.6 | 131.1 | 142.8 |
| Postprocessing (s) | 5.8 | 4.2 | 0.4 | 11.3 |
| Storage per analysis (MB) | 101.3 | 86.4 | 4.6 | 228.7 |

- **Completion: 10/10 `finished`**; DRAKVUF return code 0 in 10/10; hard timeouts 0/10.
- **Lifecycle hygiene:** 0 leftover domains, 0 leftover qemu device models after each run (before the fix in `21fdc32`, an analysis left a stuck device model that made the next restore fail, matching the 3/8 historical restore failures).
- **Containment:** 0 `CHIMERA-EGRESS-DROP` kernel log lines during the series.
- **Telemetry:** missing plugin output: `clipboardmon` 10/10 (no clipboard activity, expected), `exmon` 1/10, `tlsmon` 1/10 (no events in those windows). All other configured plugins produced output in every run.

## Observations
- **Throughput** for 120 s analyses on one VM: ~23.5 analyses/hour (3600 / 153 s).
- **Storage variance is OS noise**, not the sample: comparing the largest and smallest runs, `regmon` went 147 MB → 9 MB and `filetracer` 56 MB → 4 MB (Windows background activity). Reducing background services would shrink and stabilise telemetry but is itself a realism trade-off (a silent Windows is an artefact).
- Historical comparison **[historical, Sep 2026]:** 4/8 analyses finished; 3 failed with "Failed to restore VM vm-1".

## Limitations
- Single benign sample, single VM, 120 s window; malware behaviour and longer windows will change execution and postprocessing times.
- Restore timing here includes drakrun's network setup; the bare `xl restore` measured separately was 3.4–3.5 s (n = 3).
