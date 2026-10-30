---
title: Evasion verification
group: Operating
---
# Evasion verification (PERDEDOR)

A hardened guest is only as good as its measurement. CHIMERA verifies its sandboxes by running sandbox-detection
suites **inside** a disposable copy of the golden image and scoring what they find. These scans are separate from
malware analyses: their results never feed the classifier.

## PERDEDOR

PERDEDOR is the project's cross-platform sandbox-evasion self-test suite (the `perdedor/` submodule). Existing
tools such as Pafish and al-khaser verify Windows well, but none covers Android and none shares a report format
or a score across platforms. PERDEDOR is one suite with three agents, one JSON schema and one scoring method:

| Agent | Platform | How it runs |
|---|---|---|
| `agents/windows/` | Windows | PowerShell 7: CIM/WMI, registry, PnP devices, raw SMBIOS, native CPUID |
| `agents/linux/` | Linux | Python 3 with a small C helper for CPUID and RDTSC |
| `agents/android/` | Android | Python 3 driving the device over adb, nothing installed on the device |

```bash
pip install -e perdedor
perdedor test linux -o linux-report.json --json     # exactly one platform per run
perdedor test windows                                # on a Windows guest, or:
pwsh -File agents\windows\Invoke-Perdedor.ps1 -OutputPath windows-report.json
perdedor report linux-report.json windows-report.json -o perdedor-report.html
```

Every finding carries a category (environment artifact, timing, behavioural interaction, design-specific), a
severity and, when detected, a **remediation** string: the hardening change that would close it. Two scores are
reported side by side:

- **raw score**: clean checks over applicable checks (errored and skipped checks are not counted);
- **weighted score**: 0–100, each detection discounted by its severity, so one critical timing leak costs more than
  several informational gaps.

`perdedor/docs/CHECK_COVERAGE.md` maps each check to the Pafish, al-khaser and VMAware technique classes it
covers, and lists what is left out and why.

> PERDEDOR is an analyst-run self-test. It runs against a golden image before that image is used, never during
> a real detonation; detonation guests stay agentless.

## Scans in CHIMERA

**Sandbox Evasion** in the console (or `POST /api/evasion/scans`) starts a scan on an evasion worker, which
restores the guest, copies the tools in, runs them and collects their raw output.

| Guest | Tools |
|---|---|
| Windows | PERDEDOR, al-khaser, Pafish, VMAware, a CPUID timing probe |
| Linux | PERDEDOR and `chimera-vmcheck` |

- **Profile**: *Full* runs every tool configured for the sandbox; *Custom* picks tools and their options.
- **With DRAKVUF** (Windows only): the scan runs with the analysis plugins attached, as a malware run would. This is
  the setting that matters, since instrumentation itself can be detected.
- **Time budgets** count from the moment the tools are staged, so a tool late in a combined scan inherits the time
  of those before it. The defaults are 900 s for PERDEDOR, 1800 s for al-khaser and each single-binary tool, and
  2400 s per scan (`[evasion] default_timeout`).
- **Score**: the CHIMERA score (0–100, higher is better) passes at `score_pass_threshold` (90) and warns below
  `score_warn_threshold` (70).

Some techniques of third-party tools are excluded from the scans because running them destabilises the guest;
they are not part of any score.

```bash
curl -sS http://127.0.0.1:5000/api/evasion/scans -H 'Content-Type: application/json' \
  -d '{"sandbox_id":"linux","guest_os":"linux","tools":["perdedor","chimera-vmcheck"],"profile":"full"}'
```

Results are in `/var/lib/drakrun/evasion/<scan_id>/`: `evasion.json` (normalised findings), `report.html` and
`raw/<tool>/` with each tool's own output. **Verification Runs** shows the history and the score trend per
sandbox, which is how a hardening change is judged: several scans before, several after, per-check frequencies.
