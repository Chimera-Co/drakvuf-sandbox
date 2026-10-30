---
title: Overview
group: Start here
---
# CHIMERA documentation

CHIMERA is a malware analysis sandbox. It runs a suspicious file in a disposable Windows or Linux virtual machine
on the **Xen** hypervisor and records what the file does with **DRAKVUF**, which observes the guest through
virtual-machine introspection (VMI) instead of an agent inside it. Every upload is also analysed statically in a
separate virtual machine with no network. When the detonation ends, a classifier combines the behaviour and the
static findings into one verdict, the indicators are checked against threat-intelligence sources, and this
console shows the whole result.

**PERDEDOR** is the companion sandbox-evasion self-test suite. It runs inside a golden image before the image is
used for detonations and reports, with a score, how much the machine still looks like a sandbox. Its findings
drive CHIMERA's guest hardening.

CHIMERA started from the open-source DRAKVUF Sandbox (drakrun) by CERT Polska. The project added the static
analysis VM, the classifier and its fusion model, threat intelligence, the Linux analysis pipeline, mobile-app
static analysis, network containment with INetSim, guest anti-detection hardening, PERDEDOR and evasion
verification, and this console. It is developed by Mantek Singh Burn, Anusha Tiwari and Shreyas Tekawade.

```diagram pipeline
```

## How these docs are organised

| Section | Read it for |
|---|---|
| [Concepts](concepts-vmi.md) | The ideas the platform rests on: VMI, Xen HVM guests, altp2m, DRAKVUF plugins, anti-detection hardening, static analysis, the classifier and threat intel. |
| [Architecture](architecture.md) | The services, queues, storage layout and trust boundaries, and [how it was built](how-it-was-built.md). |
| [Build from scratch](build-host-xen.md) | A step-by-step guide from a blank Debian 12 host to a working sandbox, with the commands and configuration. |
| [Operating](operating.md) | Submitting samples, reading reports, running verification scans, looking after the services. |
| [Limitations and future scope](limitations.md) | What CHIMERA does not do yet and what is planned. |

## Conventions

- Commands run as **root on dom0** (the Debian control domain of the Xen host) unless a page says otherwise.
- The main configuration file is `/etc/drakrun/config.toml`. Its sections and defaults are defined in
  `drakrun/lib/config.py`; any key can also be set from the environment as `DRAKRUN__SECTION__KEY`.
- Results live under `/var/lib/drakrun`; configuration and VMI profiles under `/etc/drakrun` and
  `/var/lib/drakrun/profiles`.
- In the deployed layout the checkout is `/opt/chimera/src` and the Python environment is `/opt/chimera/venv`,
  both owned by root.

## Repository layout

| Path | Contents |
|---|---|
| `drakrun/` | The Python package: CLI (`drakrun …`), analysis, static, intel and evasion workers, postprocessing, web API |
| `drakrun/web/frontend/` | This console (React, Vite); these documentation pages are in `src/docs/content/` |
| `static_analyzer/` | `chimera_static`, the static analyzer, and the `Containerfile` of its image |
| `classifier/` | Feature code, training scripts, the deployable model (`classifier/deploy/`) and its runbooks |
| `perdedor/` | The PERDEDOR submodule: Windows, Linux and Android agents, scoring, report schema |
| `drakvuf/` | The DRAKVUF submodule (with LibVMI) |
| `scripts/chimera/` | Containment, systemd units, static VM, intel feeds, hardening arms, patches, benchmarks |
| `docs/chimera/` | Design notes, measured results, threat model and evaluation protocols |
| `test/` | Unit tests of the Python package |

> These pages summarise the design notes in `docs/chimera/` and the code. When a page and the code disagree,
> the code and the configuration on the host are authoritative.
