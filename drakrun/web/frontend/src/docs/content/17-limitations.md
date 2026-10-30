---
title: Limitations and future scope
group: Project
---
# Limitations and future scope

## Limitations

### Analysis

- **Files only.** There is no URL analysis mode: a link has to be wrapped in a file (a shortcut or a script) to be
  detonated.
- **Real-time guests.** A detonation lasts as long as its timeout on the wall clock. Malware that sleeps longer
  than the timeout, or waits for a date, shows little behaviour.
- **Simulated internet.** INetSim answers every protocol it knows with generic content. Malware that needs its
  real command-and-control server, or checks a response's content, does not get far; this is the price of never
  reaching the internet.
- **Mobile apps are static only.** Android and iOS apps are analysed with MobSF but never run, and the classifier
  does not score them.
- **Linux is younger than Windows.** No TLS key export, memory-dump coverage still to be verified across sample
  types, the guest kernel and its profile must match exactly, and Linux evasion scans cannot yet run with DRAKVUF
  attached.

### Detection resistance

- Timing side channels around VM exits, hardware sensors read through WMI, ACPI and SMBIOS table shapes, and the
  emulated device set remain detectable (see [hardening](concepts-hardening.md)).
- Some techniques of third-party evasion-detection tools are excluded from scans because they destabilise the
  guest.

### Verdicts and intel

- The classifier's malware data comes mostly from another sandbox's reports (WinMET, CAPEv2) and its benign data
  from CHIMERA. Despite the countermeasures, part of what a model learns can be the difference between sandboxes;
  retraining on more CHIMERA malware runs is the remedy.
- The benign set is small, so the false-positive rate on unusual legitimate software is uncertain.
- Intel matches are context, not proof, and a missing match says nothing.

### Platform

- **One host.** All services and guests share one machine. With the static VM running, a Windows and a Linux
  detonation do not fit in memory at the same time; memory admission runs them one after the other.
- **No application login.** The API and VNC rely on listening on loopback; access to the host is the access
  control.
- **Long analyses and sleep shortening.** Runs of up to 24 hours work, but the dynamic logs grow with the run
  (about 530 MB of call logs per hour even for an idle sample), so capa's dynamic TTPs are skipped on long
  runs. Sleep shortening is experimental: it only cuts single long `NtDelayExecution` sleeps in the sample's
  own processes, and in testing it rarely changed what a sample did.
- **Measured on Xen 4.19.2.** Results were measured on Xen 4.19.2 with the CHIMERA patch; later 4.19 releases
  contain security fixes that a production host should have.

## Future scope

| Item | What it means |
|---|---|
| URL analysis mode | Submit a URL; the guest's browser opens it, with the same tracing and containment |
| Deeper anti-evasion | WMI sensor values, CPUID exit timing, ACPI table contents, a natural launch parent |
| Linux dynamic analysis maturity | TLS keys, verified memory dumps, DRAKVUF-attached Linux evasion scans |
| Mobile dynamic analysis | Android in an x86 HVM guest under Xen with its own instrumentation; iOS needs virtual devices or hardware |
| Xen 4.19.6 upgrade | Rebuild on the current 4.19 point release with the CHIMERA patch and rerun the reliability check |
| Guest clock acceleration | Making guest time pass faster, so long sleeps end sooner. Tested and dropped for now: the Windows guest keeps time with the HPET and the ACPI PM timer, not the TSC, so scaling the TSC alone does not speed up its clock |
| capa on long runs | Keep capa TTPs for long analyses, for example by running capa on the sample's own process tree |
| Classifier retraining | A larger CHIMERA malware and benign set, retraining, recalibration and a refitted fusion |
