# CPUID round-trip timing harness (goal G2)

`cpuid_timing.c` times `RDTSC; CPUID; RDTSC` (the pattern behind al-khaser's `rdtsc_diff_vmexit`) and
`RDTSC; RDTSC` (no VM exit, the floor), plus an al-khaser-style 10-round average. It touches nothing but its
own output file. It was compile-checked on x86-64 only; the numbers must come from the Intel host.

## Build (on the CHIMERA host)

```sh
sudo apt install gcc-mingw-w64-x86-64          # if not installed (the behaviour probe uses it too)
x86_64-w64-mingw32-gcc -O2 -s -o cpuid_timing.exe cpuid_timing.c
gcc -O2 -o cpuid_timing cpuid_timing.c
objdump -d cpuid_timing | grep -c cpuid        # must be > 0: the CPUID must not be optimised away
sha256sum cpuid_timing.exe cpuid_timing
```

## Run

```
cpuid_timing [iterations] [output.json] [raw.csv]
```

- Linux / bare metal / dom0: `taskset -c 0 ./cpuid_timing 100000 bare-1.json bare-1.csv`
- Windows guest: `cpuid_timing.exe 100000 C:\Users\Public\h3-drakvuf-cpuidmon-1.json C:\Users\Public\h3-drakvuf-cpuidmon-1.csv`
  and read the files back the way the evasion lane reads PERDEDOR's report.

The thread pins itself to logical CPU 0. Check with `lscpu --extended` that CPU 0 is a P-core and that the
guest's vCPU 0 is pinned to a P-core too (`xl vcpu-list`); keep the same core type everywhere.

Configurations, three repeats each: bare metal (Debian booted without Xen), dom0, A0 without DRAKVUF, H3 without
DRAKVUF, H3 + DRAKVUF without cpuidmon, H3 + DRAKVUF with `cpuidmon -s`, optionally the Linux guest.

## Output

`rdtsc_rdtsc`, `rdtsc_cpuid_rdtsc` and `alkhaser_style_avg10`: n, min, p5, p25, median, p75, p95, p99, max,
mean, in TSC cycles. `alkhaser_style_detected` assumes al-khaser flags a 10-round average of 1000 cycles or more
(or 0): check that against the al-khaser source version used in the scans and correct it if it differs. Plot
the raw CSVs as one histogram per configuration (log x axis).
