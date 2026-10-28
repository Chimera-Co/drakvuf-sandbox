/*
 * CHIMERA CPUID round-trip timing harness (closes report Section 4.3 / Table 6.1 row 4).
 *
 * Measures, in TSC cycles, the cost of RDTSC; CPUID; RDTSC (the pattern of al-khaser's
 * rdtsc_diff_vmexit check) and of RDTSC; RDTSC (no VM exit) as the floor. It does nothing
 * else: no files except its own result, no network, no registry.
 *
 * Build (on the CHIMERA host, Debian):
 *   Windows guest:  x86_64-w64-mingw32-gcc -O2 -s -o cpuid_timing.exe cpuid_timing.c
 *   Linux / bare metal:  gcc -O2 -o cpuid_timing cpuid_timing.c
 *
 * Run:  cpuid_timing [iterations] [output.json] [raw.csv]
 *   iterations  default 100000 (after 2000 warm-up rounds)
 *   output.json default cpuid-timing.json in the current directory (Windows: C:\Users\Public\cpuid-timing.json)
 *   raw.csv     optional: one line per iteration "rdtsc_rdtsc,rdtsc_cpuid_rdtsc" for the histogram
 *
 * The thread is pinned to logical CPU 0 (a P-core on the Raptor Lake host; check with lscpu).
 * Keep the same core type in every configuration, or the numbers are not comparable.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
static void pin(void) { SetThreadAffinityMask(GetCurrentThread(), 1); SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST); }
static const char *DEFAULT_OUT = "C:\\Users\\Public\\cpuid-timing.json";
#else
#ifndef __APPLE__
#include <sched.h>
#endif
#include <x86intrin.h>
#ifdef __APPLE__
static void pin(void) {}
#else
static void pin(void) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(0, &s); sched_setaffinity(0, sizeof s, &s); }
#endif
static const char *DEFAULT_OUT = "cpuid-timing.json";
#endif

/* CPUID leaf 0. volatile + memory clobber so the compiler can neither drop nor move it
   (clang's <cpuid.h> macro is not volatile and was optimised away in testing). */
#if defined(__GNUC__) || defined(__clang__)
static inline void cpuid0(void)
{
    unsigned a = 0, b, c = 0, d;
    __asm__ __volatile__("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) : : "memory");
}
#else
static void cpuid0(void) { int r[4]; __cpuid(r, 0); }
#endif

static int cmp(const void *x, const void *y)
{
    uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
    return a < b ? -1 : a > b;
}

static uint64_t pct(const uint64_t *s, size_t n, double p) { return s[(size_t)(p * (n - 1))]; }

static void stats(FILE *f, const char *name, uint64_t *v, size_t n, int last)
{
    double mean = 0;
    for (size_t i = 0; i < n; i++) mean += (double)v[i];
    mean /= (double)n;
    qsort(v, n, sizeof *v, cmp);
    fprintf(f, "  \"%s\": {\"n\": %zu, \"min\": %llu, \"p5\": %llu, \"p25\": %llu, \"median\": %llu, "
               "\"p75\": %llu, \"p95\": %llu, \"p99\": %llu, \"max\": %llu, \"mean\": %.1f}%s\n",
            name, n, (unsigned long long)v[0], (unsigned long long)pct(v, n, .05), (unsigned long long)pct(v, n, .25),
            (unsigned long long)pct(v, n, .5), (unsigned long long)pct(v, n, .75), (unsigned long long)pct(v, n, .95),
            (unsigned long long)pct(v, n, .99), (unsigned long long)v[n - 1], mean, last ? "" : ",");
}

int main(int argc, char **argv)
{
    size_t n = argc > 1 ? (size_t)strtoull(argv[1], NULL, 10) : 100000;
    const char *out = argc > 2 ? argv[2] : DEFAULT_OUT;
    const char *raw = argc > 3 ? argv[3] : NULL;
    uint64_t *floor_ = malloc(n * sizeof *floor_), *exitc = malloc(n * sizeof *exitc);
    if (!floor_ || !exitc || n < 100) { fprintf(stderr, "bad iteration count\n"); return 2; }
    pin();

    for (int i = 0; i < 2000; i++) { uint64_t t = __rdtsc(); cpuid0(); (void)(__rdtsc() - t); }
    for (size_t i = 0; i < n; i++) {
        uint64_t t0 = __rdtsc();
        uint64_t t1 = __rdtsc();
        floor_[i] = t1 - t0;
        uint64_t t2 = __rdtsc();
        cpuid0();
        uint64_t t3 = __rdtsc();
        exitc[i] = t3 - t2;
    }
    if (raw) {
        FILE *r = fopen(raw, "w");
        if (r) { for (size_t i = 0; i < n; i++) fprintf(r, "%llu,%llu\n", (unsigned long long)floor_[i], (unsigned long long)exitc[i]); fclose(r); }
    }

    /* al-khaser-style: average of 10 RDTSC/CPUID/RDTSC rounds, repeated 1000 times.
       Our reading of al-khaser's rdtsc_diff_vmexit: detected when the 10-round average is >= 1000
       cycles (or 0). Verify the threshold against the al-khaser source used in the scans. */
    size_t trials = 1000, detected = 0;
    uint64_t *avg10 = malloc(trials * sizeof *avg10);
    for (size_t k = 0; k < trials; k++) {
        uint64_t sum = 0;
        for (int i = 0; i < 10; i++) { uint64_t t = __rdtsc(); cpuid0(); sum += __rdtsc() - t; }
        avg10[k] = sum / 10;
        if (avg10[k] >= 1000 || avg10[k] == 0) detected++;
    }

    FILE *f = fopen(out, "w");
    if (!f) { f = stdout; }
    fprintf(f, "{\n  \"tool\": \"chimera-cpuid-timing 1\",\n  \"iterations\": %zu,\n", n);
    stats(f, "rdtsc_rdtsc", floor_, n, 0);
    stats(f, "rdtsc_cpuid_rdtsc", exitc, n, 0);
    stats(f, "alkhaser_style_avg10", avg10, trials, 0);
    fprintf(f, "  \"alkhaser_style_detected\": \"%zu/%zu\"\n}\n", detected, trials);
    if (f != stdout) {
        fclose(f);
        printf("wrote %s\n", out);
    }
    return 0;
}
