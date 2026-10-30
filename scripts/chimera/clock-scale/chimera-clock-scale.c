/*
 * chimera-clock-scale: make a paused, restored HVM guest's clock run N times faster.
 *
 * Sets the domain's guest TSC frequency to N times its current one (hardware TSC scaling, the
 * mechanism Xen uses when a guest moves to a host with a different TSC rate), then loads the
 * domain's own HVM context back so that every vCPU's TSC continues from its current value under
 * the new ratio and the LAPIC TSC-deadline timer is re-armed with it. The guest calibrated its
 * TSC before the snapshot was taken, so its TSC, QueryPerformanceCounter and deadline-timer
 * interrupts all advance N times faster than real time. Xen's other emulated timers (PIT, RTC,
 * HPET, ACPI PM timer) keep real time.
 *
 * The domain must be paused, advertise an invariant TSC (otherwise Windows keeps time with the
 * HPET and only RDTSC would speed up) and be in the default TSC mode; the host must support TSC scaling
 * (otherwise Xen would emulate every RDTSC). Every analysis restores a fresh domain from the
 * snapshot, so nothing needs to be undone.
 *
 * Usage: chimera-clock-scale <domid> <factor>
 *        chimera-clock-scale <domid> --check   (read-only: does the domain advertise an invariant TSC?)
 * Prints one JSON line with the TSC frequency before and after. Exit code 0 on success.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xen/arch-x86/cpuid.h>

#define MAX_FACTOR 1000

static int fail(const char* what)
{
    fprintf(stderr, "chimera-clock-scale: %s: %s\n", what, strerror(errno));
    return 1;
}

/* 1 if the domain's CPUID policy advertises an invariant TSC (leaf 0x80000007 EDX bit 8), 0 if
 * not, -1 on error. Windows keeps time with the TSC only when it is invariant; otherwise it uses
 * the HPET, which Xen runs in real time, and scaling the TSC alone just makes RDTSC disagree
 * with every other clock. */
static int invariant_tsc(xc_interface* xch, uint32_t domid)
{
    uint32_t nr_leaves, nr_msrs;
    if (xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs))
        return -1;
    xc_cpu_policy_t* policy = xc_cpu_policy_init();
    xen_cpuid_leaf_t* leaves = calloc(nr_leaves, sizeof(*leaves));
    xen_msr_entry_t* msrs = calloc(nr_msrs, sizeof(*msrs));
    int result = -1;
    if (policy && leaves && msrs && !xc_cpu_policy_get_domain(xch, domid, policy) &&
        !xc_cpu_policy_serialise(xch, policy, leaves, &nr_leaves, msrs, &nr_msrs))
    {
        result = 0;
        for (uint32_t i = 0; i < nr_leaves; i++)
            if (leaves[i].leaf == 0x80000007)
                result = !!(leaves[i].d & (1u << 8));
    }
    free(msrs);
    free(leaves);
    xc_cpu_policy_destroy(policy);
    return result;
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <domid> <factor>|--check\n", argv[0]);
        return 2;
    }

    char* end;
    errno = 0;
    unsigned long domid = strtoul(argv[1], &end, 10);
    if (errno || *end || domid == 0 || domid >= DOMID_FIRST_RESERVED)
    {
        fprintf(stderr, "chimera-clock-scale: invalid domid %s\n", argv[1]);
        return 2;
    }
    /* --check: only report whether the domain advertises an invariant TSC (read-only) */
    bool check_only = !strcmp(argv[2], "--check");
    unsigned long factor = check_only ? 0 : strtoul(argv[2], &end, 10);
    if (!check_only && (errno || *end || factor < 2 || factor > MAX_FACTOR))
    {
        fprintf(stderr, "chimera-clock-scale: factor must be 2..%d\n", MAX_FACTOR);
        return 2;
    }

    xc_interface* xch = xc_interface_open(NULL, NULL, 0);
    if (!xch)
        return fail("xc_interface_open");

    xc_domaininfo_t info;
    if (xc_domain_getinfo_single(xch, domid, &info))
        return fail("xc_domain_getinfo_single");
    if (!(info.flags & XEN_DOMINF_hvm_guest))
    {
        fprintf(stderr, "chimera-clock-scale: domain %lu is not HVM\n", domid);
        return 1;
    }
    if (check_only)
    {
        int itsc = invariant_tsc(xch, domid);
        if (itsc < 0)
            return fail("reading the domain's CPUID policy");
        printf("{\"domid\": %lu, \"invariant_tsc\": %s}\n", domid, itsc ? "true" : "false");
        return 0;
    }
    if (!(info.flags & XEN_DOMINF_paused))
    {
        fprintf(stderr, "chimera-clock-scale: domain %lu is not paused\n", domid);
        return 1;
    }

    int itsc = invariant_tsc(xch, domid);
    if (itsc < 0)
        return fail("reading the domain's CPUID policy");
    if (!itsc)
    {
        fprintf(stderr, "chimera-clock-scale: domain %lu does not advertise an invariant TSC: "
                "its clock would not follow (give the image cpuid \"invtsc=1\" and a new snapshot)\n",
                domid);
        return 3;
    }

    uint32_t mode, khz, incarnation;
    uint64_t elapsed;
    if (xc_domain_get_tsc_info(xch, domid, &mode, &elapsed, &khz, &incarnation))
        return fail("xc_domain_get_tsc_info");
    if (mode != XEN_CPUID_TSC_MODE_DEFAULT)
    {
        fprintf(stderr, "chimera-clock-scale: TSC mode %" PRIu32 " is not the default mode\n", mode);
        return 1;
    }
    uint64_t new_khz = (uint64_t)khz * factor;
    if (new_khz > UINT32_MAX)
    {
        fprintf(stderr, "chimera-clock-scale: %" PRIu32 " kHz x %lu does not fit\n", khz, factor);
        return 1;
    }

    if (xc_domain_set_tsc_info(xch, domid, mode, elapsed, (uint32_t)new_khz, incarnation))
        return fail("xc_domain_set_tsc_info");

    /* Reload the HVM context: the CPU records reset each vCPU's TSC under the new ratio. */
    int size = xc_domain_hvm_getcontext(xch, domid, NULL, 0);
    if (size <= 0)
        return fail("xc_domain_hvm_getcontext (size)");
    uint8_t* buf = malloc(size);
    if (!buf)
        return fail("malloc");
    int got = xc_domain_hvm_getcontext(xch, domid, buf, size);
    if (got <= 0)
        return fail("xc_domain_hvm_getcontext");
    if (xc_domain_hvm_setcontext(xch, domid, buf, got))
        return fail("xc_domain_hvm_setcontext");
    free(buf);

    uint32_t mode_after, khz_after, incarnation_after;
    uint64_t elapsed_after;
    if (xc_domain_get_tsc_info(xch, domid, &mode_after, &elapsed_after, &khz_after, &incarnation_after))
        return fail("xc_domain_get_tsc_info (after)");
    xc_interface_close(xch);

    printf("{\"domid\": %lu, \"factor\": %lu, \"gtsc_khz_before\": %" PRIu32
           ", \"gtsc_khz_after\": %" PRIu32 ", \"tsc_mode\": %" PRIu32 "}\n",
           domid, factor, khz, khz_after, mode_after);
    return khz_after == new_khz ? 0 : 1;
}
