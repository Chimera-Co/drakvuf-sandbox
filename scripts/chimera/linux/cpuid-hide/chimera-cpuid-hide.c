/*
 * chimera-cpuid-hide: hide Xen from a guest's CPUID while it boots.
 *
 * DRAKVUF's `cpuidmon -s` hides the hypervisor during an analysis, but the guest kernel has already
 * seen Xen when the golden image booted: Linux then uses the Xen clocksource and event channels and
 * shows /sys/hypervisor, "Hypervisor detected: Xen HVM" in dmesg, and so on. This tool applies the same
 * masking from the first instruction: start the domain paused (xl create -p), run this tool, then
 * unpause. It masks what cpuidmon -s masks (drakvuf/src/plugins/cpuidmon/cpuidmon.cpp):
 *   - leaf 1 ECX bit 31 (hypervisor present)
 *   - leaves 0x40000000-0x400000ff (Xen signature "XenVMMXenVMM" and its feature leaves)
 * Only CPUID executed in long mode (EFER.LMA) is masked: hvmloader (32-bit) needs the Xen leaves to find
 * the hypercall page and powers the domain off without them, while the 64-bit kernel runs in long mode.
 * Xen executes CPUID before it sends the monitor event, so the event carries the results; we change
 * them, step over the instruction and let Xen write the registers back.
 *
 * Runs until SIGTERM/SIGINT or until the domain is gone. Stop it before `xl save`.
 *
 * Build: gcc -O2 -Wall -o chimera-cpuid-hide chimera-cpuid-hide.c $(pkg-config --cflags --libs libvmi)
 * Usage: chimera-cpuid-hide DOMAIN_NAME
 */
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define EFER_LMA (1ULL << 10)

static volatile sig_atomic_t interrupted;
static uint64_t masked;

static void on_signal(int sig)
{
    (void)sig;
    interrupted = 1;
}

static event_response_t cpuid_cb(vmi_instance_t vmi, vmi_event_t* event)
{
    (void)vmi;
    uint32_t leaf = event->cpuid_event.leaf;
    int long_mode = !!(event->x86_regs->msr_efer & EFER_LMA);

    if (long_mode && leaf == 1)
    {
        event->x86_regs->rcx &= ~0x80000000ULL;
        masked++;
    }
    else if (long_mode && leaf >= 0x40000000 && leaf <= 0x400000ff)
    {
        event->x86_regs->rax = 0;
        event->x86_regs->rbx = 0;
        event->x86_regs->rcx = 0;
        event->x86_regs->rdx = 0;
        masked++;
    }
    event->x86_regs->rip += event->cpuid_event.insn_length;
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s DOMAIN_NAME\n", argv[0]);
        return 2;
    }

    vmi_instance_t vmi = NULL;
    vmi_init_error_t error;
    if (VMI_FAILURE == vmi_init(&vmi, VMI_XEN, argv[1], VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                                NULL, &error))
    {
        fprintf(stderr, "vmi_init(%s) failed: %d\n", argv[1], error);
        return 1;
    }

    vmi_event_t event = {0};
    event.version = VMI_EVENTS_VERSION;
    event.type = VMI_EVENT_CPUID;
    event.callback = cpuid_cb;
    if (VMI_FAILURE == vmi_register_event(vmi, &event))
    {
        fprintf(stderr, "registering the CPUID event failed\n");
        vmi_destroy(vmi);
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* Callers wait for this line before unpausing the domain */
    printf("ready\n");
    fflush(stdout);

    while (!interrupted)
    {
        /* Fails once the domain is destroyed or saved */
        if (VMI_FAILURE == vmi_events_listen(vmi, 500))
            break;
    }

    vmi_clear_event(vmi, &event, NULL);
    /* Answer events that arrived while clearing so no vCPU stays blocked */
    vmi_events_listen(vmi, 0);
    vmi_destroy(vmi);
    fprintf(stderr, "chimera-cpuid-hide: %s: masked %" PRIu64 " CPUID results\n", argv[1], masked);
    return 0;
}
