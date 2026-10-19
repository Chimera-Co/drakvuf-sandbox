# Guest freeze under DRAKVUF: root cause and fix (2026-10-19)

## Symptom

Analyses and evasion scans intermittently stop producing DRAKVUF events 2–45 s after
the run starts. The guest display freezes at the same moment (the VNC screenshotter
times out), and drakrun logs `DRAKVUF output inactive for 30 s - possible VM crash`.
The run then waits out its timeout and was recorded as finished with a truncated log.

The same symptom is reported upstream in CERT-Polska/drakvuf-sandbox#1222.

## How often

PERDEDOR workload on the H1 arm, DRAKVUF attached; complete = full run, no stall.

| Configuration | Complete |
|---|---|
| procmon only | 9/10 |
| default plugins without apimon | 6/10 |
| default plugins, apimon 276 hooks (no registry-read hooks) | 11/13 |
| default plugins, apimon thin list + registry-read hooks | 2/6, and 5/10 with `shadow_memory = 384` |
| **thin list + registry-read hooks, patched QEMU below** | **10/10** |
| **276 hooks, patched QEMU below** | **10/10** |

Ordinary portal analyses were affected too: of the 10 "finished" benign-series runs on
2026-10-19 03:28–03:52, four went silent 2–23 s into a 120 s window, and every
September portal analysis that finished stopped producing events after 15–42 s.
Those September runs used the unmodified drakvuf-sandbox 0.21.0 wheel (verified
against its RECORD hashes), so the freeze is not caused by CHIMERA code changes.

## What was ruled out (each with measurements)

- apimon as such: the freeze happens without apimon (6/10).
- DRAKVUF `-F` (fast singlestep) and the user-hook injection mode: no change.
- The altp2m paging pool (`shadow_memory` 128 → 384 MB): no significant change.
- A Xen/DRAKVUF version mismatch: Xen 4.19.2 libraries and headers throughout;
  vm_event interface version 7 in both 4.19.2 and DRAKVUF's 4.20.1 submodule.
- Host heat / time of day: pass rate flat across half-hour buckets.

## Root cause (evidence at the moment of the freeze)

1. **Guest vCPUs wait for the device model, not for DRAKVUF.** Xen debug key `q`:
   every guest vCPU has `pause_count=0` and `pause_flags=4` (`VPF_blocked_in_xen`), which in
   Xen 4.19.2 only `wait_on_xen_event_channel()` in `common/ioreq.c` sets: the vCPU
   is waiting for QEMU to complete an I/O request. DRAKVUF is idle in `poll()`.
2. **The pending requests are mapcache invalidations.** The shared ioreq page (read
   with `scripts/chimera/diag/ioreq_state.py`) shows `type=8` (`IOREQ_TYPE_INVALIDATE`) on every vCPU,
   one `INPROCESS`, the rest `IOREQ_READY`.
3. **QEMU is stuck inside the invalidate handler.** gdb on qemu-system-i386:
   `cpu_handle_ioreq → handle_ioreq → xen_invalidate_map_cache → bdrv_drain_all → aio_poll`,
   blocked: draining all block I/O from inside the ioreq handler never returns while
   the emulated IDE disk has requests in flight. The most likely reason (from reading
   the QEMU source, not yet confirmed on this host) is the IDE TRIM/drain deadlock:
   an in-flight IDE TRIM keeps the block backend busy while waiting for the guest-side
   state machine, which cannot run while the drain holds the main loop
   (`hw/ide/core.c`, `block/block-backend.c`). Reported upstream as QEMU issue #2043
   and fixed in QEMU commit 095c08a7ba68; qemu-xen 8.0.5 predates the fix and lacks
   the block-layer APIs it uses, so a backport would have to be adapted.
4. **DRAKVUF triggers the invalidations.** Counted with gdb during one scan:
   QEMU receives 23 invalidations without DRAKVUF and 15,000–85,000 with it. DRAKVUF made
   27,618 `xc_altp2m_change_gfn` calls in that scan. When a trap is removed DRAKVUF
   resets the remapped page with `vmi_slat_change_gfn(view, gfn, ~0)`
   (`libdrakvuf/vmi.c:1189,1195,1219`). Xen handles that in `p2m_change_altp2m_gfn`
   (`arch/x86/mm/altp2m.c:504`), which calls `p2m_remove_entry` on the **altp2m view**.
   `p2m_remove_entry` (`arch/x86/mm/p2m.c:554`) unconditionally calls
   `ioreq_request_mapcache_invalidate()`, so every vCPU sends QEMU a synchronous
   INVALIDATE although the host p2m (which QEMU maps through) did not change.
   The code is identical in Xen 4.20.1, so upgrading Xen does not fix it.

More hooks with return traps → more trap removals → more invalidations → more chances
to hit the drain deadlock. This explains why registry-read hooks make it far worse
and procmon alone rarely freezes.

## Fixes

| Layer | Change | Status |
|---|---|---|
| QEMU 8.0.5 (qemu-xen) | Do not call `bdrv_drain_all()` in `xen_invalidate_map_cache()`; locked (in-flight DMA) mappings are already skipped by that function | **Mitigation.** Installed 2026-10-19, 20/20 runs clean (table above). Original kept as `/usr/local/lib/xen/bin/qemu-system-i386.orig-8.0.5`. Patch: `scripts/chimera/patches/qemu-xen-8.0.5-invalidate-no-drain.patch` |
| Xen 4.19.2 | Request the mapcache invalidation only when the host p2m changes (`p2m_is_hostp2m`) | **Root-cause fix.** Patch: `scripts/chimera/patches/xen-4.19.2-altp2m-no-mapcache-invalidate.patch`. Built 2026-10-19 from the same tree and `.config` as the running hypervisor (only `p2m.o` changed); staged, not installed, at `/var/lib/chimera-evidence/xen-4.19.2-chimera/xen-4.19.2-chimera.gz` (sha256 `706f6d24…e6577ee389`). Needs a host reboot (owner) |
| drakrun | Guest-CPU stall watchdog: a guest with no CPU progress for 20 s (sampled every 2 s; healthy guests never exceed ~2 s) while DRAKVUF is attached stops DRAKVUF and marks telemetry `complete=false` (`vm_stalled`) instead of silently truncating | Code + tests in this repo |
| libvmi df8547f | Upstream libvmi#1123 (attach can scan all guest memory for minutes when vCPU 0 runs user code under KVA shadowing) | Patch prepared: `scripts/chimera/patches/libvmi-df8547f-pr1123-kernel-cr3.patch`; not installed (needs KVA shadowing, unlikely on this CPU; no matching failure in our logs) |

With the QEMU patch QEMU logs `Locked DMA mapping while invalidating mapcache!` when an
invalidation arrives during a disk DMA; the mapping is kept, as the function intends.
The Xen patch removes those spurious invalidations at the source.

**Caveat on the QEMU patch.** The drain exists so that QEMU stops using a guest frame
before the hypervisor reuses it. Removing it is safe for the spurious altp2m
invalidations (the host p2m did not change), but not established safe for genuine
ones, such as a guest balloon driver returning memory: an in-flight disk request could
then write to a frame Xen has already freed, and stale mapcache bucket entries can
remain. H1 has no Xen platform device (`xen_platform_pci = 0`), so it cannot load a PV
balloon driver; A0 keeps the device and has not been checked. The no-drain QEMU is a
stop-gap. Once the host runs the patched Xen, restore the stock QEMU (rollback
below) and re-run the 10-run check; keep the no-drain QEMU only if the check fails.

### Installing the patched Xen (owner, needs a reboot)

```
sudo cp /boot/xen-4.19.2.gz /boot/xen-4.19.2.gz.orig
sudo install -m 644 /var/lib/chimera-evidence/xen-4.19.2-chimera/xen-4.19.2-chimera.gz /boot/xen-4.19.2.gz
```

Then reboot into the usual "Debian GNU/Linux, with Xen hypervisor" entry. The GRUB
entries point at `/boot/xen-4.19.2.gz`, so `update-grub` is not needed. Check
with `sudo xl dmesg | head` (build date 2026-10-19).

### Rollback

- QEMU: `sudo install -m 755 /usr/local/lib/xen/bin/qemu-system-i386.orig-8.0.5 /usr/local/lib/xen/bin/qemu-system-i386`
  (takes effect for the next VM start).
- Xen: if the patched hypervisor does not boot, pick plain "Debian GNU/Linux" in
  GRUB, run `sudo cp /boot/xen-4.19.2.gz.orig /boot/xen-4.19.2.gz` and reboot.

## Related upstream fix not in our build

DRAKVUF commit 45c7b26 (tklengyel/drakvuf PR #1874, for issue #1758) fixes injector
hangs where `createproc` completion waited for the hijacked thread to hit an arbitrary
breakpoint again. The running DRAKVUF is da982ab, which predates it. None of our
recorded injector failures has been traced to this yet (the ones examined were caused by
Defender, by a frozen guest, or by an over-long command line), but it is the next
DRAKVUF update to take.

## Evidence

`/var/lib/chimera-evidence/apimon-2026-10-19/` on the analysis host: per-run results,
`bisect-summary.txt`, `*-hang-diag-*.txt` (gdb, Xen `q`/`e` dumps, ioreq state),
`invalidate-counts.txt`, `drakvuf-ops-counts.txt`.
