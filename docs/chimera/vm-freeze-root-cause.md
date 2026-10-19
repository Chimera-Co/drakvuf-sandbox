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
| **thin list + registry-read hooks, patched Xen, stock QEMU** | **10/10** |
| **276 hooks, patched Xen, stock QEMU** | **10/10** |
| **default full hook list, patched Xen, stock QEMU** | **10/10 without a freeze**; 8/10 complete (2 DRAKVUF exits, see "Remaining DRAKVUF failure") |

With the patched Xen, QEMU received 24 mapcache invalidations during a DRAKVUF-attached
scan (16 without DRAKVUF), against 15,000–85,000 before.

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
| QEMU 8.0.5 (qemu-xen) | Do not call `bdrv_drain_all()` in `xen_invalidate_map_cache()`; locked (in-flight DMA) mappings are already skipped by that function | **Mitigation, no longer in use.** Ran 2026-10-19 10:40–16:35, 20/20 runs clean. Stock QEMU restored after the Xen fix was booted; the patched binary is kept as `/usr/local/lib/xen/bin/qemu-system-i386.chimera-nodrain`. Patch: `scripts/chimera/patches/qemu-xen-8.0.5-invalidate-no-drain.patch` |
| Xen 4.19.2 | Request the mapcache invalidation only when the host p2m changes (`p2m_is_hostp2m`) | **Root-cause fix.** Patch: `scripts/chimera/patches/xen-4.19.2-altp2m-no-mapcache-invalidate.patch`. Built 2026-10-19 from the same tree and `.config` as the running hypervisor (only `p2m.o` changed); **installed and booted 2026-10-19 16:32** as `/boot/xen-4.19.2.gz` (sha256 `706f6d24…e6577ee389`; original kept as `/boot/xen-4.19.2.gz.orig`). 30/30 runs without a freeze on the stock QEMU |
| drakrun | Guest-CPU stall watchdog: a guest with no CPU progress for 20 s (sampled every 2 s; healthy guests never exceed ~2 s) while DRAKVUF is attached stops DRAKVUF and marks telemetry `complete=false` (`vm_stalled`) instead of silently truncating | Deployed; live-tested by pausing the guest (analysis and evasion scan) |
| libvmi df8547f | Upstream libvmi#1123 (attach can scan all guest memory for minutes when vCPU 0 runs user code under KVA shadowing) | Patch prepared: `scripts/chimera/patches/libvmi-df8547f-pr1123-kernel-cr3.patch`; not installed (needs KVA shadowing, unlikely on this CPU; no matching failure in our logs) |

With the QEMU patch QEMU logs `Locked DMA mapping while invalidating mapcache!` when an
invalidation arrives during a disk DMA; the mapping is kept, as the function intends.
The Xen patch removes those spurious invalidations at the source.

**Caveat on the QEMU patch (why it was retired).** The drain exists so that QEMU stops using a guest frame
before the hypervisor reuses it. Removing it is safe for the spurious altp2m
invalidations (the host p2m did not change), but not established safe for genuine
ones, such as a guest balloon driver returning memory: an in-flight disk request could
then write to a frame Xen has already freed, and stale mapcache bucket entries can
remain. H1 has no Xen platform device (`xen_platform_pci = 0`), so it cannot load a PV
balloon driver; A0 keeps the device and has not been checked. The no-drain QEMU is a
stop-gap; with the patched Xen the stock QEMU passed the 10-run checks, so it was restored.

### Installing the patched Xen (done 2026-10-19; kept for rebuilds)

```
sudo cp /boot/xen-4.19.2.gz /boot/xen-4.19.2.gz.orig
sudo install -m 644 /var/lib/chimera-evidence/xen-4.19.2-chimera/xen-4.19.2-chimera.gz /boot/xen-4.19.2.gz
```

Then reboot and pick "Debian GNU/Linux, with Xen hypervisor" (GRUB's default entry is
plain Debian). Every Xen entry loads `/boot/xen.gz` or `/boot/xen-4.gz`, both symlinks to
`xen-4.19.2.gz`, so `update-grub` is not needed. Check with `sudo xl info | grep
cc_compile_date` (Mon Oct 19 10:59:32 IST 2026). After a reboot, start
`chimera-inetsim` and `drakrun-web` by hand; they are not enabled at boot.

### Rollback

- QEMU (back to the no-drain stop-gap, if a freeze reappears):
  `sudo install -m 755 /usr/local/lib/xen/bin/qemu-system-i386.chimera-nodrain /usr/local/lib/xen/bin/qemu-system-i386`
  (takes effect for the next VM start).
- Xen: if the patched hypervisor does not boot, pick plain "Debian GNU/Linux" in
  GRUB, run `sudo cp /boot/xen-4.19.2.gz.orig /boot/xen-4.19.2.gz` and reboot.

## DRAKVUF "re-copying remapped gfn" exits: root cause and fix

With the default full apimon hook list, DRAKVUF sometimes stopped with rc 0 after
`Critical error in re-copying remapped gfn` / `Failed to refresh shadow copy` (5 of 17
PERDEDOR scans on 2026-10-19). The guest kept running; the scan was marked incomplete.
This is a use-after-free in DRAKVUF's `libdrakvuf/vmi.c`, present in da982ab and in
upstream master (unchanged up to upstream 52483ba6, 2026-09-26).

1. A write to a page carrying breakpoints is intercepted in `_pre_mem_cb`, which saves
   a borrowed pointer to that page's breakpoint list: `pass->traps =
   g_hash_table_lookup(breakpoint_lookup_gfn, gfn)` (`vmi.c:583`; the IDRX path does the
   same at `vmi.c:473`).
2. One single-step later, `_post_mem_cb` runs trap callbacks and
   `process_free_requests()`. Removing a breakpoint on the same page calls
   `g_slist_remove()` on that list (`vmi.c:1145`), freeing nodes.
3. `refresh_shadow_copy()` then walks the saved `pass->traps` (`vmi.c:230`). If a node was freed and
   reused, its `data` is a heap pointer, and `vmi_read_8_pa()` on it fails. If it was
   freed but not yet reused, DRAKVUF silently writes `0xCC` into the shadow copy at a
   breakpoint that no longer exists.

Evidence: an instrumented build
(`scripts/chimera/patches/drakvuf-da982ab-refresh-shadow-copy-diag.patch`) caught 2
failures in 6 scans. Both failed at the breakpoint-byte read with "physical addresses"
`0x563059962ac0` and `0x5609f1936820` (DRAKVUF heap pointers), while both the original and
the shadow page mapped normally.

**Fix** (`scripts/chimera/patches/drakvuf-da982ab-refresh-shadow-copy-stale-trap-list.patch`,
applies to da982ab and b2f64d8): keep the original condition (refresh only after a
write to a page that had breakpoints, `pass->traps` used as a flag only), walk the
current list from `breakpoint_lookup_gfn`, skip breakpoints already removed, and look up
the shadow page if the page got its first breakpoint during the step. Two earlier
attempts were wrong and are recorded for reviewers: refreshing whenever the page has
breakpoints now crashed on pages without a recorded shadow (NULL `remapped_gfn`), and
refreshed after reads too (one page read 1.5 million times, run 277 s instead of ~100 s).

| DRAKVUF build, default hook list, patched Xen | Complete | Notes |
|---|---|---|
| da982ab (production) | 12/17 | 5 "re-copying remapped gfn" exits |
| da982ab + fix (diagnostic logging) | **20/20** | 96–116 s per scan; the stale-list case occurred 11 times and was handled |
| da982ab + fix (clean build, `drakvuf-da982ab-chimera1`, sha256 `d04230a0…2867e0bf`) | **5/5** | 106–111 s per scan |

**Installed 2026-10-19 18:39** as `/usr/local/bin/drakvuf` for analyses and evasion
scans (owner's decision); the original is kept as `/usr/local/bin/drakvuf.orig-da982ab`
(sha256 `0ff87cee…406ac5a8`). The temporary evasion-only systemd drop-in was removed (kept
as `/var/lib/chimera-evidence/apimon-2026-10-19/chimera-diag.conf.removed`). Check: BGInfo
portal analysis `41d079cc` complete, full 120 s, rc 0, 8/9 plugins (clipboardmon empty
as always). Rollback: `sudo install -m 755 /usr/local/bin/drakvuf.orig-da982ab
/usr/local/bin/drakvuf` (next DRAKVUF start).

## Injector readfile race

In 4 of 30 scans the injector failed to copy PERDEDOR's report out of the guest
although the agent had written it: `ReadFile` appeared to return FALSE with last error 0
(`ERROR_SUCCESS`), in `src/libinjector/win/methods/win_read_file.c` STEP6, most likely
the return trap catching another thread's call. Reading is idempotent, so
`GuestSession.get_file` now retries up to 3 times, except on a definite Windows answer
(file or path not found, access denied, virus infected).
Verified after deployment: 10/10 scans (276 hooks) produced a score; the first read
failed in 4 of them and the second attempt succeeded every time.

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
