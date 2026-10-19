# Upstream contribution draft: DRAKVUF `refresh_shadow_copy` use-after-free

Status: **draft, not submitted.** The owner submits both texts below to
[tklengyel/drakvuf](https://github.com/tklengyel/drakvuf) after reading them.

- Local branch: `fix-refresh-shadow-copy-uaf` in `drakvuf-upstream-build/drakvuf`
  (worktree `drakvuf-upstream-build/drakvuf-pr`), one commit `59091ae` on top of upstream
  `main` b2f64d8 (latest on 2026-10-19). It builds with the project's meson options, with no
  new warnings. It is checked by hand against `.astylerc`; astyle is not installed here.
- The locally installed binary was built from the same change applied to da982ab
  (`scripts/chimera/patches/drakvuf-da982ab-refresh-shadow-copy-stale-trap-list.patch`).
  The upstream commit differs only in that two adjacent comments are merged into one.
- To submit: fork on GitHub, push the branch to the fork, open the issue first, then open
  the PR with "Fixes #<issue>" added.

---

## Issue

**Title:** Use-after-free of the breakpoint list in `refresh_shadow_copy` ("Critical error in re-copying remapped gfn")

**Body:**

### Summary

`refresh_shadow_copy()` walks `pass->traps`, a pointer to a page's breakpoint list
that `_pre_mem_cb` saves when it intercepts a write. Between that interception and
the refresh, breakpoints on the same page can be removed. Removal frees nodes of that
list with `g_slist_remove()`, so `refresh_shadow_copy()` reads freed memory.

This has two outcomes:

- When a freed node has been reused, its `data` is no longer a physical address.
  `vmi_read_8_pa()` fails, DRAKVUF prints `Critical error in re-copying remapped gfn` /
  `Failed to refresh shadow copy`, and it stops (`interrupted = 1`, exit code 0).
- When it has not been reused yet, the loop uses a stale address. It can write `0xCC`
  into the shadow copy at a breakpoint that was already removed, which corrupts the
  guest's view of that code.

### Code path (b2f64d8)

1. `_pre_mem_cb` intercepts a write to a page with breakpoints and saves
   `pass->traps = g_hash_table_lookup(drakvuf->breakpoint_lookup_gfn, gfn)`. This is
   [vmi.c#L583](https://github.com/tklengyel/drakvuf/blob/b2f64d8d73d456840e5fc276c13f0df0b2b79231/src/libdrakvuf/vmi.c#L583);
   the IDRX path does the same at
   [#L473](https://github.com/tklengyel/drakvuf/blob/b2f64d8d73d456840e5fc276c13f0df0b2b79231/src/libdrakvuf/vmi.c#L473).
   This is a borrowed pointer to the live list, not a copy.
2. The vCPU single-steps. `_post_mem_cb` then runs the POST callbacks and
   `process_free_requests()`
   ([#L339](https://github.com/tklengyel/drakvuf/blob/b2f64d8d73d456840e5fc276c13f0df0b2b79231/src/libdrakvuf/vmi.c#L339)).
   Events on other vCPUs can do the same in the meantime.
3. Removing a breakpoint on that page runs
   `traps_on_gfn = g_slist_remove(traps_on_gfn, pa)`
   ([#L1145](https://github.com/tklengyel/drakvuf/blob/b2f64d8d73d456840e5fc276c13f0df0b2b79231/src/libdrakvuf/vmi.c#L1145)),
   which frees that node. The node may be the one `pass->traps` points to.
4. `refresh_shadow_copy()` walks `pass->traps`
   ([#L230](https://github.com/tklengyel/drakvuf/blob/b2f64d8d73d456840e5fc276c13f0df0b2b79231/src/libdrakvuf/vmi.c#L230)).

### How we observed it

- **Setup:** Xen 4.19.2, DRAKVUF da982ab (the function is unchanged in b2f64d8), and a
  Windows 10 x64 guest. apimon ran with its default hook list, under a workload heavy in
  registry and WMI calls. apimon's return hooks add and remove breakpoints on the same
  code pages all the time.
- **Before the fix:** 5 of 17 runs stopped with `Critical error in re-copying remapped gfn`.
- **Diagnostics:** we added logging at each failure site in `refresh_shadow_copy()`. Two
  failures were captured, and both failed at `vmi_read_8_pa()` on the breakpoint byte.
  - The "physical addresses" were `0x563059962ac0` and `0x5609f1936820`, which are
    process heap pointers.
  - The original and the remapped gfn both mapped normally through `xenforeignmemory_map`.
- **After the fix:** 25 of 25 runs completed. The case where the list changed between
  interception and refresh occurred 11 times over 20 of those runs, and each was handled.

### Suggested fix

Walk the current list from `breakpoint_lookup_gfn` in `refresh_shadow_copy()`, and skip
entries whose breakpoint is gone. Keep `pass->traps` only as the existing "write to a
page with breakpoints" condition. PR to follow.

---

## Pull request

**Title:** libdrakvuf: fix use-after-free of the breakpoint list in refresh_shadow_copy

**Body:**

Fixes #<issue>.

`_pre_mem_cb` saves a borrowed pointer to the page's breakpoint list in `pass->traps`.
Breakpoints on that page can be removed before `refresh_shadow_copy()` runs, through POST
callbacks, `process_free_requests()` or other vCPUs' events. Each removal frees list nodes
with `g_slist_remove()`, and the refresh then walks freed memory.

Changes, all in `src/libdrakvuf/vmi.c`:

- `refresh_shadow_copy()` walks the current list from `breakpoint_lookup_gfn` and skips
  entries without a `breakpoint_lookup_pa` wrapper (already removed).
- `_post_mem_cb` keeps using `pass->traps` only as the existing condition: the access was
  a write to a page that had breakpoints. So the shadow copy is still refreshed after
  writes only. The pointer is no longer dereferenced.
- If `pass->remapped_gfn` was not recorded, `refresh_shadow_copy()` looks it up. A page
  can get its first breakpoint, and so its shadow copy, during the step; that copy is
  taken after the write and is already current. The function returns without doing
  anything if there is still no remapped gfn. This also guards the IDRX path, which calls
  `refresh_shadow_copy()` without checking it.

Testing:

- **Setup:** Xen 4.19.2, a Windows 10 x64 guest, apimon with the default hook list, and a
  registry/WMI-heavy workload.
- **Without the patch:** 5 of 17 runs stopped with `Critical error in re-copying remapped gfn`.
- **With it:** 25 of 25 runs completed in 96–116 s each. Unpatched runs that did not
  hit the bug took 95–106 s.

Notes for reviewers, from two approaches we tried and dropped:

- Refreshing whenever the page currently has breakpoints dereferenced a NULL
  `pass->remapped_gfn` at startup, for pages that got their first breakpoint during
  the step.
- It also refreshed after reads. In one run a single page was read about 1.5 million times
  in a loop, and the run took 277 s instead of about 100 s. That is why `pass->traps` is
  kept as the write condition.

---

## Before submitting (owner checklist)

- [ ] Re-check that upstream `main` has not changed `refresh_shadow_copy` since b2f64d8
      (`git fetch && git log origin/main -- src/libdrakvuf/vmi.c`).
- [ ] Run astyle with the repository's `.astylerc` (the CI check) on the branch.
- [ ] Decide whether to mention the project by name; the texts above do not.
