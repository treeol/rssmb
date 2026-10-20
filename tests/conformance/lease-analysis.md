# Campaign B — smb2.lease analysis (conf/leases)

Status: **analysis only — no server changes yet.**

- Baseline: rssmb bcf45ca (post-Campaign-A), smbtorture **4.19.5**: **5/36**
  (31 failing; 3 subtests skip with golden parity — see below). Note: the
  post-A `results.md` recorded "8/31"; re-measured today under both the
  harness's 120 s cap and an uncapped run, the current number is 5/36.
  The 3/36 → 8/31 drift recorded after Campaign A was measured mid-suite
  truncation; this doc uses the full 5/36 as the true starting point.
- Golden: Samba **4.19.5** server (`samba-419-ref` container, host network
  :4450, share `tmp/samba-ref/public`, `vfs objects = streams_depot
  xattr_tdb` to mirror selftest [tmp] stream support), same 4.19.5 torture
  client: **34/36** (2 failing; golden log:
  `tmp/samba-ref/golden-smb2-lease.log`, gitignored).
- Subtests `v2_request_parent`, `v2_request` and `dynamic_share` **skip on
  both** rssmb and Samba (SMB2_CAP_DIRECTORY_LEASING not advertised /
  dynamic shares unsupported) — parity, not counted as failures.
- Reference torture source: Samba 4.19.5 `source4/torture/smb2/lease.c`
  (copy in `.reference/samba-torture/lease.c`, gitignored) and
  `lease_break_handler.c` (extracted under `/tmp/samba-4.19.5`).

## Proven golden-red subtests

`selftest/knownfail` (Samba 4.19.5 source, flat file — **not** knownfail.d)
lists both golden failures upstream:

```
^samba3.smb2.lease.statopen3
^samba3.smb2.lease.unlink # we currently do not downgrade RH lease to R after unlink
```

The same file also carries `^samba3.smb2.durable-v2-open.reopen1a-lease(ad_dc)$`
— consistent with Campaign A's findings. So the golden ceiling is **34/36,
documented by Samba itself**; `statopen3` and `unlink` are not chaseable
against Samba bytes (Samba does not implement the Windows-derived behavior
the torture asserts: granting a full RWH to a `FILE_WRITE_DATA`-only second
opener over a stat-open lease holder, and setting
`SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED` on the unlink-path break).

**Campaign target: 31/36** (34 golden-green of 36 minus the 3 golden-parity
skips already matching = every subtest that Samba itself passes, rssmb must
pass; ≥30/36 per the task). The 2 allowed failures are `statopen3` and
`unlink`, justified by the upstream knownfail entries above.

## Per-subtest table

| Subtest | Torture sequence (essentials) | Asserts | rssmb today | Samba 4.19.5 |
|---|---|---|---|---|
| request | RHW lease create; lease-on-directory rejected; **same key on 2nd file → INVALID_PARAMETER**; **stream open gets own lease**; 8-row request matrix (W/H alone never granted; R/RW/RH/RHW echoed) | grant matrix, key/file binding, stream lease | FAIL first at 0x157-era create_action rows (now G2-fixed); remaining: same-key-on-2nd-file already INVALID_PARAMETER? (needs recheck), stream opens rejected | pass (with streams_depot) |
| break_twice | two competing RWH opens from 2 connections; first open gets 2 breaks (one per contender), each acked; then upgrade re-ack | 2 break notifications, ack semantics | FAIL: second break never arrives (break-in-progress swallows the second contender's break) | pass |
| nobreakself | same connection, same lease key, second open must NOT break self | no break, `count == 0` | PASS | pass |
| statopen | stat open (FILE_READ_ATTRIBUTES) with RWH lease over existing leased file | lease granted RWH on stat open; second contending opener breaks it | FAIL SHARING_VIOLATION at :782 (stat open share-mode conflict — Samba treats attr-only opens as non-conflicting for leases) | pass |
| statopen2 | stat open + full open combos | grant matrix for stat opens | FAIL grant arithmetic (0x3 vs 0x7 — W not granted alongside a stat open on the same lease) | pass |
| statopen3 | RWH lease open (SEC_FILE_ALL), stat open (FILE_READ_ATTRIBUTES), then 2nd full open with FILE_WRITE_DATA + RWH on same key | 2nd opener granted full RWH | FAIL (0x3 vs 0x7) — **golden also fails** (upstream knownfail) | **FAIL** (knownfail) |
| statopen4 | stat open with various access masks; expect stat open to keep existing lease, no break from stat opens | no break to stat opener; grant preserved | FAIL: break sent to stat open / lease state lost | pass |
| upgrade | hold R, re-open same key requesting RH/RW/RHW; no break, grant upgraded | upgrade without break | FAIL: upgrade grant wrong (0x7 vs 0x3 rows — union arithmetic ignores pending conditions) | pass |
| upgrade2 | 16-row matrix: held R/RH, request R/RH/RW/RHW | per-row grant/broken-to | FAIL same arithmetic | pass |
| upgrade3 | 16-row matrix: held RH, second lease key contends, then LEASE1 upgrade | grant + no double break | FAIL same + double-break | pass |
| break | 16-row break_results matrix: hold, contend with 2nd key, break + grant, then same-key upgrade | per-row break-to/grant; upgrade after break re-grants only broken-to state | FAIL: upgrade after break re-grants too much (0x3 vs 0x1 at :629) | pass |
| oplock | oplock and lease interaction: batch oplock open, then lease open; lease open triggers oplock break, vice versa | cross-family breaks | FAIL: breaks time out (oplock side never acked / wrong notify channel?) | pass |
| multibreak | one lease held, 3 contenders | multiple breaks, final state | PASS | pass |
| breaking1 | break then ack with exact state | ack accepted, state recorded | FAIL: break never observed (wait timed out) — likely break sent on wrong transport/session or wrong flags so handler ignores it | pass |
| breaking2 | break, ack with reduced state | state transitions | FAIL same | pass |
| breaking3 | RWH broken to RH then R (two-stage) | staged break-to break | FAIL | pass |
| v2_breaking3 | v2 lease two-stage break with epoch | epoch increments each stage (0x13, 0x14) | FAIL epoch off-by-one (0x13 vs 0x12 — epoch incremented at grant AND at break) | pass |
| breaking4 | RWH holder vs RWH contender: holder broken to RH, contender granted RH; then holder re-opens same key | grant + break | FAIL | pass |
| breaking5 | two keys contend twice | break only once per stage | FAIL | pass |
| breaking6 | ack with state not subset of break-to | INVALID_PARAMETER ack | FAIL | pass |
| lock1 | byte-range lock by non-lease-holder breaks lease to none/RH | LEASE break on LOCK (ConflictOp::Lock path exists) | FAIL: break not triggered by LOCK | pass |
| complex1 | lease + oplock + second lease interplay across 3 opens | full notification sequence | FAIL | pass |
| v2_request_parent | directory leases | (skip — cap not advertised) | skip | skip |
| v2_request | directory leases | (skip — cap not advertised) | skip | skip |
| v2_epoch1 | v2 lease create; epoch = client_epoch + 1; re-open same key +1 each | epoch arithmetic on upgrade | FAIL epoch off-by-one (0x4713 vs 0x4712 — Samba: epoch starts at client epoch, +1 per grant/upgrade event; rssmb double-counts) | pass |
| v2_epoch2 | v2 epoch on break ack | epoch preserved across ack | FAIL same | pass |
| v2_epoch3 | v2 `lease_version` in response | lease_version = 2 in RqLs response v2 | FAIL: response version 0 (v1-shaped echo for v2 request) | pass |
| v2_complex1 | v2 multi-lease complex | epochs + breaks | FAIL | pass |
| v2_complex2 | v2 + parent dir leases | (dir-lease partial; epoch asserts) | FAIL | pass |
| v2_rename | RWH lease, rename file by another connection | lease break on rename (HandleOrDelete) + survives | FAIL: no break on rename | pass |
| dynamic_share | dynamic shares | (skip) | skip | skip |
| timeout | RWH lease; contender create async; **holder never acks**; server breaks, waits (~35s), then grants contender; late ACK → UNSUCCESSFUL | breaking create PENDS until break timeout; ack-after-timeout rejected | FAIL: breaking create returns immediately (no server-side wait for the ack), late ACK returns OK (should be UNSUCCESSFUL at :3662) | pass |
| unlink | RWH lease, 2nd connection closes + unlinks | break with ACK_REQUIRED on unlink | FAIL: break flags 0 (no ack required) / none sent — **golden also fails** (knownfail: "we currently do not downgrade RH lease to R after unlink") | **FAIL** (knownfail) |
| timeout-disconnect | breaking create; holder disconnects mid-break | pending create completes after disconnect (durable-independent) | FAIL: same pending/wait gap as timeout | pass |
| rename_wait | lease + rename, holder must see break before rename completes | rename BLOCKS on lease break wait | FAIL: rename completes without waiting (:3819 OBJECT_NAME_NOT_FOUND expected) | pass |
| duplicate_create | same lease key, same file, 2nd create same key | same lease, no break | PASS | pass |
| duplicate_open | same key re-open | no break | PASS | pass |
| v1_bug15148 | v1 lease regression (bug 15148) | no lease response on oplock-only open | PASS | pass |
| v2_bug15148 | v2 epoch regression | new_epoch in break = pre-increment value (0x4713) | FAIL: break new_epoch off-by-one (0x4714 vs 0x4713 — rssmb increments before the break notification; Samba sends the CURRENT epoch in the break, incrementing only on ack/next grant) | pass |

## Root-cause groups (ordered by subtests unblocked)

### L1 — Breaking creates never pend for the ack; late/none-ack handling
unblocks: timeout, timeout-disconnect, rename_wait, breaking1–6 (partially), complex1, v2_complex*

rssmb sends break notifications fire-and-forget and lets the triggering
operation complete immediately. MS-SMB2 §3.3.4.7/3.3.5.22: when a break
with ACK is pending, the conflicting CREATE/RENAME/WRITE must block (async,
STATUS_PENDING) until the holder acks or the server break-timeout (Samba:
35 s, `lease.lease_break_timeout`... measured from golden) expires; after
the timeout the server grants as if acked. After expiry or ack-completion,
a further ACK for a non-breaking lease is `STATUS_UNSUCCESSFUL`
(:3662 today returns OK). Rename must equally block (rename_wait expects
OBJECT_NAME_NOT_FOUND for a racing touch until the break completes).
The plumbing exists (`break_for_op` returns oneshot waiters; handle_write
ignores them) but no handler awaits them and there is no server-side
break-timeout timer.

### L2 — Lease grant arithmetic (upgrade/upgrade2/upgrade3/break/statopen2)

**Status: done (suite 28/36).** Grant now follows Samba 4.19.5
`delay_for_oplock` + `try_lease_upgrade` (open.c): stat opens neither break
nor wait (lease stat opens skip other leases) and are exempt from share-mode
checks; another open drops W; a non-lease open drops H; byte-range locks drop
R; an existing lease changes only on a strict, fully-grantable upgrade.
Oplock grants use the same rules (any H lease ⇒ no oplock). `statopen3` also
fails against a Samba 4.19.5 reference server (lease.c:943), so it is not
counted as an rssmb gap.

The request_lease candidate computation grants the union of current+requested
without honoring the Samba matrix:
- upgrade while another lease exists or after a break must not re-grant
  H/W beyond the broken-to state (break :629 expects R, got RH);
- W requires no other opens outside the lease AND no pending/stat-open
  interference — a stat open (FILE_READ_ATTRIBUTES) must not block the
  holder's W but must not be granted W itself (statopen2/4);
- per-row matrices (break_results 16 rows, upgrade tables) come from the
  torture tables quoted above — the grant function must implement exactly
  them (they are Windows-derived and Samba-matched).

### L3 — Second-contender break while a break is already in flight
unblocks: break_twice, breaking5, multibreak edge rows, complex1

`trigger_breaks` skips a lease already `breaking` (`if !rec.breaking`)
instead of queueing a stricter second break (pending_break_to escalation
exists only in ack path). Samba re-issues/escalates the break to the lower
of the two targets.

### L4 — v2 lease epoch/version field bugs
unblocks: v2_epoch1–3, v2_breaking3, v2_complex1/2, v2_bug15148, v2_rename(epoch part)

Measured deltas (rssmb vs golden):
- grant epoch = client_epoch + 2 where Samba sends client_epoch + 1
  (0x4713 vs 0x4712 — rssmb increments at grant AND once more);
- break `new_epoch` = post-increment where Samba sends the pre-increment
  epoch in the break notification and bumps the stored epoch on ack
  (v2_bug15148: expected 0x4713, got 0x4714);
- v2 response `lease_version` echoes 0 instead of 2 (v2_epoch3 :1964).

### L5 — Breaks missing on rename/lock/unlink paths + ack-required flag
unlocks: v2_rename, lock1, unlink(golden-red), rename_wait(part)

ConflictOp::HandleOrDelete exists; rename handler doesn't call break_for_op
with it; LOCK calls it but the notification apparently doesn't reach the
holder (lock1 times out) — likely same L1 delivery issue; unlink break
flags lack ACK_REQUIRED (golden-red anyway).

### L6 — stat-open share-mode conflict (statopen)
unblocks: statopen, statopen2(part)

FILE_READ_ATTRIBUTES open collides with the leased holder's share mode at
the open table (SHARING_VIOLATION at :782). Samba treats attr-only opens
as non-conflicting (they carry no read/write share). Needs
desired-access-aware share-conflict evaluation, or special-case
FILE_READ_ATTRIBUTES-only opens.

### L7 — Same-key-on-second-file + stream leases (request)

Verify INVALID_PARAMETER for lease key bound to a different file (exists —
`request_lease` returns Err), and decide stream handling: rssmb has no
stream support (names with ':' likely rejected as invalid) — Samba only
passes `request` with streams_depot. **Decision needed:** implement
minimal stream-less behavior matching Samba-without-streams (golden would
then also fail `request`… no — golden passes WITH streams configured).
rssmb cannot pass `request`'s stream section without stream support;
the subtest may remain red unless streams are in scope. Options in
implementation plan: (a) document as not-implemented (1 subtest), or
(b) treat ":stream" names as separate lease-scoped entities. Analysis
recommendation: (a) — streams are their own campaign; target stays ≥30
without it (31 of the golden-green set + request = 32 possible).

## Environment notes for implementation

- All breaks in this suite run on single- or dual-transport sessions; the
  torture's `lease_transport` assertion (break must arrive on the holder's
  transport, value `0xcbad9a00`-tagged) means notifications must go to the
  connection that OWNS the lease (recorded `notify_tx`), which rssmb does
  per-record — verify during L1 work.
- smbtorture 4.19.5's lease suite takes ~2 min wall-clock uncapped; the
  120 s harness cap truncates it (36 verdicts need ~140 s) — bump the
  runner's per-suite timeout for smb2.lease during this campaign, or count
  from the log tail. CI's nightly runs the same script — the results.md
  numbers must come from a full uncapped run.

## Expected end state

31–32/36 (all golden-green subtests; `request` depends on the stream
decision; statopen3 + unlink documented golden-red per upstream knownfail;
3 skips at parity). Full baseline re-run; regression anywhere blocks merge.
Campaign A carry-over: the durability lease precondition (RH+ lease ⇒
durable grant) is already implemented and covered by the durable suite.
