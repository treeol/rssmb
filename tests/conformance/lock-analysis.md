# Campaign C — smb2.lock analysis (conf/locks)

Status: **analysis + side tasks done — no lock-path server changes yet.**

- Baseline (this branch, 2026-10-23, uncapped harness, smbtorture 4.19.5):
  **3/22** (`truncate` passes; `rw-none`, `replay_broken_windows`,
  `ctdb-delrec-deadlock` skip). Same as the stale 2026-10-19 line — the
  lease campaigns did not move lock.
- Golden: **Samba smbd 4.19.5** (recreated `samba-419-ref` container,
  `samba-419-ref:latest`, :4450, share `public` chmod 777, alice/TestPass123):
  **22 pass / 0 fail / 3 skip** (`rw-none` — W2K8-only bug test,
  `replay_broken_windows` — skips when the server implements LockSequence,
  `ctdb-delrec-deadlock` — cluster-only). Golden log:
  `target/dbg/golden-smb2-lock.log` (gitignored area).
- Upstream `selftest/knownfail` (tag `samba-4.19.5`) lists
  `samba4.smb2.lock.valid-request`, `*.multiple-unlock` (bug 6959),
  `*.zerobyteread` (bug 6974), `*.replay_broken_windows` — **s4-ntvfs
  matrix entries**; smbd standalone passes the first three. The golden
  ceiling for us is therefore **22/25 with 3 skips**, i.e. all 22 counted
  subtests are chaseable. (The 2026-10-19 knownfail claim that some lock
  subtests are not chaseable does not hold against smbd.)
- Reference torture source:
  `.reference/samba-torture/lock.c` (Samba 4.19.5, gitignored).

## Root-cause groups (ordered by subtests unblocked)

### K1 — Wrong NTSTATUS constants (2 one-line fixes; flips ~3 subtests)
We hard-coded two wrong codes:
- LOCK conflict path (dispatch.rs `handle_lock`): `0xC000_005A` labelled
  LOCK_NOT_GRANTED — **0xC000005A is STATUS_INVALID_OWNER** (Wine
  ntstatus.h / MS-ERREF). Correct value: **0xC0000055**.
- READ/WRITE byte-range conflict: `0xC000_0070` labelled
  FILE_LOCK_CONFLICT — **0xC0000070 is STATUS_INVALID_WORKSTATION**.
  Correct value: **0xC0000054**.
These wrong codes are directly visible in the torture log
(`async`, `cancel*`, `stacking`, `contend` all saw INVALID_OWNER;
`rw-exclusive` saw INVALID_WORKSTATION). Flips (status-correct paths that
already detect the conflict): `stacking`, `contend`, `rw-exclusive`.

### K2 — Conflict semantics for same-open locks (~2)
`OpenTable::acquire_range_lock` skips ALL of the owner's own locks, and
`check_range_lock_for_write` skips all own locks too. Golden semantics
encoded by the torture:
- Same handle, overlapping **exclusive**, second FAIL_IMMEDIATELY lock →
  LOCK_NOT_GRANTED (`auto-unlock`, lock.c:563).
- Same handle holds a **shared** lock → its OWN write to the range gets
  FILE_LOCK_CONFLICT (`rw-shared`, lock.c:423 — own shared locks do NOT
  permit writes; that is the point of a shared lock).
- Same handle holds an **exclusive** lock → its OWN read/write is fine
  (covered by the rw-exclusive tail).
Rule: for writes, skip only the open's own EXCLUSIVE locks; for
exclusive acquisition, same-open overlap conflicts; shared acquisition
over own shared overlap is fine.

### K3 — Unlock validation and all-or-nothing (~3)
Our UNLOCK path ignores flag combinations and never errors:
- `SHARED|UNLOCK` (type bit with UNLOCK) → INVALID_PARAMETER
  (`unlock`, lock.c:1642).
- Multi-element unlock must be all-or-nothing: a missing range anywhere
  → RANGE_NOT_LOCKED (0xC000007E) and NO element released
  (`multiple-unlock`, lock.c:1885 bug 6959 — golden-RED for s4 but smbd
  passes it; `context` double-unlock, lock.c:2471).

### K4 — Zero-length lock and 0-byte read semantics (~3)
- Zero-length locks are VALID and granted (SMB2: length 0 with
  SHARED/EXCLUSIVE locks... the tests assert OK for 0/0 and zero-byte
  locks: `lock` lock.c:625, `zerobytelength` lock.c:1403). Our
  `length == 0 → INVALID_PARAMETER` is backwards.
- What IS invalid: flags==0 (no type bit) → INVALID_PARAMETER
  (`valid-request`, lock.c:101). Currently we return OK because the
  proto appears to parse that request as zero elements — verify proto
  Locks parsing (lock_count vs actual elements) in this group.
- `zerobyteread` (lock.c:1529, bug 6974, golden-RED on s4, smbd passes):
  0-byte read at offset 5 must return OK with 0 bytes, not END_OF_FILE
  (our read path returns EOF).

### K5 — Blocking locks + CANCEL via pending_async (~4)
Conflicts WITHOUT `FAIL_IMMEDIATELY` must pend (AsyncOp already exists;
`Command::Lock` is even named in its doc comment but never wired):
- interim STATUS_PENDING; completion on release/unlock of the blocking
  range → the pended lock is then granted (`async` lock.c:855).
- CANCEL while pended → STATUS_CANCELLED (`cancel`, lock.c:920) — the
  S1 pre-interim CANCEL fallback (mid=0 → newest session op) is the
  exact mechanism Samba's client exercises here.
- TREE_DISCONNECT / LOGOFF cancel pended locks (the suite asserts
  RANGE_NOT_LOCKED-or-OK on the follow-up unlock — accept either, as the
  test does, `cancel-tdis` :1064, `cancel-logoff` :1152).
- 35 s timeout → LOCK_NOT_GRANTED (not exercised by these subtests but
  required for correctness; mirrors the lease break timer).

### K6 — LockSequence replay detection (~2 pass + 1 skip parity)
`replay_smb3_specification_durable` / `_multi` (lock.c:3237): locks sent
with `lock_sequence` numbers; a replayed sequence number on the same
open must be detected (replay of an already-successful sequence →
return the original result / a replayed failing sequence →
LOCK_NOT_GRANTED). smbd implements LockSequence for all handles, which
also makes `replay_broken_windows` SKIP — the golden parity signal.

### K7 — Remainder (1–3, work out in order)
- `errorcode` (lock.c:1243): first conflicting lock per handle gives
  LOCK_NOT_GRANTED — we granted instead; needs a live trace.
- `range` (lock.c:2566): huge-offset conflict chain
  (`NEXT_OFFSET += ~0ull/numops`); likely u64 arithmetic or overlap
  edge at very large offsets.
- `overlap` (lock.c:2757): read-lock coalescing assertions via the
  test helpers ("the same handle cannot coalesce read locks").

## Knownfail / ceiling check
All 22 counted subtests pass on smbd 4.19.5 → target ≥19/22 is fully
within reach; K1+K2+K3 alone project to ~11, K4/K5 reach ~18-19, K6
pushes past 20. Note the 2026-10-19 claim (lease-analysis.md era) that
some lock subtests are Samba-knownfail does NOT hold against smbd —
those knownfail entries are s4-ntvfs only.

## Side tasks (done on this branch, own commits)

### S1 — notify hang root-caused and fixed (commit `ac3c2f6`)
The nightly INCOMPLETE was never a budget problem: the suite hung on
subtest 1 since the publish_on_close merge (ceb20a3) exposed the
tree-wide CLOSE cancel. Six fixes (see commit message): handle-scoped
watch cancel + STATUS_NOTIFY_CLEANUP on CLOSE/TDIS/LOGOFF/rebind,
pre-interim CANCEL (mid=0) fallback, watched-dir-deleted →
STATUS_DELETE_PENDING, CLOSE-cleanup guard self-deadlock.
Result: 4 more passing subtests (tdis1, close, logoff,
session-reconnect; rmdir1 fixed but still fails later checks in some
runs), remaining failures check-level except `basedir` — attribute-
change filter fidelity (SETATTR on the watched dir must NOT match
FILE_NOTIFY_CHANGE_ATTRIBUTES for a non-recursive... for the dir itself;
on a child must) — deferred to a future notify campaign. Budget stays
240 s with an honest comment (stall reached ~180 s).

### S2 — results.md annotations (commit `6789c8b`)
Fresh baseline row set; lease row now marks rename_wait/multibreak
timing-flaky (28–31 observed 10-20..10-23); notify row documents the
basedir debt instead of implying a truncation artifact.

## Provenance
- Samba sources fetched today from
  raw.githubusercontent.com/samba-team/samba @ samba-4.19.5:
  source4/torture/smb2/lock.c, source4/torture/smb2/notify.c,
  source4/libcli/smb2/cancel.c, libcli/smb/smbXcli_base.c,
  source3/smbd/smb2_server.c, selftest/knownfail.
- NTSTATUS codes cross-checked against Wine's include/ntstatus.h
  (matches MS-ERREF); **our own in-tree labels were wrong twice**
  (K1) — do not trust code comments for status values.
- Live runs: rssmb @ conf/locks (203b55a + notify fixes), golden
  container recreated from `samba-419-ref:latest` (its Cmd bakes the
  full smb.conf + smbpasswd setup; needs `chmod 777 /srv/*` after
  start).
