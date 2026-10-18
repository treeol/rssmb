# Campaign A — smb2.durable-v2-open analysis (conf/durable-v2)

Status: **analysis only — no server changes yet.**

- Baseline: rssmb 0.1.3 (237d8c0), smbtorture **4.19.5**: **0/15**
- Golden: Samba **4.19.5** server, same torture client: **14/15**
  (golden log: `tmp/samba-ref/golden-smb2-durable-v2-open.log`, gitignored)
- Golden setup: standalone smbd 4.19.5 (`--network host`, port 4450, share on
  tmpfs via `tmp/samba-ref/`), user `alice`, `kernel share modes/oplocks =
  no`, `posix locking = no` — mirroring Samba's selftest `[durable]` share
  (`selftest/target/Samba3.pm:3088`). With `map to guest` the golden drops to
  11/15; real-user auth is required for the reopen1a session semantics.
- Reference torture source: Samba 4.19.5
  `source4/torture/smb2/durable_v2_open.c` (copy in
  `.reference/samba-torture/durable_v2_open.c`, gitignored).
- `persistent-open-oplock`/`persistent-open-lease` pass on Samba against a
  **non-CA share**: the share does not advertise CONTINUOUS_AVAILABILITY, so
  Samba treats the persistent request as a plain durable request (torture
  picks the non-CA table, `durable_open_vs_oplock_table`). These two subtests
  are therefore **in scope for this campaign**; the original task's
  assumption that they would be the allowed failures was wrong.

## Per-subtest table

| Subtest | Torture sequence (essentials) | Asserts | rssmb today | Samba 4.19.5 | MS-SMB2 |
|---|---|---|---|---|---|
| create-blob | DH2Q open (batch oplock, timeout=UINT32_MAX); reconnect; DH2C combined with DHv1-request / DHv1-reconnect / both / DH2C+DH2Q in one CREATE | `durable_open_v2=1`, `timeout=300000`, create_action/file_attr on first open; all 4 bogus combos → `INVALID_PARAMETER` | first open: `durable_open_v2=0`, `timeout=0`; bogus combo 1 → OK (line 150) | pass | §2.2.13.2.11/12, §3.3.5.9.10/11, §3.3.5.9.12 |
| open-oplock | 32 opens: oplock ∈ {none,II,excl,batch} × share-mode 8 variants, each with DH2Q | durable granted **iff batch oplock** (`durable_open_v2` mirrors table); create_action=Created, file_attr=Archive on each fresh create | create_action=0x1, file_attr=0xa0 wrong on every created file; durable_v2 flag never in response | pass | §3.3.5.9.10 (durability requires batch oplock or lease) |
| open-lease | 40 opens: lease ∈ {none,R,RW,RH,RHW} × share-mode, each with DH2Q | durable granted **iff lease ≥ RH**; RqLs echo, oplock_level=Lease | same create_action/file_attr bugs; durable flag never set; lease echo OK on non-durable opens | pass | §3.3.5.9.10 |
| reopen1 | DH2Q open; **DH2C on same live connection** while handle open | `OBJECT_NAME_NOT_FOUND` (durable only exists after disconnect) | `SHARING_VIOLATION` (line 558) — DH2C path hits live open table | pass | §3.3.5.9.12 step 4 |
| reopen1a | DH2Q open; **session reconnect** (SESSION_SETUP with PreviousSessionId on 2nd TCP conn); DH2C from old session then new session | old-session DH2C → `USER_SESSION_DELETED`; new-session DH2C → OK, no DH2Q response blob, timeout=0 | old-session DH2C → `SHARING_VIOLATION` (line 650); PreviousSessionId is never read by rssmb | pass | §3.3.5.5 (PreviousSessionId), §3.3.5.9.12 |
| reopen1a-lease | same as reopen1a with RWH lease; 3rd reconnect with different client GUID must fail, original GUID must succeed | same as reopen1a + lease-key echo on successful reconnect; wrong-guid → `OBJECT_NAME_NOT_FOUND` | old-session → OK instead of `USER_SESSION_DELETED` (line 831) — worse, it succeeds; lease-guid scoping absent | pass | §3.3.5.9.12 + lease client-GUID scoping |
| reopen2 | DH2Q open; TCP drop; reconnect; DH2C without GUID → NOT_FOUND; wrong GUID → NOT_FOUND; right GUID+file → OK (twice, garbage params ignored) | failure cases → `OBJECT_NAME_NOT_FOUND`; success → no DH2Q blob, EXISTED, batch oplock | `INVALID_PARAMETER_6` (line 983) — DH2C without CreateGuid is parsed as zero-GUID, misses table, but path returns wrong status; success path returns SHARING_VIOLATION via open-table conflict with the still-registered original open | pass | §3.3.5.9.12 |
| reopen2b | DH2Q open; drop; DH2C with zero GUID → NOT_FOUND; then **DHv1 reconnect** (`DHnC`) → OK | DHv1 reconnect of a DH2Q open succeeds | `INVALID_PARAMETER_6` (line 1141); DHv1 contexts not parsed at all | pass | §3.3.5.9.12 |
| reopen2c | **DHv1 open** (`DHnQ`); drop; DH2C reconnect | DH2C reconnect of a v1 open → `OBJECT_NAME_NOT_FOUND` (no CreateGuid exists) | `INVALID_PARAMETER_6` (line 1230) | pass | §3.3.5.9.12 |
| reopen2-lease | lease+DH2Q open; drop; DH2C w/o lease → NOT_FOUND; wrong lease key → NOT_FOUND; wrong filename+lease → `INVALID_PARAMETER`; right everything → OK, lease re-echoed RWH | lease-key validation on reconnect; `INVALID_PARAMETER` for name/lease mismatch; lease state echoed | `INVALID_PARAMETER_6` (line 1327); no lease-key check on DH2C | pass | §3.3.5.9.12 |
| reopen2-lease-v2 | same with RqLs v2 (epoch) | same, v2 lease echoed | `INVALID_PARAMETER_6` (line 1576) | pass | §3.3.5.9.12 |
| durable-v2-setinfo | lease-v2+DH2Q open; SetInfo EOF=1 MiB; drop; reconnect → OK, size echoed | durable survives metadata change; `io.out.size`/lease echoed | fails on the lease-v2 echo (`lease_state=0`) + generic DH2C path | pass | §3.3.5.9.12 |
| app-instance | two trees, same AppInstanceId (`QFid`), batch oplock each | second open OK, **no oplock break** to first opener; first handle closes → `FILE_CLOSED` | second open → `SHARING_VIOLATION` (line 1809) | **fail** — see below | §3.3.5.9.10 |
| persistent-open-oplock | open-oplock table with persistent=1 requested | non-CA share ⇒ degrade to durable table (durable iff batch oplock; persistent never granted) | create_action/file_attr bugs; no DH2Q response blob | pass | §3.3.5.9.10 |
| persistent-open-lease | open-lease table with persistent=1 | same degradation | same bugs | pass | §3.3.5.9.10 |

## app-instance: no golden exists

Samba 4.19.5 has **no server-side AppInstanceId handling at all**. The
`app_instance_id` field exists only in the smbXsrv IDL
(`source3/librpc/idl/smbXsrv.idl:470`); `source3/smbd/smb2_create.c` never
parses the `QFid` create context (grep: zero matches for APP_INSTANCE in
source3/smbd). The observed Samba behaviour is plain oplock semantics: the
second batch-oplock open triggers a break of the first opener's oplock
(`break_info.count == 1` where the torture expects 0), and the test fails.

Decision (user, this campaign): **option (b)** — not implemented; documented
as "no Samba golden (4.19.5 has no server-side AppInstanceId support); not
implemented in this campaign". rssmb keeps its current behavior (no QFid
parsing) and the subtest is counted as the one expected failure.

**Campaign target: 14/15** (everything except app-instance).

## Root-cause groups (ordered by subtests unblocked)

### G1 — DH2Q response blob never built (unblocks 12)

`handle_create` (dispatch.rs:3341-3363) builds response create contexts only
for RqLs. When a DH2Q is granted, MS-SMB2 §3.3.5.9.10 requires a
`DH2Q` (durable handle v2 response) context containing the server timeout;
the CREATE response then shows `durable_open_v2=1`, `timeout=<server picks>`.
Samba returns **300000 ms (300 s)** regardless of the client's requested
(UINT32_MAX) — captured from the golden run.

Also: durability is currently granted whenever a DH2Q context is present
(dispatch.rs:3163-3215) — no oplock/lease precondition, and the client's
`timeout`/persistent `flags` fields are parsed but dead
(`#[allow(dead_code)]`, dispatch.rs:2531-2551).

Fix shape: after a successful create with DH2Q and **batch oplock granted**
(see G5 for the lease condition), append the DH2Q response context
(`timeout=300_000`); echo `durable_open_v2=1`, `timeout=300000`;
`persistent_open` stays 0 (no persistent support; see G6). Reject
DH2Q+DHv1-request combos per §3.3.5.9.12 with `INVALID_PARAMETER`
(referenced by create-blob line 150 — actually in G4's combination table).

Subtests: create-blob, open-oplock, open-lease, reopen1, reopen2, reopen2b,
reopen2c, reopen2-lease, reopen2-lease-v2, durable-v2-setinfo,
persistent-open-oplock, persistent-open-lease (all of them need the first
open to carry a correct durable response).

### G2 — General CREATE response bugs (unblocks 12, but really all suites)

Every created file answers `create_action=0x1` (Opened) where 0x2 (Created)
is expected, and `file_attr=0xa0` (ARCHIVE|NORMAL) where 0x20 (Archive) is
expected. Root causes:

- `create_action` is hard-coded to `CreateAction::Opened` at dispatch.rs:2973
  (DH2C path), :3023 (pipe path), :3354 (normal path). The VFS does not
  report whether the file was created vs opened; `localfs::create`
  (localfs.rs:391) knows `needs_create`/`existed` internally but the trait
  returns only OpenId. Fix: have create report the action (or infer:
  disposition Create/Supersede → Created/Overwritten; OpenIf → existed vs
  created — needs VFS trait change) and map Superseded=0x0 / Opened=0x1 /
  Created=0x2 / Overwritten=0x3 correctly per disposition + existence.
- `file_attributes_to_fscc` (fsinfo.rs:36-47) sets both `archive` and
  `normal` for regular files because `attributes_from_metadata`
  (localfs.rs:101-115) sets `normal: !is_dir`. MS-SMB2/MS-FSCC: NORMAL and
  ARCHIVE are mutually exclusive; Samba returns 0x20 (ARCHIVE only). Fix in
  the VFS mapping: `normal` only when no other attribute is set
  (Samba semantics: `normal = !is_dir && !archive && !system && ...`);
  practically for localfs: drop `normal` for files that have `archive` set.

**These are general CREATE bugs, not durable-specific** — they very likely
affect smb2.create, smb2.getinfo, smb2.setinfo numbers too. Plan: fix them
in this campaign (they block 12 durable subtests), then re-run the full
baseline and **report the side-effect on other suites; not chased further
here.**

### G3 — DH2C reconnect semantics (unblocks reopen1, reopen2, reopen2b, reopen2c, reopen2-lease, reopen2-lease-v2)

Current DH2C path (dispatch.rs:2821-2990):

1. **Statuses wrong.** Missing/expired/mismatched durable must return
   `OBJECT_NAME_NOT_FOUND` (Samba, golden); rssmb returns
   `STATUS_OBJECTID_NOT_FOUND (0xC00000F4)` for misses — but
   `INVALID_PARAMETER_6` leaks at line 1141/1230/1327/1576 cases because the
   DH2C context without a CreateGuid parses to a zero GUID and the create
   falls into ordinary file-open validation (name "" → param 6 error). Per
   §3.3.5.9.12 + golden: **any** DH2C that fails matching returns
   `OBJECT_NAME_NOT_FOUND`, except name/lease-key mismatch with a *matched*
   durable → `INVALID_PARAMETER`.
2. **Live-handle reconnect not distinguished.** DH2C on a connection where
   the handle is still open (reopen1) must be `OBJECT_NAME_NOT_FOUND`
   (the durable entry only becomes orphaned after disconnect; rssmb's
   durable table is populated at create time and remains keyed while the
   original open lives — so the DH2C "take" succeeds conceptually but then
   collides with the still-live open in the open table → `SHARING_VIOLATION`).
   Fix: mark the durable entry as orphaned only on connection cleanup
   (connection.rs:1276-1287 already skips closing the VFS handle but must
   also flip the entry state), and reject DH2C while not orphaned.
3. **DHv1 reconnect (`DHnC`) not parsed** — reopen2b reconnects a DH2Q open
   with a v1 reconnect context and expects success. Fix: parse `DHnC`/`DHv1`
   request context (file id + CreateGuid? v1 has only file id — but golden
   shows v1 reconnect succeeding for a v2 open, i.e. Samba looks up by
   file id in that case). Needs byte-level check against Samba via impacket
   (what identity does Samba match on for DHnC against a DH2Q open?).
4. **Lease-key validation on DH2C missing.** reopen2-lease: DH2C with
   lease request must match the stored lease key; wrong key →
   `OBJECT_NAME_NOT_FOUND`; wrong filename with right key →
   `INVALID_PARAMETER`; right everything → lease re-echoed with original
   state. rssmb ignores the lease context on the DH2C path entirely.
5. **Reconnect response fields:** successful DH2C must echo create_action
   EXISTED (0x1 is actually correct here), file_attr 0x20, oplock_level =
   original level (batch or Lease), **no** DH2Q response blob, timeout=0,
   and for lease opens a RqLs echo with the original lease key/state.
   Current response hard-codes `OplockLevel::None`, empty contexts
   (dispatch.rs:2970-2983).

### G4 — PreviousSessionId / session-reconnect semantics (unblocks reopen1a, reopen1a-lease)

`PreviousSessionId` (session_setup.rs:36) is parsed by the proto crate but
**never read by the server** (grep: zero uses in rssmb-server). Semantics
per golden (Samba):

- SESSION_SETUP with a non-zero PreviousSessionId and the **same user**:
  the old session is torn down (its tree connects and opens invalidated);
  subsequent requests using the old SessionId → `USER_SESSION_DELETED`.
- The old session's **durable** opens survive (they move to the new
  session's reconnect scope); a DH2C from the new session then succeeds.
- reopen1a-lease additionally scopes durable reconnect by **client GUID**:
  a reconnect from a different client GUID fails with
  `OBJECT_NAME_NOT_FOUND` even with the right CreateGuid+lease key; the
  original GUID succeeds. rssmb stores no client GUID in the durable entry.

Fix shape: store `client_guid` (and lease key when leased) in DurableEntry;
implement PreviousSessionId teardown in handle_session_setup (find old
session, verify same user, close it, return `USER_SESSION_DELETED` for
subsequent old-session traffic — the existing per-connection session
validation may already do this once the old session is removed from the
registry).

### G5 — Durable-grant precondition (batch oplock only this campaign)

Enforce: DH2Q is honored (response blob + durable entry) **only when a
batch oplock was granted**. The lease-based condition (RH/RWH lease) is
**deferred to Campaign B** (leases): the open-lease subtest requires it,
but a full lease-grant state check is B's subject. This campaign's
open-lease subtest will therefore still fail its RH/RHW rows (durable=0
expected but our DH2Q grant without precondition currently reports 0 too —
net effect on that one subtest is unchanged; see risk note). Campaign B's
analysis must pick up: durable granted iff (batch oplock OR lease with
RWH/RH state), per §3.3.5.9.10 and the golden tables.

### G6 — persistent request flag

`persistent_open` requested → we do not implement persistent handles.
Golden (non-CA share): Samba grants durable, never persistent
(`persistent_open=0` in response, DH2Q blob still present). We mirror the
golden: parse the flag, ignore for granting, never echo persistent=1.
The two persistent-* subtests pass on Samba this way and should pass for
rssmb with G1+G2 fixed.

### G7 — (deferred) durable sweeper

`DurableTable::sweep` exists (durable.rs:197) with tests, but no task ever
calls it — eviction is lazy (insert/take/peek). Not exercised by this
suite (no timeout subtest in smb2.durable-v2-open; the delay variants live
in `smb2.durable-v2-delay`, not in our baseline list). Fix while in the
area (spawn a sweep task in ServerState) but it unblocks no subtest —
lowest priority, listed for completeness.

## Golden-assertion plan (per the campaign rules)

For every state transition implemented, capture Samba's actual bytes with
impacket against the `samba-419-ref` container and assert rssmb matches on
status + relevant response fields (create contexts echoed, timeout=300000,
oplock_level, lease echo). Hand-written expectations only in addition,
never instead. Byte-for-byte means status + the relevant response fields,
normalizing run-dependent values (file ids, timestamps, GUIDs).

## Expected end state

14/15 on smb2.durable-v2-open (app-instance documented as not implemented
— no Samba golden exists). Full baseline re-run; any regression in another
suite blocks merge, with the expected positive side effect in
smb2.create/getinfo from G2 reported as such.
