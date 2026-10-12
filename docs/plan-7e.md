# Plan 7e — Encryption follow-ups (enforcement, live interop, AES-128-CCM)

Status: **Mashūra plan review round 1 folded in (§7); semantics pinned
against Samba source (§2). Ready for implementation after user go-ahead.**
Baseline: `main` @ `e03d1d5` (7d done: AES-128-GCM for 3.1.1). 203 unit tests,
impacket 8/8.

7d left encryption *mechanically* working but *policy* largely unenforced.
This step closes that gap before Step 8, then adds AES-128-CCM so 3.0/3.0.2
clients can encrypt too.

## 0. Current state (observed 2026-10-11)

| # | Gap | Evidence |
|---|---|---|
| G1 | `required` deny check is inside `if signable`, so guest/anonymous sessions bypass it; signing state is inserted *before* the deny (non-transactional) | `dispatch.rs:1068`, `:1118`, `:1149-1160` |
| G2 | `SESSION_FLAG_ENCRYPT_DATA` never set | `dispatch.rs:1253-1263` |
| G3 | No rejection of unencrypted requests; `Session.encryption_required` written, never read | `dispatch.rs:1214`, `session.rs:52` |
| G4 | TX encryption decided from the *first* member's session only, no tree-level rule; read loop and `send_unsolicited` decide differently | `connection.rs:539-559`, `dispatch.rs:2655-2674` |
| G5 | `ShareConfig.encrypt_data` never read; no `SHAREFLAG_ENCRYPT_DATA`; `TreeEntry` has no flag | `config.rs:161-164`, `dispatch.rs:1507-1518` |
| G6 | Decrypted frames: inner effective SessionIds never compared to the transform SessionId; parse-error branch runs `signing::verify_frame` on decrypted plaintext | `connection.rs:282-336`, `:356` |
| G7 | `decrypt_message` checks neither transform `Flags == 1` nor `OriginalMessageSize == ciphertext len` | `crypto.rs:393-417` |
| G8 | Crypto hard-coded to GCM; `EncryptionState` stores no cipher; no CCM; CAP_ENCRYPTION never advertised | `crypto.rs:409-411`, `dispatch.rs:1217`, `:777-784`, `:1130-1141` |
| G9 | No live encrypted client has ever exercised the AEAD path | 7d notes |

Dependencies (index.crates.io reachable 2026-10-11): `ccm 0.5.0` requires
`aead ^0.5`, `cipher ^0.4.3`, `ctr ^0.9.1`, `subtle ^2` — matches the locked
`aead 0.5.2`, `aes 0.8.4`, `cipher 0.4.4`, `ctr 0.9.2`. `ccm 0.6.x` moves to
`aead 0.6`/`cipher 0.5` and is **not** compatible with `aes-gcm 0.10`.
Confirm with `cargo tree -i ccm` after adding (3.6).

## 1. Scope

**In:** G1–G9.
**Out (deferred, recorded in `docs/next-steps.md`):** AES-256-GCM/CCM,
compression (0xFC), received-nonce replay window, per-key invocation limits
beyond the non-wrapping counter, GMAC signing, re-auth/binding over
encryption, per-open (`fsp`) encryption flags.

## 2. Semantics — pinned against Samba

The MS-SMB2 spec pages could not be fetched (web search blocked), so the
reference is **Samba master** source (fetched 2026-10-11):
`source3/smbd/smb2_server.c` (`smbd_smb2_request_dispatch`, ~3045-3450),
`smb2_sesssetup.c` (~258-316), `smb2_tcon.c` (~311-431),
`smb2_negprot.c` (~411-611), `libcli/smb/smb2_signing.c` (~688-760,
912-930). Where we deviate, it's stated.

### 2.1 Session admission (final SESSION_SETUP)
| Condition | Result (Samba) |
|---|---|
| policy ≥ desired and client `CAP_ENCRYPTION` | session `EncryptDesired` |
| policy = required | session `EncryptRequired` + `EncryptDesired` |
| guest/anonymous and `EncryptRequired` | `STATUS_ACCESS_DENIED` |
| negotiated cipher = 0 and `EncryptRequired` | `STATUS_ACCESS_DENIED` |
| guest | cipher forced to none |
| `EncryptDesired` | response sets `SESSION_FLAG_ENCRYPT_DATA` |

**Deviation (keep current default):** our `desired` is the *default* and
means "offer and accept, don't ask" — Samba's `default`/`if_required` level.
So for us: `desired` → keys derived, **flag not set**, plaintext accepted;
`required` → flag set + enforcement. (Adding a Samba-style "desired = ask the
client" level would make every default-config client encrypt; out of scope.)
All checks run before **any** per-session state is committed (signing,
encryption, session list, preauth); denial leaves the connection reusable.

### 2.2 Request processing (per message, incl. each compound member)
Order, following `smbd_smb2_request_dispatch`:
1. `do_encrypt = session.encrypt_data` (false for SESSION_SETUP).
2. If the request arrived in a transform: the resolved session's id must
   equal the transform SessionId → else **`STATUS_ACCESS_DENIED`** (Samba;
   comment notes Windows allows it). **Deviation: we disconnect** — fail
   closed, Samba notes Windows clients never send this. Then
   `was_encrypted = do_encrypt = true`.
3. `session.encrypt_data && !was_encrypted` → `STATUS_ACCESS_DENIED`, reply
   **encrypted** (`do_encrypt = true`). Applies to every command that names
   an existing session, including ECHO, LOGOFF, TREE_CONNECT and CANCEL
   (CANCEL produces no reply; it is just not acted on). SESSION_SETUP for a
   new session and NEGOTIATE never reach it (no session yet).
4. Signature verification is skipped when `was_encrypted`.
5. For commands that need a tree (Samba `need_tcon`: everything except
   NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, ECHO, CANCEL):
   `tree.encrypt_data && !was_encrypted` → `STATUS_ACCESS_DENIED`, encrypted
   reply; `tree.encrypt_data` → `do_encrypt = true`.
6. Checks 3 and 5 run **immediately before executing each member**, with the
   dispatcher's resolved session/tree (so a related member after a
   TREE_CONNECT sees the new tree). Denied members get the error response;
   other members are processed normally; related members after a denied one
   follow the existing related-failure handling (they inherit the failed
   member's error — assert the exact statuses in tests).

### 2.3 Response protection (TX)
- Reply encrypted iff the request's `do_encrypt` ended up true (2.2), **and**
  the session has an `EncryptionState`. If `do_encrypt` is true but the
  state is missing → disconnect (never plaintext).
- Never encrypt NEGOTIATE / SESSION_SETUP responses.
- Compound: one transform over the whole response chain; encrypt if any
  member's `do_encrypt` is true (all members share the transform session,
  enforced by 2.2.2 for encrypted input; for plaintext input with mixed
  sessions, use the encrypting member's session and require all members of
  that response to belong to it, else disconnect — [edge case, test it]).
- Async: interim `STATUS_PENDING` and the final response carry the original
  request's `do_encrypt`/session (stored with the pending op), never the
  CANCEL packet's.
- Server-initiated (oplock/lease break, if/when sent): encrypt iff the
  session or tree has `encrypt_data`. Audit every `send_unsolicited` caller.

### 2.4 Tree connect
| Condition | Result (Samba) |
|---|---|
| share `encrypt_data` and guest session | `STATUS_ACCESS_DENIED` |
| share `encrypt_data` and cipher = 0 / no EncryptionState | `STATUS_ACCESS_DENIED` |
| share `encrypt_data` otherwise | tree `encrypt_data`, `SHAREFLAG_ENCRYPT_DATA` |
| TREE_CONNECT itself plaintext | allowed (not `need_tcon`), unless session-level 2.2.3 rejects it |

### 2.5 Transform validation (RX, before/after AEAD)
- `len ≥ 52`; `Flags == 0x0001` else disconnect (Samba returns
  ACCESS_DENIED from decrypt → connection drop).
- `OriginalMessageSize == len - 52`, ≥ 64, ≤ `max_frame_size`, else
  disconnect.
- AEAD failure → disconnect, no reply. Plaintext must start with `0xFE 'SMB'`.
- Nonce: GCM uses wire bytes 0..12, CCM 0..11; on TX the unused tail is
  zero; on RX the tail is not checked (it's in the AAD anyway).

### 2.6 Negotiation
- 3.0/3.0.2/3.1.1: set `CAP_ENCRYPTION` in the response iff policy ≠
  disabled **and** the client set it.
- 3.1.1 with ENCRYPTION_CAPABILITIES: clear CAP_ENCRYPTION, pick the
  server-preferred common cipher (GCM > CCM), reply with one cipher (0 if
  none). `CipherCount == 0` or short data → `STATUS_INVALID_PARAMETER`.
- 3.0.x with CAP_ENCRYPTION: cipher = AES-128-CCM.
- No common cipher still lets NEGOTIATE succeed; `required` then denies at
  SESSION_SETUP (2.1).

## 3. Work items (one commit each; `cargo test` green after each)

### 3.1 Transactional admission + flag (G1, G2)
- Restructure the SESSION_SETUP success path: compute identity, signing key,
  cipher, enc/dec keys and run all 2.1 denials first; only then insert
  signing state, encryption state, session, and drop the preauth entry.
- Store the cipher in `EncryptionState` (needed by 3.6).
- Set `SessionFlags` encrypt_data under `required` (check the smb-msg
  bitfield exists; otherwise extend `patches/smb-rs-rssmb.patch`).
- Single owner for the policy bit: `EncryptionState.encrypt_data`; remove
  dead `Session.encryption_required`.
- Tests: guest/anon + `required` → denied and **no** signing/encryption/
  session entries remain, a second SESSION_SETUP on the same connection
  works; alice + `required` → flag set; `desired` → flag clear, keys present.

### 3.2 Compound walk + transform validation (G6, G7)
- Read `rssmb_wire_adapter::framing::message_ranges` and document what it
  guarantees (alignment, progress, bounds, last-member size); harden it if
  needed.
- Extract `walk_compound(payload) -> Result<Vec<Member{range, effective_sid,
  cmd, related}>, Reject>` from `verify_frame`. Plaintext: walk → signatures
  (behavior unchanged). Decrypted: walk → every `effective_sid ==
  transform_sid` and state not retiring → else disconnect; no signature
  check.
- `decrypt_message`: enforce 2.5 Flags/OriginalMessageSize checks.
- Parse-error branch: for decrypted payloads skip `verify_frame` and reply
  with an **encrypted** INVALID_PARAMETER (same transform session); for
  plaintext unchanged. SMB1 negotiate path untouched (assert in a test).
- Tests: related `u64::MAX` accepted; mismatched unrelated member →
  disconnect; flags ≠ 1 → disconnect; size mismatch → disconnect; decrypted
  malformed body → encrypted error reply; property test over random
  compounds (walk never panics, ranges in bounds).

### 3.3 Per-request enforcement + TX decision (G3, G4)
- Implement 2.2 steps 3/5/6 per member just before dispatch, producing a
  per-member `do_encrypt`; implement 2.3 from it (replacing the first-member
  heuristic in the read loop). Pending-op/async state stores `do_encrypt` +
  session for interim and final responses.
- `send_unsolicited`: audit callers; each passes either the originating
  request's protection or (server-initiated) the session/tree policy.
- Tests (all with a **validly signed** plaintext request on a
  signing-required session, so signing doesn't mask the policy result):
  plaintext READ on `required` session → ACCESS_DENIED, reply encrypted, no
  side effect, credits charged/granted normally; plaintext WRITE → file
  unchanged; plaintext ECHO → denied; encrypted READ → encrypted reply;
  compound [CREATE, READ(related)] plaintext → statuses asserted; async
  CHANGE_NOTIFY/locking interim + final encrypted; CANCEL plaintext on
  required session → not acted on; LOGOFF encrypted → encrypted reply, then
  state retired.

### 3.4 Per-share `encrypt_data` (G5)
- `TreeEntry.encrypt_data`; TREE_CONNECT per 2.4; tree check per 2.2.5
  (desired sessions too).
- Config validation: `encrypt_data = true` with `encryption = "disabled"`
  → startup error naming the share.
- Tests: the 2.4 table; plaintext TREE_CONNECT to encrypt_data share on a
  `desired` session succeeds with the flag, then plaintext READ on it →
  ACCESS_DENIED (encrypted), encrypted READ works; related
  [TREE_CONNECT, CREATE] plaintext → CREATE denied; config error.

### 3.5 Live interop, GCM (G9) — fixes only if bugs found
Setup from memory `env/rssmb-live-testing` (`tests/live/mount.sh`, docker
alpine cifs.ko). Record kernel version (`uname -r`), cifs-utils and samba
versions, exact commands. Capture with tcpdump in the container and check
**both directions** are `0xFD 'SMB'` after SESSION_SETUP.
- `desired`: `mount.sh <ip> 3.1.1 ,seal` full round-trip.
- New `tests/live/rssmb-mount-enc-required.toml`: plain `mount.sh <ip>
  3.1.1` (client should encrypt because of the session flag — observe) and
  `vers=2.1` → mount refused.
- New `rssmb-mount-enc-share.toml`: `desired` + `public.encrypt_data`,
  plain 3.1.1 mount → traffic to the share encrypted.
- `apk add samba-client` in the container: check `smbclient --help` for the
  actual encryption option, then `-m SMB3_11` with it (ls/get/put).
- impacket `run.sh` 8/8 under `disabled` and `desired` (regression).
- Negative: a ciphertext bit-flip → disconnect, no reply (tamper.py if it
  can drive encryption; otherwise unit test only, stated so).

### 3.6 AES-128-CCM + 3.0.x encryption (G8)
- `ccm = "0.5"`; `cargo tree -i ccm` and the `Cargo.lock` diff must show no
  second `aead`/`cipher` version. Type `Ccm<Aes128, U16, U11>`.
- `encrypt_message`/`decrypt_message` take the cipher; every RX/TX/async/
  error path passes `EncryptionState.cipher`.
- `NonceSource` for CCM: 8-byte counter + 3 random bytes (11), 5 zero tail;
  exhaustion and concurrency tests for both ciphers.
- Negotiation per 2.6; update the existing `!encryption()` test
  (`dispatch.rs:3035`) and the "CCM means no overlap" negotiate_ctx tests;
  add the matrix 2.x/3.0/3.0.2/3.1.1 × disabled/desired/required × client
  cap/contexts (none, empty, CCM-only, GCM-only, both, unsupported-only).
- Vectors: CCM — RFC 3610 vectors use 13-byte nonces and 8/10-byte tags, so
  they're not usable as-is. Use output from an independent implementation
  with SMB parameters (Python `cryptography` AESCCM with tag_length=16,
  11-byte nonce — install in the venv) recorded as a fixture; also cross-check
  against a captured cifs.ko `3.0,seal` session. KDF: expected-byte tests for
  3.0.x legacy labels (`SMB2AESCCM\0` + `ServerOut\0`/`ServerIn \0`) and
  3.1.1 labels, both directions, from the same independent script.
- Live: `mount.sh <ip> 3.0 ,seal` and `3.0.2 ,seal`, rerun the 3.5 matrix.

### 3.7 Docs + record
- `docs/next-steps.md`: 7e entry (done + verification), deferrals from §1.
- Document `encryption` (`disabled`/`desired`/`required`) and share
  `encrypt_data` semantics (§2.1 deviation note) where config is documented
  (README config section / example TOMLs).
- `done/` memory record per task-workflow.

## 4. Order and gates
3.1 → 3.2 → 3.3 → 3.4 (each: build, `cargo test`; impacket 8/8 after 3.3
and 3.4) → 3.5 live GCM → 3.6 CCM → rerun the full live matrix → Mashūra
implementation review → 3.7 → commit.

## 5. Risks
- Our `desired` intentionally differs from Samba's `desired` (2.1).
- Transform-session mismatch: we disconnect, Samba returns ACCESS_DENIED.
- cifs.ko behavior on SESSION_FLAG_ENCRYPT_DATA without `seal` is assumed,
  not verified, until 3.5.
- 3.2 touches signing; mitigated by the unchanged signing tests, the
  property test and impacket tamper scenarios.
- Samba is a reference implementation, not the spec; MS-SMB2 sections stay
  unverified until the spec can be fetched.

## 6. Open items for the user
- None blocking. Optional: a Samba-style `desired` that asks clients to
  encrypt (separate config value) — out of scope by default.

## 7. Mashūra plan review — round 1 (gpt-6-astra; second panelist truncated)
Verdict: revise. Its protocol points were recollection; each was checked
against Samba source or the code.
| Point | Decision |
|---|---|
| Exemptions (ECHO/CANCEL) unresolved | resolved from Samba: session check covers all commands with a session; tree check only `need_tcon` (2.2) |
| Per-member check needs dispatcher's effective tree | adopted: checks run right before each member (2.2.6) |
| Plaintext TREE_CONNECT vs session policy | resolved (2.4 + 2.2.3) |
| "Encrypt iff request encrypted" too broad | **adopted — my draft was wrong**: Samba encrypts ACCESS_DENIED replies and replies on encrypt_data sessions/trees (2.3) |
| Admission not transactional | confirmed in code (`dispatch.rs:1118` before `:1149`); fixed in 3.1 |
| Parse-error path verifies signatures on decrypted input | confirmed (`connection.rs:356`); fixed in 3.2 |
| `message_ranges` guarantees unknown | 3.2 reads/hardens it + property test |
| Cipher not plumbed / not stored | confirmed; 3.1 + 3.6 |
| Flags/OriginalMessageSize unchecked | confirmed (`crypto.rs:393-417`); 3.2 |
| Capability matrix | resolved from `smb2_negprot.c` (2.6); matrix tests in 3.6 |
| Modified vectors aren't KATs; legacy KDF needs expected bytes | adopted (3.6) |
| Signing may mask policy tests; check side effects, credits | adopted (3.3) |
| Capture both directions; record versions; check smbclient flags | adopted (3.5) |
