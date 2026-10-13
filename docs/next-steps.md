# RSSMB — Next Steps (implementation guide)

Status snapshot: 2026-10-13 (`bd8aca8`). Steps 1–10 are done: SMB 2.1–3.1.1
with signing, AES-128-GCM encryption, NTLMv2 auth, SrvSvc share enumeration,
and a standalone `rssmb-proto` protocol crate (no smb-rs dependency). 339 unit
tests pass (including 14 TCP integration tests). GNOME Files, `smbclient`,
and Linux kernel CIFS mounts all work. Steps 9–10 (hygiene, decoupling,
conformance, testing, fuzzing) complete. Next: Phase 5+ (oplock/lease,
multichannel, persistent handles).

Reference specs: MS-SMB2 (protocol), MS-FSCC (file/FS info structures),
MS-SRVS + MS-RPCE (share enumeration), MS-NLMP (NTLM), MS-ERREF (NTSTATUS).

Live verification lives in `tests/live/` (see README "Testing"):
`run.sh` drives impacket (guest, user rw, bad password, signing, tampered
signatures); `mount.sh` does a real `mount -t cifs` from a privileged
container and exercises ls/read/write/append/overwrite/mkdir/rename/delete.

---

## 0. Where we are

| Area | State |
|---|---|
| TCP / NetBIOS framing, per-connection task, shutdown | working |
| NEGOTIATE | **SMB 2.1 only**; SIGNING_REQUIRED from config |
| SESSION_SETUP: NTLMv2 (own proof check + sspi), SPNEGO or bare NTLMSSP, anonymous→guest | working (impacket, cifs.ko) |
| SMB 2.1 signing (HMAC-SHA256), per-message incl. compounds | working; unsigned/forged requests discarded under `required` |
| TREE_CONNECT (policy, IPC$ pipe share, MaximalAccess) | working |
| CREATE / CLOSE / READ / WRITE / FLUSH | working; DesiredAccess mapped; read-only shares enforced |
| QUERY_INFO incl. FileAllInformation | working |
| QUERY_DIRECTORY (cursor, buffer limit, restart) | working |
| SET_INFO: basic, EOF, rename, disposition (delete-on-close) | working |
| IOCTL: VALIDATE_NEGOTIATE_INFO, DFS referral, PIPE_TRANSCEIVE | working |
| Compound requests (NextCommand chains) | working |
| SMB 3.x / encryption | working (3.0/3.0.2/3.1.1; AES-128-GCM; encryption policy enforced) |
| Oplocks / leases | none granted (requested levels parsed) |
| SrvSvc share enumeration (NetrShareEnum/GetInfo/ServerGetInfo) | working (impacket) |

**Foundation fixes (post-review):** a request the client had no credits
for now terminates the connection without a reply (MS-SMB2 3.3.5.2.3; it
was dispatched anyway). An affordable charge above the local cap of 256
gets STATUS_INVALID_PARAMETER. Disconnects no longer stall 5 s (a leftover
clone of the write channel kept the writer alive). Propagated
compound errors now carry the member's effective SessionId/TreeId, so they
get signed. An abrupt disconnect now closes every VFS handle and cancels
async ops. Still open from that review: no MessageId window (duplicates or
replays aren't rejected), no negotiate state machine (repeated NEGOTIATE is
accepted), and LARGE_MTU is advertised without multi-credit validation.

**Known gaps found by the live tests and not yet fixed:** multi-credit
requests (>64 KiB I/O) are capped by negotiating 64 KiB; GVFS, macOS and
Windows not retested (they prefer SMB 3.x); the smb-msg patches are still
untracked (Step 9) — they now include several fixes for panics and decode
failures on real client traffic (create contexts, oplock levels).

---

## Step 1 — Unblock the GVFS session (small, do first)

### 1a. CLOSE with Flags=0 fails to decode

**Symptom (live log):** an 88-byte payload is a 64-byte header plus a 24-byte
CLOSE. `smb-msg` fails it with
`assertion failed: _flags == CloseFlags::new().with_postquery_attrib(true)`.

**Cause:** `smb-rs/crates/smb-msg/src/create.rs:827-830`: the client-side
crate hard-codes `POSTQUERY_ATTRIB` as always set and asserts it on read.
Clients are allowed to send 0, and GVFS does.

**Fix (in our patched smb-msg copy; see Step 9 about vendoring):**
```rust
pub struct CloseRequest {
    pub flags: CloseFlags,      // was: #[bw(calc=..)] #[br(assert(..))] _flags
    reserved: u32,
    pub file_id: FileId,
}
```
Then fix the call sites inside smb-rs that construct `CloseRequest`, which are
client code (`grep -rn "CloseRequest" smb-rs/crates`).

In `handle_close`:
- if `req.flags.postquery_attrib()`, query the VFS and fill in the timestamps,
  `allocation_size`, `endof_file` and `file_attributes`, and set
  `flags.postquery_attrib = true` in the response;
- otherwise leave every attribute field zero (MS-SMB2 3.3.5.10).

**Audit the other client-side asserts** in smb-msg the same way:
`grep -rn "br(assert" smb-rs/crates/smb-msg/src`. Any assert that pins a field
a *client* may legally vary must become a plain field. Known suspects:
`file.rs:59,167` (`channel == None`, fine for now) and `file.rs:96`
(`_data_length > 0`, which rejects zero-length WRITE; clients do send these).

### 1b. Never drop a request silently

`crates/rssmb-server/src/connection.rs:241-246`: a decode failure is
`continue`d with no response, so the client waits until it times out. Instead:
1. Decode the 64-byte header on its own (`Header::read`). This almost always
   succeeds even when the body does not.
2. Reply with an error response for that `command` and `message_id`, status
   `STATUS_INVALID_PARAMETER` (or `STATUS_NOT_SUPPORTED` for an unknown
   command), plus the standard ERROR body (`ErrorResponse`, 9 bytes).
3. Only drop the connection if even the header is garbage.

Also add a debug line that hex-dumps the first ~128 bytes of the failing
payload. That is how the next decode issue gets diagnosed without guessing.

**Tests:** a unit test that feeds a CLOSE with flags=0 through
`parse_payload` → `handle_message` and gets success; a test that a corrupt
body yields an error response with the correct message_id.

---

## Step 2 — Real metadata: CREATE, QUERY_INFO, QUERY_DIRECTORY

This is what makes browsing work. The structures already exist in
`smb-rs/crates/smb-fscc` (binrw read+write); we only have to fill them in.

### 2a. A shared metadata mapping
Add `crates/rssmb-server/src/fsinfo.rs`. It converts `rssmb_vfs::FileInfo`
(already has FILETIME timestamps, size, alloc size, attributes, file_id) into
each MS-FSCC class. One function per class, all pure, all unit-tested
against byte vectors.

Make sure the VFS fills in `FileInfo` correctly (LocalFs: `std::fs::Metadata`):
- timestamps → FILETIME: `(unix_ns / 100) + 116444736000000000`
- `allocation_size`: `blocks * 512` on Unix, else size rounded up to 4096
- attributes: `FILE_ATTRIBUTE_DIRECTORY` (0x10) for dirs,
  `FILE_ATTRIBUTE_ARCHIVE` (0x20) or `NORMAL` (0x80) for files, `HIDDEN` for
  dot-files (optional), `READONLY` when the share is read-only
- `file_id` (IndexNumber): the inode number; it must be stable per file

### 2b. CREATE response
`handle_create` currently uses `Default::default()` for these fields.
Fill in: `oplock_level = None`, `create_action` (FILE_OPENED/CREATED/OVERWRITTEN
from the VFS result), the four timestamps, `allocation_size`, `endof_file`,
`file_attributes`. Leave create contexts empty for now, but parse and ignore
incoming ones (MxAc, QFid, RqLs) without failing. Returning an MxAc
(maximal access) response context noticeably helps Windows and macOS later.

Also check the CreateDisposition semantics (SUPERSEDE / OPEN / CREATE /
OPEN_IF / OVERWRITE / OVERWRITE_IF) and CreateOptions `FILE_DIRECTORY_FILE`
and `FILE_NON_DIRECTORY_FILE`, which map to `STATUS_NOT_A_DIRECTORY` and
`STATUS_FILE_IS_A_DIRECTORY`. Opening an empty name means the share root.

### 2c. QUERY_INFO
`handle_query_info` (dispatch.rs ~728) ignores `info_type`/`info_class`.
Implement a match on them:

| InfoType | Class | Needed by |
|---|---|---|
| FILE (1) | FileBasicInformation (4) | everyone |
| FILE | FileStandardInformation (5) | everyone |
| FILE | FileInternalInformation (6) | GVFS, Windows |
| FILE | FileEaInformation (7) | Windows (return 0) |
| FILE | FileNetworkOpenInformation (34) | Windows, cifs.ko |
| FILE | FileAllInformation (18) | cifs.ko, smbclient |
| FILE | FileAttributeTagInformation (35) | Windows |
| FILE | FileStreamInformation (22) | macOS/Windows: return the single `::$DATA` stream |
| FILESYSTEM (2) | FileFsVolumeInformation (1) | everyone |
| FILESYSTEM | FileFsSizeInformation (3) | GVFS (free space) |
| FILESYSTEM | FileFsFullSizeInformation (7) | Windows |
| FILESYSTEM | FileFsAttributeInformation (5) | everyone: name "NTFS", flags case-preserving + unicode + persistent ACLs off |
| FILESYSTEM | FileFsDeviceInformation (4) | Windows |
| FILESYSTEM | FileFsSectorSizeInformation (11) | Windows 8+ |
| SECURITY (3) | — | return a minimal SD (owner/group Everyone, NULL DACL), or `STATUS_ACCESS_DENIED` early on |
| QUOTA (4) | — | `STATUS_NOT_SUPPORTED` |

Free and total space: `statvfs` via the `nix` crate (`nix::sys::statvfs`), or
`fs2::available_space`.

**Rules:**
- Respect `output_buffer_length`. If the structure doesn't fit, return
  `STATUS_INFO_LENGTH_MISMATCH` for fixed-size classes, or
  `STATUS_BUFFER_OVERFLOW` with truncated data for variable-size ones (names).
- An unknown class gives `STATUS_INVALID_INFO_CLASS`, never an empty success.
- Serialize with `BinWrite` from smb-fscc into a `Vec<u8>`, then build
  `QueryInfoResponse { data: QueryInfoResponseData::from(vec) }`. The field is
  private; add a constructor in our smb-msg copy if one is missing.

### 2d. QUERY_DIRECTORY
`handle_query_directory` (dispatch.rs ~775) discards the entries. Needed:
- **Per-open enumeration cursor** in `OpenEntry` (`dir_cursor: usize`,
  `dir_pattern: String`). `RESTART_SCANS` / `REOPEN` reset it,
  `RETURN_SINGLE_ENTRY` returns 1, and `INDEX_SPECIFIED` can be ignored.
- **Synthesize `.` and `..`** at the start. Every client expects them.
- **Classes:** FileIdBothDirectoryInformation (37: Windows, GVFS),
  FileBothDirectoryInformation (3), FileFullDirectoryInformation (2: cifs.ko),
  FileIdFullDirectoryInformation (38), FileDirectoryInformation (1),
  FileNamesInformation (12). All are in `smb-fscc/src/directory_info.rs`.
- **Packing:** each entry is 8-byte aligned, `NextEntryOffset` points to the
  next entry and is 0 on the last. Stop adding entries before exceeding
  `output_buffer_length`. If not even one entry fits, return
  `STATUS_BUFFER_OVERFLOW`.
- **Status:** first call with no match gives `STATUS_NO_SUCH_FILE`; cursor
  exhausted gives `STATUS_NO_MORE_FILES`. (The current code uses
  `NoMoreEntries` on the first empty call, which is wrong.)
- **Pattern** matching is already in VFS `matches_pattern`. Make sure `*`,
  `?` and the DOS wildcards `<`, `>` and `"` are handled, case-insensitively.

**Tests:** golden-byte tests for each class (take vectors from smb-rs tests
where they exist), a cursor test (3 calls → entries, entries,
NO_MORE_FILES), and an output-length truncation test.

**Live check:** `smbclient //localhost/public -N -c 'ls; get README.md'`
(there's a `samba-client` profile in `docker/compose.yml`) and GVFS browsing.

---

## Step 3 — Compound requests

Linux cifs.ko, smbclient and Windows all chain requests
(e.g. CREATE+QUERY_INFO+CLOSE in one NetBIOS frame). Today we parse only the
first message, so everything after it is lost.

Implementation in `rssmb-wire-adapter` + `connection.rs`:
1. Split the payload: read the header, and if `next_command != 0` the next
   message starts at `offset + next_command` (8-byte aligned). Repeat.
2. For **related** operations (`SMB2_FLAGS_RELATED_OPERATIONS`): inherit
   SessionId/TreeId from the previous request and replace FileId
   `0xFFFFFFFFFFFFFFFF` with the FileId produced by the previous CREATE.
   Keep the "current FileId" in a small per-compound context passed to
   dispatch.
3. If a related request fails, the remaining related ones fail with the same
   status (MS-SMB2 3.3.5.2.7.2).
4. Build the responses into one frame. Pad every response except the last
   to 8 bytes, set `next_command` to the padded length, and set
   `SMB2_FLAGS_RELATED_OPERATIONS` on related responses.

Write a test that builds a CREATE+QUERY_INFO+CLOSE compound with smb-msg's
client-side writers and checks the three responses.

---

## Step 4 — Write path: WRITE, SET_INFO, FLUSH, delete/rename

### 4a. WRITE
`handle_write` (dispatch.rs ~671): the data is in `WriteRequest`. Check how
smb-msg exposes the buffer (`file.rs` ~85-100, `data_offset`/`data_length`),
because with the server feature the data may need to be read from the raw
message slice. Call `vfs.write_at(open_id, offset, &data)` and return `count`.
Respect the share `read_only` flag (`STATUS_ACCESS_DENIED`) and the open's
granted access (requires FILE_WRITE_DATA / FILE_APPEND_DATA).

Also negotiate `max_write_size`/`max_read_size` higher (1 MiB, with
`large_mtu` already advertised). This needs credit handling (Step 6) to be
correct for multi-credit requests.

### 4b. SET_INFO
New handler. Classes to implement:
- FileBasicInformation: set timestamps and attributes (`filetime` crate;
  `-1`/0 means "don't change").
- FileEndOfFileInformation / FileAllocationInformation: truncate or extend.
- FileDispositionInformation (13) and FileDispositionInformationEx (64): mark
  delete-on-close; the actual delete happens at the last CLOSE of that file.
  Needs a `delete_pending` flag in the **global** open table (opens.rs),
  because other opens of the same file must see `STATUS_DELETE_PENDING`.
- FileRenameInformation (10): parse `ReplaceIfExists` and the target name
  (relative to the share root), normalize it through VFS path
  normalization (no `..` escape!), then `vfs.rename`.

### 4c. Sharing modes
`opens.rs` already has a global open table. In CREATE, check the requested
access against existing opens' `ShareAccess` → `STATUS_SHARING_VIOLATION`.
This is what makes Office and other Windows applications behave.

---

## Step 5 — Enforce share policy and real users

Right now any session, including a guest, can tree-connect to any share,
including `homes`, with full access.

1. **Load users** from config (`[users]` with NT hashes or passwords; better:
   a hash file, never plaintext in env). Pass them to
   `NtlmAuthProvider::with_identities(...)` (dispatch.rs, session setup)
   instead of `vec![]`. Build the provider once in `ServerState`, not per
   request.
2. **Only fall back to guest when** the client sent an anonymous (empty
   NtChallengeResponse) bind **and** `guest_access = true`. A wrong password
   for a real user must be `STATUS_LOGON_FAILURE`, not guest. Today the
   fallback is too broad: every NTLM error becomes guest. Check the
   `rssmb-auth` fallback paths.
3. **Store the identity on the `Session`** (`username`, `is_guest`,
   `session_key`).
4. **TREE_CONNECT check:** a guest is allowed only if `share.guest_ok`; a user
   only if in `valid_users` (when set). Otherwise `STATUS_ACCESS_DENIED`.
5. **MaximalAccess** from policy: read-only gives
   `FILE_GENERIC_READ|FILE_GENERIC_EXECUTE` (0x001200a9), read-write gives
   0x001f01ff. CREATE must reject requested write access on a read-only share.
6. **Validate every request** belongs to a valid session and tree. Today most
   handlers look up opens only by volatile FileId, which on a shared
   connection lets one session use another session's handle. Key the open
   table by `(session_id, tree_id, file_id)`, and return
   `STATUS_USER_SESSION_DELETED`, `STATUS_NETWORK_NAME_DELETED` or
   `STATUS_FILE_CLOSED` as appropriate.
7. **Path security:** LocalFs must refuse symlinks that escape the share root
   (canonicalize + prefix check, or `openat2(RESOLVE_BENEATH)` via
   `rustix`/`cap-std`). `cap-std` is the idiomatic Rust-safety choice here and
   worth switching LocalFs to.

Re-add the lost sspi client→server NTLM integration test (an sspi client
against our provider with a known user), plus negative tests: wrong password,
guest denied on a non-guest share.

---

## Step 6 — Credits and per-connection concurrency

- **Credits** (MS-SMB2 3.3.1.2): track a per-connection window of valid
  MessageIds. Each response grants `credit_response = max(1, min(requested,
  limit))`. Reject out-of-window, duplicate, or insufficient-CreditCharge
  requests (multi-credit: `ceil(len/65536)`). Today we echo the client's
  request back.
- **Concurrency:** dispatch is serial per connection. Spawn each request onto
  a task (bounded by a semaphore), or at minimum make CHANGE_NOTIFY and
  blocking LOCK asynchronous (an interim response with `STATUS_PENDING` and an
  AsyncId, then the final response later). Responses can be sent out of order;
  the write channel already allows this.
- **CANCEL:** look up the pending async op by AsyncId/MessageId and complete
  it with `STATUS_CANCELLED`.
- **CHANGE_NOTIFY:** GVFS and Windows Explorer keep one outstanding. Minimum
  acceptable: go pending and never complete, then complete with
  `STATUS_NOTIFY_CLEANUP` on CLOSE. Better: the `notify` crate on LocalFs.

---

## Step 7 — Signing, then SMB 3.x and encryption

Most modern clients (Windows 11 24H2, macOS, recent Samba) **require
signing**, and they prefer 3.1.1.

### 7a. SMB 2.1 signing (HMAC-SHA256)
- After SESSION_SETUP success with a non-empty session key: signing key =
  session key (already in `crypto.rs`).
- Verify incoming signatures when `SMB2_FLAGS_SIGNED` is set or signing is
  required. Signature = HMAC-SHA256(key, message with the signature field
  zeroed)[0..16].
- Sign all responses on a signed session, including the final SESSION_SETUP
  success response.
- Guest and anonymous sessions are never signed (that's why the SessionFlags
  `is_guest`/`is_null_session` are now set).
- Config `signing = "required"` gives `SIGNING_REQUIRED` in NEGOTIATE; an
  unsigned request then returns `STATUS_ACCESS_DENIED`.

### 7b. SMB 3.0 / 3.0.2 — DONE (79c39e1)

Implemented: dialect selection (highest common from client offer, implemented
set, configured range; 3.1.1 excluded until 7c), per-connection NegotiateRecord,
negotiate gate (disconnect pre-NEGOTIATE commands and repeat NEGOTIATE),
VALIDATE_NEGOTIATE_INFO (parse, compare against stored client values, re-run
dialect selection, disconnect on mismatch, echo server values), KDF label fix
(3.0: `ServerOut\0`/`ServerIn \0` with trailing space; 3.1.1: `SMBS2CCipherKey`/
`SMBC2SCipherKey`), known-answer KDF test.

Verified: 162 unit tests pass, impacket 8/8, kernel CIFS mount vers=3.0 and
vers=3.02 (full round-trip), smbclient -m SMB2.

Follow-up fixes (smbclient -m SMB3 now works, selects 3.0.2, incl. signed
authenticated sessions): smb-msg IOCTL parser no longer asserts
OutputOffset/OutputCount == 0; unknown negotiate contexts (Samba sends POSIX
extensions, type 0x0100, when offering 3.1.1) decode as
`NegotiateContextType::Unknown` instead of failing the NEGOTIATE; client
mechListMIC is verified. 7c must keep ignoring `Unknown` contexts.

**Original start-here notes (state at `2fa6f28`, now resolved):**
- `handle_negotiate` ignores the client's dialect list and always answers
  2.1. SESSION_SETUP hard-codes `DialectConfig::Smb21` again
  (`dispatch.rs`, "only dialect negotiated so far"), and
  `ConnState.negotiated_dialect` is never written. Store one negotiated
  record per connection (dialect, client GUID, security mode, capabilities)
  and use it in SESSION_SETUP, signing and VALIDATE_NEGOTIATE. Reject a
  second NEGOTIATE on the connection.
- `crypto.rs` contradicts this plan. Its 3.0 encryption/decryption
  contexts are `"SmbServerOut\0"`/`"SmbServerIn\0"`, while this section
  says `"ServerOut\0"`/`"ServerIn \0"`. The 3.1.1 labels (`"SMBAESCCM\0"`,
  and `"SmbSign\0"` as the signing context) are placeholders as well. Check
  every label against the MS-SMB2 text and add known-answer tests: the
  current 3.x tests only round-trip, so they pass with a wrong KDF.
- `SigningState.dialect` already selects CMAC vs HMAC in
  `crypto::sign_message`; it just has to receive the negotiated dialect.
- `FSCTL_VALIDATE_NEGOTIATE_INFO` (`handle_ioctl`) answers with hard-coded
  2.1 values. It must echo the negotiated record, and for 3.x a mismatch
  must end the connection.
- Live check: `tests/live/mount.sh <ip> 3.0` and `3.02` (the second
  argument is `vers=`), plus impacket's default dialect.

- Dialect selection: the highest common dialect from the client's list
  (currently hard-coded to 2.1).
- KDF (SP800-108, done): labels `"SMB2AESCMAC\0"`/`"SmbSign\0"` for signing,
  `"SMB2AESCCM\0"` with `"ServerIn \0"`/`"ServerOut\0"` for encryption.
- Signing becomes AES-128-CMAC (`aes` + `cmac` crates).
- IOCTL `FSCTL_VALIDATE_NEGOTIATE_INFO` is **mandatory** for 3.0/3.0.2: echo
  capabilities, GUID, security mode and dialect.

### 7c. SMB 3.1.1 — DONE (572fed1)

Implemented: negotiate contexts (PREAUTH_INTEGRITY with SHA-512, 32-byte
server salt; ENCRYPTION omitted; SIGNING omitted — client falls back to
AES-CMAC). Preauth integrity hash (SHA-512 chain over NEGOTIATE req/resp
+ each SESSION_SETUP req + each MORE_PROCESSING resp; final SUCCESS resp
not hashed). KDF context = preauth hash for 3.1.1, legacy fixed strings
for 3.0.x/2.x (release-enforced). Force-sign final SESSION_SETUP success
for non-guest 3.1.1 sessions (one-shot, not persistent SigningRequired).
Unknown negotiate context types and unknown context-value enum IDs
tolerated. NEGOTIATE/SESSION_SETUP in compound requests rejected.

Verified: 189 unit tests pass. impacket 8/8 (incl. signed + tamper).
smbclient -m SMB3_11 negotiates 3.1.1 (anon + alice). Kernel CIFS
vers=3.1.1 with alice authenticates and mounts. Regression: vers=3.02/
3.0/2.1, smbclient -m SMB3/SMB2 all pass.

Mashūra implementation review caught: empty-key fallback panic on KDF
error (fixed — abort session), preauth_sessions cleanup on auth failure/
restart (fixed), force_sign conflated with SigningRequired (fixed —
one-shot force_sign_once on SigningState).

Follow-up (non-blocking): GMAC signing deferred (nonce-uniqueness audit
needed); encryption (7d); end-to-end transcript golden test; echo
ENCRYPTION/SIGNING contexts for stricter Windows compliance.
- Negotiate contexts: PREAUTH_INTEGRITY (SHA-512), ENCRYPTION (AES-128-GCM,
  AES-128-CCM, optionally AES-256-*), SIGNING (AES-GMAC), plus ignoring
  unknown contexts.
- **Preauth integrity hash:** H = SHA-512(H ‖ message) over NEGOTIATE
  request/response and every SESSION_SETUP request/response except the final
  success response. Keep one copy per connection and fork it per session. The
  KDF context is then this hash instead of the label constants.
- Getting this wrong just shows up as "signature invalid" on the client.
  Write a unit test with known vectors (MS-SMB2 examples, or capture against
  Samba with Wireshark + keylog).

### 7d. Encryption — DONE (1e1dd66)

Implemented: AES-128-GCM encryption for SMB 3.1.1 (TRANSFORM_HEADER with
52-byte header, 12-byte nonce, 32-byte AAD from header[20..52], detached
16-byte tag in the Signature field). Cipher negotiated from
ENCRYPTION_CAPABILITIES context (server prefers GCM; CCM deferred — the
`ccm` crate needs network to fetch). Decryption in the connection read
loop before parsing/dispatch; encryption after encode+sign+preauth, with
handshake (NEGOTIATE/SESSION_SETUP) responses excluded. `send_unsolicited`
snapshots encryption state once (no TOCTOU, no plaintext fallback).
`encryption = "required"` denies session creation when no cipher is
available. `ShareConfig.encrypt_data` added (per-share encryption).
Signing skipped when encrypting (SIGNED flag cleared, signature zeroed).
Encryption state retired after the response is encrypted (not before).

Verified: 203 unit tests pass. impacket 8/8 (encryption=disabled regression,
encryption=desired 3.1.1). `encryption=required` denies sessions without a
cipher (tested via config). AES-128-GCM encrypt/decrypt round-trip, tamper,
wrong-key, truncated-header, and nonce uniqueness (concurrent) unit tests.

Not yet verified with a live encrypted client (impacket doesn't send
ENCRYPTION_CAPABILITIES in its negotiate; needs smbclient `-e` or Windows).

### 7e. Encryption follow-ups — DONE (a2f32dd)

**Transactional admission (7e.1, `c9f1f68`):** the `encryption = "required"`
deny check now runs for all sessions (including guest/anonymous), before any
per-session state is inserted. `SESSION_FLAG_ENCRYPT_DATA` is set on the
response when `encrypt_data` is true. `EncryptionState` stores the negotiated
cipher.

**Compound walk + transform validation (7e.2, `52fed45`):** `walk_compound()`
extracted from `verify_frame()` — shared structure/effective-session
resolution for both plaintext and decrypted frames. `decrypt_message` now
validates transform `Flags == 0x0001` and `OriginalMessageSize == ciphertext
length`. Decrypted frames: every member's effective SessionId must match the
transform SessionId and the session must have non-retiring `EncryptionState`.
Parse-error path: for decrypted payloads, signing verification skipped (AEAD
already authenticated); error reply encrypted.

**Per-request enforcement + per-share encrypt_data (7e.3-4, `14b34f4` +
`a2f32dd`):** unencrypted requests on sessions or trees with `encrypt_data` are
rejected with `STATUS_ACCESS_DENIED` (encrypted reply). Exempt: NEGOTIATE and
SESSION_SETUP. `TreeEntry.encrypt_data`; TREE_CONNECT response sets
`SHAREFLAG_ENCRYPT_DATA` when the share config has `encrypt_data`. Config
validation: `encrypt_data = true` with `encryption = "disabled"` is a startup
error.

Verified: 212 unit tests pass; impacket 8/8.

Semantics pinned against Samba master source (MS-SMB2 spec pages not
fetchable — web search blocked by API key IP restriction).

**Mashūra implementation review (round 1) caught and fixed:**
1. Guest/anon with GCM negotiated passed the `required` check — cipher
   selection now requires a signable (non-guest, keyed) session.
2. Decrypted parse-error path bypassed compound/SID validation — now runs
   `walk_compound` and validates effective SessionId binding; error reply
   encrypted directly under the transform session (not via
   `send_unsolicited`, which can't encrypt `Raw` responses).
3. CANCEL bypassed the encryption policy check — now checked before the
   CANCEL early return.

Remaining follow-up (non-blocking): AES-128-CCM for 3.0/3.0.2 (needs `ccm`
crate — network now available, `ccm 0.5.0` is compatible with our `aead
0.5.2`/`cipher 0.4.4`); AES-256-GCM/CCM; compression (0xFC); replay window;
per-key GCM usage limits; live encrypted session verification (cifs.ko
`,seal`); GMAC signing.

---

## Step 8 — IPC$ / SrvSvc (share enumeration) — DONE (`ef1216a`)

Makes `smbclient -L host` and impacket `NetrShareEnum` list shares a session
can see. GVFS/Finder and Windows `net view` are expected to work but not
verified in this step (they may need additional pipes like lsarpc/wkssvc).

Detailed plan: [`docs/plan-8.md`](plan-8.md) (Mashūra plan-reviewed).

Implemented:
- **IPC$ tree kind** (`is_ipc`): IPC$ TREE_CONNECT returns `ShareType::Pipe`;
  disk shares set `is_ipc = false`. Disk-only ops on IPC$ trees reject with
  `STATUS_INVALID_DEVICE_REQUEST`.
- **Pipe opens**: `OpenEntry.is_pipe` + `pipe_state: Arc<Mutex<PipeState>>`;
  CREATE `srvsvc` on IPC$ returns a pipe open; other names → `OBJECT_NAME_NOT_FOUND`.
  Teardown (CLOSE/LOGOFF/TREE_DISCONNECT/connection drop) skips VFS close for
  pipe opens.
- **DCE/RPC PDU codec** (`rssmb-rpc-server/pdu.rs`): BIND/BIND_ACK with
  context evaluation (accept SRVSVC v3.0/NDR20, reject others, negotiate_ack
  for feature negotiation), BIND_NAK, REQUEST reassembly (1 MiB cap),
  RESPONSE fragmentation, FAULT.
- **Pipe transports**: WRITE feeds RPC input; READ drains output queue
  (`BUFFER_OVERFLOW` with partial data); `FSCTL_PIPE_TRANSCEIVE` does both.
  `PIPE_EMPTY` when no output.
- **NDR20 + SrvSvc** (`rssmb-rpc-server/ndr.rs`): `NetrShareEnum` (15) level
  1, `NetrShareGetInfo` (16) levels 1/2/501/1005, `NetrServerGetInfo` (21)
  levels 100/101. NDR union tag (discriminant) correctly emitted.
- **Visibility**: `visible_shares_for_ctx` — browseable + guest_ok/valid_users
  filtering, sorted by name, IPC$ appended. `server_name` config field.
- **Config validation**: share named "IPC$" (case-insensitive) → startup error.
- `substitute_file_id`: added Ioctl arm for related CREATE→IOCTL compounds.

Verified: 239 unit tests pass; impacket 10/10 (guest, guestpriv, alice,
badpass, signed, guestsigned, tamper, enum_guest, enum_user).

**Not yet verified:** `smbclient -L` (docker samba-client not available in
test env); GVFS/Finder/Windows `net view` (may need lsarpc/wkssvc); encrypted
pipe I/O (not tested with `encryption = "required"`).

**Deferred:** NDR64, resumable enumeration (ResumeHandle continuation),
RPC auth, other pipes (lsarpc, samr, wkssvc, winreg), `NetrShareEnumSticky`,
async/pending pipe reads, `FSCTL_PIPE_WAIT`/`FSCTL_PIPE_PEEK`.

---

## Step 9 — Hygiene items

- **smb-rs decoupled.** All `smb_msg::`/`smb_dtyp::`/`smb_fscc::` imports
  replaced with `rssmb_proto::` (Step 9.1c-swap). `smb-rs/` moved to
  `.reference/smb-rs/` (gitignored, not a workspace dependency). The protocol
  crate `rssmb-proto` handles all wire encoding/decoding. Base SHA `7c7d4a6`.
- **`rust-version` set to 1.78** (MSRV for `std::fs::FileTimes` and
  `std::sync::OnceLock`, and the minimum for `Cargo.lock` v4).
  `rust-toolchain.toml` pins the version with
  rustfmt + clippy. CI uses the pinned toolchain + `Swatinem/rust-cache`.
  All warnings fixed — `RUSTFLAGS="-D warnings"` builds clean (Step 9.4).
- **ID allocation** (9.5 — done): SessionId is random non-zero with collision
  check; TreeId is per-connection starting at 1; FileId volatile is
  per-connection, persistent is random base + volatile. Global statics
  `NEXT_SESSION_ID` and `NEXT_FILE_ID` removed.
- **TREE_DISCONNECT / LOGOFF / connection drop** — already done: closes every
  open on that tree/session (VFS close plus global open-table removal).
- **OpenTable** (9.6 — decided): the global `OpenTable` exists and is tested
  (18 unit tests in `opens.rs`) but is **not wired into dispatch** — `handle_create`
  hardcodes `ShareAccess::all()`, so cross-connection share-mode conflicts are
  not enforced. Wire it in as part of oplock/lease work (Phase 5), where
  share-mode tracking and `STATUS_SHARING_VIOLATION` are needed.
- **Logging** (9.7 — done): decode errors use `{e}` (Display) instead of
  `{e:?}` (verbose debug) in `WireError::DecodeError` strings; hex preview
  (first 128 bytes) at debug level on parse failure; panic hook routes
  panics through `tracing::error!` (one line + location) in production.

---

## Step 10 — Testing and conformance

- **10.1 — Done.** `listen_on` + in-process harness (`crates/rssmb-tests`).
  TestServer binds an ephemeral port, returns the real addr, shuts down cleanly.
- **10.2 — Done.** TCP integration tests (`crates/rssmb-tests/tests/integration.rs`):
  14 tests covering NEGOTIATE (2.1, 3.0, 3.0.2, 3.1.1), max-common dialect,
  ECHO after negotiation, compound NEGOTIATE rejection, SMB1 magic, bad magic,
  truncated frame, empty payload, NetBIOS keep-alive, repeat NEGOTIATE disconnect,
  server shutdown. Exercises the full TCP read-loop → parse → dispatch → encode
  → write path. Does NOT cover authenticated flows (needs NTLM+signing client) —
  left to impacket.
- **10.3 — Done (code only, not CI-verified).** `tests/live/run.sh` updated with
  `encrypted` scenario tier (encryption=desired config). `tests/live/smbclient.sh`
  for smbclient interop (list, ls, get, put, -m SMB2/SMB3/SMB3_11).
  `.github/workflows/interop-ci.yml` with jobs for unit+integration tests,
  impacket, smbclient, smbtorture (nightly), fuzz (nightly).
- **10.4 — Done (code only, not CI-verified).** `tests/conformance/run-smbtorture.sh`
  runs curated smbtorture suites (smb2.connect/read/dir/compound/create/setinfo/
  getinfo/session/credits/ioctl, rpc.srvsvc) and records pass/fail in
  `tests/conformance/results.md`. CI job runs nightly.
- **10.5 — Done (code only).** `fuzz/` with 6 cargo-fuzz targets: `parse_payload`,
  `read_netbios_frame`, `extract_ntlm_token`, `extract_mech_types`,
  `proto_decode_header`, `proto_decode_plain_request`. CI job runs nightly (5 min/target).
- **10.6 — Done.** Golden-byte round-trip tests for every major `rssmb-proto` struct
  (44 new tests, 295→339): FileId, OplockBreakMsg, LeaseBreakNotify,
  LeaseBreakAckResponse, CreateResponse, CloseRequest/Response, FileAccessMask,
  CreateOptions, ShareAccessFlags, LeaseState, ErrorResponse, WriteRequest,
  ReadResponse, ReadFlags, WriteFlags, FlushResponse, SessionSetupResponse,
  SessionFlags, SessionSecurityMode, TreeDisconnect Request/Response, ShareFlags,
  TreeCapabilities. QUERY_INFO golden-byte tests: FileBasicInfo, FileStandardInfo,
  FileInternalInfo, FileNetworkOpenInfo, FileAllInfo, FileAttributeTagInfo.
  QUERY_DIRECTORY golden-byte tests: classes 1, 2, 3, 12, 37, 38. Filesystem info
  golden-byte tests: FileFsSizeInfo, FileFsDeviceInfo, FileFsFullSizeInfo. NDR
  decoder fixtures: NetrShareEnum (single/empty/3-shares), NetrShareGetInfo
  (found/not-found), NetrServerGetInfo (level 100). 3.1.1 preauth/KDF
  end-to-end transcript golden test: H0→hash chain→KDF→CMAC sign→verify +
  label isolation. Also fixed `OplockBreakMsg` StructureSize bug (12→24 per
  MS-SMB2 2.2.23.1).
- **Real clients (manual):** GVFS, macOS Finder, Windows 11 `net use`/`net view`.
- **Unverified in sandbox:** `cargo fmt --check` and `cargo clippy` (rustfmt/clippy
  not installable; rust-toolchain.toml pins them for CI). smbtorture and fuzz
  targets not run (need nightly toolchain / samba-testsuite). impacket/smbclient
  scripts not run (need impacket installed).

---

## Suggested order and rough sizing

| # | Step | Size | Unlocks |
|---|---|---|---|
| 1 | CLOSE decode + error-on-decode-failure | small | GVFS session continues |
| 2 | CREATE/QUERY_INFO/QUERY_DIRECTORY metadata | medium | browsing + reading in GVFS/smbclient |
| 3 | Compound requests | medium | cifs.ko, smbclient, Windows |
| 4 | WRITE/SET_INFO/sharing | medium | writable shares |
| 5 | Policy + users + handle scoping + path safety | medium | **safe to expose** |
| 6 | Credits + async ops | medium | Windows stability, large I/O |
| 7 | Signing → 3.0 → 3.1.1 → encryption | large | Windows/macOS defaults |
| 8 | SrvSvc | medium | share listing |
| 9/10 | Hygiene, conformance, fuzzing | ongoing | release quality |

Step 5 is the security gate: until it's done, don't expose RSSMB on anything
other than a trusted network.
