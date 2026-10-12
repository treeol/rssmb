# Plan 8 — IPC$ / SrvSvc share enumeration

Status: **DONE (`ef1216a`). All steps 8.1–8.7 complete. 239 unit tests pass,
impacket 10/10.**
Baseline: `main` @ `a3db497` (7e done, GCM live-verified with cifs.ko `,seal`).
212 unit tests pass, impacket 8/8.

Goal: `smbclient -L host` and impacket `srvs.hNetrShareEnum` list the shares a
session can see. GVFS/Finder and Windows `net view` are expected to work but
not in this step's acceptance — they depend on additional pipes (lsarpc,
wkssvc) and opnums that are out of scope here.

## 0. Current state (observed 2026-10-11)

| # | Fact | Evidence |
|---|---|---|
| S1 | IPC$ TREE_CONNECT is a stub: `ShareType::Pipe`, maximal access `0x1f01ff`, `TreeEntry` backed by an empty `MemoryFs`. No tree-kind flag. Runs before guest/valid_users policy. | `dispatch.rs:1497-1520` |
| S2 | `handle_create` calls `tree.vfs.create()` with no tree-type check; `CREATE "srvsvc"` on IPC$ goes to the empty MemoryFs and fails. | `dispatch.rs:1674-1825` (vfs call ~1763) |
| S3 | `OpenEntry` (dispatch.rs:39): `{session_id, tree_id, open_id, vfs: Arc<dyn Vfs>, dir_cursor, path}`. `vfs` is non-optional — pipe state must be `Arc<Mutex<PipeState>>` so clones share one association. | `dispatch.rs:39-48` |
| S4 | `TreeEntry` (dispatch.rs:289): `{share_name, vfs: Arc<dyn Vfs>, session_id, read_only, encrypt_data}`. `vfs` is non-optional — needs a kind field. | `dispatch.rs:289-297` |
| S5 | `substitute_file_id` (dispatch.rs:593) has no `Ioctl` arm — related CREATE→IOCTL compounds with placeholder FileId will fail open lookup. | `dispatch.rs:593-636` |
| S6 | IOCTL only handles VNI and DFS referrals. Everything else → `INVALID_DEVICE_REQUEST`. No `PIPE_TRANSCEIVE`. | `dispatch.rs:2602-2680` |
| S7 | smb-msg has `FsctlCodes::PipeTransceive = 0x0011C017`, `PipeTransceiveRequest/Response(IoctlBuffer)`. | `smb-rs/crates/smb-msg/src/ioctl/fsctl.rs:27,780,787` |
| S8 | `rssmb-rpc-server` is a stub: `RpcError`, `uuids::SRVSVC`, `is_rpc_pipe()` (accepts too many pipes, strips "PIPE" without separator — do not reuse unchanged as the CREATE allowlist). | `crates/rssmb-rpc-server/src/lib.rs` |
| S9 | `smb-rpc` PDU codec: Bind/BindAck/BindNak/Request/Response, no Fault/AlterContext, asserts `auth_length == 0`. Its NetrShareEnum is NDR64-only, client-shaped, private types. Usable for PDU structure reference but not for NDR20 stubs. | `smb-rs/crates/smb-rpc/src/pdu.rs` |
| S10 | `ServerConfig` (config.rs:14) has no `server_name` field. `NetrServerGetInfo` needs one. | `config.rs:14-60` |
| S11 | `ShareConfig` has `comment` (default ""), `browseable` (default true), `guest_ok`, `valid_users`, `encrypt_data`. Shares are `HashMap<String, ShareConfig>` — nondeterministic order; must sort by name for enumeration. | `config.rs:134-165, 42` |
| S12 | `Session` (session.rs:28): `is_guest: bool`, `user_identity: Option<Identity>`. No anonymous/guest distinction beyond `is_guest`. | `session.rs:28-53` |
| S13 | `ServerState` (lib.rs:48): no `server_name`. Has `server_guid: [u8; 16]`. | `lib.rs:48-62` |

**Decision: hand-write the DCE/RPC PDU codec and NDR20 serializer in
`rssmb-rpc-server`**, not reuse `smb-rpc`. `smb-rpc` is NDR64-only,
client-shaped, and its types are private. Patching it would add more untracked
edits to `smb-rs/` (Step 9 problem). Our codec covers only a few PDUs and
structures, so it stays small and testable.

## 1. Scope

**In:**
- Pipe opens on IPC$, served only for `srvsvc`.
- DCE/RPC connection-oriented PDUs:
  - BIND → BIND_ACK; ALTER_CONTEXT → ALTER_CONTEXT_RESP
  - REQUEST → RESPONSE or FAULT
  - BIND_NAK for pre-bind errors; FAULT for post-bind errors
  - multi-fragment request reassembly; response fragmentation
- NDR20 transfer syntax. Bind-time feature negotiation acknowledged.
- Pipe transports: WRITE+READ and `FSCTL_PIPE_TRANSCEIVE`.
- SrvSvc opnums:
  - `NetrShareEnum` (15), levels 0, 1, 2. Other levels → FAULT
    `nca_s_op_rng_error` or WERROR `ERROR_INVALID_LEVEL`.
  - `NetrShareGetInfo` (16), levels 0, 1, 2, 501, 1005.
  - `NetrServerGetInfo` (21), levels 100, 101.
- Per-session visibility filtering.
- `server_name` config field (optional, default hostname).

**Out (deferred):**
- RPC auth (`auth_length != 0`): BIND_NAK or FAULT `access_denied`.
- NDR64.
- Other pipes: lsarpc, samr, wkssvc, winreg. CREATE on them → `OBJECT_NAME_NOT_FOUND`.
- `NetrShareEnumSticky`, share add/del/set ops → FAULT `op_rng_error`.
- Async/pending pipe reads.
- `FSCTL_PIPE_WAIT` / `FSCTL_PIPE_PEEK`.
- Share security descriptors (level 502/503).
- GVFS/Finder/Windows `net view` live verification.

## 2. Design

### 2.1 Tree kind (8.1)
Add `is_ipc: bool` to `TreeEntry` (simpler than an enum — `vfs` stays as-is;
IPC$ keeps the MemoryFs placeholder but it's never used for I/O). All disk-path
handlers check `is_ipc` and reject disk-only commands:
- CREATE (non-srvsvc), READ, WRITE, QUERY_DIRECTORY, SET_INFO, FLUSH →
  `STATUS_INVALID_DEVICE_REQUEST`
- CREATE of `srvsvc` on an IPC tree → pipe open (see 2.2)

IPC$ stays exempt from guest_ok/valid_users (anonymous IPC$ is allowed in
Samba). It still goes through the 7e per-session encryption checks.

### 2.2 Pipe opens (8.1)
Add `OpenKind` to `OpenEntry`:
```rust
enum OpenKind {
    Disk,                                    // existing: vfs + open_id + dir_cursor
    Pipe(Arc<std::sync::Mutex<PipeState>>),  // new: shared RPC state
}
```
`OpenEntry` gains `kind: OpenKind`. Disk-path fields (`vfs`, `open_id`,
`dir_cursor`) are only valid when `kind == Disk`; pipe-path fields are only
valid when `kind == Pipe`. Handlers dispatch on `kind`.

CREATE on an IPC tree:
- Match the name case-insensitively against `srvsvc` after stripping a
  leading `\` and an optional `PIPE\`. **Do not reuse `is_rpc_pipe()`** — it
  accepts `PIPESRVSVC` (no separator) and other pipes outside scope.
- A match inserts an `OpenEntry` with `kind = Pipe(Arc::new(Mutex::new(PipeState::new())))`.
- Response: `CreateAction = FILE_OPENED`, `FileAttributes = NORMAL`, zero
  times/sizes, no create contexts, no oplock.
- Any other name → `STATUS_OBJECT_NAME_NOT_FOUND`.

CLOSE drops the open (and its RPC state — just drop the Arc).

Teardown (LOGOFF, TREE_DISCONNECT, connection drop): already iterate over
opens. Pipe opens must be skipped for VFS close — just remove from the map.

`PipeState` (in `rssmb-rpc-server`):
- `bound: HashMap<u16, Interface>` — bound presentation contexts
- `max_xmit_frag: u16`, `max_recv_frag: u16`
- `assoc_group_id: u32`
- `in_buf: Vec<u8>` — reassembly buffer for multi-fragment REQUESTs
- `out_queue: VecDeque<Vec<u8>>` — completed response messages waiting to be read
- `out_cursor: usize` — read position within the current message

API: `fn process(&mut self, input: &[u8], ctx: &RpcCtx) -> ProcessResult`.
Appends completed messages to `out_queue`. `fn read(&mut self, max: usize) ->
ReadResult { data: Vec<u8>, status: ReadStatus }` where `ReadStatus` is
`Data`, `Overflow`, or `Empty`.

`RpcCtx` carries: session identity (username, is_guest), share snapshot,
server name.

### 2.3 Pipe transports (8.3)
- **WRITE** on a pipe open feeds bytes to `process`. Reply `Count = len`.
- **READ** drains the output queue up to `Length`:
  - Data available: return up to `Length` bytes. If more remains in the
    current message → `STATUS_BUFFER_OVERFLOW` with the partial data.
  - Nothing queued: `STATUS_PIPE_EMPTY`. (Start simple; if clients need
    pending reads, revisit with the async-op machinery.)
- **IOCTL `FSCTL_PIPE_TRANSCEIVE`** (`0x0011C017`, flags must be
  `SMB2_0_IOCTL_IS_FSCTL`):
  - Input buffer → `process`.
  - Output drains up to `MaxOutputResponse`.
  - Leftover → `STATUS_BUFFER_OVERFLOW` with partial output.
  - FileId echoes the request.
- QUERY_INFO on a pipe open:
  - `FileStandardInformation` → zeros, `Directory=false`.
  - Anything else → `STATUS_NOT_SUPPORTED`.

**Spike (8.1):** verify the wire-adapter can encode a `ReadResponse` or
`IoctlResponse` with a warning-status (`STATUS_BUFFER_OVERFLOW`) header and a
body. If the encoder forces an `ErrorResponse` body on non-success status,
this is the first thing to fix — it blocks 8.3.

### 2.4 DCE/RPC PDU codec (8.2)
Common 16-byte header: `rpc_vers=5`, `minor=0`, `ptype`, `pfc_flags`,
`drep` (little-endian ASCII; reject big-endian drep → BIND_NAK or FAULT),
`frag_length`, `auth_length=0`, `call_id`.

Hand-write the PDU types in `rssmb-rpc-server` (not depend on smb-rpc):
- `DceRpcPdu` — parse/encode the 16-byte header + body
- BIND: parse context elements, accept SRVSVC/NDR20, reject others
- BIND_ACK: `\PIPE\srvsvc` NUL-terminated + pad to 4-byte boundary from PDU
  start (not string start); `max_xmit/recv_frag = min(client, 4280)` (our
  chosen cap, not confirmed as Samba's); `assoc_group_id` = client's or fresh
  nonzero; one result per context element.
- Feature negotiation: result=3 (negotiate_ack), reason=0 (zero feature bits),
  transfer syntax = all-zero UUID/version.
- REQUEST: reassemble fragments until LAST (cap at 1 MiB → FAULT); dispatch on
  `(context_id, opnum)`.
- RESPONSE: fragment the stub into chunks of at most `max_xmit_frag - 24`
  bytes with correct FIRST/LAST and `alloc_hint = total remaining`.
- FAULT: `alloc_hint`, `context_id`, `cancel_count=0`, `reserved=0`,
  `status` (NTSTATUS), `reserved2=0`.

State machine limits:
- Max reassembled request: 1 MiB
- Max pending output: bounded by share count (small); add per-session pipe
  open cap (e.g. 16) or note it's accepted
- Reject: continuation without FIRST, duplicate FIRST, changed context/opnum/
  call_id mid-fragment, REQUEST before BIND, interleaved calls (serialize — one
  call at a time per pipe)

`process()` returns a result type that can signal: OK, backpressure (input
discarded — WRITE must not ack all bytes), fatal pipe error (pipe closed).

### 2.5 NDR20 + SrvSvc (8.4)
Write `NdrWriter` / `NdrReader` with: alignment, u16/u32, unique/ref pointers,
conformant varying `wchar_t` strings (NUL counted), and per-operation
fixed-part/deferred-part layout.

**Do NOT use a generic "fixed part then all pointees" rule.** Each operation's
layout is derived from the MS-SRVS IDL for that specific opnum. The NDR writer
handles primitives and alignment; the operation code sequences them in the
correct order.

| Opnum | In | Out |
|---|---|---|
| 15 NetrShareEnum | ServerName (unique ptr+wstr), InfoStruct {Level, union ptr to ShareEnumStruct}, PreferedMaximumLength (u32), ResumeHandle (unique ptr+u32) | InfoStruct with filled ShareEnumContainer, TotalEntries (u32), ResumeHandle (ptr+u32), WERROR (u32) |
| 16 NetrShareGetInfo | ServerName (unique ptr+wstr), NetName (ref ptr+wstr), Level (u32) | SHARE_INFO_UNION (switch on Level), WERROR |
| 21 NetrServerGetInfo | ServerName (unique ptr+wstr), Level (u32) | SERVER_INFO_UNION (switch on Level), WERROR |

Share types: disk = `STYPE_DISKTREE` (0), IPC$ = `STYPE_IPC | STYPE_SPECIAL`
(0x80000003). Level 2: `permissions=0`, `max_uses=0xFFFFFFFF`,
`current_uses=0`, `path="C:\"` or empty, `passwd=NULL`. Level 501:
`shi501_flags=0`. Level 1005: set `SHI1005_FLAGS_ENCRYPT_DATA` (0x8000) when
`encrypt_data`.

`ResumeHandle`: return everything in one response with `ResumeHandle=0`.
Document the deviation — we don't implement resumable enumeration, and the
compatibility claim is narrowed to "few shares, single response."

### 2.6 Visibility (8.5)
`share_allows(identity, share) -> bool` — the same predicate TREE_CONNECT
uses (dispatch.rs:1542-1556), factored out:
- Guest: `guest_ok == true`
- Non-empty `valid_users`: user must be in the list (case-insensitive)
- Always true for authenticated users if `valid_users` is empty

`visible_shares(identity, config) -> Vec<ShareInfo>`:
- `browseable == true` AND `share_allows(identity, share)`
- Sort by name (deterministic)
- Append synthetic IPC$ entry (type IPC|SPECIAL)

`NetrShareGetInfo` uses `share_allows` but ignores `browseable` — hidden
shares are queryable by name (Samba does this). Unknown/invisible share →
`NERR_NetNameNotFound` (2310).

Prevent duplicate configured IPC$ entries: if the config has a share named
"IPC$", reject it at config validation (it's reserved).

## 3. Steps

| Step | Work | Check |
|---|---|---|
| 8.1 | `is_ipc` on TreeEntry; `OpenKind` on OpenEntry; CREATE/CLOSE `srvsvc` on IPC$; disk-only ops reject on IPC; `substitute_file_id` Ioctl arm; teardown skips pipe opens; spike: verify wire-adapter warning-status body encoding | unit: create srvsvc ok, create foo → not found, close, QUERY_DIRECTORY on IPC → error; `cargo test`; impacket 8/8 |
| 8.2 | `rssmb-rpc-server`: PDU codec, bind/alter/feature-negotiation, fragment reassembly + response fragmentation, FAULT paths; state machine limits | unit: golden BIND/BIND_ACK bytes (hand-checked, commit as fixtures); 2-fragment request; response split at small `max_xmit_frag` |
| 8.3 | WRITE/READ + PIPE_TRANSCEIVE plumbing, `BUFFER_OVERFLOW` with data, `PIPE_EMPTY`, pipe QUERY_INFO | unit through `handle_message`: transceive bind → bind_ack; READ continuation after overflow |
| 8.4 | NDR20 reader/writer; opnums 15/16/21 | unit: decode our response bytes with an independent decoder (impacket Python script committed as a test fixture); golden bytes for 0/1/3 shares at level 1 |
| 8.5 | `share_allows` refactor + `visible_shares` + GetInfo semantics; `server_name` config field; config validation for reserved IPC$ | unit: guest sees only guest_ok; valid_users filter; non-browseable hidden from enum but GetInfo works |
| 8.6 | Live: `tests/live/client.py` scenarios `enum_guest`, `enum_user`, `getinfo`; `smbclient -L` if available; repeat under `encryption = "required"` | impacket `run.sh` all pass (8 old + new); smbclient lists expected shares |
| 8.7 | Docs: `next-steps.md` §0 + §8 → DONE; README; remove "stub" comment | readback |

After 8.1: `cargo test` + impacket. After 8.3: `cargo test` + impacket. After
8.6: impacket. After 8.7: Mashūra implementation review, then commit per step.

## 4. Open questions (resolve during 8.1–8.3)

1. **READ on an empty pipe:** `STATUS_PIPE_EMPTY` vs pending READ. Start
   simple; if impacket/smbclient block, revisit with async-op machinery.
2. **smbclient availability:** check docker/compose for a samba-client
   profile; if missing, use Alpine with `samba-client` installed.
3. **Error status for disk ops on IPC trees:** pin against Samba source before
   finalizing; assert "error-severity" until pinned.
4. **Wire-adapter warning-status body:** does the encoder emit a ReadResponse
   body under `STATUS_BUFFER_OVERFLOW`? Spike in 8.1 — this blocks 8.3 if not.
5. **Server name source:** `config.server_name` if set, else `hostname::get()`
   fallback, else empty string. Deterministic for tests via config.

## 5. Sizing
Medium–large. Bulk is 8.2 (PDU codec) and 8.4 (NDR + opnums). 8.1, 8.3, 8.5 are
plumbing. 8.6 is live tests.

## 6. Mashūra plan review round 1 — folded in

Review by two panelists (gpt-6-astra, claude-fable-5.1). Verdict: sound
architecture, revise before implementation. Folded in:

**Must fix (done in plan above):**
1. NDR: replaced generic "top-level pointees after fixed part" with
   per-operation layout from MS-SRVS IDL. Each opnum is sequenced explicitly.
2. Three buffering layers separated: transport bytes (partial PDUs across
   writes), RPC fragments (FIRST/LAST), pipe messages (boundaries + read
   cursor). `out_queue` is `VecDeque<message>` with a per-message cursor, not a
   flat byte queue.
3. Bounded state machine: reassembly cap, pending output cap, per-session pipe
   open cap, reject interleaved calls (serialize), reject continuation without
   FIRST, duplicate FIRST, changed context/opnum/call_id. `process()` returns
   backpressure/fatal, not `()`.
4. BIND handling: directional fragment negotiation (server transmit ≤ client
   recv); reject unusably small `max_recv_frag`; one context can offer multiple
   transfer syntaxes; feature negotiation exact fields; object UUID flag
   (reject); auth trailer rejection. 4280 is our chosen cap, not confirmed
   Samba default.
5. Pagination: return everything in one response, document the deviation.
6. Handle isolation: `OpenKind::Pipe(Arc<Mutex<PipeState>>)` — shared state,
   audit all consumers (LOCK, QUERY_INFO, SET_INFO, FLUSH, teardown).
7. `server_name`: added to config (S10).
8. Share ordering: sort by name (S11).
9. `is_rpc_pipe()`: do not reuse as CREATE allowlist (S8).
10. `substitute_file_id`: add Ioctl arm (S5).
11. Acceptance narrowed: only impacket + smbclient; GVFS/Windows unverified.

**Deferred (recorded, not implemented):**
- Resumable enumeration (`ERROR_MORE_DATA` + `ResumeHandle` continuation)
- Pending pipe reads (async)
- NDR64
- Malformed-input fuzz tests (Step 10)
- Signed/encrypted live runs under `required` (added to 8.6)