# Plan — Production readiness

Status: **analysis only, nothing implemented.** Written 2026-10-13 against
HEAD `3c3b807`. Sources: a code audit of auth, DoS limits, protocol
completeness, VFS semantics and ops/supply chain. The key claims were
spot-checked by hand (`file:line` below). Line numbers drift, so re-check
them before starting a step.

"Production" here means: reachable by clients you do not fully trust (an
office LAN, a mixed Windows/macOS/Linux fleet), holding data whose loss or
corruption matters. A home NAS on a trusted LAN needs Phase 0 + Phase 1 only.

## Target use case (decided 2026-10-13)

**A reliable, secure standalone SMB server used from Windows and Linux
clients.** No Active Directory, no domain membership. Local users are
defined in RSSMB. macOS is a nice-to-have, not a target.

What that implies:
- **Authentication stays NTLMv2 over SPNEGO.** A non-domain-joined server
  gets NTLM from Windows clients. They may offer Kerberos first in SPNEGO
  and then fall back, so the SPNEGO path must cleanly select NTLM when
  Kerberos is offered first (already the case for impacket and smbclient;
  verify with Windows, see 3.9). Kerberos/AD (Phase 4) is deferred.
- **Windows defaults to take as hard requirements:** authenticated users
  only, because recent Windows blocks insecure guest logons by default.
  Signing will be required, since Windows 11 24H2 requires SMB signing on
  outbound connections by default. Treat `signing = "required"` +
  SMB 3.1.1 + encryption as the default profile, and guest as a
  Linux/dev-only convenience.
- **Watch item:** Microsoft has announced that NTLM is being deprecated
  (NTLMv1 is already removed in recent releases; NTLMv2 still works). The
  planned replacement for non-domain machines is IAKerb / local KDC.
  [inferred from Microsoft announcements — re-check status yearly.] Not
  actionable now, but it's the one way "no AD" might still end up needing
  Kerberos work later.
- **Account name forms:** Windows users type `alice`, `SERVER\alice`,
  `.\alice` or `alice@server`. Make sure NTLM user matching ignores or
  accepts the domain field (any workgroup/server name), matches the user
  name case-insensitively, and handles UPN-style names. Add tests (see 1.3).
- **Permission model:** one service OS user, with access control per share
  (`valid_users`, `read_only`) plus optional per-user read-only/read-write
  lists per share (4, option C). Per-user Unix uid mapping is not needed.

---

## Verification of the earlier gap analysis

| Claim (earlier this session) | Verdict | Correction |
|---|---|---|
| Negotiate state machine missing (next-steps.md:47-49) | **Wrong — doc is stale.** | Repeat NEGOTIATE and pre-NEGOTIATE commands disconnect (`dispatch.rs:698-718`); `NegotiateRecord` is stored and VNI validates against it (`dispatch.rs:2860-2905`). Update next-steps.md. |
| No MessageId window | **Confirmed.** | `dispatch.rs:654-663` says it outright. Severity: **high, not critical.** Over plain TCP an attacker needs MITM to replay. The real risks are (a) replaying a *signed* message under active MITM, and (b) multi-credit/large-MTU cannot be enabled safely without it. |
| Share modes not enforced | **Confirmed**, plus worse. | `ShareAccess::all()` at `dispatch.rs:1824`. Also **a new `LocalFs` per TREE_CONNECT** (`dispatch.rs:1608-1618`), so even same-share opens from two trees don't see each other. This is a **data-integrity** issue (Office/DB file corruption), not an auth bypass. |
| Path TOCTOU | **Confirmed.** | `localfs.rs:121-161`: canonicalize + `starts_with`, then a path-based reopen. `..` is blocked. Exploiting it needs an actor who can create symlinks *inside* the share. RSSMB clients can't (no reparse support), so the risk is local users / other protocols (NFS, sync tools) exporting the same directory. Severity: **critical on multi-user hosts, medium on a dedicated box.** |

New findings that weren't in the earlier list, ordered by severity:

- **Bug: SET_INFO is effectively broken.** `SetInfoRequest` discards
  InfoType (`info.rs:225-228`, `#[br(temp)]`), and dispatch checks
  `info_class.0 == 0x01` as if it were InfoType (`dispatch.rs:2551`). So
  FileBasic(4)/Rename(10)/Disposition(13)/EOF(20) are unreachable, and
  rename, delete, truncate and set-times all return `NOT_SUPPORTED`. This is
  probably a regression from the 9.1c proto swap. It went unnoticed because
  the Docker interop tests this session didn't rename or delete. Inferred
  from code, not run. Confirm with `smbclient -c 'rename a b'` or `mount.sh`.
- **Plaintext passwords in TOML**, no perms check on the config file, and
  `Debug` derived on `UserConfig` (`config.rs:68-77`, `rssmb-cli/src/main.rs:73`).
- **No auth throttling** — unbounded online password guessing (`dispatch.rs:982-991`).
- **No timeouts at all**: slowloris holds a 1 MiB buffer per connection
  forever (`connection.rs:92-100,248`).
- **`max_connections_per_ip` is parsed but never enforced** (`config.rs:35`).
  The example config sets it to 100, which misleads operators.
- **No graceful drain on shutdown** (`lib.rs:92`, `main.rs:140-152`).
- **Shipped `config/rssmb.toml` is a test config** (signing disabled, guest
  on, test password). The Dockerfile bakes it into the image (`Dockerfile:23`).
- **FLUSH doesn't fsync** (`localfs.rs:370-378`).
- **Lookup is case-sensitive.** Windows/macOS clients will hit `NotFound`
  on case mismatch (`path.rs:48-50`).
- **Signing `desired` + impacket `signed` scenario:** the server rule follows
  MS-SMB2 3.3.5.5.3 (`dispatch.rs:1222-1225`, `signing.rs:184`). The likely
  cause is the test: `client.py:99` sets `RequireMessageSigning` *after*
  `SMBConnection()` has already negotiated. [inferred — confirm by setting
  it before negotiate, or with config `signing = "required"`.]

What's already solid, so it needs no work: NTLMv2-only with constant-time
proof check; wrong password never falls back to guest (`rssmb-auth/src/lib.rs:266-312`);
negotiate gate + VNI; preauth integrity; AES-128-GCM with transform
validation; credit cap; compound length cap (20); RPC reassembly cap (1 MiB);
no `unsafe` in `crates/`; no git dependencies.

---

## Phase 0 — Fix what's broken (small, do first)

### 0.1 SET_INFO InfoType decode
Make `info_type` a real field in `SetInfoRequest` (drop `#[br(temp)]`, keep
`#[bw(calc)]` or make it a plain field). Dispatch on
`(info_type, info_class)`: File(1) → classes 4/10/13/20/19/64, Security(3)
→ Phase 3.4, others → `NOT_SUPPORTED`. Add a golden-byte test with a real
captured SET_INFO rename request. This is the test gap that let it through:
add rename + delete + truncate to `tests/live/smbclient.sh` and to an
in-process integration test.

### 0.2 Signing test diagnosis
Move `RequireMessageSigning = True` before negotiate in `client.py`, or run
`signed` against a `signing = "required"` config. If it still fails, then
it's a server bug in 3.3.5.5.3 handling.

### 0.3 Safe defaults
- Rename `config/rssmb.toml` → `config/rssmb.dev.toml`. Ship the example
  with `signing = "required"`, `guest_access = false`, no users.
- Dockerfile: don't `COPY` a config; require a mount (fail fast if missing).
- Either implement `max_connections_per_ip` (1.6) or remove it from the
  example until it is.

### 0.4 Stale docs
next-steps.md §0 table (says "SMB 2.1 only") and lines 47-55 (negotiate
state machine, smb-msg patches) are out of date. Correct them.

---

## Phase 1 — Security gate (before any untrusted network)

### 1.1 Path confinement without TOCTOU
**Recommendation:** switch LocalFs to handle-relative resolution.
- Use `cap-std` (`cap_std::fs::Dir`, opened once per share root). All
  open/create/mkdir/remove/rename/metadata go through the `Dir`, which
  resolves beneath the root with `openat2(RESOLVE_BENEATH)` on Linux ≥5.6
  and a manual `O_NOFOLLOW` walk elsewhere. Alternative: `rustix` +
  `openat2` directly, with a fallback walk.
- After CREATE, operate **only on the held fd** (fstat, ftruncate, futimens,
  fsync). For rename/delete, use `renameat`/`unlinkat` relative to the
  parent dir fd held in the handle, not the stored `full_path`.
- **Symlink policy** per share: `follow_symlinks = "never" | "within_share"`.
  Default is `never`. Report symlinks as reparse points
  (`FILE_ATTRIBUTE_REPARSE_POINT`) using `symlink_metadata`/`AT_SYMLINK_NOFOLLOW`
  and refuse to open through them with `STATUS_STOPPED_ON_SYMLINK` /
  `ACCESS_DENIED`.
- Delete `NormalizedPath::is_safe()` (it always returns true and is
  misleading).

**Tests:** a race test (thread swaps a dir for a symlink to `/` in a loop
while opens run), plus symlink-to-outside and symlink-within cases.

### 1.2 Name validation
In `NormalizedPath::from_smb_path`, reject NUL/control chars (0x00-0x1F),
`< > : " | ? *` (note `:` is the stream separator, see 3.5), trailing
dot/space, component >255 UTF-16 units, and total path >32 767. Return
`STATUS_OBJECT_NAME_INVALID`. Optionally make reserved device names
(CON, NUL, COM1…) a per-share option. Apply NFC normalization on input
(macOS sends NFD) with the `unicode-normalization` crate. Fuzz target
`normalize_path`.

### 1.3 Credential storage
- Accept NT hashes (`nt_hash = "hex"`) in a **separate users file**
  (`users_file = "/etc/rssmb/users"`). NTLMv2 only needs the NT hash, so
  plaintext is never required. Add `rssmb hash-password` to the CLI.
- Refuse to start if the users file or config is group/world-readable or
  not owned by the service user (like ssh). Allow an override flag.
- Write a manual `Debug` for `UserConfig` that redacts. Wrap keys and hashes
  in `zeroize::Zeroizing<Vec<u8>>` / `secrecy::SecretBox`. Stop rebuilding
  plaintext copies per SESSION_SETUP (`dispatch.rs:944-963`): build the
  identity store once in `ServerState`.
- Remove the test password from the committed `config/rssmb.toml` (0.3).
- **Windows account-name forms:** accept `alice`, `SERVER\alice`,
  `WORKGROUP\alice`, `.\alice` and `alice@server`. Ignore the NTLM domain
  field unless it names a *different* configured realm, and match user names
  case-insensitively. Remember that the NTLMv2 proof includes
  `UPPER(user) + domain` as the client sent it. Compute it with the
  client-supplied domain string, not a normalized one. Add tests per form.

### 1.4 Auth failure throttling
`AuthLimiter` in `ServerState`: a per-source-IP and per-username token bucket
(`governor` crate or a small `DashMap<key, (count, window_start)>`).
- After N failures (default 5/min/IP), add a growing delay (sleep before
  sending `LOGON_FAILURE`, capped at ~5 s), then refuse SESSION_SETUP from
  that IP for a cooldown.
- Count failures **per connection too**: a connection with >N failures is
  dropped (stops one TCP stream cycling SessionId=0).
- Make the timing equal for unknown user vs wrong password (always compute
  a proof against a dummy hash).
- Emit an audit event per failure (5.3).

### 1.5 MessageId window + multi-credit validation
Replace the scalar balance with a sequence window per MS-SMB2 3.3.1.1:
- Per connection: `low: u64` plus a bitset (`VecDeque<u64>` words, or the
  `bitvec` crate) covering `[low, low + granted)`. Granting extends the
  window. A request with MessageId `m` and charge `c` must have all of
  `m..m+c` inside the window and unused. Mark them used, advance `low` past
  the contiguous used prefix. CANCEL is exempt and doesn't consume.
- Violation → disconnect (already the behavior for insufficient credits).
- Validate `CreditCharge >= ceil(max(payload, expected_response)/65536)`
  for READ/WRITE/IOCTL/QUERY_DIRECTORY (3.3.5.2.5). Only then raise
  `MAX_IO_SIZE` (Phase 3.6).
- Property test: random grant/request sequences vs a reference model.

### 1.6 Resource limits and timeouts
All configurable under `[limits]` with sane defaults:

| Limit | Default | Where |
|---|---|---|
| Handshake timeout (TCP accept → SESSION_SETUP success) | 30 s | wrap the read loop in `tokio::time::timeout` until authenticated |
| Idle timeout (no request) | 15 min (keep larger than client echo intervals) | per-read `timeout` |
| Per-frame body read deadline | 30 s | `timeout(read_exact(body))` |
| Global connections | 1024 | `Arc<Semaphore>`, acquire before spawn |
| Per-IP connections | 32 | `DashMap<IpAddr, usize>` with RAII guard |
| Sessions / connection | 16 | dispatch insert sites |
| Trees / session | 64 | dispatch |
| Opens / session | 4096 | dispatch (→ `INSUFFICIENT_RESOURCES`) |
| Pending async / connection | 64 | CHANGE_NOTIFY insert (`dispatch.rs:2742-2758`) |
| RPC pipe out_queue | 1 MiB | `rssmb-rpc-server/src/lib.rs` (→ fault / pipe busy) |
| `max_frame_size` hard ceiling | 8 MiB | config validation |

Also:
- Don't allocate the full frame before data arrives: read in chunks into a
  `BytesMut` that grows, or allocate after a first chunk.
- QUERY_DIRECTORY: stream entries with incremental packing (O(n), not the
  rebuild loop at `dispatch.rs:2437-2494`). Cap entries per call. Cache the
  directory snapshot on the open (already has a cursor).
- `read_at` must clamp `len` to `MAX_IO_SIZE` before allocating (`localfs.rs:320`).

### 1.7 Health endpoint
Make the bind address configurable and default it to `127.0.0.1:8080`
(`rssmb-cli/src/health.rs:13`). Add a read timeout. Metrics stay
unauthenticated but local-only.

### 1.8 SPNEGO/NTLM hardening
- If the client offered mechListMIC capability (NTLM `MsvAvFlags` MIC bit),
  require the mechListMIC on the final leg (`rssmb-auth/src/lib.rs:206-226`).
- Verify the AUTHENTICATE message MIC (MS-NLMP 3.2.5.1.2) when `MsvAvFlags`
  says it's present. Check whether sspi already does this, and add a test
  with a tampered MIC.
- Optional `ntlm_require_target_info_timestamp` (anti-replay of NTLM blobs).

**Exit gate for Phase 1:** a third-party pentest or careful self-review
against this list, plus a fuzz run of the stateful harness (6.3). Until
then, keep the "trusted network only" warning in the README.

---

## Phase 2 — Data integrity with multiple clients

### 2.1 One open table per share, wired into CREATE
- Create one `LocalFs` (or `ShareBackend`) per **share** at startup, held in
  `ServerState`. Trees get an `Arc` to it (fixes `dispatch.rs:1608-1618`).
- Identify a file by `(dev, ino)` from fstat after open, not by path. Use
  that as the `OpenTable` key. Wire `OpenTable::check_and_add` into
  `handle_create` with the client's real `ShareAccess` and `DesiredAccess`,
  returning `STATUS_SHARING_VIOLATION`. Remove on CLOSE and teardown.
- This is the prerequisite for oplocks/leases (3.1).

### 2.2 Delete-pending semantics
Keep `delete_pending` on the shared per-file entry (2.1), not per handle.
Effects:
- New CREATEs on that file get `STATUS_DELETE_PENDING`.
- FileStandardInformation.DeletePending reflects it.
- Unlink happens at the **last** close.
- Non-empty directory → `STATUS_DIRECTORY_NOT_EMPTY` at SET_INFO time.
- Propagate unlink errors instead of ignoring them (`localfs.rs:561-575`).

### 2.3 Byte-range locks (LOCK command)
Currently `NOT_SUPPORTED` (`dispatch.rs:786-789`). Office, SQLite-over-SMB,
and many apps need it.
- Per-file lock list in the shared entry: `(offset, length, owner=(session, fileid), exclusive)`.
- Conflict checks on LOCK, READ and WRITE (mandatory locking semantics for
  SMB).
- `FAIL_IMMEDIATELY` vs blocking. Blocking locks go async: PENDING with an
  AsyncId, completed on unlock, cancellable via CANCEL.
- Release all locks on CLOSE and teardown.
- Don't map to POSIX fcntl locks (process-wide, and they'd conflict
  in-process). Keep them in-memory. Optionally add OFD locks later for
  cross-protocol coherence.

### 2.4 Durability
FLUSH → `sync_data()` (`localfs.rs:370-378`). Return flush/close errors
instead of ignoring them. Per-share `strict_sync = true|false` (Samba has
the same knob). Honor `WRITE_THROUGH` in CreateOptions/Write flags with
`O_DSYNC` or a sync after write.

### 2.5 Case-insensitive lookup
Per-share `case_sensitive = false` (default for Windows/macOS clients).
- On a lookup miss, scan the parent directory for a case-insensitive match
  (Unicode simple case folding via `caseless` / `unicase`, not ASCII). Cache
  dir listings with an mtime check.
- Detect ambiguity (two names differing only in case) → open the exact
  match if present, otherwise `OBJECT_NAME_COLLISION` on create.
- Long-term: recommend case-folding filesystems (ext4 `casefold`, ZFS
  `casesensitivity=insensitive`), with a detect-and-skip fast path.

### 2.6 Atomic rename and supersede
`renameat2(RENAME_NOREPLACE)` when `ReplaceIfExists = false` (rustix),
instead of check-then-rename (`localfs.rs:603-609`). For Supersede, create
a temp file and rename it over the target instead of remove + create, and
don't ignore `remove_file` errors (`localfs.rs:198`). Rename of an open
directory/file: check the share table for conflicting opens
(`SHARING_VIOLATION` / `ACCESS_DENIED`).

### 2.7 Async hygiene and concurrency
- Wrap blocking `std::fs` calls in `spawn_blocking` (or use `cap-async-std`
  / tokio fs consistently) (`localfs.rs:135,149,218,226…`).
- Replace the single tokio `Mutex` over the opens map (held across I/O,
  `localfs.rs:310-351`) with per-handle locks (`DashMap<id, Arc<Mutex<File>>>`)
  plus positional I/O (`pread`/`pwrite` via `FileExt::read_at`) so no seek
  state is shared.
- Consider bounded concurrent dispatch per connection (Semaphore of ~16) so
  one slow READ doesn't block an ECHO. Responses can already go out of
  order.

### 2.8 Attributes
Apply FileBasicInformation attributes (TODO at `dispatch.rs:2600`): map
READONLY ↔ owner write bit. Store HIDDEN/SYSTEM/ARCHIVE in an xattr
(`user.DOSATTRIB`, Samba-compatible format if you want interop). Store
creation time in an xattr or statx btime.

---

## Phase 3 — Client compatibility and performance

Order matters: 3.1–3.4 are what Windows Explorer notices. Priorities for the
target use case (Windows + Linux):

| Item | Windows | Linux cifs.ko | Priority |
|---|---|---|---|
| 3.2 CHANGE_NOTIFY | Explorer auto-refresh, and it keeps one outstanding per folder | not needed | **high** |
| 3.4 Security descriptors | Properties dialog, some apps and installers | not needed | **high** (minimal synth SD) |
| 3.5 FileStreamInformation + real FS sizes | Explorer free-space, copy pre-checks | `df` | **high** (small) |
| 3.8 copychunk | Explorer copy within the share (big speedup) | `cp --reflink`/`copy_file_range` uses it | medium |
| 3.1 Leases | performance, Office | not needed (cifs uses leases if offered, optional) | medium |
| 3.3 Durable handles v2 | sleep/Wi-Fi roaming without "network path lost" errors | reconnect after network blips | medium |
| 3.6 Large MTU | throughput (1 MiB I/O) | throughput | medium |
| 3.7 AES-256 / CCM | only if policy requires it; 3.1.1 + AES-128-GCM is enough | same | low |
| 3.8 wkssvc/lsarpc | `net view`, SID→name in the Security tab | not needed | low–medium |
| mDNS / AFP streams / Finder | n/a | n/a | **out of scope** (macOS) |
| SMB 3.1.1 POSIX extensions | n/a | `mount -o posix` for real Unix modes/symlinks | optional, later |

### 3.1 Leases (and oplocks) — **DONE** (commit `d76142a`)
Implemented: file leases v1/v2 (RqLs/RqL2 create contexts) with R/RH/RW
states, keyed by client lease key in the shared open table; break
notifications via `send_unsolicited` with ack timeout and staged downgrade;
traditional oplocks (Level II, Exclusive, Batch) for non-lease clients.

### 3.2 CHANGE_NOTIFY
Currently a stub that never completes (`dispatch.rs:2742-2770`).
- Minimum: complete pending notifies with `STATUS_NOTIFY_CLEANUP` on CLOSE
  of that handle, and honor CANCEL.
- Real: the `notify` crate (inotify) per watched directory, refcounted and
  shared between watchers. Translate events into FILE_NOTIFY_INFORMATION,
  respecting CompletionFilter + WATCH_TREE. On overflow, return
  `STATUS_NOTIFY_ENUM_DIR`. Bound the per-watch buffer (1.6).

### 3.3 Durable handles v2 (DH2Q/DH2C)
Laptops on Wi-Fi and macOS rely on reconnect. Keep the open alive (with its
fd, locks, lease) for the durable timeout after disconnect, keyed by
CreateGuid. On DH2C reconnect, validate session user + lease key and
re-attach. Requires 2.1/3.1. Persistent handles (CA shares) are out of scope.

### 3.4 Security descriptors
Explorer's Properties → Security tab, and many apps, call
QUERY_INFO/SECURITY. Currently `ACCESS_DENIED` (`dispatch.rs:2392-2398`).
- Synthesize an SD from POSIX mode: owner/group as well-known SIDs or
  `S-1-22-1-uid` / `S-1-22-2-gid` (Samba "Unix Users" convention), and a
  DACL mapping rwx to the corresponding rights.
- SET_INFO/SECURITY: accept and ignore (configurable), or map a simple DACL
  back to the mode. Never return success while silently dropping an
  owner/ACL change on a share marked `acl = "strict"`.

### 3.5 Streams and FS info
- FileStreamInformation (22): return the single `::$DATA` stream.
  `name:stream` opens → `OBJECT_NAME_NOT_FOUND`, or map ADS to xattrs
  (`user.DosStream.*`) behind an option. macOS uses `AFP_AfpInfo` /
  `AFP_Resource`. Finder works without them but copies get noisy.
- FS info (`fsinfo.rs:150-186`): real `statvfs` sizes, stable volume serial
  (hash of share root + share name), FS attributes reflecting actual support
  (case-preserving, unicode; not ACL/streams unless implemented).

### 3.6 Large MTU
After 1.5: advertise 1 MiB (or 8 MiB) max read/write/transact. Multi-credit
charge is validated. Check the RPC and directory paths against the larger
buffers.

### 3.7 Crypto completeness
- AES-128-CCM: required for 3.0/3.0.2 encryption (Windows 8/2012 era,
  older Samba). `ccm 0.5` fits the current `aead 0.5` stack.
- AES-256-GCM/CCM (Windows 11 / Server 2022 can be configured to require it).
- Echo the ENCRYPTION and SIGNING negotiate contexts properly. AES-GMAC
  signing after a nonce-uniqueness review.
- Per-key nonce counters with rekey / session expiry before 2^32 GCM
  messages (well beyond realistic use, but make it explicit).
- Compression: skip unless there's a concrete need.

### 3.8 Extras that real clients probe
- `FSCTL_SRV_COPYCHUNK` / `_WRITE` + `FSCTL_SRV_REQUEST_RESUME_KEY`:
  server-side copy. Windows and macOS use it for copies within a share
  (big UX win). Use `copy_file_range`.
- `FSCTL_QUERY_NETWORK_INTERFACE_INFO` — **DONE** (commit `11b33fd`): NIC
  enumeration via `getifaddrs` (background refresher, fail-closed snapshot)
  feeding the multichannel interface-discovery response; multichannel is
  implemented (session binding across connections).
- RPC: `wkssvc` (NetrWkstaGetInfo) and `lsarpc` (LsarOpenPolicy2 /
  LsarLookupSids2 / name lookup) for `net view`, Finder and the Explorer
  security tab name resolution (pairs with 3.4).
- mDNS/DNS-SD advertisement (`_smb._tcp`) for Finder discovery. WS-Discovery
  for Windows Network neighborhood (optional, separate small daemon/task).

### 3.9 Client matrix (manual, before each release)
Windows 11 (Explorer copy/rename/delete, Office save, `net use`,
`robocopy /mir`), macOS (Finder copy, Time Machine is out of scope unless
AAPL extensions are implemented), GNOME Files, cifs.ko `vers=2.1…3.1.1,seal`,
smbclient. Record results in `docs/testing.md`.

---

## Phase 4 — Identity and permission model — **DEFERRED**

Decided 2026-10-13: no AD and no per-user uid mapping for the target use
case. The only in-scope piece is **option C** below, as a small extension to
share policy: per-share `read_users` / `write_users` lists in addition to
`valid_users` / `read_only`, enforced in TREE_CONNECT (MaximalAccess) and
CREATE (`DesiredAccess`). Do it alongside 2.1. The rest of this section is
kept for reference.

Today all file access runs as the single server OS user. Authorization is
per share only (`guest_ok`, `valid_users`, `read_only`). That's acceptable
for "one service account, share-level permissions" deployments, and it's a
deliberate product decision. Write it down in the README.

If per-user filesystem permissions are required:
- **Option A (recommended): privilege-separated workers.** A root (or
  CAP_SETUID) parent forks per-session or per-user worker processes that
  `setresuid`/`setgroups` to the mapped Unix user and do the VFS I/O over a
  socketpair. Strong isolation, Samba-like, more work.
- **Option B: per-thread `setfsuid`/`setfsgid`** around each blocking VFS
  call on a dedicated thread pool (Linux-only, subtle, easy to get wrong
  with async). Not recommended.
- **Option C: in-process ACL layer** (per-share user → rights map checked
  in dispatch). Simplest, but enforcement is only as good as RSSMB's own
  code.

**Kerberos / AD:** required for domain-joined Windows fleets (NTLM is
increasingly disabled by policy). This is substantial: SPNEGO with
krb5/AP-REQ via `sspi`'s Kerberos (verify server-side support) or
`libgssapi`, keytab handling, PAC parsing for group SIDs, and
idmap (SID ↔ uid). Treat as a separate project. Until then, document
"standalone users only, no domain membership".

---

## Phase 5 — Operations

### 5.1 Configuration
- `#[serde(deny_unknown_fields)]` on all config structs (`config.rs:7,137`).
- Validation: share paths exist and are directories, dialect min ≤ max,
  ports, limit sanity, `guest_ok` without `guest_access` warning, and a
  warning on `signing != "required"` when bound to non-loopback.
- `rssmb check-config` subcommand.

### 5.2 Lifecycle
- **Graceful drain:** track connection tasks in a `JoinSet`. On SIGTERM:
  stop accepting, signal all connections (`CancellationToken` instead of
  `Notify::notify_waiters`, which misses tasks not currently waiting —
  `lib.rs:92`), wait up to `shutdown_grace` (default 10 s, matching
  compose), then abort. Close VFS handles (fsync).
- **SIGHUP reload:** reload users and share definitions into an
  `ArcSwap<Config>`. Existing sessions keep their state. New
  TREE_CONNECTs see the new shares. Removed shares disconnect their trees.
- Replace `.unwrap()` in the signal handler (`main.rs:120-141`).

### 5.3 Logging and audit
- `tracing-subscriber` with a JSON option (`--log-format json`).
- Separate **audit** target (`target: "rssmb::audit"`): logon success and
  failure (user, source IP, dialect, signed/encrypted), tree connect/deny,
  create-with-delete, rename, delete, set-security. Off by default for file
  ops, on for auth.
- Log hygiene: hex payload previews and filenames only at `trace`, never
  `debug` (`connection.rs:359`). Compose default `RUST_LOG=info`, not
  `debug` (`compose.yml:30`). Usernames are fine in audit, not in general
  debug lines.

### 5.4 Metrics
Prometheus on the health port: connections (current/total/rejected by
limit), sessions by dialect / signed / encrypted, auth failures by reason,
throttled IPs, bytes read/written, per-command latency histograms,
open handles, pending async ops, lease breaks.

### 5.5 Packaging
- **systemd unit** with `User=rssmb`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
  `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=<share roots>`,
  `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `SystemCallFilter=@system-service`.
- **Docker:** pin base images by digest; enable `read_only: true` + tmpfs;
  `cap_add: [NET_BIND_SERVICE]` explicitly (the comment at
  `compose.yml:48-50` is misleading on hosts without
  `ip_unprivileged_port_start=0`); no baked config (0.3); `HEALTHCHECK` uses
  the configurable address.
- Release binaries: static musl builds, checksums, signed (cosign/minisign).
  Optionally .deb/.rpm via `cargo-deb` / `cargo-generate-rpm`.

---

## Phase 6 — Assurance and release process

### 6.1 Supply chain
`cargo deny` (advisories, licenses, bans, sources) + `cargo audit` in CI.
Pin GitHub Actions by SHA. Dependabot or Renovate for Cargo + Actions. Track
the transitive pre-release `rsa 0.10.0-rc.18` (via sspi?). Check whether a
stable version is reachable, or whether the dependency can be avoided. SBOM
(`cargo cyclonedx`) attached to releases.

### 6.2 Conformance
Actually run the smbtorture suites (10.4 is code-only) and commit the
baseline. Add `smb2.lock`, `smb2.lease`, `smb2.durable-v2-open`,
`smb2.notify`, `smb2.rename`, `smb2.delete-on-close-perms`, `smb2.sharemode`
as their features land. Gate PRs on "no regression by test identity".

### 6.3 Fuzzing
Run the existing 6 targets continuously (OSS-Fuzz-style or a nightly with a
persistent corpus). Add: the stateful connection harness (the 10.5 item not
yet done; the most valuable), `normalize_path`, NTLM AUTHENTICATE parser in
`rssmb-auth`, transform-header parse, NDR decoders, SET_INFO class payloads.
Every crash becomes a regression test.

### 6.4 Testing additions
- Property/model tests: credit window (1.5), share-mode/lock matrix
  (2.1/2.3), path normalization (1.2).
- Load tests: 1000 idle connections (memory/conn), sustained 1 MiB READ/WRITE
  throughput, directory with 100k entries, many concurrent CHANGE_NOTIFY.
  Record baseline numbers.
- Chaos: kill -9 mid-write, disk full (`ENOSPC` → `STATUS_DISK_FULL`), share
  root removed while connected.

### 6.5 Project hygiene
`SECURITY.md` (disclosure contact, supported versions), `CHANGELOG.md`,
semver tags, a documented threat model (what RSSMB defends against: network
attackers, malicious authenticated users; what it doesn't: local users with
share write access before 1.1, root), and an external security review before
calling 1.0.

---

## Suggested order

| # | Step | Size | Why now |
|---|---|---|---|
| 0.1–0.4 | SET_INFO bug, signing test, safe defaults, stale docs | small | broken behavior / footguns |
| 1.3 | credentials (hashes, users file, perms, zeroize) | small–medium | plaintext secrets |
| 1.6 | timeouts + connection/resource limits | medium | trivial DoS today |
| 1.4 | auth throttling | small | unbounded guessing |
| 1.1–1.2 | cap-std confinement, symlink policy, name validation | medium–large | the critical FS boundary |
| 1.5 | MessageId window + CreditCharge validation | medium | replay + unlocks large MTU |
| 1.7–1.8 | health bind, MIC hardening | small | |
| 5.1–5.3 | config strictness, drain, reload, audit log | medium | operable |
| 2.1–2.2 | per-share open table, share modes, delete-pending | medium | multi-client integrity |
| 2.4–2.7 | fsync, case-insensitivity, atomic rename, async hygiene | medium | data safety + Windows/mac UX |
| 2.3 | byte-range locks | medium | Office/DB apps |
| 3.2, 3.4, 3.5 | CHANGE_NOTIFY, security descriptors, streams/FS info | medium | Explorer/Finder polish |
| 3.1, 3.3, 3.6 | leases, durable handles, large MTU | large | performance + roaming clients |
| 3.7–3.8 | CCM/AES-256, copychunk, wkssvc/lsarpc, mDNS | medium | compatibility |
| 5.4–5.5, 6.x | metrics, packaging, supply chain, conformance, fuzz, review | ongoing | release quality |
| 4 | identity model / Kerberos | large, optional | **deferred** — only option C (per-share user rw lists) is in scope |

**For the target use case (reliable + secure, Windows + Linux, no AD), the
release-1.0 scope is:**

1. Phase 0 (all).
2. Phase 1 (all), including the Windows account-name forms in 1.3.
3. Phase 2 (all): share modes, delete-pending, byte-range locks, fsync,
   case-insensitive lookup, atomic rename, async hygiene, attributes.
   Windows apps (Office, Explorer) depend on 2.1–2.3 and 2.5.
4. Phase 3 high-priority items: 3.2 CHANGE_NOTIFY, 3.4 minimal security
   descriptors, 3.5 streams + real FS sizes. Then 3.3 durable handles and
   3.6 large MTU for reliability and throughput.
5. Phase 4 option C (per-share read/write user lists).
6. Phase 5 (all) and Phase 6.1–6.4, plus the Windows 11 + cifs.ko client
   matrix (3.9) passing.

Copychunk (3.8 remaining), AES-256/CCM (3.7), wkssvc/lsarpc and POSIX
extensions are post-1.0. macOS and Kerberos/AD remain out of scope.
Leases (3.1), SMB over QUIC, and multichannel (session binding +
interface discovery) are **implemented** post-1.0; multichannel binding
hardening (per-channel signing keys) and persistent handles are pending.
