# Changelog

All notable changes to RSSMB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`multichannel` default flipped to `false`.** SMB 3.x multichannel is
  now off by default until binding hardening lands; set `multichannel = true`
  in the server config to re-enable. The server still honors the capability
  when explicitly enabled.

## [0.1.6] - 2026-10-23

### Added

- **Byte-range locks: smb2.lock 22/22 (was 3/22; smb2.durable-v2-open
  14/15, smb2.lease 30/9, smbtorture 4.19.5).** Campaign C brings the
  lock suite to full golden parity with Samba 4.19.5 (22 pass / 3
  cluster-only skips):
  - **Blocking locks (MS-SMB2 3.3.5.14).** A lock without
    `FAIL_IMMEDIATELY` that conflicts with an existing range now pends
    as `STATUS_PENDING` and is granted when the conflicting range is
    released, or `LOCK_NOT_GRANTED` after a 35 s timeout. `CANCEL`
    completes the pended lock with `STATUS_CANCELLED`; `CLOSE`,
    `TREE_DISCONNECT`, and `LOGOFF` complete it with
    `RANGE_NOT_LOCKED`. Completion ownership is strict — only the path
    that removes the pending-async entry sends the one out-of-band
    response, preventing `INVALID_NETWORK_RESPONSE` from a double-send.
  - **LockSequence replay detection (MS-SMB2 3.3.5.14).** Per-open
    64-bucket array (`sequence >> 4` = bucket, `& 0xF` = value);
    replayed successful sequences are silently suppressed. Enabled for
    all opens (`SMB2_CAP_MULTI_CHANNEL`), matching smbd — this is also
    what makes `replay_broken_windows` SKIP with golden parity.
  - **Same-open conflict semantics.** Re-acquiring an exclusive lock
    over an existing own lock conflicts (`LOCK_NOT_GRANTED`, no
    auto-unlock); shared locks stack freely over own locks; the open's
    own shared locks block its own writes (the point of a shared lock).
  - **smbd-exact flag validation.** First-element switch determines
    unlock vs lock mode; `SHARED|UNLOCK` etc → `INVALID_PARAMETER`;
    unlock batching (applied unlocks persist, first miss →
    `RANGE_NOT_LOCKED`); zero-length locks are valid stacked entries;
    `offset+length` overflow → `INVALID_LOCK_RANGE` (but `max/1` is
    valid — only true overflow errors).

### Fixed

- **Four wrong NTSTATUS wire values (K1).** Full audit of all 32 enum
  variants + 15 raw `Other(0x…)` literals against Wine's `ntstatus.h`
  (2717 defines, MS-ERREF §2.3.1 mirror): `LOCK_NOT_GRANTED` was
  `0xC000005A` (STATUS_INVALID_OWNER) → `0xC0000055`; `FILE_LOCK_CONFLICT`
  was `0xC0000070` (STATUS_INVALID_WORKSTATION) → `0xC0000054`;
  `DuplicateObjectId` was `0xC0000042` (STATUS_INVALID_PORT_HANDLE) →
  `0xC000022A`; `PIPE_EMPTY` was `0xC0000050` (STATUS_EA_TOO_LARGE) →
  `0xC00000D9`. New named variants replace the raw literals so this
  class of bug cannot silently recur.
- **0-byte READ killed the connection.** The `ReadResponse` encoder
  asserted `!buffer.is_empty()` and the wire encoder returned empty,
  terminating the connection — a 0-byte READ (Length=0) is legal
  (torture `zerobyteread`) and now returns `OK` + 0 bytes before the
  lock-conflict check.
- **`CHANGE_NOTIFY` no longer hangs or dies with the session** (S1,
  session lifecycle). Six server fixes, all verified against smbtorture
  4.19.5 (`smb2.notify` no longer stalls the nightly; `close`, `logoff`,
  `session-reconnect`, `tdis1` now pass): CLOSE of a handle cancels
  only that handle's watch with `STATUS_NOTIFY_CLEANUP`; pre-interim
  CANCEL (mid=0) cancels the newest pending op; TDIS/LOGOFF complete
  pending watches; durable reconnect re-binds watches; deleting the
  watched directory completes the watch; CLOSE-cleanup no longer
  self-deadlocks.
- **TREE_DISCONNECT of an already-disconnected tree returned
  `ACCESS_DENIED`** (was `NETWORK_NAME_DELETED`, MS-SMB2 3.3.5.9;
  torture `connect.c:234`). `smb2.connect` now passes fully.
- **Second LOGOFF returned `OK`** (was `USER_SESSION_DELETED`,
  MS-SMB2 3.3.5.6; torture `connect.c:248`).

## [0.1.5] - 2026-10-21

### Added

- **Per-share atomic publish-on-close (`publish_on_close`, default `false`).**
  New files on shares with the option enabled are written under a hidden
  temp name (`.rssmb-tmp.<final-name>.<8 hex>`, same directory) and atomically
  renamed to the final name when the last SMB handle closes. SMB clients
  observe the final name throughout (CREATE by name, QUERY_DIRECTORY,
  QUERY_INFO, rename, delete, CHANGE_NOTIFY, case-insensitive lookup all go
  through a single VFS resolution hook); only the backing filesystem sees the
  temp name. Fixes host-side consumers (watchers, ingest pipelines, backups)
  reading a pre-sized file with zero data while a client is still writing.
  Covers CREATE / OPEN_IF-when-creating / OVERWRITE_IF / SUPERSEDE on regular
  files; plain OPEN of an existing file is untouched (deliberate). Durable
  handles carry the pending entry (reconnect resumes it; durable expiry
  publishes as a close). Crash orphans (`.rssmb-tmp.*`, no map entry, older
  than 1 h) are removed at share startup and by a 10-minute sweep in the
  server sweeper.

## [0.1.4] - 2026-10-20

### Added

- **Leases: smbtorture smb2.lease 28/36** (was 3/36 at v0.1.3;
  Samba 4.19.5 reference: 34/36). Deferred CREATEs now pend as
  STATUS_PENDING and complete on lease-break ACK or the 35 s timeout
  (L1), and lease/oplock grant rules match Samba's — upgrades grant only
  the requested level per the current-open context, overwrite/truncate
  breaks to NONE, rename and sharing violations break only handle caching,
  stepped re-breaks keep read caching while write/handle caching is held
  (L2). Remaining 8 failures tracked in `tests/conformance/results.md`
  (L1.1 rename_wait intermittent, L2.1 ACK_REQUIRED, L2.2 v2 epoch).
- **Durable handles v2/v1 conformance — smb2.durable-v2-open 14/15**
  (was 0/15; smbtorture 4.19.5). DHnQ/DHnC v1 contexts are parsed alongside
  DH2Q/DH2C; reconnects look up the durable open by the persistent file id
  (Samba's model), verify the CreateGuid for v2, and honor orphan gating — a
  durable only reconnects after its owning connection dropped. Durable
  opens survive metadata changes, multiple reconnect cycles, and
  PreviousSessionId session reconnects (old session torn down; its traffic
  then fails with USER_SESSION_DELETED, mirroring Samba). Lease-backed
  durables validate the lease key and are scoped to the client GUID.
- Background durable sweeper task: expired orphaned durables are evicted
  (VFS handles closed) without waiting for client traffic to touch the
  table; a live connection's durable never expires — the timeout counts
  from the disconnect.

### Fixed

- **Cargo builds with `-D warnings` failed** (the setting CI uses): 21
  clippy lints (needless clones, ignored `Result`s, unit-assert
  comparisons) and one tokio `set_times` shadowing in the vfs. No
  behavior changes intended; the rustls-webpki 0.103.16 bump is for
  RUSTSEC-2026-0382.
- **CREATE responses reported wrong create_action and file attributes.**
  Every open answered `create_action=Opened`; created files now correctly
  report Created, superseded files Superseded, overwritten files
  Overwritten (the VFS create now reports the action). New files reported
  FILE_ATTRIBUTE_ARCHIVE|NORMAL; NORMAL is now only set when no other
  attribute applies (MS-FSCC). Side effect: smb2.create 5/12 → 6/11,
  smb2.lease 3/36 → 8/31 (assertions on those fields), smb2.session
  44/22 → 46/20.
- **Concurrent v1 durable opens corrupted each other.** All DHnQ durables
  shared one zero-GUID table key, so a second v1 open evicted the first
  and closed its file handle mid-session (Linux cifs clients request a v1
  durable on every SMB 2.1 open). v1 durables are keyed by their SMB
  persistent file id, matching Samba.
- **A durable open's VFS handle could be closed while still in use** when
  the durable timeout elapsed on a live connection; the timeout now starts
  at disconnect (Samba: disconnect_time), not at open.
- **Strict CREATE parsing rejected legitimate durable-reconnect requests.**
  Unknown OplockLevel / ImpersonationLevel / CreateDisposition wire values
  failed the whole request decode; these fields are advisory and ignored
  on reconnects (MS-SMB2 3.3.5.9.12), so they now parse leniently.

## [0.1.3] - 2026-10-18

### Changed

- **READ throughput: requests are dispatched concurrently.** Independent
  READ and ECHO requests now run in per-request tasks (bounded by the credit
  window), responses are encrypted in place, and full-size reads use
  positional `pread` on pooled buffers — no per-handle lock across the disk
  read and no per-read 1 MiB zeroed allocation. Measured (Linux CIFS 3.1.1,
  sealed, 1 MiB, direct, iodepth 16): 391 → ~550 MiB/s; iodepth 4:
  333 → ~889 MiB/s; unsealed iodepth 16: ~775 → ~1533 MiB/s. Compound
  requests and related-operation chains stay strictly sequential; response
  ordering is unchanged (out-of-order only for independent requests, which
  MS-SMB2 permits). The read-path profile and flamegraphs live in
  `tests/perf/`.

### Fixed

- **smbtorture nightly job failed every suite with
  NT_STATUS_OBJECT_NAME_NOT_FOUND.** The harness passed an empty host into
  the share UNC (environment variables were never exported to the job), and
  `--option=torture:port` is ignored by smbtorture 4.19.5 — the suite always
  dialed port 445. The harness now validates RSSMB_HOST/PORT/SHARE, uses the
  real `-p/--smb-ports` flag, and records per-subtest results; a baseline
  against 0.1.2 is committed at `tests/conformance/results.md`
  (115 passing / 190 failing subtests, with names).

### Documentation

- Features and roadmap now match the smbtorture baseline; durable handles v2
  and leases are marked partial with links to the conformance results, and
  the README gains a "Conformance status" section (115/305, four largest
  gaps listed).

## [0.1.2] - 2026-10-18

### Fixed

- **Full-size WRITE requests dropped the connection.** The server advertised MaxWriteSize = 1 MiB but rejected any frame larger than `max_frame_size` (1 MiB), so a compliant client's 1 MiB WRITE (payload + SMB2/WRITE/transform headers) was treated as oversized and the connection closed. The wire limit now allows fixed header headroom above `max_frame_size`, and the advertised I/O sizes are derived from `max_frame_size`.
- **QUERY_DIRECTORY rejected FileDirectoryInformation and FileNamesInformation.** The protocol enum for FileInformationClass used wrong MS-FSCC §2.4 codes (`FileDirectoryInformation` = 2 instead of 1, `FileFullDirectoryInformation` = 14 instead of 2) and had no `FileNamesInformation` (12). Requests with class 1 or 12 failed to decode and were answered with STATUS_INVALID_PARAMETER, which broke directory listing for go-smb2 / rclone. The response encoders were already keyed on the correct codes and are unchanged.
- **QUERY_DIRECTORY with an unsupported FileInformationClass returned STATUS_INVALID_PARAMETER.** MS-SMB2 3.3.5.18 requires STATUS_INVALID_INFO_CLASS. The class byte is now decoded raw, so any non-directory class (e.g. 14 = FilePositionInformation, or undefined values) reaches the handler and gets STATUS_INVALID_INFO_CLASS.
- **NetrShareEnum / NetrShareGetInfo sent a NULL remark pointer for shares without a comment.** Legal NDR, but go-smb2 (as bundled in rclone ≤ 1.75) reads a remark for every entry and failed share listing with "broken net share enum response format". Empty comments are now sent as the empty string, as Samba and Windows do. Referent IDs are now distinct (0x00020000, +4) instead of all 1.
- **NetrShareEnum wrote deferred strings in the wrong order, scrambling share names and comments.** All netnames were emitted before all remarks, but NDR (C706 §14.3.12.3) requires each element's pointees in element order (`name[0], remark[0], name[1], …`). As soon as any share had a comment, clients paired names and comments wrongly (smbclient `-L` showed `private` with comment `public`). The reply is now byte-identical to Samba's for the same share set.
- **NetrShareGetInfo reply had an extra leading `Level` field.** The `[out] LPSHARE_INFO InfoStruct` union is marshalled as discriminant + arm (MS-SRVS 3.1.4.10); rssmb wrote `Level` and then the discriminant, shifting every following field by 4 bytes. Strict NDR clients (e.g. impacket `hNetrShareGetInfo`) failed to parse the reply. It is now byte-identical to Samba's. The request parser also expected a referent ID before `NetName`, which is a top-level `[ref]` pointer with no wire representation (C706 §14.3.11.1), so real clients' requests were misread and answered with `ERROR_INVALID_LEVEL`.
- **SPNEGO first-leg negTokenResp omitted `negState` and `supportedMech`.** RFC 4178 §4.2.2 requires both on the acceptor's first response. Strict clients (go-smb2 / rclone, Windows) rejected session setup with "server selected an unsupported mechanism"; smbclient and Linux CIFS tolerated the omission. Added an rclone (go-smb2) interop job to Interop CI that runs on every push and pull request to `main`, so a strict SPNEGO client now gates PRs.

## [0.1.1] - 2026-10-18

### Fixed

- **WRITE acknowledged before data reached the file.** `write_at` returned as
  soon as tokio had buffered the data, while the actual `write(2)` still ran in
  the background. A follow-up QUERY_INFO, CLOSE or re-open could observe the
  old file size or contents, and write errors (e.g. disk full) were silently
  lost after the client had already been told the write succeeded. Writes now
  complete (without fsync) before the WRITE response is sent.

## [0.1.0] - 2026-10-17

First public release. SMB 2.1 – 3.1.1 server with NTLMv2 auth, AES-128-GCM
encryption, durable handles v2, file leases v1/v2 + traditional oplocks,
multichannel, SMB over QUIC, and SrvSvc share enumeration.

Release artifacts: static musl binaries for `x86_64` and `aarch64` Linux,
and a multi-arch `FROM scratch` image at `ghcr.io/treeol/rssmb`.

### Added

#### Phase 0 — Fix What's Broken
- SET_INFO InfoType decode fix (was `#[br(temp)]`, discarded before use)
- Signing test timing fix (cancellation race)
- Safe config defaults
- Stale docs cleanup

#### Phase 1 — Security Gate
- **1.1** Path confinement via cap-std (openat2/RESOLVE_BENEATH, TOCTOU-free)
- **1.2** Name validation (NFC normalization, control/reserved chars, length limits)
- **1.3** NT hash precomputed at startup, `IdentityStore`, redacted `Debug`, CLI subcommands
- **1.4** Auth failure throttling (per-IP exponential backoff + hard cooldown)
- **1.5** MessageId sequence window (bounded `HashSet`, overflow-safe arithmetic)
- **1.6+1.7** Idle timeout (900s default), global + per-IP connection limits, health bind to 127.0.0.1
- **1.8** NTLM AUTHENTICATE message MIC verification, MsvAvTimestamp anti-replay

#### Phase 2 — Data Integrity
- **2.1** Share-mode conflict enforcement (bidirectional, MS-SMB2 3.3.5.15)
- **2.2** Delete-on-close at last close (persistent across OpenTable entry removal)
- **2.3** Byte-range locks (mandatory locking, all-or-nothing batch, overflow-safe overlap)
- **2.4** FLUSH durability (errors propagated, not silently logged)
- **2.5** Case-insensitive lookup (NFC-aware, ambiguous-match safety)
- **2.6** Close error propagation (delete-on-close unlink errors surfaced)
- **2.7** Per-handle async locks (RwLock<HashMap<Arc<Mutex<FileHandle>>>>)
- **2.8** FileBasicInfo attributes (READONLY → owner write bit)

#### Phase 3 — High-Priority Features
- **3.2** CHANGE_NOTIFY (inotify-based directory watching, FILE_NOTIFY_INFORMATION)
- **3.3** Durable handles v2 (DH2Q/DH2C, CreateGuid-keyed, background sweeper)
- **3.4** Security descriptors (self-relative SD synthesis from POSIX uid/gid/mode)
- **3.5** Streams + FS info (FileStreamInformation, statvfs, stable volume serial)
- **3.6** Large MTU (1 MiB, multi-credit safe via sequence window)

#### Phase 4 — Per-Share Access Lists
- `read_users` / `write_users` on `ShareConfig`
- TREE_CONNECT gate, CREATE/WRITE/SET_INFO enforcement
- DH2C reconnect checks `write_access`

#### Phase 5 — Operations
- **5.1** Config: `deny_unknown_fields`, extended `validate()`, `validate_paths()`, `warnings()`
- **5.2** Lifecycle: race-free `ShutdownSignal`, `JoinSet` graceful drain, SIGHUP live reload
- **5.3** Audit logging (`rssmb::audit` target), `--log-format json`, hex preview at `trace!`
- **5.4** Prometheus metrics on `/metrics`
- **5.5** Hardened systemd unit, Docker `read_only` + `tmpfs`

#### Phase 6 — Assurance
- **6.1** `cargo deny` + `cargo audit` in CI, Dependabot for Cargo + GitHub Actions
- **6.2** Expanded smbtorture conformance suites
- **6.3** New fuzz targets: `normalize_path`, `ntlm_authenticate`, `decrypt_transform`
- **6.4** Property tests (credit window, share-mode/lock matrix, path normalization), load + chaos scripts
- **6.5** `SECURITY.md`, `CHANGELOG.md`, threat model, external security review (pending)

### Changed
- `rust-toolchain.toml` → `stable` (was `1.78`)
- `MAX_IO_SIZE` raised from 64 KiB to 1 MiB
- `RUST_LOG=info` default in compose (was `debug`)