# Changelog

All notable changes to RSSMB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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