# Changelog

All notable changes to RSSMB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-17

First public release. SMB 2.1 – 3.1.1 server with NTLMv2 auth, AES-128-GCM
encryption, durable handles v2, file leases v1/v2 + traditional oplocks,
multichannel, SMB over QUIC, and SrvSvc share enumeration.

## [Unreleased]

### Added — Release 1.0 Scope

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
- **6.1** `cargo deny` + `cargo audit` in CI, GitHub Actions pinned by SHA, Dependabot
- **6.2** Expanded smbtorture conformance suites
- **6.3** New fuzz targets: `normalize_path`, `ntlm_authenticate`, `decrypt_transform`
- **6.4** Property tests (credit window, share-mode/lock matrix, path normalization), load + chaos scripts
- **6.5** `SECURITY.md`, `CHANGELOG.md`, threat model, external security review (pending)

### Changed
- `rust-toolchain.toml` → `stable` (was `1.78`)
- `MAX_IO_SIZE` raised from 64 KiB to 1 MiB
- `RUST_LOG=info` default in compose (was `debug`)