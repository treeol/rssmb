# RSSMB — Rust SMB Server for Dynamic Container Environments

## Goal

A pure-Rust SMB2/3 **server** designed for dynamic deployment in Docker/Swarm/Kubernetes.
Leverages Rust's memory safety for a robust, exploit-resistant file-sharing server.
Builds on the wire-protocol knowledge from `smb-rs/` (the client implementation in
this repo) but implements the server half from scratch.

## What exists: `smb-rs/` assessment

`smb-rs` is a **client-only application** — it connects *to* SMB servers and performs
file operations. No listener, session acceptor, share dispatch, or handle table exists.

However, the **wire message crate** (`smb-msg`) is not client-only. It has explicit
`server` and `both` feature flags, and the derive macros (`smb-msg-derive`) flip
`BinRead`↔`BinWrite` based on role: with `feature = "server"`, request structures
gain `BinRead` (server decodes incoming) and response structures gain `BinWrite`
(server encodes outgoing). Server-specific message fields are gated behind
`#[cfg(feature = "server")]` in `info/set.rs`, `ioctl/msg.rs`, `ioctl/fsctl.rs`,
`dfsc.rs`, `smb1.rs`, and `test.rs`.

Other crates: `smb-dtyp` (shared types), `smb-fscc` (FS control codes), `smb-rpc`
(DCE/RPC) are protocol-level definitions usable by both client and server.
`smb-transport` is client-only. `smb` (high-level API) is client-only.

Additionally, the `sspi` crate (used by `smb-rs` for client auth) **does** implement
the NTLM acceptor side — `accept_security_context` with `CredentialUse::Inbound` on
the `Ntlm` struct — with documented examples of the server-side handshake loop.

### Reuse decision (revised after audit + Mashūra review)

| Component | Reuse? | Rationale |
|---|---|---|
| Wire messages (`smb-msg`) | **Yes — depend with `server` feature** | Already has server-direction codec. Derive macros flip read/write by role. Server-specific fields exist. Pin by git revision. |
| Shared types (`smb-dtyp`) | **Yes** | GUID, SID, security descriptors, bitfields — protocol-level, role-agnostic. |
| FS control codes (`smb-fscc`) | **Yes** | Info classes, access masks — protocol-level, role-agnostic. |
| DCE/RPC (`smb-rpc`) | **Yes — extend for server-side** | Provides NDR encoding. Server-side dispatch is missing but the PDU/NDR types are reusable. |
| Derive macros (`smb-msg-derive`, `smb-dtyp-derive`) | **Yes (transitive)** | Required by `smb-msg` and `smb-dtyp`. |
| Transport (`smb-transport`) | **No** | Client-only `connect()`. Server needs its own listener. |
| Client API (`smb`) | **No** | Entirely client-side logic. |
| `smb-rs` CLI | **Yes — as interop test client** | Run their client against our server to validate wire compatibility. |
| `sspi` crate | **Yes — for NTLM acceptor** | Implements `accept_security_context` on `Ntlm` with `CredentialUse::Inbound`. |
| Test harness (Samba container) | **Yes — reuse approach** | Samba client + `smb-rs` client for interop testing. |

**Reuse feasibility gate (Phase 0 task):** Before committing to the dependency,
compile `smb-msg` with `--features server --no-default-features`, run its test suite,
and audit for: compound-message offset handling, unknown negotiate context handling,
error response construction paths, frame-length allocation bounds, and
`ResponseContent::associated_cmd()` panic paths. If the audit reveals unfixable
deficiencies, fall back to a vendored fork with targeted patches.

## Architecture

### Crate structure

```
rssmb/                          # workspace root
  Cargo.toml                    # workspace manifest, resolver 2
  crates/
    rssmb-server/               # core server: connection engine, session state,
                                #   tree dispatch, open table, handle management,
                                #   credit tracking, compound/async scheduling,
                                #   signing, encryption, oplock/lease engine
    rssmb-wire-adapter/         # thin adapter over smb-msg (server feature),
                                #   adds server-side validation, bounds checking,
                                #   error response construction, framing
    rssmb-auth/                 # authentication: NTLM acceptor via sspi,
                                #   SPNEGO/GSS token wrapping (ASN.1 DER),
                                #   credential store, session key export
    rssmb-vfs/                  # VFS trait + backends: LocalFs, MemoryFs
                                #   share-root confinement, handle-based ops,
                                #   case-insensitive lookup, path normalization
    rssmb-rpc-server/           # DCE/RPC server-side: SrvSvc share enum,
                                #   bind/alter/await, fragmentation/reassembly,
                                #   IPC$ named pipe dispatch
    rssmb-cli/                  # server binary: config, CLI args, signals,
                                #   health endpoint, metrics
    rssmb-tests/                # integration test harness, interop tests,
                                #   fuzz targets
  docker/
    Dockerfile                  # multi-stage build → minimal runtime image
    docker-compose.yml          # dev + test: Samba client, smb-rs client, our server
  config/
    rssmb.toml.example          # example config: shares, auth, listen, dialects
  .github/
    workflows/
      ci.yml                    # fmt, clippy, test (unit + interop), build, fuzz
  fuzz/                         # cargo-fuzz targets for wire codec
```

### Dependency graph

```
rssmb-wire-adapter  → smb-msg (server), smb-dtyp, smb-fscc
rssmb-auth          → sspi, rssmb-wire-adapter
rssmb-vfs           → smb-dtyp, smb-fscc, tokio
rssmb-rpc-server    → smb-rpc (or extend), rssmb-wire-adapter
rssmb-server        → rssmb-wire-adapter, rssmb-auth, rssmb-vfs,
                      rssmb-rpc-server, smb-msg
rssmb-cli           → rssmb-server, rssmb-vfs
rssmb-tests         → rssmb-server, rssmb-vfs (dev-dep)
```

### External dependencies

- `tokio` — async runtime (sole runtime; no sync/async duality)
- `bytes` — zero-copy buffer management
- `sspi` — NTLM acceptor (existing crate, proven)
- `aes` + `aes-gcm` + `ccm` — encryption (SMB 3.0+)
- `hmac` + `sha2` + `cmac` — signing (HMAC-SHA256 2.x, AES-CMAC 3.0, AES-GMAC 3.1.1)
- `md-5` — NTLMv2 HMAC-MD5 (NTLM internals via sspi, but may be needed for key exchange)
- `rand` — nonces, session IDs
- `toml` — config
- `clap` — CLI
- `tracing` — structured logging
- `thiserror` — error types
- `notify` — filesystem change notifications for CHANGE_NOTIFY (inotify backend)
- `async-trait` — async trait objects for Vfs/Authenticator (object-safe)

Note: `binrw`, `modular-bitfield` come transitively via `smb-msg`/`smb-dtyp` —
we don't use them directly.

### Key design decisions (revised)

**1. Async-only, with concurrent connection engine.**
`tokio` as sole runtime. The connection loop is NOT sequential
"dispatch → await → respond." Each connection runs:
- A **read task** that frames incoming messages, validates message IDs/credits,
  and dispatches to a handler.
- A **write task** that serializes outgoing messages (responses, async interims,
  unsolicited oplock/lease breaks, notifications) through a channel.
- Handlers run as spawned tasks; the write task multiplexes results in order.
This allows STATUS_PENDING, cancellation, and server-initiated breaks without deadlock.

**2. Wire codec: reuse smb-msg behind adapter.**
`smb-msg` with `server` feature provides BinRead for requests, BinWrite for
responses. The `rssmb-wire-adapter` crate wraps this with:
- Frame-level parsing: recognize `\xfeSMB` (plain), `\xfdSMB` (transform/encrypt),
  `\xfcSMB` (compress) headers at the framing layer — before dispatch.
- Bounds checking: cap NetBIOS/SMB frame length (24-bit field, set server max ~1MB).
- Compound/related request chaining (NextCommand offsets, FileId = 0xFFFFFFFFFFFFFFFF).
- Credit tracking: grant/charge per MS-SMB2 §3.2 and §3.3.
- Error response construction that avoids `associated_cmd()` panic paths.
- Unknown negotiate context skipping (forward-compatible per MS-SMB2).
- Original byte preservation for preauth integrity hash chain (do not re-encode).

**3. Authentication: multi-round acceptor conversation.**
Not `authenticate(credentials) -> Identity`. Instead:
```rust
#[async_trait]
trait AuthProvider: Send + Sync {
    async fn step(&self, input_token: &[u8], state: &mut AuthState)
        -> AuthStep;
}
enum AuthStep {
    Continue { output_token: Vec<u8> },
    Complete { output_token: Vec<u8>, identity: Identity,
               session_key: Vec<u8>, flags: AuthFlags },
    Reject { reason: AuthError },
}
```
- SPNEGO/GSS token wrapping (ASN.1 DER) — Windows clients wrap NTLMSSP in SPNEGO.
- `sspi` Ntlm acceptor for the NTLM mechanism (verify sspi version compatibility in Phase 0).
- Credential store: username + NT hash, loaded from config (secrets, not ConfigMap).
- Session key exported for signing/encryption key derivation.
- Auth rate limiting, challenge lifetime, MIC validation, NTLMv1 rejection.

**4. VFS: handle-centric, not path-centric.**
```rust
#[async_trait]
trait Vfs: Send + Sync {
    // Open/create returns an Open handle, not a path-based result
    async fn create(&self, share: &str, path: &str, args: &CreateArgs,
                    identity: &Identity) -> Result<OpenId>;
    async fn read_at(&self, open: OpenId, offset: u64, len: u32) -> Result<Bytes>;
    async fn write_at(&self, open: OpenId, offset: u64, data: &[u8]) -> Result<u32>;
    async fn close(&self, open: OpenId) -> Result<()>;
    async fn flush(&self, open: OpenId) -> Result<()>;
    async fn lock(&self, open: OpenId, range: LockRange, exclusive: bool) -> Result<()>;
    async fn unlock(&self, open: OpenId, range: LockRange) -> Result<()>;
    // Directory enumeration is handle-based, stateful, with cursor
    async fn query_dir(&self, open: OpenId, pattern: &str, class: DirInfoClass,
                       restart: bool, max_results: usize) -> Result<Vec<DirEntry>>;
    async fn query_info(&self, open: OpenId, class: InfoClass) -> Result<FileInfo>;
    async fn set_info(&self, open: OpenId, class: InfoClass, info: &FileInfo) -> Result<()>;
    async fn notify(&self, open: OpenId, filter: NotifyFilter) -> Result<NotifyStream>;
    async fn ioctl(&self, open: OpenId, ctl: FsCtlCode, input: &[u8]) -> Result<Vec<u8>>;
    // File identity for cross-session open tracking
    async fn file_id(&self, open: OpenId) -> Result<FileId>;
}
```
Key VFS contract requirements:
- **Share-root confinement**: `LocalFs` must prevent path traversal (symlinks, `..`,
  absolute paths). Use `openat`-style relative operations where possible; canonicalize
  and verify containment; test against symlink races.
- **Case-insensitive lookup**: Windows clients expect case-insensitive paths.
  `LocalFs` on Linux needs a case-folding strategy (scan+compare, or build an index).
- **Path normalization**: `\` separators, UTF-16→UTF-8 conversion, trailing slashes.
- **Open semantics**: disposition (supersede/open/open-if/overwrite/overwrite-if),
  share access (read/write/delete sharing), create options, delete-on-close.
- **File identity**: stable ID across rename/hardlinks for cross-session open tracking.
- **Alternate data streams**: `file:stream` — MVP: reject or return not-supported.
- **Authorization**: server enforces access mask checks before VFS calls;
  VFS backends do not re-authorize.
- **Bounded results**: `query_dir` returns at most `max_results`; caller requests more.
  Server holds enumeration cursor on the open handle for resume.

**5. Open table: global, keyed by file identity.**
Not per-session. A global `OpenTable` tracks all opens across all sessions:
- File identity → list of opens (for share-mode conflict detection).
- Share access mode (read/write/delete) per open → enforce sharing violations on CREATE.
- Byte-range locks per file identity → enforce across sessions.
- Oplock/lease state per file identity → (Phase 6) track break/ack.
- Delete-on-close pending flag → block new opens when set.

**6. Dialect negotiation: conservative advertisement.**
Only advertise capabilities we have implemented. Per phase:
- Phase 1: SMB 2.1 (signing via HMAC-SHA256). No encryption, no leasing, no multichannel.
- Phase 2: add 3.0/3.1.1 with signing (AES-CMAC/GMAC), preauth integrity, encryption.
- Phase 6: add leasing/directory leasing caps.
- Never advertise what we can't honor (clients act on advertised caps).
- `FSCTL_VALIDATE_NEGOTIATE_INFO` must be implemented for 3.0+ (Windows disconnects).
- SMB1 `\xffSMB` multi-protocol negotiate: respond with 0x02FF wildcard or close.

**7. Signing and encryption: integrated with session establishment.**
- Signing: HMAC-SHA256 (2.x), AES-CMAC (3.0), AES-GMAC (3.1.1).
- Key derivation: SP800-108 counter-mode HMAC-SHA256 (3.0/3.0.2/3.1.1), with
  dialect-specific labels and contexts (verify against MS-SMB2 §3.1.4 and §3.2.5).
- Preauth integrity: SHA-512 hash chain over original negotiate + session setup
  bytes (3.1.1). Preserve original wire bytes; do not re-encode.
- Encryption: AES-128/256-CCM and GCM (3.0+), directional keys, nonce management.
- All of this is in Phase 2 (secure sessions), NOT deferred to a later phase.
- Guest sessions: signing not applicable; document the policy — guest sessions
  use no signing; non-guest sessions require signing when `signing = required`.
- Config: `signing = required | desired | disabled`, `encryption = required | desired | disabled`.
- Default: `signing = required`, `encryption = desired` (for 3.0+).

**8. Oplocks/leases: design early, grant late.**
- Phase 3: no oplock/lease grants (return no oplock in CREATE response). This is
  a valid conservative choice — clients fall back to no caching.
- Phase 6: implement oplock (Batch/Level1/Level2) and lease grant/break/ack.
- Lease tracking is per file identity, not per handle (multiple opens share a lease).
- Before granting: implement conflict detection, pending break queue,
  outbound break sending (via the connection's write task), ack processing,
  timeouts, and disconnect cleanup.

**9. Container-native design.**
- **Single replica per share** (MVP). Multiple replicas on RWX PVC would break
  oplocks/leases/byte-range locks. Document this as an explicit MVP restriction.
- Config via file (`rssmb.toml`) + env var overrides (`RSSMB_*`).
  NT hashes in k8s Secrets (mounted as files), not ConfigMap or env.
- Signal handling: SIGTERM/SIGINT → graceful drain (refuse new sessions,
  send disconnect to existing sessions, cancel outstanding ops, close connections).
  No protocol-level witness notification in MVP — clients see I/O errors on restart.
  Document this as a known limitation.
- Health: dedicated HTTP endpoint on a separate port (not TCP on 445) for
  liveness (is the server alive) and readiness (are shares/auth/storage initialized).
- Metrics: Prometheus endpoint (connection count, auth success/failure,
  ops/sec, latency, error rates).
- Config hot-reload: SIGHUP → reload share definitions (from ConfigMap mount).
- Port 445: either `NET_BIND_SERVICE` capability, `net.ipv4.ip_unprivileged_port_start`,
  or k8s Service port mapping. State which in deployment docs.
- UID/GID mapping: all writes happen as container UID; document identity→UID mapping.
- Multi-stage Dockerfile: build → distroless or alpine runtime, non-root user.
- K8s examples: Deployment (replicas: 1), Service, ConfigMap (shares), Secret (auth).
- Restart semantics: every restart is a disruptive event for connected clients.
  cifs.ko reconnects sessions but reopens files only with durable handles (Phase 8).
  MVP: clients must remount after restart. Document clearly.

## Implementation phases (revised)

### Phase 0 — Feasibility gate + workspace setup
- [ ] Cargo workspace, crate skeletons, CI pipeline (fmt/clippy/build)
- [ ] **Feasibility gate**: compile `smb-msg --features server --no-default-features`,
      run its tests, audit for: compound offset handling, unknown negotiate contexts,
      error response paths, frame length allocation bounds, `associated_cmd()` panics.
      Decision: depend / vendor-and-patch / re-implement. Record decision.
- [ ] **sspi acceptor prototype**: write a small test that runs `sspi`'s NTLM
      `accept_security_context` with `CredentialUse::Inbound`. Confirm it works
      with the pinned version. Record decision.
- [ ] **Client/dialect/backend matrix**: document target client matrix
      (smb-rs client, Linux cifs.ko with `vers=2.1` and `vers=3.1.1`,
      Samba smbclient, Windows 11 24H2 if available). Record dialects and features
      to advertise per phase.
- [ ] Docker dev environment (Rust toolchain + Samba client container + smb-rs)
- [ ] `rssmb-cli` skeleton (minimal binary that starts/stops, binds no port yet)

### Phase 1 — Transport + connection engine
- [ ] `rssmb-wire-adapter`: framing layer — recognize `\xfeSMB` (plain),
      `\xfdSMB` (transform), `\xfcSMB` (compress) at frame level
- [ ] TCP listener on 445, accept loop, per-connection task
- [ ] Connection engine: read task (frame → validate message ID/credits → dispatch),
      write task (channel → serialize → send), handler spawn
- [ ] Credit tracking: grant/charge per MS-SMB2
- [ ] Compound/related request chaining (NextCommand, related flag, FileId placeholder)
- [ ] STATUS_PENDING + AsyncId support (async responses)
- [ ] Cancel handling (match pending message IDs)
- [ ] LOGOFF + disconnect cleanup
- [ ] Message-ID validation and windowing
- [ ] Frame length cap (reject oversized NetBIOS/SMB frames — DoS prevention)
- [ ] Negotiate responder: dialect selection, capabilities, 3.1.1 contexts
      (preauth integrity, encryption, transport, netname, signing)
      — advertise only what we support per phase
- [ ] SMB1 multi-protocol negotiate handling (`\xffSMB` → 0x02FF or close)
- [ ] `rssmb-cli`: bind 445, accept, negotiate (responds to negotiate only)
- [ ] Integration test: `smb-rs` client connects and negotiates successfully

### Phase 2 — Secure session establishment (auth + signing + crypto)
- [ ] `rssmb-auth`: SPNEGO/GSS ASN.1 DER token parsing (negTokenInit/negTokenResp)
- [ ] `rssmb-auth`: NTLM acceptor via `sspi` (Type 1 → Type 2 → Type 3 handshake)
      using `accept_security_context` with `CredentialUse::Inbound`
- [ ] Session setup responder: multi-round (STATUS_MORE_PROCESSING_REQUIRED),
      bind auth to SMB session, export session key
- [ ] Credential store: username + NT hash from config file (secrets)
- [ ] Guest authentication (no signing for guest sessions — explicit policy)
- [ ] Auth rate limiting, challenge lifetime, MIC validation, NTLMv1 rejection
- [ ] **Signing**: HMAC-SHA256 (2.x), AES-CMAC (3.0), AES-GMAC (3.1.1)
- [ ] **Key derivation**: SP800-108 counter-mode HMAC-SHA256
      (verify labels/contexts against MS-SMB2 §3.1.4/§3.2.5)
- [ ] **Preauth integrity**: SHA-512 hash chain over original negotiate +
      session setup bytes (3.1.1). Preserve original wire bytes.
- [ ] **Encryption**: AES-128/256-CCM and GCM, directional keys, nonce management
- [ ] Config: `signing = required|desired|disabled`, `encryption = required|desired|disabled`
- [ ] FSCTL_VALIDATE_NEGOTIATE_INFO responder (3.0+)
- [ ] Integration tests:
  - `smb-rs` client authenticates (NTLM) and establishes a signed session
  - Tampered-signature rejection test
  - Encrypted session test (3.1.1)
  - Auth failure tests (bad password, disabled account)
  - Guest auth test (with signing policy documented)

### Phase 3 — Core file serving (tree connect + create + I/O + metadata)
- [ ] `rssmb-vfs`: `Vfs` trait (handle-centric, as specified above)
- [ ] `rssmb-vfs`: `LocalFs` backend (tokio::fs, share-root confinement, symlink guard)
- [ ] `rssmb-vfs`: `MemoryFs` backend (for tests)
- [ ] Case-insensitive path lookup strategy for `LocalFs`
- [ ] Tree connect/disconnect responder: share lookup, permission check, IPC$
- [ ] Global open table: file-identity-keyed, share-mode tracking, conflict detection
- [ ] CREATE responder: disposition, share access, create options, desired access,
      delete-on-close, no oplock/lease grant (conservative MVP)
- [ ] Create contexts: skip unknown ones (forward-compatible), handle known ones
      (SecD, AlSi, QFid, MxAc — at minimum skip; implement as needed)
- [ ] READ responder: buffered read at offset
- [ ] WRITE responder: buffered write at offset
- [ ] CLOSE responder: handle cleanup, delete-on-close execution
- [ ] FLUSH responder
- [ ] LOCK/UNLOCK responder: byte-range locks (global table, cross-session)
- [ ] QUERY_INFO: file info, FS info (FileFsAttributeInformation,
      FileFsVolumeInformation, FileFsSizeInformation — needed immediately by
      Windows clients after tree connect), security descriptor
- [ ] SET_INFO responder
- [ ] QUERY_DIRECTORY: handle-based, stateful enumeration with cursor,
      wildcard pattern matching, restart/resume
- [ ] CHANGE_NOTIFY: filesystem notifications via `notify` crate (inotify backend)
- [ ] IOCTL: FSCTL_* handlers (sparse, reparse — return not-supported for MVP;
      implement list_directory, query_allocation, etc. as needed)
- [ ] `rssmb-fscc`: import/extend info class coverage from smb-fscc
- [ ] Authorization: access mask enforcement before VFS calls
- [ ] `rssmb-cli`: config file parsing (shares, auth, listen, dialects), env overrides
- [ ] Integration tests:
  - `smb-rs` client: connect to share, create, read, write, close
  - `smb-rs` CLI `info`: list shares, file/dir info, quota
  - `smb-rs` CLI `copy`: local↔remote file copy
  - Cross-client: two sessions open same file with conflicting share access → SHARING_VIOLATION
  - Delete-on-close: file removed after last close
  - Malformed offsets/counts → proper NTSTATUS errors
  - `smbclient` (Samba): connect, list, get, put (if available in CI)
  - `mount.cifs` with `vers=3.1.1`: mount, read, write, unmount (if available in CI)

### Phase 4 — DCE/RPC server-side (share enumeration)
- [ ] `rssmb-rpc-server`: IPC$ named pipe CREATE/read/write/transceive
- [ ] RPC bind/alter context negotiation
- [ ] RPC fragmentation/reassembly
- [ ] SrvSvc: NetShareEnumAll (share listing)
- [ ] Integration test: `smb-rs` client `info` subcommand lists shares via RPC

### Phase 5 — Oplocks + leases
- [ ] Oplock engine: Batch, Level1, Level2 grant/break/ack
- [ ] Lease engine: v1/v2 lease keys, grant/break/ack
- [ ] Lease tracking: per file identity (not per handle), multi-open participation
- [ ] Conflict detection → outbound break via connection write task
- [ ] Ack processing, timeouts, disconnect cleanup
- [ ] Now advertise `SMB2_GLOBAL_CAP_LEASING` and `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`
- [ ] Integration tests: multi-client oplock/lease scenarios, break on write, break on close

### Phase 6 — Container-native + production readiness
- [ ] `rssmb-cli`: full CLI (config, args, signal handling)
- [ ] Health endpoint: HTTP on separate port (liveness + readiness)
- [ ] Metrics: Prometheus endpoint
- [ ] SIGHUP: config hot-reload (share definitions)
- [ ] Graceful drain: SIGTERM → refuse new sessions, disconnect existing,
      cancel outstanding ops, close connections
- [ ] Multi-stage Dockerfile (build → distroless/alpine, non-root)
- [ ] docker-compose: our server + Samba client + `smb-rs` client for interop
- [ ] K8s examples: Deployment (replicas: 1), Service, ConfigMap, Secret
- [ ] Connection limits (per-connection, total), resource bounds
- [ ] Audit logging: auth events, file access, admin operations → structured stdout
- [ ] Documentation: README, configuration guide, deployment guide, troubleshooting
- [ ] Performance targets: measure throughput/latency for large reads/writes

### Phase 7 — Fuzzing + conformance
- [ ] `cargo-fuzz` targets: wire codec, negotiate, session setup, create, read, write
- [ ] `smbtorture smb2.*` subsets (if available)
- [ ] Windows interop: Windows 11 24H2 (signing required by default) — `net use`,
      `copy`, `dir`, `robocopy` — if Windows test environment available
- [ ] Tampered-signature/ciphertext rejection tests
- [ ] Malformed-message fuzz: compound offsets, oversized lengths, unknown contexts
- [ ] Resource exhaustion: connection flood, handle flood, large directory

### Phase 8 — Advanced (future, post-MVP)
- [ ] Kerberos authentication acceptor (keytab-based service account)
- [ ] Durable handles + continuous availability (for graceful restart — the real
      requirement for "dynamic" k8s deployments)
- [ ] Witness protocol (server move notification, not durable handle recovery)
- [ ] Multichannel support
- [ ] DFS referrals
- [ ] QUIC transport (SMB over QUIC, port 443)
- [ ] RDMA transport
- [ ] Compression support
- [ ] S3 VFS backend
- [ ] FUSE VFS backend
- [ ] Clustered operation (coordinated opens/locks/leases across replicas)

## Interop testing strategy

1. **Unit tests**: roundtrip encode/decode for every message type using smb-msg's
   hex test vectors (import verbatim if depending on smb-msg).
2. **`smb-rs` client interop**: use the existing `smb-rs` CLI against our server.
   Note: shares protocol assumptions with us — not sufficient alone.
3. **Samba client interop**: `smbclient` and `mount.cifs` with `vers=2.1` and `vers=3.1.1`.
4. **Windows interop** (if available): Windows 11 24H2, `net use`, `copy`, `robocopy`.
   **Mandatory if Windows compatibility is a stated requirement.**
5. **smbtorture**: `smbtorture smb2.*` protocol conformance subsets.
6. **Packet capture**: `tcpdump`/Wireshark to verify on-wire byte correctness.
7. **Fuzzing**: `cargo-fuzz` for the codec and message processing paths.
8. **Negative tests**: tampered signatures, malformed frames, oversized lengths,
   auth failures, sharing violations, unknown contexts.

## MVP restrictions (explicit)

- **NTLM-only authentication.** No Kerberos/domain join. Sufficient for Linux/macOS
  clients (cifs.ko, smbclient) and standalone shares. Windows clients with
  NTLM-blocking policies (domain-joined enterprise, Win11 24H2 with strict policy)
  will not authenticate. Kerberos is Phase 8.
- **Single replica.** No clustered operation. Multiple replicas on RWX PVC would
  break oplocks/leases/byte-range locks. Document as Deployment(replicas: 1).
- **No durable handles.** Every pod restart is a disruptive event — clients
  see I/O errors and must remount. Durable handles + witness is Phase 8.
- **Guest auth limited.** Windows disables insecure guest by default (since 1709).
  Guest auth is for non-Windows clients and explicit configurations only.
- **No SMB1.** Security risk, deprecated. SMB1 multi-protocol negotiate gets
  0x02FF wildcard or connection close.
- **No compression.** Deferred to Phase 8. Compression header (`\xfcSMB`)
  recognized at framing layer but compression not applied.

## Non-goals (for MVP)

- SMB1 protocol support
- Active Directory / Kerberos realm join
- DFS root server
- QUIC/RDMA transport
- Multichannel
- Persistent/durable handles / witness protocol
- S3/FUSE VFS backends
- Clustered multi-replica operation
