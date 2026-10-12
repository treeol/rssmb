# Step 7c — SMB 3.1.1 implementation plan

Status: **spec items verified against smb-rs reference impl; Mashūra plan review pending**. Baseline: `1b80131`.

Spec verification note: the live MS-SMB2 spec on learn.microsoft.com is
JS-rendered and unreachable from the sandbox. The `[verify]` items below are
confirmed against the smb-rs reference client implementation
(`smb-rs/crates/smb/`), which is spec-derived and self-consistent. Each
verified item now carries **[verified: smb-rs]** with the file:line. Items
still unverified are marked **[unverified]**.

Goal: negotiate SMB 3.1.1 with real clients (smbclient, Linux cifs.ko, impacket,
later Windows and macOS). That needs negotiate contexts, the preauth integrity
hash, KDF contexts based on that hash, and AES-GMAC signing. Encryption itself
(TRANSFORM_HEADER) stays in 7d. 7c only negotiates and records the cipher and
derives the keys.

Spec references are MS-SMB2. Items marked **[verify]** are recalled from memory
and must be checked against the spec text before they are coded.

---

## 0. Current state (observed)

| Area | Location | State |
|---|---|---|
| Dialect ceiling | `dispatch.rs:171-179` | `IMPLEMENTED_DIALECTS` and `EFFECTIVE_MAX_DIALECT` stop at `Smb302` |
| NEGOTIATE | `dispatch.rs:662-746` | `handle_negotiate(state, conn, req)` gets no raw bytes; response has `negotiate_context_list: None` (734) |
| NegotiateRecord | `dispatch.rs:110-120` | dialect + client GUID/secmode/caps + server caps/secmode; no 3.1.1 fields |
| SESSION_SETUP | `dispatch.rs:753-990` | `provider.step` (830), MORE_PROCESSING (844), `Complete{session_key}` (848), extra mechListMIC round (861-894), session created and `compute_signing_key` called (916-939) |
| KDF | `crypto.rs:38-124` | 3.1.1 labels are right, but the context is still `SmbSign\0`/`ServerOut\0`/`ServerIn \0` (TODO) |
| Signing | `crypto.rs:133-174`, `signing.rs:50-159` | HMAC-SHA256 for 2.x, AES-CMAC for 3.x, selected by `SigningState.dialect`; no GMAC |
| Wire loop | `connection.rs:265-411` | raw payload → verify (328) → `handle_message(..., &payload)` (342) → credits → `encode_response` (383) → `sign_response_frame` (398) → send (408) |
| smb-msg | `negotiate.rs` | contexts decode; unknown context types are tolerated (`1b80131`); unknown values inside contexts (`HashAlgorithm`, `EncryptionCipher`, `SigningAlgorithmId`, `CompressionAlgorithm`, `Dialect`) still fail the whole request |
| Deps | `Cargo.toml`, `Cargo.lock` | sha2 0.10, hmac 0.12, aes 0.8, cmac 0.7, aes-gcm 0.10.3 (gives GMAC), rand 0.8; **no `ccm`** (only needed in 7d) |
| Config | `config.rs:80` | `max_dialect` already defaults to `smb311`; all live configs set `smb311` |

---

## 1. smb-msg: tolerate unknown values inside contexts

Why: the same failure class as `1b80131`. A client that offers a new cipher,
signing algorithm or hash ID would otherwise fail the whole NEGOTIATE.

- Add an `Unknown(u16)` catch-all to `HashAlgorithm`, `EncryptionCipher`,
  `SigningAlgorithmId` and `CompressionAlgorithm`, using the same magic-tagged
  pattern as `NegotiateContextType`. Keep the known variants first.
- `Dialect` in the request dialect list: decode unknown values as
  `Dialect::Unknown(u16)` (or parse the list as raw `u16` in the server
  adapter). Constraint: `Dialect` is `Ord`/`Copy` and `NegotiateRequest`
  checks `dialects.contains(&Smb0311)`, so `Unknown` must sort predictably and
  never equal a known dialect. `select_dialect` already skips unmapped values.
- Regenerate `patches/smb-rs-rssmb.patch`, document it in `patches/README.md`,
  and add wire-adapter tests: unknown cipher, signing algorithm, hash and
  dialect each decode, and the known values in the same list survive.

## 2. Negotiate context processing (server side)

New module `crates/rssmb-server/src/negotiate_ctx.rs` with pure functions, so it
is unit-testable without I/O:

```rust
pub struct Negotiated311 {
    pub preauth_hash_alg: HashAlgorithm,     // always Sha512
    pub salt: [u8; 32],                      // server salt (random)
    pub cipher: Option<EncryptionCipher>,    // chosen, for 7d; None = no encryption
    pub signing_alg: SigningAlgorithmId,     // AesGmac | AesCmac
}
pub fn process_request_contexts(req: &NegotiateRequest, cfg: &Config)
    -> Result<(Negotiated311, Vec<NegotiateContext>), NtStatus>;
```

Rules (MS-SMB2 3.3.5.4; confirmed against smb-rs `dialects.rs:169-229`):

1. **PREAUTH_INTEGRITY_CAPABILITIES**
   - Missing → `STATUS_INVALID_PARAMETER`.
   - More than one → `STATUS_INVALID_PARAMETER`.
   - `HashAlgorithmCount == 0` → `STATUS_INVALID_PARAMETER`.
   - SHA-512 not offered → `STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP` (`0xC05D0000`).
     This needs a new `NtStatus` variant in `rssmb-wire-adapter/src/error.rs`.
   - Response: one hash (SHA-512) plus a 32-byte random salt (`rand::rngs::OsRng`).
   - **[verified: smb-rs]** `preauth_hash.rs:8` confirms `SUPPORTED_ALGOS = [Sha512]`;
     `dialects.rs:198-205` rejects non-SHA512 with `NegotiationError`.
2. **ENCRYPTION_CAPABILITIES**: more than one → `STATUS_INVALID_PARAMETER`.
   **Decision for 7c:** omit the encryption context entirely. `cipher = None`.
   Do not derive encryption keys. Never set `SMB2_GLOBAL_CAP_ENCRYPTION` for
   3.1.1. **[verified: smb-rs]** `dialects.rs:36`: client cap mask never sets
   encryption for 3.1.1. `dialects.rs:208-220`: client accepts no cipher if
   server sends no encryption context and client doesn't require encryption.
3. **SIGNING_CAPABILITIES**: more than one → `STATUS_INVALID_PARAMETER`.
   **[verified: smb-rs]** `dialects.rs:183-195` — client takes the *first*
   algorithm from the server's response list. **Decision for 7c:** always use
   AES-CMAC. Do not send a SIGNING_CAPABILITIES context back. Client falls back
   to `default_signing_algo()` = `AesCmac` for 3.1.1
   (**[verified: smb-rs]** `dialects.rs:124`). If the client offers signing
   algorithms and none overlap with ours (CMAC), return
   `STATUS_INVALID_PARAMETER`.
4. **COMPRESSION_CAPABILITIES**: duplicates → `STATUS_INVALID_PARAMETER`.
   Compression is not supported, so don't respond and don't set any compression
   state.
5. **NETNAME, TRANSPORT_CAPABILITIES, RDMA_TRANSFORM, `Unknown(_)`**: ignore and
   don't respond. Never echo a context we don't act on.
6. Context count and offset sanity is already enforced by the parser. A
   NEGOTIATE that offers 3.1.1 but carries zero contexts falls under rule 1.
7. Validation runs **only if 3.1.1 is selected**. **[verified: smb-rs]**
   `dialects.rs:99-107` — context processing dispatches only on `Smb0311`.
   If the client offers 3.1.1 and we pick 3.0.2 (e.g. `max_dialect` caps it),
   ignore the contexts (current behavior).

Response: `negotiate_context_list: Some(vec![preauth, signing?])`. smb-msg's
writer aligns the context list to 8 and computes the offset; its existing
`test_response!` covers that. Add a server-side encode→decode test anyway.

## 3. NegotiateRecord and dialect gate

- `IMPLEMENTED_DIALECTS += Smb311`; `EFFECTIVE_MAX_DIALECT = Smb311`. Update
  the doc comments and the existing `select_dialect` tests that assert 3.1.1 is
  excluded.
- `NegotiateRecord` gains `neg311: Option<Negotiated311>`. It is `Some` iff the
  dialect is 3.1.1.
- `large_mtu` and `security_mode` logic stays as it is. 3.1.1 capabilities are
  the same as 3.0.2 minus encryption.
- **VALIDATE_NEGOTIATE_INFO under 3.1.1**: today it returns
  `STATUS_NOT_SUPPORTED` outside 3.0/3.0.2. **[unverified]** what MS-SMB2
  3.3.5.15.12 prescribes for 3.1.1. The smb-rs client doesn't send VNI on 3.1.1
  (preauth integrity replaces it), and Samba/cifs.ko likely don't either.
  **Decision:** keep returning `STATUS_NOT_SUPPORTED` for 3.1.1. If a client
  does send it, the error response won't be hashed (it's an error, not a
  SESSION_SETUP response), so no preauth corruption. This is the safest
  minimal behavior.

## 4. Preauth integrity hash (the core of 7c)

Definition (MS-SMB2 3.3.5.4 / 3.3.5.5; **[verified: smb-rs]**
`connection/preauth_hash.rs:20-43`, `session/setup.rs:133-170`):

```
H0 = 64 zero bytes
Conn.H = SHA512(SHA512(H0 ‖ NEGOTIATE_req) ‖ NEGOTIATE_resp)
Session.H starts as Conn.H when SESSION_SETUP has SessionId == 0 (new session)
for each SESSION_SETUP request:                  Session.H = SHA512(Session.H ‖ req)
for each SESSION_SETUP response with MORE_PROCESSING_REQUIRED:
                                                 Session.H = SHA512(Session.H ‖ resp)
final SUCCESS response: NOT hashed; keys use the Session.H that includes the final request
```

"Message" means the exact SMB2 message bytes on the wire: header plus body,
without the 4-byte NetBIOS header, and for compound members only that member's
slice. Responses are hashed **after** credits are patched and after signing,
since those are the bytes the client hashes.

### 4.1 Plumbing

- **Request bytes:** `handle_plain` already has `raw_frame`. Pass the message
  slice to `handle_negotiate` and `handle_session_setup` (new `raw: &[u8]`
  parameter). The negotiate gate runs first, so rejected pre-NEGOTIATE traffic
  is never hashed.
- **Response bytes** only exist in `connection.rs` after `encode_response` +
  `sign_response_frame`. Add to `ConnState`:

  ```rust
  pub preauth_conn: Mutex<Option<[u8; 64]>>,           // Conn.H (3.1.1 only)
  pub preauth_sessions: Mutex<HashMap<u64, [u8; 64]>>, // in-progress sessions
  ```

  The response-associated directive travels on `FramedResponse` (not on
  ConnState). After `sign_response_frame` (`connection.rs:398`), if the
  response carries a preauth-hash directive and is a single plain message, hash
  `encoded[4..]` (no NetBIOS header) into the target. Do this before the
  send. The read loop is sequential, so ordering is guaranteed. Document that
  invariant. Bind the directive to expected command/status/SessionId and
  consume it exactly once; fail closed on mismatches (review §1).
- **Hash implementation:** `crypto::preauth_update(h: &[u8;64], msg: &[u8]) -> [u8;64]`
  using `sha2::Sha512`, with unit tests.
- **Decoder-error path:** define how malformed SESSION_SETUP terminates or
  clears pending preauth state; it must not silently resume a transcript
  after an unaccounted exchange (review §1).

### 4.2 Session lifecycle

- `SessionId == 0` + 3.1.1: allocate the id (existing code) and insert
  `preauth_sessions[sid] = Conn.H`, then hash the request. On continuation
  (`pending_sessions` contains sid), hash the request into the existing entry.
- MORE_PROCESSING response → `preauth_pending = Session(sid)`.
- Success: compute keys from `preauth_sessions[sid]`, which by now includes
  the final request, then **remove** the entry. Failure or `LogonFailure`:
  remove the entry.
- **One pending auth per connection** (Mashūra review §1): `ConnState` has one
  `auth_state`. A second SESSION_SETUP while one is pending → reject. The
  preauth hash is per-session, but auth state is per-connection.
- **Compound rejection** (Mashūra review §1): reject compounds containing
  NEGOTIATE or SESSION_SETUP on a 3.1.1 connection with
  `STATUS_INVALID_PARAMETER`. This prevents the response-before-hash race.
  No real client compounds these.
- **Extra SPNEGO mechListMIC round (`dispatch.rs:861-894`):** keys are derived
  only when the STATUS_SUCCESS response is produced, not at
  `AuthStep::Complete`. If the server answers that leg with MORE_PROCESSING
  and then does another round, the 3.1.1 key uses the hash through the request
  that gets the STATUS_SUCCESS response. Add a test that sends the extra round
  and checks the key.
- Bound the size of `preauth_sessions`. It is cleared together with
  `pending_sessions`. Connection teardown drops everything. Define numeric
  limits and expiration.
- Re-authentication and session binding stay unsupported (current behavior).
  A non-zero unknown SessionId keeps being rejected and must not create a
  hash entry.
- **SESSION_SETUP inside a compound on a 3.1.1 connection: reject with
  `STATUS_INVALID_PARAMETER`** (also covers the compound race above).

## 5. KDF with preauth context

- Change the `crypto.rs` API to take the context explicitly and return `Result`:

  ```rust
  pub enum KdfContext<'a> { Legacy, Preauth(&'a [u8; 64]) }
  pub fn compute_signing_key(sk, dialect, ctx: KdfContext) -> Result<Vec<u8>, CryptoError>;
  ```

  For 3.1.1 + `Legacy` → `Err`. For 3.0.x + `Preauth` → `Err`. For 2.x, `Legacy`
  is the only valid context (and the key is the session key directly, no KDF).
  No `debug_assert` — release-enforced.
  Labels stay as they are (`SMBSigningKey\0`, `SMBS2CCipherKey\0`,
  `SMBC2SCipherKey\0`).
  **[verified: smb-rs]** `session/state.rs:41-44` —
  `if (dialect == Smb0311) != preauth_hash.is_some() { error }` — preauth hash
  must be present for 3.1.1 and absent for 3.0.x. This is a hard invariant the
  server must uphold.
  **[verified: smb-rs]** `session/state.rs:32-34` — when no preauth hash (3.0.x),
  the fallback contexts are `SmbSign\0`, `ServerOut\0`, `ServerIn \0` (with
  trailing space), matching our current 3.0.x code.
- **Encryption keys:** not derived in 7c (cipher is `None`). 7d will add
  `compute_encryption_key`/`compute_decryption_key` with preauth context when
  encryption is implemented.
- Known-answer tests:
  1. SHA-512 preauth chain plus the resulting signing key, from a published
     worked example. Candidates: the Microsoft Open Specifications blog "SMB
     3.1.1 Pre-authentication integrity in Windows 10", or test vectors in the
     smb-rs client (`session/state.rs:500`, `crypto/kbkdf.rs`).
  2. If no external vector can be obtained, derive one from a Samba capture
     with a known password and treat it as a regression fixture, clearly
     labeled as self-derived.

## 6. Signing algorithm selection (3.1.1)

**Decision for 7c (Mashūra review):** always use AES-128-CMAC for 3.1.1. Do
not send a SIGNING_CAPABILITIES context back; the client falls back to its
default signing algorithm, which is `AesCmac` for 3.1.1
(**[verified: smb-rs]** `dialects.rs:124`).

This avoids the GMAC nonce-uniqueness risk (review §4) entirely. GMAC support
is deferred until MessageId reuse can be audited across async ops, CANCEL,
unsolicited responses, and compound members.

The GMAC implementation below is kept in the plan for when that audit is done.

### GMAC (deferred)

- `SigningState` gains `alg: SigningAlg { HmacSha256, AesCmac, AesGmac }`,
  set from `NegotiateRecord`. `sign_message` and `verify_signature` switch
  on `alg` instead of `dialect`.
- GMAC (smb-rs `crypto/signing.rs:141-228`, MS-SMB2 3.1.4.1
  **[verified: smb-rs]**):
  AES-128-GCM with key = signing key, empty plaintext, AAD = the whole message
  with its signature field zeroed, signature = 16-byte tag. Nonce (12 bytes) =
  MessageId (u64 LE) ‖ u32 LE flags, where bit 0 = `server_to_redir` (1 for
  responses, 0 for requests) and bit 1 = 1 if the command is CANCEL.
  **[verified: smb-rs]** `signing.rs:191-199`: `NonceSuffixFlags { msg_id: B64,
  is_server: bool, is_cancel: bool, __: B30 }`.
- **Precondition for GMAC:** audit MessageId uniqueness under the same signing
  key. Repeated MessageIds with different message bytes would reuse a GMAC
  nonce, compromising authentication. Until audited, CMAC is the safe default.
- **Inbound validation:** verify the direction flag in the nonce matches the
  message role (request bit = 0, response bit = 1). Don't trust an
  attacker-controlled role bit.

## 7. Final SESSION_SETUP response signing (3.1.1)

MS-SMB2 3.3.5.5.3 **[verified: smb-rs]**: for 3.1.1, the server must sign the
final successful SESSION_SETUP response of a non-anonymous, non-guest session,
whatever the signing configuration, because the client checks it to
authenticate the preauth hash. **[verified: smb-rs]**
`session/setup.rs:217-222` — client errors with `InvalidMessage("Expected a
signed message!")` if the final success response is not signed/encrypted and
the session is not guest/null.

**Implementation (Mashūra review §2):** add `force_sign: bool` to
`FramedResponse::Plain` (or a separate variant). This travels with the
response, not on cloned `SigningState`. `sign_response_frame` checks it
per-message. Missing signing key on a force-sign → fail closed (don't send
the response unsigned). Install the signing key before encoding. Guest and
anonymous sessions remain unsigned (no key).

The extra mechListMIC leg must not activate session signing state prematurely.
Keys are installed only when the STATUS_SUCCESS response is produced.

## 8. Config and behavior switches

- No new config keys are required. `min_dialect`/`max_dialect` already
  include `smb311`.
- Optional: `signing_algorithms` preference. Defer.
- Make sure `max_dialect = "smb302"` still yields 3.0.2 against 3.1.1-offering
  clients (regression test), so 3.1.1 has an off switch while it beds in.

## 9. Test plan

Unit (`cargo test`):
- smb-msg tolerance (§1) in `rssmb-wire-adapter`.
- `negotiate_ctx`: each rule in §2, including duplicates, missing preauth, no
  SHA-512 overlap (the status code), signing choice ordering, unknown contexts
  ignored and not echoed, encryption context policy.
- `select_dialect`: 3.1.1 now selected; capped by `max_dialect`.
- Preauth chain: hash order across NEGOTIATE and 2-leg and 3-leg
  SESSION_SETUP, final response not hashed, entry removed on failure, two
  concurrent sessions on one connection fork independently.
- KDF known-answer test with a preauth context; GMAC tests.
- Integration (`crates/rssmb-tests`, if feasible offline): drive the server
  with the smb-rs `smb` client crate at 3.1.1 (CMAC and GMAC). Caveat: it
  shares the smb-msg codec, so it is not fully independent.

Live (see memory `env/rssmb-live-testing`):
- `smbclient -m SMB3` → logs show `dialect=Smb311`. Anonymous and signed
  `alice` sessions, ls/get/put. Samba normally offers AES-GMAC, so this covers
  GMAC.
- Kernel `tests/live/mount.sh <ip> 3.1.1` and `3.1.1 ,sign` (cifs.ko is likely
  CMAC by default, which covers the CMAC path), plus the full round-trip
  script.
- impacket: check whether its SMB3 client negotiates 3.1.1 **[verify]**;
  `tests/live/run.sh` 8/8 must still pass either way.
- Regression: vers=3.02, 3.0, 2.1 mounts; `-m SMB3_02/SMB3_00/SMB2`;
  `max_dialect = "smb302"` config.
- Negative live checks: corrupt the preauth state (debug-only knob, or a
  tamper.py variant that alters a SESSION_SETUP byte) → the client rejects the
  signed final response.
- Capture: the docker daemon mounts *host* paths, so for pcaps stream
  `tcpdump -w -` to stdout from the container instead of using `-v`.

## 10. Documentation

- `docs/next-steps.md` §7c: mark done and record the verification.
  Note the 7d hand-off (cipher recorded, 3.1.1 keys derived, CAP_ENCRYPTION
  still off).
- `patches/README.md`: §1 additions.
- No `docs/configuration.md` exists. If §8's optional key is added, document it
  in `config.example`/README instead.

## 11. Order of work (each step builds and tests green; updated per Mashūra)

1. **Enum compatibility** (§1): decide `Dialect::Unknown` approach. If added,
   fix `NegotiateDialect` casts, `is_smb3()` ordering, `CompressionAlgorithm::Display`.
   Add `Unknown(u16)` to `HashAlgorithm`, `EncryptionCipher`, `SigningAlgorithmId`,
   `CompressionAlgorithm`. Test affected reference crates + root workspace.
   Regen patch.
2. **Crypto primitives** (§5, §6): `preauth_update`, `KdfContext` API returning
   `Result`, release-enforced context validation (3.1.1 requires Preauth, 3.0.x
   requires Legacy). GMAC primitives + tests (sign/verify roundtrip, wrong-role
   nonce, nonce uniqueness). Known-answer KDF test through the public API.
   No behavior change for existing callers (2.x/3.0.x pass `Legacy`).
3. **Context processing** (§2): `negotiate_ctx.rs` (pure) + tests. Each rule in
   §2, including duplicates, missing preauth, no SHA-512 overlap (the status
   code), signing choice (always CMAC for 7c), encryption context omitted,
   unknown contexts ignored and not echoed. Malformed-wire tests.
4. **Auth state + compound policy** (review §1): reject compounds containing
   NEGOTIATE or SESSION_SETUP on 3.1.1. One pending auth per connection. Bound
   `preauth_sessions` with cleanup on every terminal error.
5. **Preauth plumbing** (§4): NegotiateRecord/`neg311` + ConnState preauth fields
   + connection-loop response hashing with response-associated metadata (not
   connection-global `preauth_pending`). Request bytes to handlers. Loop-level
   transcript tests (mandatory). 3.1.1 still disabled.
6. **SESSION_SETUP + forced signing** (§4.2, §7): hashing, key derivation with
   preauth context, `force_sign` on the `FramedResponse` (not on cloned state).
   Extra mechListMIC round key-derivation timing. Guest/anonymous unsigned.
7. **Enable 3.1.1** in `IMPLEMENTED_DIALECTS`/`EFFECTIVE_MAX_DIALECT`. Always CMAC
   for 7c (no signing context sent; client falls back to CMAC default).
8. **Live matrix** (§9), Mashūra implementation review, docs, commit.
   Record client versions, negotiated algorithm in logs.

## 12. Risks / open questions (updated after Mashūra plan review)

### Resolved by review (decisions folded in)

- **Auth state ownership** (review §1): `ConnState` has one `auth_state` per
  connection. Per-session preauth hashes with interleaved auth would break
  this. **Decision:** permit only one pending authentication per connection at
  a time. A second SESSION_SETUP while one is pending → reject with
  `STATUS_REQUEST_NOT_ACCEPTED` or `STATUS_INVALID_PARAMETER`. The preauth hash
  is per-session (keyed by SessionId in a HashMap), but auth state is
  per-connection, so only one session can be establishing at a time. This is
  the current behavior (the code already rejects non-zero unknown SessionIds).
- **Compound handshake race** (review §1): a compound could dispatch NEGOTIATE
  then SESSION_SETUP before the negotiate response is encoded/hashed.
  **Decision:** reject compounds containing NEGOTIATE or SESSION_SETUP on a
  3.1.1 connection with `STATUS_INVALID_PARAMETER`. No real client compounds
  these. This removes the response-before-hash race.
- **Force-sign mechanism** (review §2): a cloned SigningState flag won't
  consume the original. **Decision:** add `force_sign: bool` to
  `FramedResponse::Plain` (or a `FramedResponse::PlainForceSign` variant).
  `sign_response_frame` checks this per-message. It is not connection-global
  state; it travels with the response. Missing signing key on a force-sign
  → fail closed (don't send the response unsigned).
- **KDF enforcement** (review §3): **Decision:** `compute_signing_key` etc.
  return `Result<Vec<u8>, CryptoError>`. Reject 3.1.1+Legacy AND 3.0.x+Preauth
  in release builds. No `debug_assert`.
- **GMAC nonce uniqueness** (review §4): MessageId reuse under the same signing
  key would compromise GMAC. **Decision:** default to AES-CMAC for 3.1.1; prefer
  GMAC only if the client offers it AND we have MessageId uniqueness guarantees.
  For 7c, use CMAC as the safe default. If the client sends SIGNING_CAPABILITIES
  with AES-GMAC, negotiate it but document the nonce-uniqueness audit as a
  precondition. **Simpler safe path for 7c:** always use AES-CMAC for 3.1.1,
  ignore the signing context for now. This avoids the GMAC nonce risk entirely
  until we can audit MessageId reuse. The client falls back to CMAC
  (`dialects.rs:124`: `default_signing_algo()` = `AesCmac` for 3.1.1).
- **Encryption context** (review §5): **Decision:** omit the encryption
  context entirely. `cipher = None`. Do not derive encryption keys. Remove any
  wording about "choosing a cipher". The 7d hand-off records `cipher = None`,
  not a selected cipher.
- **Enum compatibility** (review §6): adding `Unknown` to `Dialect` breaks
  `NegotiateDialect` discriminants (`as isize` casts) and `is_smb3()` (ordering).
  **Decision:** do NOT add `Unknown` to `Dialect`. Instead, parse the dialect
  list as `Vec<u16>` in the server adapter and check for known values. Or keep
  `Dialect` as-is and let unknown values fail the `BinRead` decode — the
  `dialect_count` field controls how many u16 values are read, and unknown
  values would fail. **Simpler approach:** parse the raw dialect list bytes
  before the structured parse, or add `Unknown(u16)` to `Dialect` and fix all
  casts. Check which is less work after reading the code.
- **Signing selection** (review §6): explicit behavior for no-common-signing-
  algorithm. **Decision:** if client offers signing algorithms and none overlap
  with ours (CMAC), return `STATUS_INVALID_PARAMETER`. If client sends no
  signing context, use CMAC (the 3.1.1 default). For 7c, always use CMAC and
  don't send a signing context back (client falls back to CMAC).

### Still open

- No independent known-answer vector for preauth chain + KDF through the public
  API (§5). The existing `test_kdf_sp800_108_known_answer` covers the primitive;
  need a full-transcript fixture.
- GMAC nonce for async CANCEL — deferred with the GMAC deferral.
- `Dialect::Unknown` approach — need to check smb-msg code for cast sites.
- Loop-level tests for preauth hashing (mandatory per review).
