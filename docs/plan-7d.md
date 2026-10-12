# Step 7d — SMB 3.x encryption implementation plan

Status: **draft, Mashūra plan review round 1 folded in (§14); the round-1
decisions override any earlier section that contradicts them**. Baseline:
`244df5c` (7c done).

Goal: real clients (smbclient `--client-protection=encrypt`, Linux cifs.ko
`seal`, impacket, and later Windows and macOS) can run encrypted sessions and
shares over SMB 3.0, 3.0.2 and 3.1.1. That needs negotiating a cipher,
deriving the per-session encryption and decryption keys, decrypting
TRANSFORM_HEADER frames before dispatch, encrypting responses after encode,
and enforcing the `encryption` policy at session and tree level.

Spec references are MS-SMB2. Items marked **[verify]** are recalled from memory
and must be checked against the spec text before they are coded, or against
the smb-rs reference client (`smb-rs/crates/smb/`) as was done in 7c. The live
spec pages are JS-rendered and unreachable from the sandbox.

---

## 0. Current state (observed)

| Area | Location | State |
|---|---|---|
| RX framing | `rssmb-wire-adapter/src/framing.rs:63-81` | `0xFD 'SMB'` → `FramedMessage::Encrypted(raw)`; not parsed further |
| RX dispatch | `dispatch.rs:300-309` | `Encrypted` → `Error{NotSupported, Negotiate, mid=u64::MAX}` |
| Read loop | `connection.rs:234-445` | NetBIOS read → `parse_payload` (catch_unwind) → `verify_frame` (Plain/Compound only) → `handle_message` → credits → `encode_response` → `sign_response_frame` → preauth hash `encoded[4..]` → retire signing → `write_tx.send` |
| Credits | `connection.rs:341-366` | only Plain/Compound are ledgered; encrypted frames are not charged and get 0 grant |
| Unsolicited TX | `dispatch.rs:2524-2539` | `send_unsolicited`: encode → sign → send. Used by CANCEL / async interim and the read-loop parse-error path (`connection.rs:309`). A second TX path that must encrypt too |
| TX framing | `rssmb-wire-adapter/src/lib.rs:76,167` | `FramedResponse::Encrypted(Vec<u8>)` exists (raw passthrough) |
| smb-msg | `smb-rs/crates/smb-msg/src/encrypted.rs:15-63` | `EncryptedHeader {signature u128, nonce [u8;16], original_message_size u32, reserved u16, _flags u16 (write 1, read asserts ==1), session_id u64}`, `STRUCTURE_SIZE = 52`, `aead_bytes()` = 32 bytes from Nonce onward, `EncryptedMessage` (header + body until EOF), 2 binrw KATs |
| KDF | `crypto.rs:151-203` | `compute_encryption_key` (S2C) / `compute_decryption_key` (C2S) exist and are correct for 128-bit: 3.0.x `SMB2AESCCM\0` + `ServerOut\0` / `ServerIn \0`; 3.1.1 `SMBS2CCipherKey\0` / `SMBC2SCipherKey\0` + preauth hash. Always L=128. **Unused** |
| Session | `session.rs:28-75,132-133` | `encryption_key`, `encryption_required` fields; `authenticate_step` sets `encryption_key = session_key` as a **placeholder** (wrong key, must not be used) |
| Per-session crypto store | `dispatch.rs:97,115-128` | `ConnState.signing: RwLock<HashMap<u64, SigningState>>`; `SigningState {key, required, dialect, retiring, force_sign_once}`. No encryption state |
| NEGOTIATE | `dispatch.rs:755-772` | caps = large_mtu only; comment says encryption cap deliberately not advertised; contexts processed only for 3.1.1 |
| negotiate_ctx | `negotiate_ctx.rs:17,55,84-87,124,131` | `Negotiated311.cipher` hard-coded `None`; ENCRYPTION_CAPABILITIES only checked for duplicates; no response context |
| SESSION_SETUP | `dispatch.rs:999-1005,1037-1129` | session flags only `is_guest`/`is_null_session`; signing key derived at 1074; no encryption keys |
| TREE_CONNECT | `dispatch.rs:1305,1384` | `share_flags` default; no `ENCRYPT_DATA`. `TreeEntry {share_name, vfs, session_id, read_only}` (262) |
| Config | `config.rs:29-31,115-130,134-160` | `encryption: EncryptionPolicy {Disabled, Desired, Required}`, **default `Desired`**, parsed but unused. `ShareConfig` has no encrypt key. All live TOMLs set `encryption = "disabled"` |
| Deps | `Cargo.toml:37-42`, `Cargo.lock` | `aes 0.8.4`, `aes-gcm 0.10.3`, `aead 0.5.2`, `cmac 0.7`, `rand 0.8`. **No `ccm`**; not in the local cargo cache (needs network or vendoring) |
| smb-msg flags | `session_setup.rs:117-118`, `tree_connect.rs:327-328`, `negotiate.rs:80` | `SessionFlags.encrypt_data`, `ShareFlags.encrypt_data`, `GlobalCapabilities.encryption` all exist |

---

## 1. Scope

**In:**
- AES-128-GCM and AES-128-CCM. 3.0/3.0.2 use CCM only. 3.1.1 picks from the
  client's ENCRYPTION_CAPABILITIES list in server preference order:
  `AES-128-GCM > AES-128-CCM`.
- TRANSFORM_HEADER receive/send for plain and compound messages.
- `encryption = disabled | desired | required` (global) and a new per-share
  `encrypt_data` (bool, default false).
- Both TX paths (read loop and `send_unsolicited`).

**Out (deferred, recorded in follow-ups):**
- AES-256-CCM/GCM. These need L=256 in the KDF, and for 3.1.1 the full session
  key **[verify]**. With NTLM the session key is 16 bytes, so this is mostly a
  KDF/length change, but it is deferred to keep the AEAD surface small. We
  simply don't select them. Windows 11 also offers 128-GCM.
- `RejectUnencryptedAccess = false` (allowing unencrypted access to an
  encrypt-required share by non-3.x clients). We always reject.
- COMPRESSION_TRANSFORM_HEADER (0xFC), including compressed-inside-encrypted.
- Encryption of re-authentication or session binding (both remain unsupported).
- GMAC signing (still deferred from 7c).

## 2. Dependencies

- Add `ccm = "0.5"` to the workspace and to `rssmb-server`. ccm 0.5.x targets
  `aead 0.5` / `aes 0.8`, which matches `aes-gcm 0.10.3` and `aes 0.8.4`
  **[verify: crate versions and API on crates.io before adding]**. smb-rs uses
  `ccm ^0.6` + `aes ^0.9`, which is incompatible with our versions, so we
  can't copy its types verbatim.
- Network is needed for `cargo fetch`. If it isn't available, this step is
  **BLOCKED**: ask the user. Don't hand-roll CCM.
- Use `aes_gcm::Aes128Gcm` (12-byte nonce, 16-byte tag) and
  `ccm::Ccm<Aes128, U16, U11>` (11-byte nonce, 16-byte tag). Use the detached
  in-place APIs (`encrypt_in_place_detached` / `decrypt_in_place_detached`) so
  the tag goes into the header Signature field and the body stays separate.

## 3. Crypto module (`crypto.rs`, pure, unit-testable)

```rust
pub enum Cipher { Aes128Ccm, Aes128Gcm }          // server-side, closed set
impl Cipher { fn nonce_len(&self) -> usize { 11 | 12 } fn id(&self) -> u16 { 1 | 2 } }

pub fn encrypt_message(cipher, key: &[u8;16], nonce: &[u8;16], session_id: u64,
                       plaintext: &mut Vec<u8>) -> Result<[u8;52], CryptoError>;
//   builds EncryptedHeader{nonce, original_message_size = len, flags=1, session_id},
//   AAD = header.aead_bytes() (32 bytes), encrypts in place, sets signature = tag.
pub fn decrypt_message(cipher, key: &[u8;16], hdr: &EncryptedHeader, aad: &[u8;32],
                       ciphertext: &mut Vec<u8>) -> Result<(), CryptoError>;
```

- Nonce on the wire is 16 bytes. Only the first `nonce_len` bytes are used and
  the rest **MUST be zero** on send (MS-SMB2 2.2.41 **[verify]**; smb-rs
  `encryptor_decryptor.rs:23-97` zero-fills). On receive, use only the first
  `nonce_len` bytes. Don't reject non-zero padding unless the spec says so
  **[verify]**.
- AAD = the 32 header bytes from Nonce to SessionId inclusive (confirmed by
  smb-msg `aead_bytes()` and smb-rs). Compute the AAD from the **received raw
  bytes** (`payload[20..52]`), not from re-serialising the parsed header. That
  way a lenient parse can never authenticate different bytes than the client
  sent.
- `compute_encryption_key` / `compute_decryption_key` already exist and are
  correct for 128-bit. Add known-answer tests through the public API (see §10).
- Zeroize: keys live in `Vec<u8>`/`[u8;16]` like the signing keys. Adding
  `zeroize` is out of scope; it goes in the step 9 hygiene list.

## 4. Negotiation

### 4.1 SMB 3.0 / 3.0.2 (`handle_negotiate`)
- Set `SMB2_GLOBAL_CAP_ENCRYPTION` in the response iff `config.encryption !=
  Disabled` **and** the client set CAP_ENCRYPTION in its NEGOTIATE request
  **[verify: 3.3.5.4. Is it gated on the client's cap or only on server
  support?]**. Record `cipher = Some(Aes128Ccm)` in `NegotiateRecord`
  (new field `cipher: Option<Cipher>`) when it is set.
- VALIDATE_NEGOTIATE_INFO already echoes `server_capabilities` from the
  record. Make sure the echoed caps include ENCRYPTION when it was sent, or VNI
  fails on 3.0.x. Covered by the existing echo-from-record code; add a test.

### 4.2 SMB 3.1.1 (`negotiate_ctx.rs`)
- `process_request_contexts(req, cfg)` gets the encryption policy. If the
  client sent ENCRYPTION_CAPABILITIES and policy != Disabled: pick the first
  server-preferred cipher present in the client list (`Unknown(_)` ignored).
  Respond with an ENCRYPTION_CAPABILITIES context with `CipherCount = 1` and
  the chosen cipher.
- No overlap: respond with `CipherCount = 1, Cipher = 0` (no common cipher),
  `cipher = None` **[verify: 3.3.5.4. Respond with cipher 0 vs omit the
  context]**. Don't fail the NEGOTIATE.
- `CipherCount == 0` in the request → `STATUS_INVALID_PARAMETER` **[verify]**.
- **Do not** set `SMB2_GLOBAL_CAP_ENCRYPTION` for 3.1.1. Encryption support is
  signalled by the context **[verify: 3.3.5.4. CAP_ENCRYPTION is 3.0/3.0.2
  only]**. smb-rs `dialects.rs:36` never sets it for 3.1.1 (verified in 7c).
- Policy `Disabled` → omit the context (current 7c behavior).
- Context ordering in the response: PREAUTH first, then ENCRYPTION. smb-msg's
  writer handles the 8-byte alignment. Add an encode→decode test.
- `Negotiated311.cipher` now carries the choice. `NegotiateRecord.cipher`
  becomes the single source for both dialect families (for 3.1.1 it is
  derived from `neg311.cipher`).
- Preauth: the NEGOTIATE response now has a second context, and those bytes
  are hashed as before (the response hashing is generic). No change needed,
  but the live 3.1.1 tests re-verify it.

## 5. Session setup

On the success path (`dispatch.rs:1037-1129`), only for a 3.x dialect with
`NegotiateRecord.cipher = Some(c)` and a non-guest, non-anonymous session
whose session key is non-empty:

1. Derive `enc_key = compute_encryption_key(sk, dialect, ctx)` (S2C) and
   `dec_key = compute_decryption_key(sk, dialect, ctx)` (C2S) with the same
   `KdfContext` used for the signing key (preauth hash for 3.1.1, legacy for
   3.0.x). On a KDF error, abort the session with LogonFailure. That is the
   same fail-closed path as signing (7c review fix).
2. Insert `EncryptionState` into the new per-connection map (§6).
3. `encrypt_data` for the session = `config.encryption == Required`. If set,
   set `SessionFlags.encrypt_data` in the final response.
4. Remove the placeholder `encryption_key = session_key` from
   `session.rs:133`. Store the real keys only in `EncryptionState`, or drop
   the `Session.encryption_key` field if nothing reads it. A wrong key lying
   around is a footgun.

Policy enforcement at SESSION_SETUP:
- `encryption = Required` and (`cipher = None` **or** the session is
  guest/anonymous) → fail SESSION_SETUP with `STATUS_ACCESS_DENIED`
  **[verify: 3.3.5.5.3. Exact status and whether guest is rejected here or
  only at tree connect]**. Rationale: a session that can never be encrypted
  must not be created under a mandatory-encryption policy. Clean up
  preauth/pending auth exactly as on any other auth failure.
- The **final SESSION_SETUP response is not encrypted**. For 3.1.1 it is
  signed (force_sign_once from 7c). For 3.0.x it is signed when signing
  applies. Encryption starts with the next request **[verify: 3.3.5.5.3; the
  client can't decrypt before it has processed the response]**.

## 6. Per-connection encryption state

```rust
pub struct EncryptionState {
    pub cipher: Cipher,
    pub enc_key: [u8; 16],          // server → client
    pub dec_key: [u8; 16],          // client → server
    pub encrypt_data: bool,         // session-level requirement
    pub nonce: Arc<NonceSource>,    // shared by both TX paths
    pub retiring: bool,             // LOGOFF: keep only for the LOGOFF response
}
// ConnState.encryption: RwLock<HashMap<u64 /*SessionId*/, EncryptionState>>
```

- Kept beside `ConnState.signing`, with the same lifecycle: inserted at
  session success, `retiring` set on LOGOFF, `retain(!retiring)` after the
  LOGOFF response is sent, dropped with the connection.
- **Nonce uniqueness (critical for GCM):** `NonceSource` = 64-bit per-session
  counter in the first 8 bytes. The allocator is non-wrapping:
  `fetch_update`/CAS with a permanently exhausted state, **not** `fetch_add`
  (see §14.5). Then plus random bytes
  fixed per session for the rest of the cipher's nonce length (GCM 4 bytes,
  CCM 3 bytes), with the remaining bytes of the 16 zero. The counter never
  wraps. At `u64::MAX`, refuse to encrypt and disconnect. The key is
  per-session and server-direction-only (the client uses `dec_key`'s
  counterpart), so server nonces only need to be unique among
  server-originated messages of that session. Both TX paths must take nonces
  from the same `NonceSource` (`Arc`), never from a clone of a counter.
  Alternative considered: fully random 96-bit nonces (smb-rs does this). The
  birthday bound is acceptable, but a counter is deterministic and testable.
- Received nonces: no replay window is required by the spec **[verify]**.
  Don't implement one. Record it as a follow-up.

## 7. Receive path (decrypt before dispatch)

Do it in `connection.rs`, between `read_netbios_payload` and `parse_payload`.
That keeps dispatch, signing and preauth logic seeing only plaintext SMB2.

```
payload starts with 0xFD 'SMB' →
  len >= 52                                  else disconnect
  parse EncryptedHeader (catch_unwind; binrw asserts flags == 1)
                                             parse error → disconnect
  original_message_size == payload.len()-52 and >= 64 and <= max_frame_size
                                             else disconnect
  st = encryption[session_id]                missing → disconnect [verify: 3.3.5.2.1.1]
  connection dialect is 3.x and cipher set   else disconnect
  decrypt(st.cipher, st.dec_key, nonce, aad=payload[20..52], body)
                                             auth failure → disconnect (3.3.5.2.1.1)
  plaintext must start with 0xFE 'SMB'       (no nested transform/compression) else disconnect
  validated compound walk (§14.1): every member's *effective* SessionId
  (related members inherit; raw field may be u64::MAX) == transform SessionId,
  structure valid for ALL members before ANY is dispatched   else disconnect
  continue the normal loop with payload = plaintext, was_encrypted = Some(session_id)
```

- **Disconnect, don't respond**, on any transform failure. The spec says the
  server MUST disconnect on decryption failure **[verify exact wording]**, and
  replying to unauthenticated input leaks oracle information. Use the existing
  `Err(InvalidData)` return so normal connection cleanup runs.
- **Signature verification is skipped** for messages that arrived encrypted.
  The AEAD authenticates them, and clients send them with Signature = 0 and no
  SIGNED flag **[verify: 3.3.5.2.4]**. `verify_frame` must not reject an
  unsigned inner message on a signing-required session when `was_encrypted`
  is set.
- **Credits:** after decryption the frame is Plain/Compound and is ledgered
  normally. That changes the current "encrypted = not ledgered" behavior,
  which only existed because encrypted frames were rejected.
- The parse-error path (`connection.rs:272-317`): if the decrypted plaintext
  fails to parse, the error reply must be encrypted too (§8).
- NEGOTIATE and SESSION_SETUP inside an encrypted frame: NEGOTIATE is already
  rejected by the negotiate gate (repeat NEGOTIATE → disconnect).
  SESSION_SETUP over an encrypted frame means re-auth or binding, which stays
  unsupported, so the existing rejection applies. Preauth hashing must never
  run on such a message. Assert that `preauth_hash_response` is not set when
  `was_encrypted` is set, and fail closed (disconnect) if it is.

## 8. Send path (encrypt after encode)

Refactor the duplicated encode/sign/send sequence into one function used by
both the read loop and `send_unsolicited`:

```rust
fn finalize_frame(conn_state, resp: &FramedResponse, client_signed: &[bool],
                  encrypt_for: Option<u64 /*SessionId*/>) -> Result<Bytes, Fatal>
  encoded = encode_response(resp)
  if encrypt_for.is_some():
      clear SMB2_FLAGS_SIGNED and zero signature on every member   [verify: 3.3.4.1.1]
  else:
      sign_response_frame(...)        (as today, incl. force_sign_once)
  preauth hash (only when not encrypting; read-loop only)
  if let Some(sid) = encrypt_for:
      st = encryption[sid] (missing → Fatal: never fall back to plaintext)
      wrap encoded[4..] in TRANSFORM_HEADER with st.nonce.next(), st.enc_key
      rewrite the NetBIOS length (52 + len)
```

**When to encrypt (`encrypt_for`)**, decided per response:
1. The request arrived encrypted → encrypt with the same SessionId
   (MS-SMB2 3.3.4.1.4 **[verify]**).
2. Else, the response's session has `EncryptionState.encrypt_data`, or the
   response's tree has `TreeEntry.encrypt_data` → encrypt. In practice this
   only matters for unsolicited messages, because §9 rejects the unencrypted
   request beforehand.
3. Never encrypt: NEGOTIATE responses, SESSION_SETUP responses (including the
   final one), responses with SessionId 0, or SessionIds that have no
   `EncryptionState`.

- **Compound responses** are encrypted as one transform over the whole chain.
  smb-rs and Windows do it this way **[verify]**. The transform SessionId is
  the request's transform SessionId.
- **Async/unsolicited** (`send_unsolicited`, CANCEL, interim STATUS_PENDING):
  callers pass the originating request's `was_encrypted`/SessionId so that
  rule 1 applies. Today `send_unsolicited` takes `client_signed: bool`. Extend
  the signature, or pass a small `ReplyCtx {client_signed, encrypt_for}`
  struct, and update all call sites. The parse-error path in the read loop
  passes the transform SessionId when the bad message was decrypted.
- Max frame: an encrypted frame is 52 bytes larger. Observed:
  `MAX_IO_SIZE = 65536` (`dispatch.rs:35`) for read/write/transact, and the
  default `max_frame_size = 1 MiB` (`config.rs:77`). That leaves headroom, but
  budget it explicitly: SMB header + body + compound padding + 52-byte
  transform + 4-byte NetBIOS. Check that `max_frame_size` is applied to the
  *transform* frame on RX and that `OriginalMessageSize` is bounded
  separately. Test a maximum-size WRITE (RX) and READ (TX) under encryption.
- Order with credits: credits are patched before encode, as today. Encryption
  happens after, so the client sees the real grant.

## 9. Policy enforcement (unencrypted requests)

MS-SMB2 3.3.5.2.9 / 3.3.5.2.11 **[verify section numbers]**:
- A request that arrives **unencrypted** on a session with `encrypt_data` →
  `STATUS_ACCESS_DENIED`. Exceptions: the SESSION_SETUP that established it,
  and NEGOTIATE (no session).
- A request that arrives **unencrypted** for a tree with `encrypt_data` →
  `STATUS_ACCESS_DENIED`.
- TREE_CONNECT to a share with `encrypt_data = true`:
  - session has `EncryptionState` → set `ShareFlags.encrypt_data` in the
    response and `TreeEntry.encrypt_data = true`;
  - session has none (guest/anon, 2.x dialect, no common cipher) →
    `STATUS_ACCESS_DENIED` (RejectUnencryptedAccess = true semantics).
- IPC$ is not special-cased. It follows the global policy.
- Where: one check in `handle_plain` / per compound member before the command
  handler runs, using `was_encrypted`, the session's `EncryptionState`, and
  the tree's `TreeEntry`. The access-denied reply itself goes out
  **unencrypted** (the request was unencrypted), and signed if signing
  applies.
- `encryption = "desired"`: offer the cipher, derive keys, and accept and
  answer encrypted requests, but never set `encrypt_data` and never reject
  plaintext. Note that `desired` is the current **default**. After 7d, a
  default config advertises encryption. That is intended, but call it out in
  the docs.

## 10. Config and docs

- New `ShareConfig.encrypt_data: bool` (`#[serde(default)]`).
- Global `encryption` already exists. Document its semantics (§9).
- A share with `encrypt_data = true` under `encryption = "disabled"` is a
  config error: refuse to start with a clear message. Don't silently drop the
  share requirement.
- No `docs/configuration.md` and no `config.example.json` exist (checked in
  7c). Document the keys where the existing TOML examples/README describe
  config **[check at implementation time]**.
- New live config `tests/live/rssmb-live-encrypted.toml`: `encryption =
  "required"`, plus a second variant with `desired` and one share with
  `encrypt_data = true`.
- `docs/next-steps.md` §7d: mark it done and record the verification and the
  deferrals (AES-256, compression, replay window, RejectUnencryptedAccess).

## 11. Test plan

Unit (`cargo test`, the documented suite; baseline 189 green):
- AEAD primitives: AES-128-GCM and AES-128-CCM known-answer vectors. Sources:
  NIST/RFC 3610 vectors for CCM with 11-byte nonce and 16-byte tag (adapt if
  the RFC vectors use a different tag length), the NIST GCM vector, plus at
  least **one SMB-level vector**: an encrypted SMB2 message with key, nonce,
  AAD and ciphertext from the MS Open Specifications "SMB 3.0/3.1.1
  encryption" worked examples, or from smb-rs tests if it has any
  **[verify availability]**. If no SMB-level external vector is obtainable,
  record that explicitly and rely on live interop as the independent check.
- KDF: known-answer for `compute_encryption_key`/`compute_decryption_key`
  (3.0.x legacy context, 3.1.1 preauth context).
- Transform: encrypt→decrypt round-trip. Tamper with each region (AAD byte,
  nonce, ciphertext, tag, OriginalMessageSize, SessionId) → decrypt fails.
  Unknown SessionId; size mismatch; truncated header; flags != 1; nested 0xFD
  and 0xFC plaintext rejected.
- Nonce source: strictly increasing, unique across concurrent `next()` calls
  (multi-thread test), zero padding, exhaustion → error.
- negotiate_ctx: cipher selection order (GCM over CCM), client-only-256 → no
  common cipher (cipher 0), `Unknown` ignored, `CipherCount = 0` rejected,
  `Disabled` → context omitted, response encode→decode with two contexts.
- NEGOTIATE 3.0.x: CAP_ENCRYPTION set/unset by policy and client cap. VNI
  echo still matches.
- Loop-level (connection tests like the 7c transcript tests): an encrypted
  request gets an encrypted response with a fresh nonce. Unencrypted request
  on an `encrypt_data` session → ACCESS_DENIED in plaintext. A decrypt failure
  closes the connection with no response. Compound in one transform → one
  transform response. The CANCEL interim for an encrypted request is
  encrypted. Signature not required inside the transform on a
  signing-required session. LOGOFF over encryption: the response is encrypted
  and the state is retired afterwards.
- Policy: `required` + guest/anon → SESSION_SETUP denied. `encrypt_data`
  share + no-cipher session → TREE_CONNECT denied. Config validation
  (`encrypt_data` under `disabled`).

Live (memory `env/rssmb-live-testing`; `tests/live/`):
- smbclient: `-m SMB3_11 --client-protection=encrypt` (or `-e`) and `-m SMB3_02
  -e`. Logs must show the negotiated cipher and the `encrypted` session flag.
  ls/get/put work. Samba prefers AES-128-GCM for 3.1.1 (covers GCM) and CCM
  for 3.0.2 (covers CCM).
- Kernel cifs.ko: `tests/live/mount.sh <ip> 3.1.1 ,seal` and `3.0 ,seal`,
  with the full round-trip script. Server `required` + client without `seal`
  → the kernel must still work (the server sets the session flag and the
  client encrypts anyway) **[verify cifs behavior]**.
- impacket: `run.sh` 8/8 must still pass with `encryption = "disabled"` (the
  current live configs) **and** with `desired`. Add an encrypted scenario if
  impacket's SMB3 client supports encryption when the server sets
  ENCRYPT_DATA **[verify]**.
- Regression: 2.1/3.0/3.0.2/3.1.1 unencrypted mounts with `encryption =
  "desired"` (the new default behavior). smbclient `-m SMB2` against a
  `required` server → session denied (expected).
- Negative: tamper.py variant that flips a ciphertext byte → the server
  disconnects without a reply.

## 12. Order of work (revised after Mashūra round 1; each step builds and `cargo test` is green)

0. **Pin the spec.** Resolve every `[verify]` against a pinned MS-SMB2
   revision (or the smb-rs reference + Samba source if the spec stays
   unreachable). Record clause, chosen behavior, and the wire-level test for
   each in §14.0. A `[verify]` item that stays unresolved blocks the step that
   depends on it.
1. **Deps + AEAD primitives** (§2, §3): `ccm`, `Cipher`, transform
   encrypt/decrypt over raw bytes (a header builder or constructor is needed,
   because `EncryptedHeader` fields are private, §14.7), non-wrapping
   `NonceSource`, exact KATs (§14.7). No behavior change.
2. **TX refactor, behavior-preserving** (§8, §14.2, §14.4): `TxProtection`,
   `finalize_frame` with the fixed step order, `send_unsolicited` returning
   `Result` and able to end the connection, an audit of every TX path.
   `TxProtection::Plain` everywhere, so the existing tests prove the refactor.
3. **Validated compound walk** (§14.1): split structure/effective-session
   validation out of `verify_frame` into a shared walk used by both plaintext
   (followed by signature check) and decrypted (no signature check) frames.
   Existing signing tests must still pass.
4. **Negotiation + session keys + state** (§4, §5, §6, §14.6): cipher
   negotiation, atomic key installation, `EncryptionState` with leases,
   lifecycle. Everything stays behind an internal `ENCRYPTION_READY` gate:
   no CAP_ENCRYPTION, no ENCRYPTION context, no `SessionFlags.encrypt_data`.
   With the gate closed, `encryption = "required"` (or any `encrypt_data`
   share) is a **startup error**, never a silent downgrade.
5. **RX decrypt + response protection + async context** (§7, §8, §14.3): wire
   it up in loop-level tests with the gate forced open in tests only.
6. **Policy enforcement + share config** (§9, §10, §14.4), including the
   signing-vs-policy ordering and the negative tests.
7. **Open the gate**, then the live matrix (§11, §14.8), Mashūra
   implementation review, docs, commit.

## 13. Risks / open questions

- **`ccm` availability** (network). Blocks step 1 if it can't be fetched.
- **Nonce reuse** is the catastrophic failure mode for GCM (§14.5).
- **3.1.1 no-common-cipher encoding** and **CAP_ENCRYPTION for 3.0.x vs
  3.1.1**: resolve in step 0.
- **Default policy `desired`**: decided per review. The finished
  implementation advertises encryption under `desired`, and the public
  default does not change. Until step 7, the internal gate keeps
  advertisement off.
- No independent SMB-level encryption vector may be available offline. In
  that case live interop with Samba and cifs.ko is the independent check, and
  the fixtures are labeled self-derived.

## 14. Mashūra plan review — round 1 decisions

The review (gpt-6-astra; the second panelist's response was truncated) said
**revise before implementation**. Its protocol statements are recalled, not
spec-quoted, so they feed step 0 rather than replace it. I checked the
code-level claims myself (marked *observed*).

### 14.0 Spec items (step 0 resolves them; the review's recollection is noted)
| Item | Review recollection | Plan default until pinned |
|---|---|---|
| 3.0.x CAP_ENCRYPTION | server advertises its support; not conditional on the client bit | advertise when policy != Disabled; *use* only if the client also set it |
| 3.1.1 CAP_ENCRYPTION | not used (contexts instead) | never set |
| 3.1.1 no common cipher | one entry, value 0; NEGOTIATE succeeds | same; `required` then denies SESSION_SETUP |
| Disabled + client sent ENCRYPTION ctx | omission ≠ no-overlap; check | **open**: decide in step 0 between omit and cipher 0 |
| Malformed ENCRYPTION ctx (`CipherCount = 0`) | INVALID_PARAMETER, regardless of policy | validate independently of policy |
| Final SESSION_SETUP response | not encrypted; stays signed | same (the "client can't decrypt yet" rationale is dropped) |
| Decrypt/auth failure | disconnect, no SMB error | same; other malformed-transform cases are classified separately in step 0 |
| Inner signature in a transform | ignore; don't reject a non-zero SIGNED flag/signature | same; on TX clear SIGNED and zero signatures before encrypting |
| Async/interim responses | not exempt from encryption | protected per the original operation (§14.3) |
| Plaintext policy violation reply | ACCESS_DENIED, unencrypted | same (fixes the §8 rule 2 contradiction) |
| Nonce padding | send zeros; receiver uses the prefix; all 16 bytes are in the AAD | same; don't reject non-zero padding |

### 14.1 Compound validation is not "skip verify_frame"
`signing::verify_frame` also validates compound boundaries, resolves related
SessionIds, and checks retiring state (*observed in the review's excerpt;
re-read at step 3*). Decrypted frames must still go through that structural
walk:
1. authenticate the transform;
2. walk the whole compound and resolve effective SessionIds (related members
   inherit them);
3. every effective SessionId == the transform SessionId, and the session is
   valid and not retiring;
4. only then dispatch any member;
5. SMB signature verification applies to plaintext transport only.
Tests: a related-member `u64::MAX` sentinel accepted; an unrelated member
targeting another session rejected; malformed `NextCommand`; an invalid
*later* member causes **no** side effects from earlier members.

### 14.2 Explicit protection decision
Replace `encrypt_for: Option<u64>` with
`enum TxProtection { Plain, Encrypted(Arc<EncryptionState>) }`, computed by
one policy function in this precedence:
1. NEGOTIATE / initial SESSION_SETUP responses → Plain (signed per 7c rules).
2. Plaintext encryption-policy denial (ACCESS_DENIED) → Plain.
3. Response to an authenticated encrypted request → Encrypted (that session).
4. Session `encrypt_data` or tree `encrypt_data` → Encrypted.
5. Otherwise Plain.
If the decision is Encrypted and the state is missing or exhausted, the
connection is torn down. **Never downgrade.** The decision is made from
request and operation context, not inferred from the response headers.
Compound TX: one transform per response frame, and every member must belong
to the same session as the transform. For a plaintext compound whose members
would need different protection (different sessions or trees with different
`encrypt_data`), the policy check in §9 fails the offending member with
ACCESS_DENIED, so the frame stays Plain. A response is never encrypted under
another session's key.

### 14.3 Async completions keep the original request's protection
*Observed:* `AsyncOp {command, session_id, tree_id, cancel}`
(`dispatch.rs:249-258`) carries no protection. The CANCEL path signs according
to the **CANCEL** request's flag (`dispatch.rs:2518`). Add
`protection: TxProtection` (and the client-signed flag) to `AsyncOp`, captured
when the original request is dispatched. Both STATUS_PENDING and the final
completion use it. CANCEL itself gets no response. The cancelled completion
of the *target* uses the target's protection. Snapshot tree protection at
dispatch time, because async headers carry no TreeId and the tree may be
disconnected later. LOGOFF while ops are pending: completions are sent
before the session's state is retired (or they are dropped together with the
session). Define this in step 5 and test it.

### 14.4 TX ordering, TX-path audit, policy vs signing order
- `finalize_frame` order: encode → patch remaining header fields (including
  the post-encode credit patch for `FramedResponse::Error`, *observed*
  `connection.rs:398-400`) → sign, or clear the signature for encryption →
  apply an explicitly directed preauth hash → encrypt → enqueue, with errors
  propagated. Unsolicited sends never consume `preauth_hash_response`.
- `send_unsolicited` currently returns `()` and drops send errors
  (*observed* `dispatch.rs:2538`). It must return `Result` so that encryption
  failure or nonce exhaustion ends the connection.
- TX-path audit (*observed*, `grep write_tx.send|encode_response`): production
  paths are only `connection.rs:386/440` and `dispatch.rs:2525/2538`.
  `connection.rs:641,716` are tests. `FramedResponse::Encrypted` passthrough
  stays unused and is removed or made unreachable so it can't bypass
  `finalize_frame`. The audit is re-run at step 7.
- **Policy vs signing order:** with the default `signing = required`, an
  unsigned plaintext request on an `encrypt_data` session is discarded by
  `verify_frame` before the ACCESS_DENIED check can run. Step 0 pins the
  normative order (3.3.5.2.x). Tests cover both a **signed** and an
  **unsigned** plaintext violation.
- Encrypted SESSION_SETUP (re-auth/binding) is rejected **before** the auth
  and preauth handlers mutate state. An assertion on the response directive
  is too late.

### 14.5 Nonce correctness
- Non-wrapping allocator: `fetch_update` that fails at the limit and leaves
  a permanently exhausted state. Concurrent boundary test.
- Uniqueness must hold **per key**, not per SessionId. The 3.0.x legacy KDF
  doesn't include the SessionId, so the same session key gives the same
  directional key. NTLM session keys are fresh per authentication, so keys
  don't repeat in practice. Document this assumption, and keep re-auth and
  binding rejected, because those could reset counters under a retained key.
  Future multichannel support must share one allocator per key across
  channels.
- Per-key usage limits for GCM/CCM (invocation and data limits) are a
  separate question from nonce exhaustion. Don't claim "safe until u64::MAX".
  Step 0 records the applicable bound. If it is reachable at 64 KiB I/O, the
  connection is torn down at a conservative limit.

### 14.6 Atomic installation and lifecycle
- Derive the signing key and both encryption keys **before** publishing any
  session state. On any failure, clean up pending auth, preauth and every
  key. Re-read the earlier success-return branch (`dispatch.rs:999-1005`) so
  that policy and key installation can't be bypassed.
- *Observed:* signing state is retired with `retain(!retiring)` **before**
  enqueue (`connection.rs:435`). Define retirement as "after protection is
  applied" for the LOGOFF frame. `EncryptionState` is held as `Arc` leases
  so in-flight async senders keep a valid key until they finish, and a broad
  `retain` must not remove state another outstanding response needs.

### 14.7 Fixtures and header construction
- `EncryptedHeader` has private fields (`reserved`, `_flags`); *observed*
  `encrypted.rs:24-28`. Build the 52-byte header ourselves as raw bytes in
  `crypto.rs` (smb-msg is used only for parsing), or add a constructor via
  the patch. Test reserved bytes, flags = 1, and the tag byte order
  (`u128` LE).
- The two smb-msg transform tests are serialization fixtures, **not** AEAD
  KATs. Use exact published vectors for AES-128-GCM (12-byte nonce) and
  AES-128-CCM (11-byte nonce, 16-byte tag), with no "adapted" vectors, or
  clearly attributed self-generated fixtures cross-checked against an
  independent implementation (e.g. Python `cryptography`, in the sandbox).

### 14.8 Live acceptance criteria
- `smbclient -m` sets a *maximum* dialect. Record the version, and confirm the
  negotiated dialect from server logs.
- Evidence of encryption = captured `0xFD 'SMB'` frames (tcpdump to stdout
  from the container, see 7c) plus the negotiated cipher in server logs. A
  session flag log alone is not enough. Under `desired`, the server does not
  set `SessionFlags.encrypt_data`. Client-initiated encryption is still
  accepted and answered encrypted.
- Record the smbclient, kernel and impacket versions.
- `desired` rejects plaintext only when the **target share** requires
  encryption.
