//! SMB signing and crypto operations — key derivation, signing, verification.
//!
//! Implements the key-derivation and message-signing primitives described in
//! MS-SMB2 §3.1.4 and §3.2.5.
//!
//! # Dialect dispatch summary
//!
//! | Dialect      | Signing key derivation           | Sign algorithm |
//! |--------------|----------------------------------|----------------|
//! | 2.0.2 / 2.1  | Session key directly (first 16B)  | HMAC-SHA256→16  |
//! | 3.0 / 3.0.2  | SP800-108 KDF HMAC-SHA256, L=128  | AES-128-CMAC    |
//! | 3.1.1        | SP800-108 KDF HMAC-SHA256, L=128  | AES-128-CMAC    |
//!
//! For encryption/decryption:
//! - 3.0 / 3.0.2: label="SMB2AESCCM\x00", context="ServerOut\x00" / "ServerIn \x00"
//! - 3.1.1: label="SMBS2CCipherKey\x00" / "SMBC2SCipherKey\x00",
//!   context=PreauthIntegrityHashValue

use std::sync::atomic::AtomicU64;

use aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::config::DialectConfig;

/// HMAC-SHA256 alias.
type HmacSha256 = Hmac<Sha256>;

/// A 64-byte preauth integrity hash value (SHA-512 output).
pub type PreauthHashValue = [u8; 64];

/// KDF context for key derivation.
///
/// - `Legacy`: the fixed context strings used by SMB 3.0/3.0.2
///   (`"SmbSign\x00"`, `"ServerOut\x00"`, `"ServerIn \x00"`).
/// - `Preauth`: the 64-byte preauth integrity hash value used by SMB 3.1.1.
///
/// Per MS-SMB2 and the smb-rs reference implementation (`session/state.rs:41-44`),
/// 3.1.1 MUST use a preauth hash and 3.0.x MUST NOT. This is enforced in
/// release builds by `compute_signing_key` returning `Result`.
#[derive(Clone, Copy)]
pub enum KdfContext<'a> {
    /// Fixed context string (3.0/3.0.2 and 2.x).
    Legacy,
    /// Preauth integrity hash value (3.1.1 only).
    Preauth(&'a PreauthHashValue),
}

/// Error from key derivation.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("preauth hash required for dialect {0:?} but not provided")]
    MissingPreauth(DialectConfig),
    #[error("preauth hash provided but dialect {0:?} does not use it")]
    UnexpectedPreauth(DialectConfig),
}

/// SP800-108 counter-mode KDF using HMAC-SHA256 as the PRF.
///
/// Construction per NIST SP 800-108 and MS-SMB2 §3.1.4:
///   K(1) = HMAC(SK, counter(4) || label || 0x00 || context || L(4))
/// where counter is big-endian 1, 0x00 is a separator byte,
/// and L is the output length in bits (big-endian 32).
///
/// For SMB 3.x, L=128 (16 bytes output, AES-128 key size).
/// The session key is truncated to 16 bytes before use as the HMAC key.
fn kdf_sp800_108(session_key: &[u8], label: &[u8], context: &[u8], output_bits: u32) -> Vec<u8> {
    // SMB 3.x uses only the first 16 bytes of the session key as the KDF key.
    let kdf_key = &session_key[..16.min(session_key.len())];
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(kdf_key).expect("HMAC accepts any key length");
    // Counter = 1 (big-endian u32)
    mac.update(&1u32.to_be_bytes());
    // Label
    mac.update(label);
    // Separator
    mac.update(&[0x00]);
    // Context
    mac.update(context);
    // Output length in bits as big-endian u32
    mac.update(&output_bits.to_be_bytes());
    let full = mac.finalize().into_bytes();
    // Truncate to the requested number of bytes
    let output_bytes = (output_bits / 8) as usize;
    full[..output_bytes].to_vec()
}

/// Resolve a `KdfContext` to the raw context bytes for a given dialect.
///
/// Returns an error if the context/dialect combination is invalid:
/// - 3.1.1 requires `Preauth`, rejects `Legacy`.
/// - 3.0/3.0.2/2.x require `Legacy`, reject `Preauth`.
fn resolve_context<'a>(
    dialect: DialectConfig,
    ctx: KdfContext<'a>,
    legacy_fallback: &'a [u8],
) -> Result<&'a [u8], CryptoError> {
    match (dialect, ctx) {
        (DialectConfig::Smb311, KdfContext::Preauth(h)) => Ok(h),
        (DialectConfig::Smb311, KdfContext::Legacy) => Err(CryptoError::MissingPreauth(dialect)),
        (
            DialectConfig::Smb2002
            | DialectConfig::Smb21
            | DialectConfig::Smb30
            | DialectConfig::Smb302,
            KdfContext::Legacy,
        ) => Ok(legacy_fallback),
        (
            DialectConfig::Smb2002
            | DialectConfig::Smb21
            | DialectConfig::Smb30
            | DialectConfig::Smb302,
            KdfContext::Preauth(_),
        ) => Err(CryptoError::UnexpectedPreauth(dialect)),
    }
}

/// Derive the **signing key** from the session key per MS-SMB2 §3.1.4.
///
/// - SMB 2.0.2 / 2.1: The signing key IS the session key (first 16 bytes).
///   No KDF or HMAC derivation is applied.
/// - SMB 3.0 / 3.0.2: KDF(SK, label="SMB2AESCMAC\x00", context="SmbSign\x00", L=128)
/// - SMB 3.1.1: KDF(SK, label="SMBSigningKey\x00", context=PreauthIntegrityHash, L=128)
///
/// Returns a 16-byte key suitable for AES-128-CMAC or HMAC-SHA256 signing.
///
/// # Errors
/// Returns `CryptoError::MissingPreauth` if 3.1.1 is used with `Legacy` context.
/// Returns `CryptoError::UnexpectedPreauth` if 3.0.x/2.x is used with `Preauth`.
pub fn compute_signing_key(
    session_key: &[u8],
    dialect: DialectConfig,
    ctx: KdfContext,
) -> Result<Vec<u8>, CryptoError> {
    match dialect {
        DialectConfig::Smb2002 | DialectConfig::Smb21 => {
            // 2.x: signing key = session key (first 16 bytes, truncated).
            // Per MS-SMB2 §3.2.5.2.1, the session key is used directly for signing.
            // Validate context is Legacy (not Preauth).
            resolve_context(dialect, ctx, b"")?;
            let key = &session_key[..16.min(session_key.len())];
            Ok(key.to_vec())
        }
        DialectConfig::Smb30 | DialectConfig::Smb302 => {
            let context = resolve_context(dialect, ctx, b"SmbSign\x00")?;
            Ok(kdf_sp800_108(session_key, b"SMB2AESCMAC\x00", context, 128))
        }
        DialectConfig::Smb311 => {
            let context = resolve_context(dialect, ctx, b"")?;
            Ok(kdf_sp800_108(
                session_key,
                b"SMBSigningKey\x00",
                context,
                128,
            ))
        }
    }
}

/// Derive the **encryption key** (server→client direction) per MS-SMB2 §3.1.4.
///
/// - SMB 3.0 / 3.0.2: KDF(SK, label="SMB2AESCCM\x00", context="ServerOut\x00", L=128)
/// - SMB 3.1.1: KDF(SK, label="SMBS2CCipherKey\x00", context=PreauthHash, L=128)
/// - SMB 2.x: encryption not supported; returns empty vec.
///
/// Not used in 7c (encryption is 7d). Provided for 7d.
pub fn compute_encryption_key(
    session_key: &[u8],
    dialect: DialectConfig,
    ctx: KdfContext,
) -> Result<Vec<u8>, CryptoError> {
    match dialect {
        DialectConfig::Smb2002 | DialectConfig::Smb21 => {
            resolve_context(dialect, ctx, b"")?;
            Ok(Vec::new())
        }
        DialectConfig::Smb30 | DialectConfig::Smb302 => {
            let context = resolve_context(dialect, ctx, b"ServerOut\x00")?;
            Ok(kdf_sp800_108(session_key, b"SMB2AESCCM\x00", context, 128))
        }
        DialectConfig::Smb311 => {
            let context = resolve_context(dialect, ctx, b"")?;
            Ok(kdf_sp800_108(
                session_key,
                b"SMBS2CCipherKey\x00",
                context,
                128,
            ))
        }
    }
}

/// Derive the **decryption key** (client→server direction) per MS-SMB2 §3.1.4.
///
/// - SMB 3.0 / 3.0.2: KDF(SK, label="SMB2AESCCM\x00", context="ServerIn \x00", L=128)
/// - SMB 3.1.1: KDF(SK, label="SMBC2SCipherKey\x00", context=PreauthHash, L=128)
/// - SMB 2.x: not supported.
///
/// Not used in 7c (encryption is 7d). Provided for 7d.
pub fn compute_decryption_key(
    session_key: &[u8],
    dialect: DialectConfig,
    ctx: KdfContext,
) -> Result<Vec<u8>, CryptoError> {
    match dialect {
        DialectConfig::Smb2002 | DialectConfig::Smb21 => {
            resolve_context(dialect, ctx, b"")?;
            Ok(Vec::new())
        }
        DialectConfig::Smb30 | DialectConfig::Smb302 => {
            let context = resolve_context(dialect, ctx, b"ServerIn \x00")?;
            Ok(kdf_sp800_108(session_key, b"SMB2AESCCM\x00", context, 128))
        }
        DialectConfig::Smb311 => {
            let context = resolve_context(dialect, ctx, b"")?;
            Ok(kdf_sp800_108(
                session_key,
                b"SMBC2SCipherKey\x00",
                context,
                128,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// SMB 3.x message encryption (MS-SMB2 §3.2.5.3, §3.3.4.1, §3.3.5.2.1)
// ---------------------------------------------------------------------------

/// The negotiated encryption cipher.
///
/// Only AES-128-GCM is implemented in this build (the `ccm` crate requires
/// network to fetch). AES-128-CCM (needed for 3.0/3.0.2 encryption) is
/// deferred until the dependency is available. AES-256 variants are deferred
/// to a later step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// AES-128-GCM — 12-byte nonce, 16-byte tag. The primary 3.1.1 cipher.
    Aes128Gcm,
    // Aes128Ccm — deferred (ccm crate not available offline).
    // Aes256Gcm, Aes256Ccm — deferred.
}

impl Cipher {
    /// The number of significant nonce bytes (the rest of the 16-byte wire
    /// nonce is zero-padded).
    pub fn nonce_len(&self) -> usize {
        match self {
            Cipher::Aes128Gcm => 12,
        }
    }

    /// The MS-SMB2 encryption cipher ID.
    pub fn id(&self) -> u16 {
        match self {
            Cipher::Aes128Gcm => 0x0002,
        }
    }
}

/// Error from encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD decryption failed — authentication tag mismatch")]
    DecryptFailed,
    #[error("nonce space exhausted — too many encrypted messages on this session")]
    NonceExhausted,
    #[error("key length mismatch: expected 16, got {0}")]
    BadKeyLength(usize),
}

/// TRANSFORM_HEADER fixed layout (MS-SMB2 §2.2.41):
///   magic (4) | signature (16) | nonce (16) | original_message_size (4) |
///   reserved (2) | flags (2) | session_id (8) = 52 bytes
const TRANSFORM_HEADER_SIZE: usize = 52;
const TRANSFORM_MAGIC: [u8; 4] = [0xfd, 0x53, 0x4d, 0x42]; // \xfdSMB
const TRANSFORM_SIG_OFF: usize = 4;
const TRANSFORM_NONCE_OFF: usize = 20;
const TRANSORM_AAD_SIZE: usize = 32; // header[20..52] — nonce onward, excluding magic+sig

/// A source of unique nonces for encryption.
///
/// Uses a 64-bit counter in the first 8 bytes of the nonce, plus random
/// bytes for the rest of the cipher's nonce length. The counter is
/// non-wrapping (fetch_update with a permanently exhausted state), so
/// even under concurrent access it can never produce a duplicate nonce.
/// At exhaustion the allocator returns an error and the connection must
/// be terminated.
///
/// **Uniqueness assumption:** nonces are unique *per key*. The KDF does
/// not incorporate SessionId, so the same session key produces the same
/// directional key. NTLM session keys are fresh per authentication, so
/// keys don't repeat in practice. Re-authentication and session binding
/// (which could reset counters under a retained key) are rejected.
/// Future multichannel support must share one allocator per key across
/// all channels.
pub struct NonceSource {
    counter: AtomicU64,
    suffix: [u8; 8], // random bytes filling nonce[8..nonce_len]
    nonce_len: usize,
}

impl NonceSource {
    /// Create a new nonce source for the given cipher with a random suffix.
    pub fn new(cipher: Cipher) -> Self {
        use rand::RngCore;
        let mut suffix = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut suffix);
        Self {
            counter: AtomicU64::new(0),
            suffix,
            nonce_len: cipher.nonce_len(),
        }
    }

    /// Allocate the next nonce. Returns the 16-byte wire nonce (zero-padded
    /// beyond `nonce_len`) or an error if the counter is exhausted.
    pub fn next(&self) -> Result<[u8; 16], EncryptionError> {
        use std::sync::atomic::Ordering;
        // Non-wrapping increment via compare_exchange loop.
        // At u64::MAX the counter is permanently exhausted.
        let mut current = self.counter.load(Ordering::Relaxed);
        loop {
            if current == u64::MAX {
                return Err(EncryptionError::NonceExhausted);
            }
            let new = current + 1;
            match self
                .counter
                .compare_exchange(current, new, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let n = current;
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&n.to_le_bytes());
        // Fill nonce[8..nonce_len] with the random suffix.
        let fill = self.nonce_len.saturating_sub(8);
        nonce[8..8 + fill].copy_from_slice(&self.suffix[..fill]);
        // Remaining bytes (if any) stay zero.
        Ok(nonce)
    }
}

/// Build a 52-byte TRANSFORM_HEADER as raw bytes.
///
/// The `signature` field (16 bytes at offset 4) is set to zero; the caller
/// fills it with the AEAD tag after encryption. `flags` is always 1
/// (MS-SMB2: 1 = AES-128-CCM for 3.0.x, 1 = encrypted for 3.1.1).
pub fn build_transform_header(
    nonce: &[u8; 16],
    original_message_size: u32,
    session_id: u64,
) -> [u8; TRANSFORM_HEADER_SIZE] {
    let mut hdr = [0u8; TRANSFORM_HEADER_SIZE];
    hdr[..4].copy_from_slice(&TRANSFORM_MAGIC);
    // signature: zero (offset 4..20)
    hdr[TRANSFORM_NONCE_OFF..TRANSFORM_NONCE_OFF + 16].copy_from_slice(nonce);
    hdr[36..40].copy_from_slice(&original_message_size.to_le_bytes());
    // reserved: 0 (offset 40..42)
    hdr[42..44].copy_from_slice(&1u16.to_le_bytes()); // flags = 1
    hdr[44..52].copy_from_slice(&session_id.to_le_bytes());
    hdr
}

/// The 32-byte AAD for the AEAD: header bytes from Nonce onward (offset 20..52).
fn transform_aad(hdr: &[u8; TRANSFORM_HEADER_SIZE]) -> [u8; TRANSORM_AAD_SIZE] {
    hdr[TRANSFORM_NONCE_OFF..TRANSFORM_NONCE_OFF + TRANSORM_AAD_SIZE]
        .try_into()
        .unwrap()
}

/// Encrypt an SMB2 message using AES-128-GCM.
///
/// Returns the full 52-byte transform header (with the AEAD tag written into
/// the signature field) and the ciphertext (same length as plaintext).
///
/// The caller provides the 16-byte key and a fresh nonce from `NonceSource`.
/// `original_message_size` is the plaintext length (MS-SMB2 §2.2.41:
/// the size of the SMB2 message before encryption).
pub fn encrypt_message(
    key: &[u8; 16],
    nonce: &[u8; 16],
    original_message_size: u32,
    session_id: u64,
    plaintext: &mut [u8],
) -> Result<([u8; TRANSFORM_HEADER_SIZE], [u8; 16]), EncryptionError> {
    let hdr = build_transform_header(nonce, original_message_size, session_id);
    let aad = transform_aad(&hdr);
    // The AEAD nonce is the first 12 bytes (GCM) of the 16-byte wire nonce.
    let gcm_nonce = GenericArray::from_slice(&nonce[..12]);
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    // encrypt_in_place_detached: encrypts the buffer in place and returns
    // the 16-byte tag. It does NOT append the tag to the buffer.
    let tag = cipher
        .encrypt_in_place_detached(gcm_nonce, &aad, plaintext)
        .map_err(|_| EncryptionError::EncryptFailed)?;
    Ok((hdr, tag.into()))
}

/// Decrypt an SMB2 message that arrived in a TRANSFORM_HEADER frame.
///
/// `raw` is the full frame starting with `\xfdSMB` (52-byte header + ciphertext).
/// On success, `ciphertext` is replaced with the decrypted plaintext (same
/// length minus the 16-byte tag appended by the AEAD).
///
/// The AAD is computed from the raw header bytes (offset 20..52), not from
/// re-serialised fields — this ensures we authenticate exactly the bytes the
/// client sent.
pub fn decrypt_message(
    key: &[u8; 16],
    raw: &[u8], // starts with \xfdSMB, len >= 52
) -> Result<Vec<u8>, EncryptionError> {
    if raw.len() < TRANSFORM_HEADER_SIZE {
        return Err(EncryptionError::DecryptFailed);
    }
    // Validate transform header fields (MS-SMB2 §2.2.41):
    //   Flags must be 0x0001 (encrypted).
    let tf_flags = u16::from_le_bytes(raw[42..44].try_into().unwrap());
    if tf_flags != 1 {
        return Err(EncryptionError::DecryptFailed);
    }
    // OriginalMessageSize must equal the ciphertext length (the plaintext
    // length, since GCM is a stream cipher — ciphertext == plaintext len).
    let original_message_size = u32::from_le_bytes(raw[36..40].try_into().unwrap()) as usize;
    let ciphertext_len = raw.len() - TRANSFORM_HEADER_SIZE;
    if original_message_size != ciphertext_len {
        return Err(EncryptionError::DecryptFailed);
    }
    // The 16-byte wire nonce is at offset 20..36.
    let nonce = &raw[TRANSFORM_NONCE_OFF..TRANSFORM_NONCE_OFF + 16];
    // AAD = header bytes from Nonce onward (offset 20..52) = 32 bytes.
    let aad = &raw[TRANSFORM_NONCE_OFF..TRANSFORM_HEADER_SIZE];
    // The signature (AEAD tag) is at offset 4..20.
    let tag: [u8; 16] = raw[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16]
        .try_into()
        .map_err(|_| EncryptionError::DecryptFailed)?;
    // The GCM nonce is the first 12 bytes of the 16-byte wire nonce.
    let gcm_nonce = GenericArray::from_slice(&nonce[..12]);
    let ciphertext = &raw[TRANSFORM_HEADER_SIZE..];
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(gcm_nonce, aad, &mut buf, GenericArray::from_slice(&tag))
        .map_err(|_| EncryptionError::DecryptFailed)?;
    Ok(buf)
}

/// Update the preauth integrity hash: H' = SHA-512(H ‖ message).
///
/// Per MS-SMB2 §3.3.5.4 / §3.3.5.5 and the smb-rs reference
/// (`connection/preauth_hash.rs:28-38`):
/// - Start with H0 = 64 zero bytes.
/// - For each hashed message: H = SHA-512(H ‖ message_bytes).
///
/// "Message" means the exact SMB2 message bytes on the wire (header + body),
/// without the 4-byte NetBIOS header. For compound members, only that
/// member's slice.
pub fn preauth_update(hash: &PreauthHashValue, message: &[u8]) -> PreauthHashValue {
    let mut hasher = Sha512::new();
    hasher.update(hash);
    hasher.update(message);
    hasher.finalize().into()
}

/// Sign an SMB message, producing a 16-byte signature.
///
/// - SMB 2.x: `HMAC-SHA256(signing_key, message)`, truncated to 16 bytes.
/// - SMB 3.0 / 3.0.2 / 3.1.1: `AES-128-CMAC(signing_key, message)`.
///
/// The caller must zero the 16-byte `Signature` field of the SMB2 header
/// in `message` before signing.
pub fn sign_message(signing_key: &[u8], message: &[u8], dialect: DialectConfig) -> [u8; 16] {
    match dialect {
        DialectConfig::Smb2002 | DialectConfig::Smb21 => {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            let full = mac.finalize().into_bytes();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&full[..16]);
            sig
        }
        DialectConfig::Smb30 | DialectConfig::Smb302 | DialectConfig::Smb311 => {
            let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(signing_key)
                .expect("CMAC key must be 16 bytes for AES-128");
            mac.update(message);
            let full = mac.finalize();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&full.into_bytes()[..16]);
            sig
        }
    }
}

/// Verify a message signature. Returns `true` if the computed signature matches.
/// Uses constant-time comparison.
pub fn verify_signature(
    signing_key: &[u8],
    message: &[u8],
    signature: &[u8; 16],
    dialect: DialectConfig,
) -> bool {
    let computed = sign_message(signing_key, message, dialect);
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(signature.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Return the current time as a Windows FILETIME (100ns intervals since 1601-01-01).
pub fn filetime_now() -> u64 {
    const UNIX_EPOCH_DELTA_SECS: u64 = 11_644_473_600;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch");
    (UNIX_EPOCH_DELTA_SECS + now.as_secs()) * HUNDRED_NS_PER_SEC + (now.subsec_nanos() / 100) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SESSION_KEY_16: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    #[test]
    fn test_sign_verify_roundtrip_smb21_hmac() {
        let dialect = DialectConfig::Smb21;
        let key = compute_signing_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        assert_eq!(
            key.len(),
            16,
            "SMB 2.x signing key should be 16 bytes (session key)"
        );
        let message = b"hello SMB 2.1 message to sign";
        let sig = sign_message(&key, message, dialect);
        assert_eq!(sig.len(), 16);
        assert!(verify_signature(&key, message, &sig, dialect));
        let tampered = {
            let mut m = message.to_vec();
            m[0] ^= 0xff;
            m
        };
        assert!(!verify_signature(&key, &tampered, &sig, dialect));
    }

    #[test]
    fn test_sign_verify_roundtrip_smb30_cmac() {
        let dialect = DialectConfig::Smb30;
        let key = compute_signing_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        assert_eq!(
            key.len(),
            16,
            "SMB 3.0 signing key should be 16 bytes (L=128)"
        );
        let message = b"hello SMB 3.0 message to sign";
        let sig = sign_message(&key, message, dialect);
        assert_eq!(sig.len(), 16);
        assert!(verify_signature(&key, message, &sig, dialect));
        let tampered = {
            let mut m = message.to_vec();
            m[0] ^= 0x01;
            m
        };
        assert!(!verify_signature(&key, &tampered, &sig, dialect));
    }

    #[test]
    fn test_sign_verify_roundtrip_smb311_cmac() {
        let dialect = DialectConfig::Smb311;
        let preauth = [0u8; 64];
        let key = compute_signing_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Preauth(&preauth))
            .unwrap();
        assert_eq!(key.len(), 16);
        let message = b"hello SMB 3.1.1 message to sign";
        let sig = sign_message(&key, message, dialect);
        assert_eq!(sig.len(), 16);
        assert!(verify_signature(&key, message, &sig, dialect));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let dialect = DialectConfig::Smb30;
        let key1 = compute_signing_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        let key2 = compute_signing_key(&[0xff; 16], dialect, KdfContext::Legacy).unwrap();
        let message = b"some message";
        let sig = sign_message(&key1, message, dialect);
        assert!(!verify_signature(&key2, message, &sig, dialect));
    }

    #[test]
    fn test_signing_keys_differ_per_dialect() {
        let k30 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb30,
            KdfContext::Legacy,
        )
        .unwrap();
        let preauth = [0u8; 64];
        let k311 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth),
        )
        .unwrap();
        assert_ne!(k30, k311, "3.0 and 3.1.1 signing keys must differ");

        // SMB 2.1 uses session key directly — different from 3.0 KDF output.
        let k21 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb21,
            KdfContext::Legacy,
        )
        .unwrap();
        assert_ne!(k21, k30);
        // 2.1 key IS the session key (first 16 bytes).
        assert_eq!(k21, &TEST_SESSION_KEY_16[..]);
    }

    #[test]
    fn test_smb30_and_smb302_keys_match() {
        let k30 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb30,
            KdfContext::Legacy,
        )
        .unwrap();
        let k302 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb302,
            KdfContext::Legacy,
        )
        .unwrap();
        assert_eq!(k30, k302);
    }

    #[test]
    fn test_encryption_decryption_keys_differ() {
        let dialect = DialectConfig::Smb30;
        let enc =
            compute_encryption_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        let dec =
            compute_decryption_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        assert_ne!(enc, dec, "encryption and decryption keys must differ");

        let preauth = [0u8; 64];
        let enc = compute_encryption_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth),
        )
        .unwrap();
        let dec = compute_decryption_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth),
        )
        .unwrap();
        assert_ne!(enc, dec);
    }

    /// 3.1.1 uses different encryption labels than 3.0/3.0.2
    /// (SMBS2CCipherKey vs SMB2AESCCM).
    #[test]
    fn test_smb311_encryption_labels_differ_from_smb30() {
        let enc30 = compute_encryption_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb30,
            KdfContext::Legacy,
        )
        .unwrap();
        let preauth = [0u8; 64];
        let enc311 = compute_encryption_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth),
        )
        .unwrap();
        assert_ne!(enc30, enc311);
    }

    #[test]
    fn test_signing_key_is_deterministic() {
        let preauth = [0u8; 64];
        let k1 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth),
        )
        .unwrap();
        let k2 = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth),
        )
        .unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_signing_key_length_16_bytes() {
        let preauth = [0u8; 64];
        for &d in &[
            DialectConfig::Smb2002,
            DialectConfig::Smb21,
            DialectConfig::Smb30,
            DialectConfig::Smb302,
            DialectConfig::Smb311,
        ] {
            let ctx = if d == DialectConfig::Smb311 {
                KdfContext::Preauth(&preauth)
            } else {
                KdfContext::Legacy
            };
            let k = compute_signing_key(&TEST_SESSION_KEY_16, d, ctx).unwrap();
            assert_eq!(k.len(), 16, "signing key for {:?} should be 16 bytes", d);
        }
    }

    #[test]
    fn test_empty_message_signature() {
        let dialect = DialectConfig::Smb21;
        let key = compute_signing_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        let sig = sign_message(&key, &[], dialect);
        assert_eq!(sig.len(), 16);
        assert!(verify_signature(&key, &[], &sig, dialect));
    }

    #[test]
    fn test_filetime_now_is_recent() {
        let ft = filetime_now();
        assert!(
            ft > 132_500_000_000_000_000,
            "filetime_now returned {ft}, expected a value in the 2020s"
        );
        assert!(
            ft < 134_800_000_000_000_000,
            "filetime_now returned {ft}, suspiciously far in the future"
        );
    }

    #[test]
    fn test_filetime_monotonic_ish() {
        let a = filetime_now();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = filetime_now();
        assert!(b > a, "filetime should advance: {a} -> {b}");
    }

    #[test]
    fn test_smb21_signing_key_is_session_key() {
        // SMB 2.x: signing key = session key (first 16 bytes), no derivation.
        let key = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb21,
            KdfContext::Legacy,
        )
        .unwrap();
        assert_eq!(key, &TEST_SESSION_KEY_16[..]);
    }

    /// Known-answer test for the SP800-108 KDF primitive, using the vector
    /// from smb-rs/crates/smb/src/session/state.rs tests.
    /// Validates counter/separator/L encoding independently of dialect labels.
    #[test]
    fn test_kdf_sp800_108_known_answer() {
        let session_key: [u8; 16] = [
            0xDA, 0x90, 0xB1, 0xDF, 0x80, 0x5C, 0x34, 0x9F, 0x88, 0x86, 0xBA, 0x02, 0x9E, 0xA4,
            0x5C, 0xB6,
        ];
        let preauth_hash: PreauthHashValue = [
            0x47, 0x95, 0x78, 0xb1, 0x87, 0x23, 0x05, 0x6a, 0x4c, 0x3e, 0x6f, 0x73, 0x2f, 0x36,
            0xf1, 0x9c, 0xcc, 0xdd, 0x51, 0x6f, 0x49, 0x56, 0x6b, 0xa0, 0x43, 0xce, 0x59, 0x6a,
            0x13, 0x42, 0x27, 0xd9, 0x64, 0xef, 0x0a, 0xa6, 0xa6, 0x27, 0x1a, 0xfe, 0x4f, 0xe6,
            0x4b, 0x4d, 0x8c, 0xb2, 0xe6, 0xa1, 0x95, 0x11, 0xed, 0xbb, 0xf6, 0xd7, 0x7d, 0xce,
            0xf0, 0x33, 0xda, 0xed, 0x8c, 0x71, 0x81, 0xb2,
        ];
        let expected_signing_key: [u8; 16] = [
            0x6D, 0xAC, 0xCE, 0xDE, 0x5B, 0x4E, 0x36, 0x08, 0xAD, 0x6E, 0xA5, 0x47, 0x33, 0xCA,
            0x31, 0x63,
        ];
        // Test through the public API with KdfContext::Preauth.
        let derived = compute_signing_key(
            &session_key,
            DialectConfig::Smb311,
            KdfContext::Preauth(&preauth_hash),
        )
        .unwrap();
        assert_eq!(
            derived, expected_signing_key,
            "KDF output does not match known-answer vector"
        );
    }

    /// Verify that the 3.0 encryption context strings are distinct —
    /// "ServerOut\0" (no trailing space) vs "ServerIn \0" (trailing space).
    /// This catches the classic typo of forgetting the space in "ServerIn ".
    #[test]
    fn test_smb30_encryption_keys_differ_by_direction() {
        let dialect = DialectConfig::Smb30;
        let enc =
            compute_encryption_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        let dec =
            compute_decryption_key(&TEST_SESSION_KEY_16, dialect, KdfContext::Legacy).unwrap();
        assert_ne!(enc, dec, "ServerOut and ServerIn keys must differ");
        // Also verify 3.0.2 produces the same keys as 3.0
        let enc2 = compute_encryption_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb302,
            KdfContext::Legacy,
        )
        .unwrap();
        let dec2 = compute_decryption_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb302,
            KdfContext::Legacy,
        )
        .unwrap();
        assert_eq!(enc, enc2, "3.0 and 3.0.2 encryption keys must match");
        assert_eq!(dec, dec2, "3.0 and 3.0.2 decryption keys must match");
    }

    // --- KdfContext validation tests ---

    #[test]
    fn test_kdf_rejects_311_with_legacy() {
        let result = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb311,
            KdfContext::Legacy,
        );
        assert!(matches!(result, Err(CryptoError::MissingPreauth(_))));
    }

    #[test]
    fn test_kdf_rejects_30_with_preauth() {
        let preauth = [0u8; 64];
        let result = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb30,
            KdfContext::Preauth(&preauth),
        );
        assert!(matches!(result, Err(CryptoError::UnexpectedPreauth(_))));
    }

    #[test]
    fn test_kdf_rejects_21_with_preauth() {
        let preauth = [0u8; 64];
        let result = compute_signing_key(
            &TEST_SESSION_KEY_16,
            DialectConfig::Smb21,
            KdfContext::Preauth(&preauth),
        );
        assert!(matches!(result, Err(CryptoError::UnexpectedPreauth(_))));
    }

    // --- Preauth hash tests ---

    #[test]
    fn test_preauth_update_zero_initial() {
        // H0 = 64 zero bytes. H1 = SHA-512(H0 ‖ "hello").
        let h0 = [0u8; 64];
        let h1 = preauth_update(&h0, b"hello");
        assert_ne!(h1, h0);
        // Must be 64 bytes (SHA-512 output).
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_preauth_update_chains() {
        // H2 = SHA-512(H1 ‖ "world"), where H1 = SHA-512(H0 ‖ "hello").
        let h0 = [0u8; 64];
        let h1 = preauth_update(&h0, b"hello");
        let h2 = preauth_update(&h1, b"world");

        // Order matters: hashing "world" first gives a different result.
        let h1_alt = preauth_update(&h0, b"world");
        let h2_alt = preauth_update(&h1_alt, b"hello");
        assert_ne!(h2, h2_alt, "preauth hash order must matter");
    }

    #[test]
    fn test_preauth_update_deterministic() {
        let h0 = [0u8; 64];
        let h1a = preauth_update(&h0, b"test message");
        let h1b = preauth_update(&h0, b"test message");
        assert_eq!(h1a, h1b, "preauth hash must be deterministic");
    }

    #[test]
    fn test_preauth_update_empty_message() {
        let h0 = [0u8; 64];
        let h1 = preauth_update(&h0, b"");
        // SHA-512 of 64 zero bytes — a known, deterministic value.
        assert_ne!(h1, h0, "hashing empty message must change the hash");
    }

    // --- Encryption (AES-128-GCM) tests ---

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let nonce_src = NonceSource::new(Cipher::Aes128Gcm);
        let nonce = nonce_src.next().unwrap();
        let plaintext = b"Hello, SMB 3.1.1 encrypted message!".to_vec();
        let mut pt = plaintext.clone();
        let (hdr, tag) =
            encrypt_message(&key, &nonce, pt.len() as u32, 0x1234_5678, &mut pt).unwrap();
        // hdr is the 52-byte transform header (sig zeroed); tag is the AEAD tag.
        // Write the tag into the header's signature field.
        let mut full_hdr = hdr;
        full_hdr[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16].copy_from_slice(&tag);
        // The wire frame is: header + ciphertext.
        let mut wire = Vec::new();
        wire.extend_from_slice(&full_hdr);
        wire.extend_from_slice(&pt);
        // Decrypt.
        let decrypted = decrypt_message(&key, &wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = [0x42u8; 16];
        let nonce_src = NonceSource::new(Cipher::Aes128Gcm);
        let nonce = nonce_src.next().unwrap();
        let plaintext = b"sensitive data".to_vec();
        let mut pt = plaintext.clone();
        let (hdr, tag) = encrypt_message(&key, &nonce, pt.len() as u32, 42, &mut pt).unwrap();
        let mut full_hdr = hdr;
        full_hdr[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16].copy_from_slice(&tag);
        let mut wire = Vec::new();
        wire.extend_from_slice(&full_hdr);
        wire.extend_from_slice(&pt);
        // Tamper with a ciphertext byte.
        wire[TRANSFORM_HEADER_SIZE + 3] ^= 0x01;
        assert!(decrypt_message(&key, &wire).is_err());
    }

    #[test]
    fn test_decrypt_tampered_aad_fails() {
        let key = [0x42u8; 16];
        let nonce_src = NonceSource::new(Cipher::Aes128Gcm);
        let nonce = nonce_src.next().unwrap();
        let plaintext = b"sensitive data".to_vec();
        let mut pt = plaintext.clone();
        let (hdr, tag) = encrypt_message(&key, &nonce, pt.len() as u32, 42, &mut pt).unwrap();
        let mut full_hdr = hdr;
        full_hdr[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16].copy_from_slice(&tag);
        let mut wire = Vec::new();
        wire.extend_from_slice(&full_hdr);
        wire.extend_from_slice(&pt);
        // Tamper with the session_id in the AAD (offset 44..52).
        wire[44] ^= 0x01;
        assert!(decrypt_message(&key, &wire).is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = [0x42u8; 16];
        let wrong_key = [0x99u8; 16];
        let nonce_src = NonceSource::new(Cipher::Aes128Gcm);
        let nonce = nonce_src.next().unwrap();
        let plaintext = b"sensitive data".to_vec();
        let mut pt = plaintext.clone();
        let (hdr, tag) = encrypt_message(&key, &nonce, pt.len() as u32, 42, &mut pt).unwrap();
        let mut full_hdr = hdr;
        full_hdr[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16].copy_from_slice(&tag);
        let mut wire = Vec::new();
        wire.extend_from_slice(&full_hdr);
        wire.extend_from_slice(&pt);
        assert!(decrypt_message(&wrong_key, &wire).is_err());
    }

    #[test]
    fn test_decrypt_truncated_header_fails() {
        let key = [0x42u8; 16];
        let short = vec![0xfd, 0x53, 0x4d, 0x42, 0x00];
        assert!(decrypt_message(&key, &short).is_err());
    }

    #[test]
    fn test_decrypt_rejects_bad_flags() {
        let key = [0x42u8; 16];
        let nonce_src = NonceSource::new(Cipher::Aes128Gcm);
        let nonce = nonce_src.next().unwrap();
        let plaintext = b"sensitive data".to_vec();
        let mut pt = plaintext.clone();
        let (hdr, tag) = encrypt_message(&key, &nonce, pt.len() as u32, 42, &mut pt).unwrap();
        let mut full_hdr = hdr;
        full_hdr[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16].copy_from_slice(&tag);
        let mut wire = Vec::new();
        wire.extend_from_slice(&full_hdr);
        wire.extend_from_slice(&pt);
        // Corrupt the flags field (offset 42..44) from 1 to 0.
        wire[42] = 0;
        assert!(
            decrypt_message(&key, &wire).is_err(),
            "flags != 1 must be rejected"
        );
    }

    #[test]
    fn test_decrypt_rejects_size_mismatch() {
        let key = [0x42u8; 16];
        let nonce_src = NonceSource::new(Cipher::Aes128Gcm);
        let nonce = nonce_src.next().unwrap();
        let plaintext = b"sensitive data".to_vec();
        let mut pt = plaintext.clone();
        let (hdr, tag) = encrypt_message(&key, &nonce, pt.len() as u32, 42, &mut pt).unwrap();
        let mut full_hdr = hdr;
        full_hdr[TRANSFORM_SIG_OFF..TRANSFORM_SIG_OFF + 16].copy_from_slice(&tag);
        let mut wire = Vec::new();
        wire.extend_from_slice(&full_hdr);
        wire.extend_from_slice(&pt);
        // Corrupt OriginalMessageSize (offset 36..40) to a wrong value.
        wire[36] = 0xFF;
        assert!(
            decrypt_message(&key, &wire).is_err(),
            "size mismatch must be rejected"
        );
    }

    #[test]
    fn test_nonce_source_strictly_increasing() {
        let src = NonceSource::new(Cipher::Aes128Gcm);
        let n0 = src.next().unwrap();
        let n1 = src.next().unwrap();
        // The counter part (first 8 bytes, LE) must be 0 then 1.
        let c0 = u64::from_le_bytes(n0[..8].try_into().unwrap());
        let c1 = u64::from_le_bytes(n1[..8].try_into().unwrap());
        assert_eq!(c0, 0);
        assert_eq!(c1, 1);
        // Suffix (bytes 8..12 for GCM) must be the same across calls.
        assert_eq!(&n0[8..12], &n1[8..12]);
        // Bytes 12..16 must be zero (padding beyond nonce_len).
        assert_eq!(&n0[12..], &[0u8; 4]);
        assert_eq!(&n1[12..], &[0u8; 4]);
    }

    #[test]
    fn test_nonce_source_unique_concurrent() {
        use std::sync::Arc;
        use std::thread;
        let src = Arc::new(NonceSource::new(Cipher::Aes128Gcm));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&src);
            handles.push(thread::spawn(move || {
                let mut nonces = Vec::new();
                for _ in 0..1000 {
                    nonces.push(s.next().unwrap());
                }
                nonces
            }));
        }
        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        let mut seen = std::collections::HashSet::new();
        for n in &all {
            assert!(seen.insert(*n), "duplicate nonce detected");
        }
        assert_eq!(all.len(), 4000);
    }

    #[test]
    fn test_transform_header_layout() {
        let nonce = [0xAAu8; 16];
        let hdr = build_transform_header(&nonce, 0x1234_5678, 0xDEAD_BEEF_CAFE_BABE);
        // Magic.
        assert_eq!(&hdr[..4], b"\xfdSMB");
        // Signature: zero (offset 4..20).
        assert!(hdr[4..20].iter().all(|&b| b == 0));
        // Nonce (offset 20..36).
        assert_eq!(&hdr[20..36], &nonce[..]);
        // OriginalMessageSize (offset 36..40, LE).
        assert_eq!(
            u32::from_le_bytes(hdr[36..40].try_into().unwrap()),
            0x1234_5678
        );
        // Reserved (offset 40..42) = 0.
        assert_eq!(hdr[40..42], [0, 0]);
        // Flags (offset 42..44) = 1.
        assert_eq!(u16::from_le_bytes(hdr[42..44].try_into().unwrap()), 1);
        // SessionId (offset 44..52, LE).
        assert_eq!(
            u64::from_le_bytes(hdr[44..52].try_into().unwrap()),
            0xDEAD_BEEF_CAFE_BABE
        );
    }

    // ── 3.1.1 preauth/KDF end-to-end transcript golden test ──────────────
    //
    // Simulates the full SMB 3.1.1 preauth flow:
    // 1. Start with H0 = 64 zero bytes.
    // 2. Accumulate preauth hash over two mock messages (NEGOTIATE + SESSION_SETUP).
    // 3. Derive signing key from session key + final preauth hash via KDF.
    // 4. Sign a mock SMB2 message with the derived signing key (AES-128-CMAC).
    // 5. Verify the signature round-trips.
    //
    // The test validates that the full chain (preauth hash → KDF → CMAC) is
    // deterministic and self-consistent. Known-answer vectors for the KDF
    // step are from the smb-rs reference test data (test_kdf_sp800_108_known_answer
    // above); this test additionally validates the preauth hash chain and
    // CMAC signing on top of the KDF output.

    #[test]
    fn test_smb311_preauth_kdf_signing_transcript() {
        let dialect = DialectConfig::Smb311;

        // Step 1: H0 = 64 zero bytes.
        let h0: PreauthHashValue = [0u8; 64];

        // Step 2: Accumulate preauth hash over mock SMB2 messages.
        // In a real 3.1.1 session, the server hashes:
        //   - NEGOTIATE request (wire bytes)
        //   - NEGOTIATE response (wire bytes)
        //   - SESSION_SETUP request(s) (wire bytes)
        //   - SESSION_SETUP response(s) (wire bytes)
        // We use mock messages here; the test validates determinism and
        // chain correctness, not correctness of specific SMB2 bytes.
        let mock_negotiate_req = b"\xfeSMB\x00\x00\x00\x00mock_negotiate_request";
        let mock_negotiate_resp = b"\xfeSMB\x00\x00\x00\x00mock_negotiate_response";

        let h1 = preauth_update(&h0, mock_negotiate_req);
        let h2 = preauth_update(&h1, mock_negotiate_resp);

        // The preauth hash must have changed at each step.
        assert_ne!(h1, h0, "preauth hash must change after first message");
        assert_ne!(h2, h1, "preauth hash must change after second message");
        assert_eq!(h2.len(), 64, "preauth hash must be 64 bytes (SHA-512)");

        // Step 3: Derive signing key from session key + final preauth hash.
        let session_key: [u8; 16] = [
            0xDA, 0x90, 0xB1, 0xDF, 0x80, 0x5C, 0x34, 0x9F, 0x88, 0x86, 0xBA, 0x02, 0x9E, 0xA4,
            0x5C, 0xB6,
        ];
        let signing_key =
            compute_signing_key(&session_key, dialect, KdfContext::Preauth(&h2)).unwrap();
        assert_eq!(
            signing_key.len(),
            16,
            "signing key must be 16 bytes (AES-128)"
        );

        // Step 4: Sign a mock SMB2 message with AES-128-CMAC.
        // In a real session, the 16-byte Signature field in the SMB2 header
        // would be zeroed before signing. We simulate that with a mock message.
        let mock_message = b"\xfeSMB\x00\x00\x00\x00mock_signed_message_payload";
        let signature = sign_message(&signing_key, mock_message, dialect);
        assert_eq!(signature.len(), 16);

        // Step 5: Verify the signature round-trips.
        assert!(verify_signature(
            &signing_key,
            mock_message,
            &signature,
            dialect
        ));

        // Step 6: Verify tampering is detected.
        let tampered = {
            let mut m = mock_message.to_vec();
            m[4] ^= 0x01;
            m
        };
        assert!(
            !verify_signature(&signing_key, &tampered, &signature, dialect),
            "tampered message must fail signature verification"
        );

        // Step 7: Verify a different preauth hash produces a different signing key.
        let h_alt = preauth_update(&h0, b"different_message");
        let signing_key_alt =
            compute_signing_key(&session_key, dialect, KdfContext::Preauth(&h_alt)).unwrap();
        assert_ne!(
            signing_key, signing_key_alt,
            "different preauth hashes must produce different signing keys"
        );

        // Step 8: Verify the same inputs produce the same signing key (determinism).
        let signing_key_again =
            compute_signing_key(&session_key, dialect, KdfContext::Preauth(&h2)).unwrap();
        assert_eq!(
            signing_key, signing_key_again,
            "same preauth hash must produce same signing key (determinism)"
        );
    }

    /// Verify that the 3.1.1 encryption/decryption key derivation produces
    /// keys that differ from the signing key, confirming label isolation.
    #[test]
    fn test_smb311_encryption_keys_differ_from_signing_key() {
        let session_key: [u8; 16] = [0x42u8; 16];
        let preauth: PreauthHashValue = [0x55u8; 64];
        let dialect = DialectConfig::Smb311;

        let signing_key =
            compute_signing_key(&session_key, dialect, KdfContext::Preauth(&preauth)).unwrap();
        let enc_key =
            compute_encryption_key(&session_key, dialect, KdfContext::Preauth(&preauth)).unwrap();
        let dec_key =
            compute_decryption_key(&session_key, dialect, KdfContext::Preauth(&preauth)).unwrap();

        // All three keys must be different (different labels).
        assert_ne!(
            signing_key, enc_key,
            "signing and encryption keys must differ"
        );
        assert_ne!(
            signing_key, dec_key,
            "signing and decryption keys must differ"
        );
        assert_ne!(
            enc_key, dec_key,
            "encryption and decryption keys must differ"
        );
    }
}
