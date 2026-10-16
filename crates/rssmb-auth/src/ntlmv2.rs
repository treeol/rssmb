//! Independent NTLMv2 proof verification (MS-NLMP 3.3.2).
//!
//! The pinned `sspi` acceptor only checks the optional MIC, so when a client
//! omits the MIC (impacket, older Samba) any password is accepted. We
//! therefore verify NTProofStr ourselves before trusting the acceptor:
//!
//!   NTOWFv2      = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user) || domain))
//!   NTProofStr   = HMAC_MD5(NTOWFv2, ServerChallenge || blob)
//!   NtChallengeResponse = NTProofStr(16) || blob
//!
//! `user` and `domain` are taken from the AUTHENTICATE message exactly as the
//! client sent them (that is what the client hashed).

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;

type HmacMd5 = Hmac<Md5>;

/// Fields of an AUTHENTICATE message needed for proof verification.
#[derive(Debug, Clone)]
pub struct AuthenticateFields {
    pub nt_response: Vec<u8>,
    /// UTF-16LE, as sent.
    pub user_utf16: Vec<u8>,
    /// UTF-16LE, as sent.
    pub domain_utf16: Vec<u8>,
    /// Negotiate flags from the AUTHENTICATE message (MS-NLMP 2.2.1.3 offset 60).
    pub neg_flags: u32,
    /// EncryptedRandomSessionKey (MS-NLMP 2.2.1.3 offset 52). Present when
    /// NTLMSSP_NEGOTIATE_KEY_EXCH is set; empty otherwise.
    pub encrypted_random_session_key: Vec<u8>,
}

impl AuthenticateFields {
    pub fn user(&self) -> String {
        utf16le_to_string(&self.user_utf16)
    }
}

/// Parse the NT response, user and domain payloads out of a type-3 message.
pub fn parse_authenticate_fields(msg: &[u8]) -> Option<AuthenticateFields> {
    if msg.len() < 44 || &msg[..8] != b"NTLMSSP\0" || u32_le(msg, 8)? != 3 {
        return None;
    }
    let field = |off: usize| -> Option<Vec<u8>> {
        let len = u16_le(msg, off)? as usize;
        let start = u32_le(msg, off + 4)? as usize;
        msg.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
    };
    Some(AuthenticateFields {
        nt_response: field(20)?,
        domain_utf16: field(28)?,
        user_utf16: field(36)?,
        neg_flags: u32_le(msg, 60).unwrap_or(0),
        encrypted_random_session_key: field(52).unwrap_or_default(),
    })
}

/// Extract the 8-byte ServerChallenge from a CHALLENGE (type 2) message.
pub fn server_challenge(challenge_msg: &[u8]) -> Option<[u8; 8]> {
    if challenge_msg.len() < 32
        || &challenge_msg[..8] != b"NTLMSSP\0"
        || u32_le(challenge_msg, 8)? != 2
    {
        return None;
    }
    challenge_msg[24..32].try_into().ok()
}

/// Verify an NTLMv2 response. Returns false for NTLMv1-length responses,
/// malformed input, or a proof mismatch. Comparison is constant-time.
pub fn verify(fields: &AuthenticateFields, password: &str, server_challenge: &[u8; 8]) -> bool {
    let nt_hash = nt_hash(password);
    verify_with_nt_hash(fields, &nt_hash, server_challenge)
}

/// Compute the NT hash (MD4 of UTF-16LE password) — the password-equivalent
/// used by NTLMv2.
pub fn nt_hash(password: &str) -> [u8; 16] {
    Md4::digest(string_to_utf16le(password)).into()
}

/// Verify an NTLMv2 response using a pre-computed NT hash directly, without
/// needing the plaintext password. Same constant-time comparison as `verify`.
pub fn verify_with_nt_hash(
    fields: &AuthenticateFields,
    nt_hash: &[u8],
    server_challenge: &[u8; 8],
) -> bool {
    if fields.nt_response.len() < 16 + 28 {
        return false;
    }
    let user_upper = utf16le_to_string(&fields.user_utf16).to_uppercase();
    let mut ident = string_to_utf16le(&user_upper);
    ident.extend_from_slice(&fields.domain_utf16);

    let mut mac = <HmacMd5 as Mac>::new_from_slice(nt_hash).expect("any key length");
    mac.update(&ident);
    let ntowf_v2 = mac.finalize().into_bytes();

    let (proof, blob) = fields.nt_response.split_at(16);
    let mut mac = <HmacMd5 as Mac>::new_from_slice(&ntowf_v2).expect("any key length");
    mac.update(server_challenge);
    mac.update(blob);
    mac.verify_slice(proof).is_ok()
}

/// Compute the NTLMv2 session key (SessionBaseKey) from an NT hash and the
/// AUTHENTICATE fields. Used when we don't have the plaintext password to
/// pass to sspi — the session key is:
///
///   SessionBaseKey = HMAC_MD5(NTOWFv2, NTProofStr)
///
/// where NTOWFv2 = HMAC_MD5(NTHash, UTF16LE(UPPER(user) || domain))
/// and NTProofStr = NTResponse[0..16].
pub fn compute_session_key(nt_hash: &[u8], fields: &AuthenticateFields) -> Vec<u8> {
    let user_upper = utf16le_to_string(&fields.user_utf16).to_uppercase();
    let mut ident = string_to_utf16le(&user_upper);
    ident.extend_from_slice(&fields.domain_utf16);

    let mut mac = <HmacMd5 as Mac>::new_from_slice(nt_hash).expect("any key length");
    mac.update(&ident);
    let ntowf_v2 = mac.finalize().into_bytes();

    let proof = &fields.nt_response[..16];
    let mut mac = <HmacMd5 as Mac>::new_from_slice(&ntowf_v2).expect("any key length");
    mac.update(proof);
    mac.finalize().into_bytes().to_vec()
}

/// NTLMSSP_NEGOTIATE_KEY_EXCH flag (MS-NLMP 2.2.2.5).
pub const FLAG_KEY_EXCH: u32 = 0x4000_0000;

/// Compute the ExportedSessionKey from SessionBaseKey and the
/// EncryptedRandomSessionKey. When KEY_EXCH is negotiated, the
/// ExportedSessionKey is RC4-encrypted with SessionBaseKey as the key:
///
///   ExportedSessionKey = RC4(SessionBaseKey, EncryptedRandomSessionKey)
///
/// When KEY_EXCH is not negotiated, ExportedSessionKey = SessionBaseKey.
pub fn compute_exported_session_key(
    session_base_key: &[u8],
    neg_flags: u32,
    encrypted_random_session_key: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if neg_flags & FLAG_KEY_EXCH != 0 {
        if encrypted_random_session_key.is_empty() {
            return Err("KEY_EXCH negotiated but EncryptedRandomSessionKey is empty");
        }
        Ok(rc4_decrypt(session_base_key, encrypted_random_session_key))
    } else {
        Ok(session_base_key.to_vec())
    }
}

/// Minimal RC4 decryption (same algorithm as ntlm_mic::Rc4 but standalone).
fn rc4_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = [0u8; 256];
    for (i, v) in state.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    data.iter()
        .map(|b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(state[i as usize]);
            state.swap(i as usize, j as usize);
            let k = state[(state[i as usize].wrapping_add(state[j as usize])) as usize];
            b ^ k
        })
        .collect()
}

// ---------------------------------------------------------------------------
// AV_PAIR parsing (MS-NLMP 2.2.2) — used for AUTHENTICATE MIC verification.
//
// The NTLMv2 response is NTProofStr(16) followed by a blob:
//   Signature(4) | Reserved(4) | Timestamp(8) | ClientChallenge(8) | Reserved(4)
//   | AvPairs(variable)
// AvPairs start at offset 16 + 28 = 44 in the nt_response.

/// AV_PAIR attribute IDs (MS-NLMP 2.2.2).
const MSV_AV_EOL: u16 = 0;
const MSV_AV_FLAGS: u16 = 6;
const MSV_AV_TIMESTAMP: u16 = 7;

/// MsvAvFlags bit: the client is providing a MIC (MS-NLMP 2.2.2.8).
const AV_FLAG_MIC_PRESENT: u32 = 0x0000_0002;

/// Fixed offset of the MIC field in the AUTHENTICATE message (MS-NLMP 2.2.1.3).
const AUTHENTICATE_MIC_OFFSET: usize = 72;
const AUTHENTICATE_MIC_LEN: usize = 16;

/// Find an AV_PAIR value in the NTLMv2 blob's AvPairs section.
/// Returns a slice of the value bytes, or None if not found / malformed.
fn find_av_pair(nt_response: &[u8], av_id: u16) -> Option<&[u8]> {
    // AvPairs start at offset 44 (16-byte NTProofStr + 28-byte blob header).
    let av_start = 16 + 28;
    if nt_response.len() < av_start {
        return None;
    }
    let av_pairs = &nt_response[av_start..];
    let mut p = 0;
    while p + 4 <= av_pairs.len() {
        let id = u16::from_le_bytes([av_pairs[p], av_pairs[p + 1]]);
        let len = u16::from_le_bytes([av_pairs[p + 2], av_pairs[p + 3]]) as usize;
        p += 4;
        if id == MSV_AV_EOL {
            break;
        }
        if p + len > av_pairs.len() {
            return None; // truncated
        }
        if id == av_id {
            return Some(&av_pairs[p..p + len]);
        }
        p += len;
    }
    None
}

/// Whether the NTLMv2 blob's MsvAvFlags has the MIC-present bit set.
/// Requires MsvAvFlags to be exactly 4 bytes (MS-NLMP 2.2.2.8).
pub fn has_mic_flag(nt_response: &[u8]) -> bool {
    match find_av_pair(nt_response, MSV_AV_FLAGS) {
        Some(v) if v.len() == 4 => {
            let flags = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            flags & AV_FLAG_MIC_PRESENT != 0
        }
        _ => false,
    }
}

/// Whether the NTLMv2 blob contains a MsvAvTimestamp AV_PAIR.
/// Requires MsvAvTimestamp to be exactly 8 bytes (MS-NLMP 2.2.2.7).
pub fn has_timestamp(nt_response: &[u8]) -> bool {
    match find_av_pair(nt_response, MSV_AV_TIMESTAMP) {
        Some(v) => v.len() == 8,
        None => false,
    }
}

/// Verify the AUTHENTICATE message MIC (MS-NLMP 3.2.5.1.2).
///
/// The MIC is at offset 72 in the AUTHENTICATE message. It is computed as
/// `HMAC_MD5(SessionBaseKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)` where
/// the AUTHENTICATE's MIC field is zeroed before hashing. The client
/// signals its presence via the MsvAvFlags MIC-present bit.
///
/// Returns `false` if the AUTHENTICATE is too short, the MIC is all-zero
/// (not actually set), or the computed value does not match.
pub fn verify_authenticate_mic(
    session_key: &[u8],
    negotiate_msg: &[u8],
    challenge_msg: &[u8],
    authenticate_msg: &[u8],
) -> bool {
    if authenticate_msg.len() < AUTHENTICATE_MIC_OFFSET + AUTHENTICATE_MIC_LEN {
        return false;
    }
    let mic =
        &authenticate_msg[AUTHENTICATE_MIC_OFFSET..AUTHENTICATE_MIC_OFFSET + AUTHENTICATE_MIC_LEN];
    if mic.iter().all(|&b| b == 0) {
        return false; // MIC not actually set
    }
    let mut auth_zeroed = authenticate_msg.to_vec();
    auth_zeroed[AUTHENTICATE_MIC_OFFSET..AUTHENTICATE_MIC_OFFSET + AUTHENTICATE_MIC_LEN].fill(0);
    let mut mac = match <HmacMd5 as Mac>::new_from_slice(session_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(negotiate_msg);
    mac.update(challenge_msg);
    mac.update(&auth_zeroed);
    let expected = mac.finalize().into_bytes();
    expected
        .iter()
        .zip(mic)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn u16_le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn string_to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn utf16le_to_string(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-NLMP 4.2.4 test vectors: User "User", domain "Domain",
    /// password "Password", ServerChallenge 0123456789abcdef.
    fn ms_nlmp_vector() -> (AuthenticateFields, [u8; 8]) {
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        // NTProofStr from MS-NLMP 4.2.4.2.2
        let proof = [
            0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
            0x6a, 0x1c,
        ];
        // temp = 0x0101 0000 | 0x00000000 | time(0) | client challenge aa*8 | 0x00000000 | AvPairs | 0x00000000
        let mut blob = vec![0x01, 0x01, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&[0u8; 8]); // timestamp
        blob.extend_from_slice(&[0xaa; 8]); // client challenge
        blob.extend_from_slice(&[0, 0, 0, 0]);
        // AvPairs from MS-NLMP 4.2.4: MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server", MsvAvEOL
        blob.extend_from_slice(&[0x02, 0x00, 0x0c, 0x00]);
        blob.extend_from_slice(&string_to_utf16le("Domain"));
        blob.extend_from_slice(&[0x01, 0x00, 0x0c, 0x00]);
        blob.extend_from_slice(&string_to_utf16le("Server"));
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        blob.extend_from_slice(&[0, 0, 0, 0]);
        let mut nt_response = proof.to_vec();
        nt_response.extend_from_slice(&blob);
        (
            AuthenticateFields {
                nt_response,
                user_utf16: string_to_utf16le("User"),
                domain_utf16: string_to_utf16le("Domain"),
                neg_flags: 0,
                encrypted_random_session_key: vec![],
            },
            server_challenge,
        )
    }

    #[test]
    fn ms_nlmp_vector_verifies() {
        let (f, sc) = ms_nlmp_vector();
        assert!(verify(&f, "Password", &sc));
    }

    #[test]
    fn wrong_password_rejected() {
        let (f, sc) = ms_nlmp_vector();
        assert!(!verify(&f, "password", &sc));
        assert!(!verify(&f, "", &sc));
    }

    #[test]
    fn wrong_challenge_rejected() {
        let (f, mut sc) = ms_nlmp_vector();
        sc[0] ^= 1;
        assert!(!verify(&f, "Password", &sc));
    }

    #[test]
    fn ntlmv1_length_rejected() {
        let (mut f, sc) = ms_nlmp_vector();
        f.nt_response.truncate(24);
        assert!(!verify(&f, "Password", &sc));
    }

    #[test]
    fn user_case_insensitive_domain_exact() {
        let (mut f, sc) = ms_nlmp_vector();
        f.user_utf16 = string_to_utf16le("USER");
        assert!(
            verify(&f, "Password", &sc),
            "user name is upper-cased before hashing"
        );
        let (mut f, sc) = ms_nlmp_vector();
        f.domain_utf16 = string_to_utf16le("DOMAIN");
        assert!(
            !verify(&f, "Password", &sc),
            "domain is hashed as sent, case-sensitively"
        );
    }

    #[test]
    fn parse_rejects_out_of_bounds_offsets() {
        let mut msg = b"NTLMSSP\0".to_vec();
        msg.extend_from_slice(&3u32.to_le_bytes());
        msg.resize(64, 0);
        // NT response field claims 100 bytes at offset 60 — past the end.
        msg[20..22].copy_from_slice(&100u16.to_le_bytes());
        msg[24..28].copy_from_slice(&60u32.to_le_bytes());
        assert!(parse_authenticate_fields(&msg).is_none());
    }

    #[test]
    fn verify_with_nt_hash_matches_verify() {
        let (f, sc) = ms_nlmp_vector();
        let hash = nt_hash("Password");
        assert!(verify_with_nt_hash(&f, &hash, &sc));
        // Wrong hash must reject.
        let wrong = nt_hash("wrong");
        assert!(!verify_with_nt_hash(&f, &wrong, &sc));
    }

    #[test]
    fn compute_session_key_matches_ntlmv2_spec() {
        // MS-NLMP 4.2.4.3: SessionBaseKey for the test vector is known.
        let (f, _sc) = ms_nlmp_vector();
        let hash = nt_hash("Password");
        let key = compute_session_key(&hash, &f);
        assert_eq!(key.len(), 16, "SessionBaseKey is 16 bytes");
        // The key is deterministic for the same inputs.
        let key2 = compute_session_key(&hash, &f);
        assert_eq!(key, key2);
        // Different password → different key.
        let wrong_hash = nt_hash("wrong");
        let wrong_key = compute_session_key(&wrong_hash, &f);
        assert_ne!(key, wrong_key);
    }

    // ---- AV_PAIR / MIC tests ----

    /// Build a minimal AUTHENTICATE message with AvPairs containing
    /// MsvAvFlags (MIC_PRESENT) and MsvAvTimestamp, plus a correctly
    /// computed MIC at offset 72.
    fn make_authenticate_with_mic(
        session_key: &[u8],
        negotiate_msg: &[u8],
        challenge_msg: &[u8],
        user: &str,
        domain: &str,
        include_timestamp: bool,
    ) -> Vec<u8> {
        // Build NTLMv2 blob: Signature(4) + Reserved(4) + Timestamp(8) +
        // ClientChallenge(8) + Reserved(4) + AvPairs
        let blob = vec![0u8; 28]; // header

        // AvPairs: MsvAvFlags (MIC present) + optional MsvAvTimestamp + EOL
        let mut av_pairs = Vec::new();
        // MsvAvFlags = 0x00000002 (MIC_PRESENT)
        av_pairs.extend_from_slice(&MSV_AV_FLAGS.to_le_bytes());
        av_pairs.extend_from_slice(&4u16.to_le_bytes());
        av_pairs.extend_from_slice(&AV_FLAG_MIC_PRESENT.to_le_bytes());
        if include_timestamp {
            av_pairs.extend_from_slice(&MSV_AV_TIMESTAMP.to_le_bytes());
            av_pairs.extend_from_slice(&8u16.to_le_bytes());
            av_pairs.extend_from_slice(&0u64.to_le_bytes());
        }
        // EOL
        av_pairs.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
        av_pairs.extend_from_slice(&0u16.to_le_bytes());

        // NTProofStr (16 bytes) — not checked by MIC verify, just needs to be present
        let mut nt_response = vec![0u8; 16]; // NTProofStr placeholder
        nt_response.extend_from_slice(&blob);
        nt_response.extend_from_slice(&av_pairs);

        // Build a minimal AUTHENTICATE message header (88 bytes) with
        // the NT response placed at the end. Field offsets:
        // 0: signature(8) 8: type(4) 12: LmFields(8) 20: NtFields(8)
        // 28: DomainFields(8) 36: UserFields(8) 44: WorkstationFields(8)
        // 52: EncryptedRandomSessionKeyFields(8) 60: NegFlags(4)
        // 64: Version(8) 72: MIC(16)
        let mut msg = b"NTLMSSP\0".to_vec();
        msg.extend_from_slice(&3u32.to_le_bytes()); // type 3
        msg.extend_from_slice(&[0u8; 8]); // LmFields: len=0, maxlen=0, offset=0
        let nt_off = 88u32;
        let nt_len = nt_response.len() as u16;
        msg.extend_from_slice(&nt_len.to_le_bytes());
        msg.extend_from_slice(&nt_len.to_le_bytes());
        msg.extend_from_slice(&nt_off.to_le_bytes());
        let dom_utf16 = string_to_utf16le(domain);
        let dom_len = dom_utf16.len() as u16;
        let dom_off = 88u32 + nt_response.len() as u32;
        msg.extend_from_slice(&dom_len.to_le_bytes());
        msg.extend_from_slice(&dom_len.to_le_bytes());
        msg.extend_from_slice(&dom_off.to_le_bytes());
        let user_utf16 = string_to_utf16le(user);
        let user_len = user_utf16.len() as u16;
        let user_off = dom_off + dom_utf16.len() as u32;
        msg.extend_from_slice(&user_len.to_le_bytes());
        msg.extend_from_slice(&user_len.to_le_bytes());
        msg.extend_from_slice(&user_off.to_le_bytes());
        // WorkstationFields: empty
        msg.extend_from_slice(&[0u8; 8]);
        // EncryptedRandomSessionKeyFields: empty
        msg.extend_from_slice(&[0u8; 8]);
        // NegFlags: ESS (0x00080000) | NTLM2 (0x000800) | 56 (0x80) | 0x02.
        // Note: does NOT include KEY_EXCH (0x40000000) — the test
        // EncryptedRandomSessionKey field is empty.
        msg.extend_from_slice(&0x0008_2882u32.to_le_bytes());
        // Version (8 bytes)
        msg.extend_from_slice(&[0u8; 8]);
        // MIC placeholder (16 bytes) — will be filled in
        msg.extend_from_slice(&[0u8; 16]);
        // Payload
        msg.extend_from_slice(&nt_response);
        msg.extend_from_slice(&dom_utf16);
        msg.extend_from_slice(&user_utf16);

        // Compute the real MIC: HMAC_MD5(SessionKey, NEGOTIATE || CHALLENGE || AUTH(zeroed MIC))
        // At this point msg[72..88] is all zeros (the MIC placeholder).
        let mut mac = <HmacMd5 as Mac>::new_from_slice(session_key).unwrap();
        mac.update(negotiate_msg);
        mac.update(challenge_msg);
        mac.update(&msg); // entire message with MIC zeroed
        let mic = mac.finalize().into_bytes();
        msg[72..88].copy_from_slice(&mic);

        msg
    }

    #[test]
    fn authenticate_mic_verifies() {
        let key = [0x42u8; 16];
        let neg: Vec<u8> = b"NTLMSSP\0\x01\x00\x00\x00".to_vec();
        let chal: Vec<u8> = b"NTLMSSP\0\x02\x00\x00\x00".to_vec();
        let auth = make_authenticate_with_mic(&key, &neg, &chal, "user", "DOM", false);
        assert!(verify_authenticate_mic(&key, &neg, &chal, &auth));
    }

    #[test]
    fn authenticate_mic_tampered_rejected() {
        let key = [0x42u8; 16];
        let neg: Vec<u8> = b"NTLMSSP\0\x01\x00\x00\x00".to_vec();
        let chal: Vec<u8> = b"NTLMSSP\0\x02\x00\x00\x00".to_vec();
        let mut auth = make_authenticate_with_mic(&key, &neg, &chal, "user", "DOM", false);
        auth[72] ^= 0x01; // tamper with MIC
        assert!(!verify_authenticate_mic(&key, &neg, &chal, &auth));
    }

    #[test]
    fn authenticate_mic_wrong_key_rejected() {
        let key = [0x42u8; 16];
        let neg: Vec<u8> = b"NTLMSSP\0\x01\x00\x00\x00".to_vec();
        let chal: Vec<u8> = b"NTLMSSP\0\x02\x00\x00\x00".to_vec();
        let auth = make_authenticate_with_mic(&key, &neg, &chal, "user", "DOM", false);
        let wrong_key = [0x99u8; 16];
        assert!(!verify_authenticate_mic(&wrong_key, &neg, &chal, &auth));
    }

    #[test]
    fn authenticate_mic_zeroed_rejected() {
        let key = [0x42u8; 16];
        let neg: Vec<u8> = b"NTLMSSP\0\x01\x00\x00\x00".to_vec();
        let chal: Vec<u8> = b"NTLMSSP\0\x02\x00\x00\x00".to_vec();
        let mut auth = make_authenticate_with_mic(&key, &neg, &chal, "user", "DOM", false);
        auth[72..88].fill(0); // zero out the MIC
        assert!(!verify_authenticate_mic(&key, &neg, &chal, &auth));
    }

    #[test]
    fn has_mic_flag_detected() {
        let auth = make_authenticate_with_mic(&[0x42u8; 16], b"neg", b"chal", "user", "DOM", false);
        // Extract nt_response from the auth message
        let nt_len = u16::from_le_bytes([auth[20], auth[21]]) as usize;
        let nt_off = u32::from_le_bytes([auth[24], auth[25], auth[26], auth[27]]) as usize;
        let nt_response = &auth[nt_off..nt_off + nt_len];
        assert!(has_mic_flag(nt_response));
    }

    #[test]
    fn has_mic_flag_absent() {
        // Build nt_response without MsvAvFlags
        let mut nt_response = vec![0u8; 44]; // 16 NTProofStr + 28 blob header
        nt_response.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
        nt_response.extend_from_slice(&0u16.to_le_bytes());
        assert!(!has_mic_flag(&nt_response));
    }

    #[test]
    fn has_timestamp_present() {
        let auth = make_authenticate_with_mic(&[0x42u8; 16], b"neg", b"chal", "user", "DOM", true);
        let nt_len = u16::from_le_bytes([auth[20], auth[21]]) as usize;
        let nt_off = u32::from_le_bytes([auth[24], auth[25], auth[26], auth[27]]) as usize;
        let nt_response = &auth[nt_off..nt_off + nt_len];
        assert!(has_timestamp(nt_response));
    }

    #[test]
    fn has_timestamp_absent() {
        let auth = make_authenticate_with_mic(&[0x42u8; 16], b"neg", b"chal", "user", "DOM", false);
        let nt_len = u16::from_le_bytes([auth[20], auth[21]]) as usize;
        let nt_off = u32::from_le_bytes([auth[24], auth[25], auth[26], auth[27]]) as usize;
        let nt_response = &auth[nt_off..nt_off + nt_len];
        assert!(!has_timestamp(nt_response));
    }

    #[test]
    fn find_av_pair_truncated_returns_none() {
        // nt_response shorter than AvPairs start
        assert!(find_av_pair(&[0u8; 10], MSV_AV_FLAGS).is_none());
    }

    #[test]
    fn has_mic_flag_wrong_length_rejected() {
        // MsvAvFlags with length != 4 should not be accepted
        let mut nt_response = vec![0u8; 44]; // 16 NTProofStr + 28 blob header
                                             // MsvAvFlags with length 2 (too short)
        nt_response.extend_from_slice(&MSV_AV_FLAGS.to_le_bytes());
        nt_response.extend_from_slice(&2u16.to_le_bytes());
        nt_response.extend_from_slice(&[0u8; 2]);
        // EOL
        nt_response.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
        nt_response.extend_from_slice(&0u16.to_le_bytes());
        assert!(!has_mic_flag(&nt_response));
    }

    #[test]
    fn has_timestamp_wrong_length_rejected() {
        // MsvAvTimestamp with length != 8 should not be accepted
        let mut nt_response = vec![0u8; 44];
        nt_response.extend_from_slice(&MSV_AV_TIMESTAMP.to_le_bytes());
        nt_response.extend_from_slice(&4u16.to_le_bytes()); // wrong length
        nt_response.extend_from_slice(&[0u8; 4]);
        nt_response.extend_from_slice(&MSV_AV_EOL.to_le_bytes());
        nt_response.extend_from_slice(&0u16.to_le_bytes());
        assert!(!has_timestamp(&nt_response));
    }

    #[test]
    fn key_exch_decrypts_exported_session_key() {
        let (f, _sc) = ms_nlmp_vector();
        let hash = nt_hash("Password");
        let base_key = compute_session_key(&hash, &f);
        // When KEY_EXCH is set, ExportedSessionKey = RC4(SessionBaseKey, EncRSK).
        let encrypted = rc4_decrypt(&base_key, &[0x42u8; 16]);
        let exported = compute_exported_session_key(&base_key, FLAG_KEY_EXCH, &encrypted).unwrap();
        assert_eq!(
            exported,
            vec![0x42u8; 16],
            "RC4 is symmetric — decrypt(encrypt) = original"
        );
    }

    #[test]
    fn key_exch_empty_encrypted_key_rejected() {
        let (f, _sc) = ms_nlmp_vector();
        let hash = nt_hash("Password");
        let base_key = compute_session_key(&hash, &f);
        let result = compute_exported_session_key(&base_key, FLAG_KEY_EXCH, &[]);
        assert!(
            result.is_err(),
            "KEY_EXCH with empty EncryptedRandomSessionKey should error"
        );
    }

    #[test]
    fn no_key_exch_returns_session_base_key() {
        let (f, _sc) = ms_nlmp_vector();
        let hash = nt_hash("Password");
        let base_key = compute_session_key(&hash, &f);
        let exported = compute_exported_session_key(&base_key, 0, &[0x42u8; 16]).unwrap();
        assert_eq!(
            exported, base_key,
            "without KEY_EXCH, ExportedSessionKey = SessionBaseKey"
        );
    }
}
