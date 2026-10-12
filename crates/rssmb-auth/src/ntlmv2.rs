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
    })
}

/// Extract the 8-byte ServerChallenge from a CHALLENGE (type 2) message.
pub fn server_challenge(challenge_msg: &[u8]) -> Option<[u8; 8]> {
    if challenge_msg.len() < 32 || &challenge_msg[..8] != b"NTLMSSP\0" || u32_le(challenge_msg, 8)? != 2 {
        return None;
    }
    challenge_msg[24..32].try_into().ok()
}

/// Verify an NTLMv2 response. Returns false for NTLMv1-length responses,
/// malformed input, or a proof mismatch. Comparison is constant-time.
pub fn verify(fields: &AuthenticateFields, password: &str, server_challenge: &[u8; 8]) -> bool {
    // NTLMv2 responses are NTProofStr(16) + blob (>= 28 bytes header).
    if fields.nt_response.len() < 16 + 28 {
        return false;
    }
    let nt_hash = Md4::digest(string_to_utf16le(password));

    let user_upper = utf16le_to_string(&fields.user_utf16).to_uppercase();
    let mut ident = string_to_utf16le(&user_upper);
    ident.extend_from_slice(&fields.domain_utf16);

    let mut mac = <HmacMd5 as Mac>::new_from_slice(&nt_hash).expect("any key length");
    mac.update(&ident);
    let ntowf_v2 = mac.finalize().into_bytes();

    let (proof, blob) = fields.nt_response.split_at(16);
    let mut mac = <HmacMd5 as Mac>::new_from_slice(&ntowf_v2).expect("any key length");
    mac.update(server_challenge);
    mac.update(blob);
    mac.verify_slice(proof).is_ok()
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
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
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
            0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c,
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
        assert!(verify(&f, "Password", &sc), "user name is upper-cased before hashing");
        let (mut f, sc) = ms_nlmp_vector();
        f.domain_utf16 = string_to_utf16le("DOMAIN");
        assert!(!verify(&f, "Password", &sc), "domain is hashed as sent, case-sensitively");
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
}
