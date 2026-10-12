//! SPNEGO `mechListMIC` for NTLM (RFC 4178 §5; MS-NLMP 3.4.4.2 / 3.4.5).
//!
//! When the client's AUTHENTICATE carries a MIC, Samba's client (libsmbclient,
//! used by GVFS / GNOME Files and smbclient) and Windows sign the DER-encoded
//! mechTypes list with NTLM session security and send it as `mechListMIC`.
//! They then refuse a final negTokenResp that does not carry the server's
//! own `mechListMIC` (Samba reports NT_STATUS_INVALID_NETWORK_RESPONSE).
//!
//! An NTLM message signature with extended session security is
//! `Version(1) | Checksum(8) | SeqNum(4)`, where
//! `Checksum = HMAC_MD5(SigningKey, SeqNum || Message)[0..8]`, additionally
//! RC4-encrypted with the direction's sealing key when key exchange was
//! negotiated. Both MICs are the first message on their direction's RC4
//! handle, so a fresh RC4 state and SeqNum 0 are correct here.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
pub const FLAG_ESS: u32 = 0x0008_0000;
/// NTLMSSP_NEGOTIATE_128
pub const FLAG_128: u32 = 0x2000_0000;
/// NTLMSSP_NEGOTIATE_KEY_EXCH
pub const FLAG_KEY_EXCH: u32 = 0x4000_0000;

const C2S_SIGN: &[u8] = b"session key to client-to-server signing key magic constant\0";
const S2C_SIGN: &[u8] = b"session key to server-to-client signing key magic constant\0";
const C2S_SEAL: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const S2C_SEAL: &[u8] = b"session key to server-to-client sealing key magic constant\0";

/// Which side produced the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

fn md5_concat(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Minimal RC4 (only used for the 8-byte MIC checksum).
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (k, v) in s.iter_mut().enumerate() {
            *v = k as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

/// Whether the negotiated flags are a combination we can sign for:
/// extended session security with 128-bit keys (the sealing key is then
/// the full MD5 output). Anything else → no MIC is exchanged.
pub fn supported(neg_flags: u32) -> bool {
    neg_flags & FLAG_ESS != 0 && neg_flags & FLAG_128 != 0
}

/// Compute the 16-byte NTLM signature of `msg` for `dir` with SeqNum `seq`,
/// as the first message on that direction's RC4 handle.
pub fn sign(exported_session_key: &[u8], neg_flags: u32, dir: Direction, seq: u32, msg: &[u8]) -> [u8; 16] {
    let (sign_magic, seal_magic) = match dir {
        Direction::ClientToServer => (C2S_SIGN, C2S_SEAL),
        Direction::ServerToClient => (S2C_SIGN, S2C_SEAL),
    };
    let signing_key = md5_concat(exported_session_key, sign_magic);
    let mut mac = <HmacMd5 as Mac>::new_from_slice(&signing_key).expect("any key length");
    mac.update(&seq.to_le_bytes());
    mac.update(msg);
    let digest = mac.finalize().into_bytes();
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&digest[..8]);
    if neg_flags & FLAG_KEY_EXCH != 0 {
        let sealing_key = md5_concat(exported_session_key, seal_magic);
        Rc4::new(&sealing_key).apply(&mut checksum);
    }
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..12].copy_from_slice(&checksum);
    out[12..].copy_from_slice(&seq.to_le_bytes());
    out
}

/// Constant-time check of a client's mechListMIC (SeqNum 0).
pub fn verify_client(exported_session_key: &[u8], neg_flags: u32, mech_types: &[u8], mic: &[u8]) -> bool {
    if mic.len() != 16 {
        return false;
    }
    let expected = sign(exported_session_key, neg_flags, Direction::ClientToServer, 0, mech_types);
    expected.iter().zip(mic).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_answer() {
        // Classic test vector: key "Key", plaintext "Plaintext".
        let mut data = *b"Plaintext";
        Rc4::new(b"Key").apply(&mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn signature_layout_and_direction() {
        let key = [0x55u8; 16];
        let flags = FLAG_ESS | FLAG_128 | FLAG_KEY_EXCH;
        let s = sign(&key, flags, Direction::ServerToClient, 0, b"mechtypes");
        assert_eq!(&s[..4], &[1, 0, 0, 0], "version 1");
        assert_eq!(&s[12..], &[0, 0, 0, 0], "seqnum 0");
        let c = sign(&key, flags, Direction::ClientToServer, 0, b"mechtypes");
        assert_ne!(s, c, "directions use different keys");
        assert!(verify_client(&key, flags, b"mechtypes", &c));
        assert!(!verify_client(&key, flags, b"mechtypes", &s));
        assert!(!verify_client(&key, flags, b"other", &c));
    }

    #[test]
    fn key_exch_changes_checksum() {
        let key = [0x11u8; 16];
        let with = sign(&key, FLAG_ESS | FLAG_128 | FLAG_KEY_EXCH, Direction::ServerToClient, 0, b"m");
        let without = sign(&key, FLAG_ESS | FLAG_128, Direction::ServerToClient, 0, b"m");
        assert_ne!(with[4..12], without[4..12]);
    }
}
