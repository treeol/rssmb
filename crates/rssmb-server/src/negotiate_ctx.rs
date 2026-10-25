//! SMB 3.1.1 negotiate context processing (MS-SMB2 §3.3.5.4).
//!
//! Pure functions that validate the client's negotiate contexts and produce
//! the server's response contexts. No I/O — unit-testable in isolation.

use rand::rngs::SysRng;
use rand::rand_core::UnwrapErr;
use rand::Rng;
use rssmb_proto::negotiate::{
    EncryptionCapabilities, EncryptionCipher, HashAlgorithm, NegotiateContext,
    NegotiateContextType, NegotiateRequest, PreauthIntegrityCapabilities, SigningAlgorithmId,
    TransportCapabilities,
};
use rssmb_wire_adapter::error::NtStatus;

use crate::config::EncryptionPolicy;

/// Result of processing the client's 3.1.1 negotiate contexts.
#[derive(Debug, Clone)]
pub struct Negotiated311 {
    /// Always SHA-512 (the only defined hash algorithm).
    pub preauth_hash_alg: HashAlgorithm,
    /// 32-byte random server salt.
    pub salt: Vec<u8>,
    /// Encryption cipher negotiated (None if no common cipher or encryption
    /// is disabled). Only AES-128-GCM is implemented in this build.
    pub cipher: Option<EncryptionCipher>,
    /// Signing algorithm (always AES-CMAC for 7c/7d; GMAC deferred).
    pub signing_alg: SigningAlgorithmId,
    /// Connection.AcceptTransportSecurity (MS-SMB2 3.3.5.4): true when
    /// client offered `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY` on a transport
    /// that provides transport-layer security (QUIC / TLS 1.3).
    pub accept_transport_security: bool,
}

/// The server-side cipher we implement, matched against the client's offer.
/// Only AES-128-GCM is available (the `ccm` crate is not fetchable offline).
const SERVER_CIPHERS: &[EncryptionCipher] = &[EncryptionCipher::Aes128Gcm];

/// Process the client's negotiate contexts for SMB 3.1.1.
///
/// Returns the negotiated state and the response contexts to send back.
/// Only called when dialect 3.1.1 is selected (MS-SMB2 §3.3.5.4).
///
/// `encryption_policy` controls whether we advertise a cipher and send an
/// ENCRYPTION_CAPABILITIES context in the response.
pub fn process_request_contexts(
    req: &NegotiateRequest,
    encryption_policy: EncryptionPolicy,
) -> Result<(Negotiated311, Vec<NegotiateContext>), NtStatus> {
    process_request_contexts_for_transport(req, encryption_policy, false)
}

/// Process the client's negotiate contexts for SMB 3.1.1 with transport awareness.
///
/// When `is_quic` is true and the client includes a `TransportCapabilities`
/// context with `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY`, the server sets
/// `accept_transport_security = true` and echoes the `TransportCapabilities`
/// context in the response (MS-SMB2 §2.2.3.1.5, §3.3.5.4).
pub fn process_request_contexts_for_transport(
    req: &NegotiateRequest,
    encryption_policy: EncryptionPolicy,
    is_quic: bool,
) -> Result<(Negotiated311, Vec<NegotiateContext>), NtStatus> {
    let contexts = req.negotiate_context_list.as_ref();

    // Count context types for duplicate detection.
    let mut preauth_count = 0;
    let mut encryption_count = 0;
    let mut signing_count = 0;
    let mut compression_count = 0;
    let mut has_transport_ctx = false;

    if let Some(ctxs) = contexts {
        for ctx in ctxs {
            match ctx.context_type {
                NegotiateContextType::PreauthIntegrityCapabilities => preauth_count += 1,
                NegotiateContextType::EncryptionCapabilities => encryption_count += 1,
                NegotiateContextType::SigningCapabilities => signing_count += 1,
                NegotiateContextType::CompressionCapabilities => compression_count += 1,
                NegotiateContextType::TransportCapabilities => has_transport_ctx = true,
                // Netname, RdmaTransform, Unknown: ignore for duplicate-counting.
                _ => {}
            }
        }
    }

    // --- PREAUTH_INTEGRITY_CAPABILITIES (mandatory for 3.1.1) ---
    if preauth_count == 0 {
        return Err(NtStatus::InvalidParameter);
    }
    if preauth_count > 1 {
        return Err(NtStatus::InvalidParameter);
    }

    // Extract the preauth context.
    let preauth = req
        .get_ctx_preauth_integrity_capabilities()
        .ok_or(NtStatus::InvalidParameter)?;

    if preauth.hash_algorithms.is_empty() {
        return Err(NtStatus::InvalidParameter);
    }

    // Must offer SHA-512.
    let sha512 = preauth
        .hash_algorithms
        .iter()
        .find(|a| **a == HashAlgorithm::Sha512);
    let preauth_hash_alg = sha512
        .copied()
        .ok_or(NtStatus::SmbNoPreauthIntegrityHashOverlap)?;

    // --- ENCRYPTION_CAPABILITIES (optional, at most one) ---
    if encryption_count > 1 {
        return Err(NtStatus::InvalidParameter);
    }

    // If the client sent an encryption context with CipherCount == 0, reject.
    // (This is distinct from no encryption context at all.)
    if encryption_count == 1 {
        if let Some(enc_ctx) = req.get_ctx_encryption_capabilities() {
            if enc_ctx.ciphers.is_empty() {
                return Err(NtStatus::InvalidParameter);
            }
        }
    }

    // Select a cipher if encryption is enabled and the client offered one
    // that we support. Server preference: AES-128-GCM.
    let selected_cipher =
        if encryption_policy != EncryptionPolicy::Disabled && encryption_count == 1 {
            if let Some(enc_ctx) = req.get_ctx_encryption_capabilities() {
                // Pick the first server-preferred cipher that the client offers.
                SERVER_CIPHERS
                    .iter()
                    .find(|sc| enc_ctx.ciphers.iter().any(|cc| *cc == **sc))
                    .copied()
            } else {
                None
            }
        } else {
            None
        };

    // --- SIGNING_CAPABILITIES (optional, at most one) ---
    if signing_count > 1 {
        return Err(NtStatus::InvalidParameter);
    }
    // 7c: always use AES-CMAC. Don't send a signing context back.
    // Client falls back to default_signing_algo() = AesCmac for 3.1.1.
    let signing_alg = SigningAlgorithmId::AesCmac;

    // If the client sent a signing context, verify at least one algorithm
    // overlaps with ours (CMAC). If no overlap, reject.
    if signing_count == 1 {
        if let Some(signing_ctx) = req.get_ctx_signing_capabilities() {
            let has_overlap = signing_ctx
                .signing_algorithms
                .contains(&SigningAlgorithmId::AesCmac);
            if !has_overlap {
                return Err(NtStatus::InvalidParameter);
            }
        }
    }

    // --- COMPRESSION_CAPABILITIES (optional, at most one) ---
    if compression_count > 1 {
        return Err(NtStatus::InvalidParameter);
    }
    // Not supported. Don't send a compression context.

    // --- TRANSPORT_CAPABILITIES (optional, at most one; MS-SMB2 2.2.3.1.5 / 3.3.5.4) ---
    let accept_transport_security = if is_quic && has_transport_ctx {
        req.get_ctx_transport_capabilities()
            .map(|tc| tc.accept_transport_layer_security())
            .unwrap_or(false)
    } else {
        false
    };

    // --- Generate server salt (32 random bytes) ---
    let mut salt = vec![0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut salt);

    let negotiated = Negotiated311 {
        preauth_hash_alg,
        salt,
        cipher: selected_cipher,
        signing_alg,
        accept_transport_security,
    };

    // --- Build response contexts ---
    // Send: PREAUTH_INTEGRITY_CAPABILITIES (with our salt).
    // Send: ENCRYPTION_CAPABILITIES if we selected a cipher.
    // Send: TRANSPORT_CAPABILITIES if accept_transport_security is negotiated.
    // Don't send: SIGNING, COMPRESSION.
    let mut response_contexts = vec![PreauthIntegrityCapabilities {
        hash_algorithms: vec![preauth_hash_alg],
        salt: negotiated.salt.clone(),
    }
    .into()];

    if let Some(cipher) = selected_cipher {
        response_contexts.push(
            EncryptionCapabilities {
                ciphers: vec![cipher],
            }
            .into(),
        );
    }

    if accept_transport_security {
        response_contexts.push(
            TransportCapabilities::new()
                .with_accept_transport_layer_security(true)
                .into(),
        );
    }

    Ok((negotiated, response_contexts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EncryptionPolicy;
    use rssmb_proto::negotiate::*;
    use rssmb_proto::Guid;

    fn make_negotiate(contexts: Vec<NegotiateContext>) -> NegotiateRequest {
        NegotiateRequest {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            capabilities: GlobalCapabilities::new(),
            client_guid: Guid::from([7u8; 16]),
            dialects: vec![Dialect::Smb0311],
            negotiate_context_list: Some(contexts),
        }
    }

    fn make_preauth() -> NegotiateContext {
        PreauthIntegrityCapabilities {
            hash_algorithms: vec![HashAlgorithm::Sha512],
            salt: vec![0xab; 32],
        }
        .into()
    }

    #[test]
    fn test_missing_preauth_rejected() {
        let req = make_negotiate(vec![]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_no_contexts_rejected() {
        let req = make_negotiate(vec![]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_valid_preauth_succeeds() {
        let req = make_negotiate(vec![make_preauth()]);
        let (neg, ctxs) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        assert_eq!(neg.preauth_hash_alg, HashAlgorithm::Sha512);
        assert_eq!(neg.salt.len(), 32);
        assert!(neg.cipher.is_none());
        assert_eq!(neg.signing_alg, SigningAlgorithmId::AesCmac);
        // Response: only preauth context.
        assert_eq!(ctxs.len(), 1);
        assert_eq!(
            ctxs[0].context_type,
            NegotiateContextType::PreauthIntegrityCapabilities
        );
    }

    #[test]
    fn test_no_sha512_overlap_rejected() {
        let req = make_negotiate(vec![PreauthIntegrityCapabilities {
            hash_algorithms: vec![HashAlgorithm::Unknown(0x02)],
            salt: vec![0xab; 32],
        }
        .into()]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(
            result,
            Err(NtStatus::SmbNoPreauthIntegrityHashOverlap)
        ));
    }

    #[test]
    fn test_duplicate_preauth_rejected() {
        let req = make_negotiate(vec![make_preauth(), make_preauth()]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_duplicate_encryption_rejected() {
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Gcm],
            }
            .into(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Ccm],
            }
            .into(),
        ]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_duplicate_signing_rejected() {
        let req = make_negotiate(vec![
            make_preauth(),
            SigningCapabilities {
                signing_algorithms: vec![SigningAlgorithmId::AesCmac],
            }
            .into(),
            SigningCapabilities {
                signing_algorithms: vec![SigningAlgorithmId::AesGmac],
            }
            .into(),
        ]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_duplicate_compression_rejected() {
        let req = make_negotiate(vec![
            make_preauth(),
            CompressionCapabilities {
                flags: CompressionCapsFlags::new(),
                compression_algorithms: vec![CompressionAlgorithm::LZ4],
            }
            .into(),
            CompressionCapabilities {
                flags: CompressionCapsFlags::new(),
                compression_algorithms: vec![CompressionAlgorithm::LZ77],
            }
            .into(),
        ]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_signing_no_overlap_rejected() {
        let req = make_negotiate(vec![
            make_preauth(),
            SigningCapabilities {
                signing_algorithms: vec![SigningAlgorithmId::AesGmac],
            }
            .into(),
        ]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_signing_with_cmac_succeeds() {
        let req = make_negotiate(vec![
            make_preauth(),
            SigningCapabilities {
                signing_algorithms: vec![SigningAlgorithmId::AesCmac],
            }
            .into(),
        ]);
        let (neg, ctxs) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        assert_eq!(neg.signing_alg, SigningAlgorithmId::AesCmac);
        // Don't send signing context back (client uses default).
        assert_eq!(ctxs.len(), 1);
    }

    #[test]
    fn test_unknown_contexts_ignored() {
        let req = make_negotiate(vec![
            make_preauth(),
            NegotiateContext {
                context_type: NegotiateContextType::Unknown(0x0100),
                data: NegotiateContextValue::Unknown {
                    type_id: 0x0100,
                    data: vec![0x93; 16],
                },
            },
            SigningCapabilities {
                signing_algorithms: vec![SigningAlgorithmId::AesCmac],
            }
            .into(),
        ]);
        let (_neg, ctxs) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        // Unknown context ignored, not echoed.
        assert_eq!(ctxs.len(), 1);
        assert_eq!(
            ctxs[0].context_type,
            NegotiateContextType::PreauthIntegrityCapabilities
        );
    }

    #[test]
    fn test_empty_hash_algorithms_rejected() {
        let req = make_negotiate(vec![PreauthIntegrityCapabilities {
            hash_algorithms: vec![],
            salt: vec![0xab; 32],
        }
        .into()]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_sha512_among_multiple_algorithms_succeeds() {
        // Client offers SHA-512 and an unknown algorithm.
        let req = make_negotiate(vec![PreauthIntegrityCapabilities {
            hash_algorithms: vec![HashAlgorithm::Unknown(0x02), HashAlgorithm::Sha512],
            salt: vec![0xab; 32],
        }
        .into()]);
        let (neg, _) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        assert_eq!(neg.preauth_hash_alg, HashAlgorithm::Sha512);
    }

    #[test]
    fn test_cipher_selected_when_gcm_offered() {
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Gcm],
            }
            .into(),
        ]);
        let (neg, ctxs) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        assert_eq!(neg.cipher, Some(EncryptionCipher::Aes128Gcm));
        // Response has preauth + encryption contexts.
        assert_eq!(ctxs.len(), 2);
        assert_eq!(
            ctxs[1].context_type,
            NegotiateContextType::EncryptionCapabilities
        );
    }

    #[test]
    fn test_cipher_none_when_disabled() {
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Gcm],
            }
            .into(),
        ]);
        let (neg, ctxs) = process_request_contexts(&req, EncryptionPolicy::Disabled).unwrap();
        assert!(neg.cipher.is_none());
        // Only preauth context in response.
        assert_eq!(ctxs.len(), 1);
    }

    #[test]
    fn test_cipher_none_when_no_overlap() {
        // Client offers only AES-128-CCM (which we don't implement yet).
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Ccm],
            }
            .into(),
        ]);
        let (neg, ctxs) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        assert!(neg.cipher.is_none());
        // Only preauth context (no encryption context when no common cipher).
        assert_eq!(ctxs.len(), 1);
    }

    #[test]
    fn test_empty_cipher_list_rejected() {
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities { ciphers: vec![] }.into(),
        ]);
        let result = process_request_contexts(&req, EncryptionPolicy::Desired);
        assert!(matches!(result, Err(NtStatus::InvalidParameter)));
    }

    #[test]
    fn test_cipher_required_no_overlap_succeeds_negotiate() {
        // `required` + no common cipher: NEGOTIATE must succeed (cipher=None).
        // The `required` policy denies SESSION_SETUP later.
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Ccm],
            }
            .into(),
        ]);
        let (neg, _ctxs) = process_request_contexts(&req, EncryptionPolicy::Required).unwrap();
        assert!(neg.cipher.is_none());
    }

    #[test]
    fn test_gcm_preferred_over_ccm_when_both_offered() {
        // Client offers CCM first, GCM second. Server prefers GCM.
        let req = make_negotiate(vec![
            make_preauth(),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Ccm, EncryptionCipher::Aes128Gcm],
            }
            .into(),
        ]);
        let (neg, _ctxs) = process_request_contexts(&req, EncryptionPolicy::Desired).unwrap();
        assert_eq!(neg.cipher, Some(EncryptionCipher::Aes128Gcm));
    }
}
