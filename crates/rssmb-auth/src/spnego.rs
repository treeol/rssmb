//! SPNEGO/GSS-API token parsing (ASN.1 DER).
//!
//! Windows clients wrap NTLMSSP tokens in SPNEGO (Simple and Protected
//! GSS-API Negotiation Mechanism, RFC 4178) tokens. The server must
//! parse the SPNEGO wrapper to extract the NTLMSSP token, and wrap
//! responses in SPNEGO negTokenResp.

/// SPNEGO OID: 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// NTLMSSP signature: "NTLMSSP\0"
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

/// Extract the NTLMSSP token from a potentially SPNEGO-wrapped input.
///
/// Handles three cases:
/// - Raw NTLMSSP (starts with "NTLMSSP\0") → return as-is
/// - SPNEGO negTokenInit (starts with 0x60) → scan for NTLMSSP signature
/// - SPNEGO negTokenResp (starts with 0xA1) → scan for NTLMSSP signature
pub fn extract_ntlm_token(input: &[u8]) -> Result<Vec<u8>, String> {
    // Check if it's raw NTLMSSP
    if input.len() >= 8 && &input[..8] == NTLMSSP_SIGNATURE {
        return Ok(input.to_vec());
    }

    if input.is_empty() {
        return Err("empty input".to_string());
    }

    // Accept SPNEGO negTokenInit (0x60) or negTokenResp (0xA1)
    if input[0] != 0x60 && input[0] != 0xA1 {
        // Not SPNEGO and not NTLMSSP — try scanning anyway as fallback
    }

    // Scan for the NTLMSSP signature anywhere in the token.
    // This works for both negTokenInit and negTokenResp because the
    // NTLMSSP token is always embedded as an OCTET STRING within the
    // SPNEGO structure, and "NTLMSSP\0" is a unique 8-byte marker.
    if let Some(pos) = find_subslice(input, NTLMSSP_SIGNATURE) {
        return Ok(input[pos..].to_vec());
    }

    // No NTLMSSP token found — could be a SPNEGO response with no token
    // (e.g. final negTokenResp with just negState=accept-completed)
    Err("no NTLMSSP token found in SPNEGO wrapper".to_string())
}

/// Extract the DER-encoded `mechTypes` SEQUENCE OF from a SPNEGO
/// negTokenInit.
///
/// The mechTypes are the first element `[0]` of the negTokenInit sequence.
/// We return the raw DER bytes of the inner `SEQUENCE OF` (the `0x30 ...`
/// part, not the `[0]` context wrapper), which is the object signed by
/// the `mechListMIC` (RFC 4178 §5).
pub fn extract_mech_types(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input[0] != 0x60 {
        return None;
    }
    // Layout: 60 <len> [06 <len> <SPNEGO OID>] A0 <len> 30 <len> A0 <len> 30 <len> ...
    // We need the inner 30 (SEQUENCE OF) inside the second A0.
    let mut p = 1; // skip 0x60
    p += der_len_size(&input[p..])?; // skip outer length
    // Skip the SPNEGO OID (06 <len> <bytes>).
    if input.get(p) != Some(&0x06) {
        return None;
    }
    p += 1; // skip 0x06
    let oid_len = der_len_value(&input[p..])?;
    p += der_len_size(&input[p..])?; // skip length
    p += oid_len; // skip OID bytes
    // Now expect A0 (negTokenInit [0]).
    if input.get(p) != Some(&0xA0) {
        return None;
    }
    p += 1; // skip A0
    let init_len = der_len_value(&input[p..])?;
    p += der_len_size(&input[p..])?; // skip length
    // Inside negTokenInit: expect 30 (SEQUENCE).
    if input.get(p) != Some(&0x30) {
        return None;
    }
    p += 1; // skip 0x30
    p += der_len_size(&input[p..])?; // skip SEQUENCE length
    // Now expect A0 (mechTypes [0]).
    if input.get(p) != Some(&0xA0) {
        return None;
    }
    p += 1; // skip A0
    let mt_len = der_len_value(&input[p..])?;
    p += der_len_size(&input[p..])?; // skip length
    // p now points at the inner 0x30 SEQUENCE OF — this is what gets signed.
    let end = p + mt_len;
    input.get(p..end).map(|s| s.to_vec())
}

/// Skip a DER length encoding and return the number of bytes it occupies.
fn der_len_size(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some(1)
    } else if data[0] == 0x81 {
        Some(2)
    } else if data[0] == 0x82 {
        Some(3)
    } else {
        None
    }
}

/// Read the value of a DER length encoding (the actual content length).
fn der_len_value(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some(data[0] as usize)
    } else if data[0] == 0x81 {
        data.get(1).map(|&b| b as usize)
    } else if data[0] == 0x82 {
        data.get(1..3)
            .map(|b| ((b[0] as usize) << 8) | (b[1] as usize))
    } else {
        None
    }
}

/// Structural classification of an NTLMSSP AUTHENTICATE (type 3) message.
///
/// Layout (MS-NLMP 2.2.1.3): signature(8) | MessageType u32 @8 |
/// LmChallengeResponseFields @12 | NtChallengeResponseFields @20 |
/// DomainNameFields @28 | UserNameFields @36 — each field is
/// (len u16, maxlen u16, offset u32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticateSummary {
    pub lm_len: u16,
    /// The LM response is exactly one 0x00 byte.
    pub lm_is_single_zero: bool,
    pub nt_len: u16,
    pub user_len: u16,
}

impl AuthenticateSummary {
    /// MS-NLMP 3.2.5.1.2: an anonymous AUTHENTICATE has an empty
    /// NtChallengeResponse, an LM response that is empty or a single zero
    /// byte, and an empty user name.
    pub fn is_anonymous(&self) -> bool {
        self.nt_len == 0
            && (self.lm_len == 0 || self.lm_is_single_zero)
            && self.user_len == 0
    }
}

/// Parse the fixed header of an NTLMSSP AUTHENTICATE message. Returns
/// `None` if `token` is not a type-3 message or any of the LM / NT /
/// domain / user fields points outside the token.
pub fn parse_authenticate(token: &[u8]) -> Option<AuthenticateSummary> {
    if token.len() < 44 || &token[..8] != NTLMSSP_SIGNATURE {
        return None;
    }
    let u16_at = |o: usize| u16::from_le_bytes([token[o], token[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([token[o], token[o + 1], token[o + 2], token[o + 3]]);
    if u32_at(8) != 3 {
        return None;
    }
    // (len, offset) of each field must lie within the token.
    let field = |o: usize| -> Option<&[u8]> {
        let len = u16_at(o) as usize;
        let off = u32_at(o + 4) as usize;
        token.get(off..off.checked_add(len)?)
    };
    let lm = field(12)?;
    field(20)?;
    field(28)?;
    field(36)?;
    Some(AuthenticateSummary {
        lm_len: u16_at(12),
        lm_is_single_zero: lm == [0u8],
        nt_len: u16_at(20),
        user_len: u16_at(36),
    })
}

/// Wrap an NTLMSSP response token in a SPNEGO negTokenResp.
///
/// This is a minimal SPNEGO negTokenResp wrapper:
/// ```text
/// SEQUENCE {
///   [1] negTokenResp {
///     [2] responseToken (OCTET STRING)
///   }
/// }
/// ```
pub fn wrap_ntlm_response(ntlm_token: &[u8]) -> Vec<u8> {
    // Minimal SPNEGO negTokenResp:
    // 0xA1 (CONTEXT [1] CONSTRUCTED) + length
    //   0x30 (SEQUENCE) + length
    //     0xA2 (CONTEXT [2] CONSTRUCTED) + length
    //       0x04 (OCTET STRING) + length + token

    let inner_octet = der_tlv(0x04, ntlm_token);
    let ctx2 = der_tlv(0xA2, &inner_octet);
    let seq = der_tlv(0x30, &ctx2);
    let outer = der_tlv(0xA1, &seq);
    outer
}

/// Build a SPNEGO negTokenResp for the final accept-completed leg,
/// including a `mechListMIC` (RFC 4178 §5) when the client's NTLMSSP
/// negotiation requested signing (Samba/Windows clients require this).
///
/// Structure:
/// ```text
/// [1] negTokenResp {
///   [0] negState = accept-completed (ENUMERATED 0)
///   [2] responseToken (OCTET STRING)  — empty
///   [3] mechListMIC (OCTET STRING)
/// }
/// ```
pub fn wrap_accept_completed(mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    // [0] negState = accept-completed (0)
    let neg_state = der_tlv(0x0A, &[0u8]); // ENUMERATED, value 0
    let ctx0 = der_tlv(0xA0, &neg_state);

    // [2] responseToken — empty (NTLM has no final token)
    let empty_octet = der_tlv(0x04, &[]);
    let ctx2 = der_tlv(0xA2, &empty_octet);

    let mut inner = ctx0;
    inner.extend_from_slice(&ctx2);

    // [3] mechListMIC
    if let Some(mic) = mech_list_mic {
        let mic_octet = der_tlv(0x04, mic);
        let ctx3 = der_tlv(0xA3, &mic_octet);
        inner.extend_from_slice(&ctx3);
    }

    let seq = der_tlv(0x30, &inner);
    let outer = der_tlv(0xA1, &seq);
    outer
}

/// Build a DER TLV (Tag-Length-Value) element.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(2 + value.len());
    result.push(tag);
    if value.len() < 0x80 {
        result.push(value.len() as u8);
    } else if value.len() < 0x100 {
        result.push(0x81);
        result.push(value.len() as u8);
    } else {
        result.push(0x82);
        result.push((value.len() >> 8) as u8);
        result.push(value.len() as u8);
    }
    result.extend_from_slice(value);
    result
}

/// Extract the client's `mechListMIC` from a SPNEGO negTokenResp.
///
/// The negTokenResp is:
/// ```text
/// A1 <len>           -- [1] negTokenResp
///   30 <len>         -- SEQUENCE
///     [0] negState   -- optional
///     [2] responseToken -- optional
///     [3] mechListMIC  -- the client's signature
/// ```
/// We walk the SEQUENCE looking for context tag [3] (0xA3) and extract
/// its OCTET STRING value.
pub fn extract_mech_list_mic(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input[0] != 0xA1 {
        return None;
    }
    let mut p = 1; // skip A1
    let outer_len = der_len_value(&input[p..])?;
    p += der_len_size(&input[p..])?;
    let outer_end = p + outer_len;

    // Expect SEQUENCE (0x30)
    if input.get(p) != Some(&0x30) {
        return None;
    }
    p += 1;
    let seq_len = der_len_value(&input[p..])?;
    p += der_len_size(&input[p..])?;
    let _seq_end = p + seq_len;

    // Walk the SEQUENCE elements looking for [3] (0xA3).
    while p < outer_end && p < input.len() {
        let tag = input[p];
        p += 1;
        let len = der_len_value(&input[p..])?;
        p += der_len_size(&input[p..])?;
        let content_end = p + len;

        if tag == 0xA3 {
            // [3] mechListMIC — expect OCTET STRING (0x04) inside
            if input.get(p) != Some(&0x04) {
                return None;
            }
            let octet_len_offset = p + 1;
            let octet_len = der_len_value(&input[octet_len_offset..])?;
            let octet_len_size = der_len_size(&input[octet_len_offset..])?;
            let data_start = octet_len_offset + octet_len_size;
            let data_end = data_start + octet_len;
            return input.get(data_start..data_end).map(|s| s.to_vec());
        }

        // Skip this element
        p = content_end;
    }

    None
}

/// Find a subslice within a slice.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_ntlmssp_detected() {
        let mut token = b"NTLMSSP\0".to_vec();
        token.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let result = extract_ntlm_token(&token).unwrap();
        assert_eq!(result, token);
    }

    #[test]
    fn test_spnego_ntlmssp_extracted() {
        // Construct a minimal SPNEGO-wrapped NTLMSSP token
        let ntlm_token = b"NTLMSSP\0\x01\x00\x00\x00";
        let octet = der_tlv(0x04, ntlm_token);
        let ctx2 = der_tlv(0xA2, &octet);
        let seq = der_tlv(0x30, &ctx2);
        let outer = der_tlv(0xA1, &seq);
        // Prepend a SEQUENCE tag to simulate SPNEGO framing
        let spnego = der_tlv(0x60, &outer);

        let result = extract_ntlm_token(&spnego).unwrap();
        assert_eq!(result, ntlm_token);
    }

    #[test]
    fn test_empty_input_rejected() {
        let result = extract_ntlm_token(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_response() {
        let ntlm = b"NTLMSSP\0\x02\x00\x00\x00";
        let wrapped = wrap_ntlm_response(ntlm);
        // Should start with 0xA1 (CONTEXT [1])
        assert_eq!(wrapped[0], 0xA1);
        // Should contain the NTLM token
        assert!(find_subslice(&wrapped, ntlm).is_some());
    }

    #[test]
    fn test_der_tlv_short() {
        let data = vec![0x01, 0x02, 0x03];
        let tlv = der_tlv(0x04, &data);
        assert_eq!(tlv, vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_der_tlv_long() {
        let data = vec![0x00; 200];
        let tlv = der_tlv(0x04, &data);
        assert_eq!(tlv[0], 0x04);
        assert_eq!(tlv[1], 0x81); // long form length
        assert_eq!(tlv[2], 200);
    }

    #[test]
    fn test_extract_mech_list_mic_present() {
        // Build a negTokenResp with [3] mechListMIC:
        // A1 <len> 30 <len> [0] negState [3] mechListMIC
        let mic_bytes = [0xAAu8; 16];
        let mic_octet = der_tlv(0x04, &mic_bytes);
        let ctx3 = der_tlv(0xA3, &mic_octet);

        let neg_state = der_tlv(0x0A, &[0u8]);
        let ctx0 = der_tlv(0xA0, &neg_state);

        let mut inner = ctx0;
        inner.extend_from_slice(&ctx3);
        let seq = der_tlv(0x30, &inner);
        let outer = der_tlv(0xA1, &seq);

        let extracted = extract_mech_list_mic(&outer);
        assert_eq!(extracted, Some(mic_bytes.to_vec()));
    }

    #[test]
    fn test_extract_mech_list_mic_absent() {
        // negTokenResp without [3] mechListMIC
        let neg_state = der_tlv(0x0A, &[0u8]);
        let ctx0 = der_tlv(0xA0, &neg_state);
        let seq = der_tlv(0x30, &ctx0);
        let outer = der_tlv(0xA1, &seq);

        assert_eq!(extract_mech_list_mic(&outer), None);
    }

    #[test]
    fn test_extract_mech_list_mic_with_response_token_before() {
        // negTokenResp with [2] responseToken before [3] mechListMIC
        let mic_bytes = [0xBBu8; 16];
        let mic_octet = der_tlv(0x04, &mic_bytes);
        let ctx3 = der_tlv(0xA3, &mic_octet);

        let resp_octet = der_tlv(0x04, &[0x01, 0x02, 0x03]);
        let ctx2 = der_tlv(0xA2, &resp_octet);

        let neg_state = der_tlv(0x0A, &[0u8]);
        let ctx0 = der_tlv(0xA0, &neg_state);

        let mut inner = ctx0;
        inner.extend_from_slice(&ctx2);
        inner.extend_from_slice(&ctx3);
        let seq = der_tlv(0x30, &inner);
        let outer = der_tlv(0xA1, &seq);

        let extracted = extract_mech_list_mic(&outer);
        assert_eq!(extracted, Some(mic_bytes.to_vec()));
    }

    #[test]
    fn test_extract_mech_list_mic_non_spnego_returns_none() {
        assert_eq!(extract_mech_list_mic(&[]), None);
        assert_eq!(extract_mech_list_mic(&[0x60, 0x00]), None); // not A1
    }
}
