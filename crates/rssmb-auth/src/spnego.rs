//! SPNEGO/GSS-API token parsing (ASN.1 DER).
//!
//! Windows clients wrap NTLMSSP tokens in SPNEGO (Simple and Protected
//! GSS-API Negotiation Mechanism, RFC 4178) tokens. The server must
//! parse the SPNEGO wrapper to extract the NTLMSSP token, and wrap
//! responses in SPNEGO negTokenResp.
//!
//! All parsing uses checked arithmetic and bounded slices: each TLV's
//! content is sliced within its parent, preventing out-of-bounds reads
//! and trailing-data inclusion (Mashūra findings 1 and 3).

/// SPNEGO OID: 1.3.6.1.5.5.2
#[allow(dead_code)]
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// NTLMSSP signature: "NTLMSSP\0"
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

// ---------------------------------------------------------------------------
// Bounded DER TLV reader
//
// `der_tlv_split` reads a tag + length from the start of `data` and
// returns (tag, content_slice, remaining_after_tlv). The content slice
// is strictly within `data`; if the declared length exceeds the
// available bytes, it returns `None`.

/// Read a DER tag + length from the start of `data`.
/// Returns `(tag, content_bytes, remaining_bytes_after_this_TLV)`.
fn der_tlv_split(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let (len, len_size) = der_len(&data[1..])?;
    let content_start = 1usize.checked_add(len_size)?;
    let content_end = content_start.checked_add(len)?;
    let content = data.get(content_start..content_end)?;
    let remaining = data.get(content_end..).unwrap_or(&[]);
    Some((tag, content, remaining))
}

/// Read a DER length encoding. Returns `(value, bytes_consumed)`.
fn der_len(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else if data[0] == 0x81 {
        data.get(1).map(|&b| (b as usize, 2))
    } else if data[0] == 0x82 {
        data.get(1..3)
            .map(|b| (((b[0] as usize) << 8) | (b[1] as usize), 3))
    } else {
        None // lengths > 65535 not supported
    }
}

/// Read the content of a TLV with the expected tag. Returns
/// `(content, remaining)` or `None` if the tag doesn't match or the
/// TLV is malformed.
fn der_expect(data: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    let (tag, content, remaining) = der_tlv_split(data)?;
    if tag != expected_tag {
        return None;
    }
    Some((content, remaining))
}

/// Read an OCTET STRING (0x04) content from `data`.
fn der_octet_string(data: &[u8]) -> Option<(&[u8], &[u8])> {
    der_expect(data, 0x04)
}

/// Walk the elements of a SEQUENCE content slice, calling `f` for each
/// element. The slice passed to `f` is the element's content, bounded
/// within the SEQUENCE. Returns the first non-None result.
fn walk_sequence<T>(seq_content: &[u8], mut f: impl FnMut(u8, &[u8]) -> Option<T>) -> Option<T> {
    let mut rest = seq_content;
    while !rest.is_empty() {
        let (tag, content, remaining) = der_tlv_split(rest)?;
        if let Some(result) = f(tag, content) {
            return Some(result);
        }
        rest = remaining;
    }
    None
}

// ---------------------------------------------------------------------------
// SPNEGO token extraction

/// Extract the NTLMSSP token from a potentially SPNEGO-wrapped input.
///
/// Handles three cases:
/// - Raw NTLMSSP (starts with "NTLMSSP\0") → return as-is
/// - SPNEGO negTokenInit (0x60) → parse the wrapper and extract the
///   mechToken OCTET STRING from [0] negTokenInit > SEQUENCE > [2]
/// - SPNEGO negTokenResp (0xA1) → parse the wrapper and extract the
///   responseToken OCTET STRING from SEQUENCE > [2]
///
/// Returns `Err` if the input is not a valid SPNEGO wrapper containing
/// an NTLMSSP token. The caller should not fall back to passing the raw
/// wrapper to the NTLM parser (finding 1).
pub fn extract_ntlm_token(input: &[u8]) -> Result<Vec<u8>, String> {
    // Raw NTLMSSP — return as-is.
    if input.len() >= 8 && &input[..8] == NTLMSSP_SIGNATURE {
        return Ok(input.to_vec());
    }

    if input.is_empty() {
        return Err("empty input".to_string());
    }

    // SPNEGO negTokenInit: [APPLICATION 0] (0x60)
    //   OID (0x06) <SPNEGO OID>
    //   [0] (0xA0) negTokenInit
    //     SEQUENCE (0x30)
    //       [0] (0xA0) mechTypes
    //       [2] (0xA2) mechToken  ← OCTET STRING with NTLMSSP
    if input[0] == 0x60 {
        return extract_from_neg_token_init(input);
    }

    // SPNEGO negTokenResp: [1] (0xA1)
    //   SEQUENCE (0x30)
    //     [0] (0xA0) negState      (optional)
    //     [2] (0xA2) responseToken  (optional) ← OCTET STRING with NTLMSSP
    //     [3] (0xA3) mechListMIC    (optional)
    if input[0] == 0xA1 {
        return extract_from_neg_token_resp(input);
    }

    Err("not a SPNEGO wrapper or raw NTLMSSP".to_string())
}

/// Extract the NTLMSSP token from a negTokenInit (0x60).
fn extract_from_neg_token_init(input: &[u8]) -> Result<Vec<u8>, String> {
    // [APPLICATION 0] outer
    let (outer_content, _) = der_expect(input, 0x60)
        .ok_or_else(|| "malformed negTokenInit: bad outer TLV".to_string())?;

    // OID — must be SPNEGO OID
    let (oid_tag, oid_content, after_oid) = der_tlv_split(outer_content)
        .ok_or_else(|| "malformed negTokenInit: bad OID TLV".to_string())?;
    if oid_tag != 0x06 {
        return Err("malformed negTokenInit: expected OID".to_string());
    }
    if oid_content != SPNEGO_OID {
        return Err("not a SPNEGO OID".to_string());
    }

    // [0] negTokenInit
    let (init_content, _) = der_expect(after_oid, 0xA0)
        .ok_or_else(|| "malformed negTokenInit: missing [0] negTokenInit".to_string())?;

    // SEQUENCE
    let (seq_content, _) = der_expect(init_content, 0x30)
        .ok_or_else(|| "malformed negTokenInit: missing SEQUENCE".to_string())?;

    // Walk the SEQUENCE looking for [2] (0xA2) mechToken
    let token = walk_sequence(seq_content, |tag, content| {
        if tag == 0xA2 {
            // mechToken: OCTET STRING containing NTLMSSP
            der_octet_string(content).map(|(octet, _)| octet.to_vec())
        } else {
            None
        }
    })
    .ok_or_else(|| "negTokenInit: no mechToken ([2]) found".to_string())?;

    Ok(token)
}

/// Extract the NTLMSSP token from a negTokenResp (0xA1).
fn extract_from_neg_token_resp(input: &[u8]) -> Result<Vec<u8>, String> {
    // [1] negTokenResp
    let (resp_content, _) = der_expect(input, 0xA1)
        .ok_or_else(|| "malformed negTokenResp: bad outer TLV".to_string())?;

    // SEQUENCE
    let (seq_content, _) = der_expect(resp_content, 0x30)
        .ok_or_else(|| "malformed negTokenResp: missing SEQUENCE".to_string())?;

    // Walk the SEQUENCE looking for [2] (0xA2) responseToken
    let token = walk_sequence(seq_content, |tag, content| {
        if tag == 0xA2 {
            // responseToken: OCTET STRING containing NTLMSSP
            der_octet_string(content).map(|(octet, _)| octet.to_vec())
        } else {
            None
        }
    })
    .ok_or_else(|| "negTokenResp: no responseToken ([2]) found".to_string())?;

    Ok(token)
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

    // [APPLICATION 0] outer
    let (outer_content, _) = der_expect(input, 0x60)?;

    // OID — must be SPNEGO OID
    let (oid_tag, oid_content, after_oid) = der_tlv_split(outer_content)?;
    if oid_tag != 0x06 || oid_content != SPNEGO_OID {
        return None;
    }

    // [0] negTokenInit
    let (init_content, _) = der_expect(after_oid, 0xA0)?;

    // SEQUENCE
    let (seq_content, _) = der_expect(init_content, 0x30)?;

    // [0] mechTypes
    let (mt_content, _) = der_expect(seq_content, 0xA0)?;

    // Inner SEQUENCE OF — the signed object. Return the full DER TLV
    // (0x30 tag + length + content), not just the content, because the
    // mechListMIC is computed over the full SEQUENCE OF DER bytes.
    // Parse the inner 0x30 TLV to find its total byte length, then
    // slice that range from mt_content.
    let (inner_tag, inner_content, _) = der_tlv_split(mt_content)?;
    if inner_tag != 0x30 {
        return None;
    }
    // The TLV spans from the start of mt_content to the end of inner_content.
    // inner_content is a subslice of mt_content, so we can compute the
    // total length from the content's offset.
    let content_start = inner_content.as_ptr() as usize - mt_content.as_ptr() as usize;
    let total_len = content_start + inner_content.len();
    Some(mt_content.get(..total_len)?.to_vec())
}

// ---------------------------------------------------------------------------
// Structural classification of NTLMSSP AUTHENTICATE

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
        self.nt_len == 0 && (self.lm_len == 0 || self.lm_is_single_zero) && self.user_len == 0
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
    let u32_at =
        |o: usize| u32::from_le_bytes([token[o], token[o + 1], token[o + 2], token[o + 3]]);
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

// ---------------------------------------------------------------------------
// SPNEGO response wrapping

/// Wrap an NTLMSSP CHALLENGE token in the acceptor's first SPNEGO
/// negTokenResp.
///
/// RFC 4178 §4.2.2 requires the acceptor's first negTokenResp to carry
/// both `negState` and `supportedMech`. Strict initiators (go-smb2 /
/// rclone, Windows) reject the response if `supportedMech` is absent.
///
/// Structure (DER SEQUENCE order is mandatory):
/// ```text
/// A1 {                                  -- [1] negTokenResp
///   30 {                                -- SEQUENCE
///     A0 { 0A 01 01 }                   -- [0] negState = accept-incomplete (1)
///     A1 { 06 <NTLMSSP OID> }           -- [1] supportedMech = 1.3.6.1.4.1.311.2.2.10
///     A2 { 04 <ntlm_token> }            -- [2] responseToken
///   }
/// }
/// ```
pub fn wrap_ntlm_response(ntlm_token: &[u8]) -> Vec<u8> {
    // [0] negState = accept-incomplete (ENUMERATED 1)
    let mut inner = der_tlv(0xA0, &der_tlv(0x0A, &[0x01]));
    // [1] supportedMech = NTLMSSP OID
    inner.extend_from_slice(&der_tlv(0xA1, &der_tlv(0x06, NTLMSSP_OID)));
    // [2] responseToken
    inner.extend_from_slice(&der_tlv(0xA2, &der_tlv(0x04, ntlm_token)));

    let seq = der_tlv(0x30, &inner);
    der_tlv(0xA1, &seq)
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
///
/// Note: `accept-completed` refers to the mechanism negotiation being
/// complete (NTLM has authenticated), not the overall SPNEGO exchange.
/// The client sends its `mechListMIC` in a follow-up round; the server
/// verifies it in the `awaiting_mic` branch of `step()`. This matches
/// Samba/Windows behavior (finding 2).
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

    der_tlv(0xA1, &seq)
}

// ---------------------------------------------------------------------------
// mechListMIC extraction

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
/// We walk the SEQUENCE (bounded by `seq_end`) looking for context tag
/// [3] (0xA3) and extract its OCTET STRING value. All bounds are checked
/// against the parent SEQUENCE content, not the whole input (finding 3).
pub fn extract_mech_list_mic(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input[0] != 0xA1 {
        return None;
    }

    // [1] negTokenResp
    let (resp_content, _) = der_expect(input, 0xA1)?;

    // SEQUENCE
    let (seq_content, _) = der_expect(resp_content, 0x30)?;

    // Walk the SEQUENCE elements (bounded by seq_content) looking for
    // [3] (0xA3). Each element's content is sliced within seq_content.
    walk_sequence(seq_content, |tag, content| {
        if tag == 0xA3 {
            // [3] mechListMIC — expect OCTET STRING (0x04) inside
            der_octet_string(content).map(|(data, _)| data.to_vec())
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// DER TLV encoding (for response wrapping)

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

/// Find a subslice within a slice.
#[cfg(test)]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_ntlm_token tests ---

    #[test]
    fn test_raw_ntlmssp_detected() {
        let mut token = b"NTLMSSP\0".to_vec();
        token.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let result = extract_ntlm_token(&token).unwrap();
        assert_eq!(result, token);
    }

    /// Build a valid SPNEGO negTokenInit with an NTLMSSP mechToken.
    fn build_neg_token_init(ntlm_token: &[u8]) -> Vec<u8> {
        // SPNEGO OID
        let oid = der_tlv(0x06, SPNEGO_OID);
        // mechTypes: SEQUENCE OF { NTLMSSP OID }
        let ntlm_oid = der_tlv(0x06, NTLMSSP_OID);
        let mech_types_inner = der_tlv(0x30, &ntlm_oid);
        let mech_types = der_tlv(0xA0, &mech_types_inner);
        // mechToken: [2] OCTET STRING
        let mech_token_octet = der_tlv(0x04, ntlm_token);
        let mech_token = der_tlv(0xA2, &mech_token_octet);
        // SEQUENCE inside negTokenInit
        let mut seq_inner = mech_types;
        seq_inner.extend_from_slice(&mech_token);
        let seq = der_tlv(0x30, &seq_inner);
        // [0] negTokenInit
        let neg_init = der_tlv(0xA0, &seq);
        // [APPLICATION 0] outer
        let mut outer_inner = oid;
        outer_inner.extend_from_slice(&neg_init);
        der_tlv(0x60, &outer_inner)
    }

    /// Build a valid SPNEGO negTokenResp with a responseToken.
    fn build_neg_token_resp(ntlm_token: &[u8]) -> Vec<u8> {
        let resp_octet = der_tlv(0x04, ntlm_token);
        let ctx2 = der_tlv(0xA2, &resp_octet);
        let seq = der_tlv(0x30, &ctx2);
        der_tlv(0xA1, &seq)
    }

    #[test]
    fn test_spnego_neg_token_init_extracted() {
        let ntlm_token = b"NTLMSSP\0\x01\x00\x00\x00";
        let spnego = build_neg_token_init(ntlm_token);
        let result = extract_ntlm_token(&spnego).unwrap();
        assert_eq!(result, ntlm_token);
    }

    #[test]
    fn test_spnego_neg_token_resp_extracted() {
        let ntlm_token = b"NTLMSSP\0\x03\x00\x00\x00";
        let spnego = build_neg_token_resp(ntlm_token);
        let result = extract_ntlm_token(&spnego).unwrap();
        assert_eq!(result, ntlm_token);
    }

    #[test]
    fn test_neg_token_resp_no_token_returns_err() {
        // negTokenResp with negState but no responseToken
        let neg_state = der_tlv(0x0A, &[0u8]);
        let ctx0 = der_tlv(0xA0, &neg_state);
        let seq = der_tlv(0x30, &ctx0);
        let outer = der_tlv(0xA1, &seq);
        let result = extract_ntlm_token(&outer);
        assert!(
            result.is_err(),
            "negTokenResp without responseToken should error"
        );
    }

    #[test]
    fn test_empty_input_rejected() {
        let result = extract_ntlm_token(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_spnego_rejected() {
        let result = extract_ntlm_token(&[0x42, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_neg_token_init_rejected() {
        // Truncated negTokenInit
        let result = extract_ntlm_token(&[0x60, 0x10, 0x06]);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_oid_rejected() {
        // Build a negTokenInit with a wrong OID
        let wrong_oid = der_tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x03]); // not SPNEGO
        let mech_types_inner = der_tlv(0x30, &der_tlv(0x06, NTLMSSP_OID));
        let mech_types = der_tlv(0xA0, &mech_types_inner);
        let mech_token = der_tlv(0xA1, &der_tlv(0x04, b"NTLMSSP\0\x01"));
        let mut seq_inner = mech_types;
        seq_inner.extend_from_slice(&mech_token);
        let seq = der_tlv(0x30, &seq_inner);
        let neg_init = der_tlv(0xA0, &seq);
        let mut outer_inner = wrong_oid;
        outer_inner.extend_from_slice(&neg_init);
        let spnego = der_tlv(0x60, &outer_inner);
        let result = extract_ntlm_token(&spnego);
        assert!(result.is_err(), "wrong OID should be rejected");
    }

    #[test]
    fn test_trailing_data_not_included() {
        // Build a negTokenResp with responseToken + trailing mechListMIC.
        // The extracted token should be just the responseToken OCTET STRING,
        // not including the mechListMIC.
        let ntlm_token = b"NTLMSSP\0\x03\x00\x00\x00";
        let resp_octet = der_tlv(0x04, ntlm_token);
        let ctx2 = der_tlv(0xA2, &resp_octet);
        let mic_octet = der_tlv(0x04, &[0xBBu8; 16]);
        let ctx3 = der_tlv(0xA3, &mic_octet);
        let mut seq_inner = ctx2;
        seq_inner.extend_from_slice(&ctx3);
        let seq = der_tlv(0x30, &seq_inner);
        let outer = der_tlv(0xA1, &seq);
        let result = extract_ntlm_token(&outer).unwrap();
        assert_eq!(
            result, ntlm_token,
            "trailing mechListMIC should not be included"
        );
    }

    // --- extract_mech_list_mic tests ---

    #[test]
    fn test_extract_mech_list_mic_present() {
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
        let neg_state = der_tlv(0x0A, &[0u8]);
        let ctx0 = der_tlv(0xA0, &neg_state);
        let seq = der_tlv(0x30, &ctx0);
        let outer = der_tlv(0xA1, &seq);

        assert_eq!(extract_mech_list_mic(&outer), None);
    }

    #[test]
    fn test_extract_mech_list_mic_with_response_token_before() {
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

    #[test]
    fn test_extract_mech_list_mic_truncated_returns_none() {
        // Truncated after the outer A1 tag
        assert_eq!(extract_mech_list_mic(&[0xA1, 0x10, 0x30]), None);
    }

    #[test]
    fn test_extract_mech_list_mic_element_exceeds_sequence() {
        // Build a SEQUENCE where the [3] element claims more content than
        // the SEQUENCE contains. The bounded parser should reject this.
        //
        // A1 07 30 02 A3 03 04 01 AA
        //  ^     ^  ^  ^  ^  ^  ^  ^
        //  A1    30 [3] 04 01 AA   — but the SEQUENCE says len=2, so [3]
        //  with len=3 extends beyond the SEQUENCE.
        let malformed = [0xA1, 0x07, 0x30, 0x02, 0xA3, 0x03, 0x04, 0x01, 0xAA];
        assert_eq!(
            extract_mech_list_mic(&malformed),
            None,
            "element extending beyond SEQUENCE should return None"
        );
    }

    #[test]
    fn test_extract_mech_list_mic_no_octet_string_inside() {
        // [3] containing a non-OCTET-STRING tag
        let bad_inner = der_tlv(0x05, &[0x00]); // NULL tag
        let ctx3 = der_tlv(0xA3, &bad_inner);
        let seq = der_tlv(0x30, &ctx3);
        let outer = der_tlv(0xA1, &seq);
        assert_eq!(extract_mech_list_mic(&outer), None);
    }

    // --- wrap tests ---

    #[test]
    fn test_wrap_response() {
        let ntlm = b"NTLMSSP\0\x02\x00\x00\x00";
        let wrapped = wrap_ntlm_response(ntlm);
        assert_eq!(wrapped[0], 0xA1);
        assert!(find_subslice(&wrapped, ntlm).is_some());
    }

    #[test]
    fn test_wrap_ntlm_response_first_leg_has_neg_state_and_supported_mech() {
        let ntlm = b"NTLMSSP\0\x02\x00\x00\x00challenge-body";
        let wrapped = wrap_ntlm_response(ntlm);

        // [1] negTokenResp — nothing after it
        let (resp, rest) = der_expect(&wrapped, 0xA1).expect("outer [1]");
        assert!(rest.is_empty(), "trailing bytes after negTokenResp");
        // SEQUENCE — nothing after it
        let (seq, rest) = der_expect(resp, 0x30).expect("SEQUENCE");
        assert!(rest.is_empty(), "trailing bytes after SEQUENCE");

        // [0] negState = accept-incomplete
        let (tag, ctx0, seq) = der_tlv_split(seq).expect("[0]");
        assert_eq!(tag, 0xA0);
        let (enum_content, rest) = der_expect(ctx0, 0x0A).expect("ENUMERATED");
        assert_eq!(enum_content, &[0x01]);
        assert!(rest.is_empty());

        // [1] supportedMech = NTLMSSP OID
        let (tag, ctx1, seq) = der_tlv_split(seq).expect("[1]");
        assert_eq!(tag, 0xA1);
        let (oid, rest) = der_expect(ctx1, 0x06).expect("OID");
        assert_eq!(oid, NTLMSSP_OID);
        assert!(rest.is_empty());

        // [2] responseToken = input token
        let (tag, ctx2, seq) = der_tlv_split(seq).expect("[2]");
        assert_eq!(tag, 0xA2);
        let (token, rest) = der_octet_string(ctx2).expect("OCTET STRING");
        assert_eq!(token, ntlm);
        assert!(rest.is_empty());

        assert!(seq.is_empty(), "unexpected elements after [2]");
    }

    #[test]
    fn test_wrap_ntlm_response_roundtrips_through_extract() {
        let ntlm = b"NTLMSSP\0\x02\x00\x00\x00challenge-body";
        let wrapped = wrap_ntlm_response(ntlm);
        assert_eq!(extract_from_neg_token_resp(&wrapped).unwrap(), ntlm);
        assert_eq!(extract_ntlm_token(&wrapped).unwrap(), ntlm);

        // Long token (> 255 bytes) exercises the 0x82 length form.
        let mut long = b"NTLMSSP\0\x02\x00\x00\x00".to_vec();
        long.extend(std::iter::repeat_n(0x5Au8, 400));
        let wrapped = wrap_ntlm_response(&long);
        assert_eq!(extract_ntlm_token(&wrapped).unwrap(), long);
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

    // --- extract_mech_types tests ---

    #[test]
    fn test_extract_mech_types() {
        let ntlm_token = b"NTLMSSP\0\x01\x00\x00\x00";
        let spnego = build_neg_token_init(ntlm_token);
        let mech_types = extract_mech_types(&spnego);
        assert!(mech_types.is_some(), "mechTypes should be extracted");
        // The inner SEQUENCE OF should start with 0x30
        assert_eq!(mech_types.unwrap()[0], 0x30);
    }

    #[test]
    fn test_extract_mech_types_non_init_returns_none() {
        let ntlm_token = b"NTLMSSP\0\x03\x00\x00\x00";
        let resp = build_neg_token_resp(ntlm_token);
        assert_eq!(extract_mech_types(&resp), None);
    }
}
