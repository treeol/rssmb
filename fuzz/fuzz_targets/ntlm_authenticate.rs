// Fuzz target: ntlm_authenticate (rssmb-auth ntlmv2.rs)
// Exercises NTLM AUTHENTICATE parsing — parse_authenticate_fields,
// has_mic_flag, has_timestamp, verify_authenticate_mic. These are the
// largest pre-auth attack surfaces after SPNEGO token extraction.
// Panic = finding.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rssmb_auth::ntlmv2::parse_authenticate_fields(data);
    let _ = rssmb_auth::ntlmv2::has_mic_flag(data);
    let _ = rssmb_auth::ntlmv2::has_timestamp(data);
    // verify_authenticate_mic needs a session key; use a zero key so
    // the fuzz target exercises the parsing/comparison logic without
    // crypto. The MIC will never match a zero key, but the parsing and
    // bounds-checking paths are still exercised.
    let zero_key = [0u8; 16];
    let _ = rssmb_auth::ntlmv2::verify_authenticate_mic(&zero_key[..], data, data, data);
});