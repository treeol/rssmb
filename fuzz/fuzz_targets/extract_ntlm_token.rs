// Fuzz target: extract_ntlm_token (rssmb-auth spnego.rs)
// SPNEGO/NTLM token extraction — the largest pre-auth attack surface.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rssmb_auth::spnego::extract_ntlm_token;

fuzz_target!(|data: &[u8]| {
    let _ = extract_ntlm_token(data);
});