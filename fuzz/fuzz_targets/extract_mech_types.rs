// Fuzz target: extract_mech_types (rssmb-auth spnego.rs)
// SPNEGO mechanism type extraction — ASN.1 parsing.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rssmb_auth::spnego::extract_mech_types;

fuzz_target!(|data: &[u8]| {
    let _ = extract_mech_types(data);
});