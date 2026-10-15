// Fuzz target: decrypt_transform (rssmb-server crypto.rs)
// Exercises the SMB 3.x transform-header decryption path with arbitrary
// bytes. The key is a fixed zero key — decryption will always fail
// (GCM tag mismatch), but the header parsing, bounds checking, and
// AAD extraction paths are exercised. Panic = finding.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let zero_key = [0u8; 16];
    let _ = rssmb_server::crypto::decrypt_message(&zero_key, data);
});