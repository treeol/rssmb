// Fuzz target: normalize_path (rssmb-vfs path.rs)
// Exercises NormalizedPath::from_smb_path with arbitrary UTF-8 strings —
// NFC normalization, path traversal rejection, name validation, length
// limits. Panic = finding.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str;

fuzz_target!(|data: &[u8]| {
    // from_smb_path takes &str — only feed valid UTF-8.
    if let Ok(s) = str::from_utf8(data) {
        let _ = rssmb_vfs::NormalizedPath::from_smb_path(s);
    }
});