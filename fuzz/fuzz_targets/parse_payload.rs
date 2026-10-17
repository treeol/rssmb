// Fuzz target: parse_payload (wire-adapter framing.rs)
// Exercises the SMB2 frame parser with arbitrary bytes.
// Panic = finding. Fix at source, add crash input as regression test.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rssmb_wire_adapter::framing::parse_payload;

fuzz_target!(|data: &[u8]| {
    let _ = parse_payload(data);
});