// Fuzz target: read_netbios_frame (wire-adapter framing.rs)
// Exercises the NetBIOS session-service frame reader.
// The 0x81 copy_to_bytes(len) panic risk lives here — check
// buf.remaining() before copy_to_bytes(len).
#![no_main]
use libfuzzer_sys::fuzz_target;
use rssmb_wire_adapter::framing::read_netbios_frame;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    let _ = read_netbios_frame(&mut cursor);
});