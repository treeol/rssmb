// Fuzz target: proto_decode_plain_request (rssmb-proto plain.rs)
// Exercises PlainRequest::read_le with arbitrary bytes — exercises
// all command-body decoders (negotiate, session_setup, create, etc.).
#![no_main]
use libfuzzer_sys::fuzz_target;
use binrw::BinRead;
use rssmb_proto::plain::PlainRequest;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = PlainRequest::read_le(&mut cursor);
});