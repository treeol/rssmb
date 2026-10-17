// Fuzz target: proto_decode_header (rssmb-proto header.rs)
// Exercises Header::read_le with arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use binrw::BinRead;
use rssmb_proto::header::Header;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = Header::read_le(&mut cursor);
});