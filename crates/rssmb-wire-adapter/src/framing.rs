//! Frame-level parsing: recognize SMB2 plain, transform, compress, and SMB1
//! magic bytes at the framing layer.

use bytes::{Buf, BufMut, BytesMut};
use crate::{SMB2_MAGIC, TRANSFORM_MAGIC, COMPRESS_MAGIC, SMB1_MAGIC, MAX_FRAME_SIZE, WireError, FramedMessage};
use rssmb_proto::plain::PlainRequest;

/// Read a NetBIOS-framed SMB message from a buffer.
///
/// NetBIOS session service framing:
///   byte 0:    session message type (0x00 = message, 0x81 = session request,
///              0x82 = positive response, 0x83 = negative response, 0x85 = keep-alive)
///   bytes 1-3: 24-bit big-endian length
///   bytes 4+:  payload
pub fn read_netbios_frame(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    if buf.remaining() < 4 {
        return Err(WireError::IncompleteFrame);
    }

    let msg_type = buf.get_u8();
    let mut len = 0u32;
    len |= (buf.get_u8() as u32) << 16;
    len |= (buf.get_u8() as u32) << 8;
    len |= buf.get_u8() as u32;

    // Handle NetBIOS session request (type 0x81) — just read and discard for now
    if msg_type == 0x81 {
        if len as usize > MAX_FRAME_SIZE {
            return Err(WireError::OversizedFrame(len as usize));
        }
        let data = buf.copy_to_bytes(len as usize);
        // Session request — we could validate the called/calling names here
        return Ok(data.to_vec());
    }

    if msg_type == 0x85 {
        // Keep-alive — no payload
        return Ok(Vec::new());
    }

    if msg_type != 0x00 {
        return Err(WireError::UnknownNetbiosType(msg_type));
    }

    if len as usize > MAX_FRAME_SIZE {
        return Err(WireError::OversizedFrame(len as usize));
    }

    if buf.remaining() < len as usize {
        return Err(WireError::IncompleteFrame);
    }

    let payload = buf.copy_to_bytes(len as usize);
    Ok(payload.to_vec())
}

/// Parse a raw payload (after NetBIOS framing) into a FramedMessage.
///
/// Supports SMB2 compound requests: if the first message's header has
/// `next_command != 0`, the payload contains multiple chained requests.
/// Each sub-message is decoded from a bounded sub-slice so body parsers
/// can't read into the next message.
pub fn parse_payload(data: &[u8]) -> Result<FramedMessage, WireError> {
    if data.len() < 4 {
        return Err(WireError::IncompleteFrame);
    }

    let magic = &data[..4];

    if magic == SMB2_MAGIC {
        parse_plain_payload(data)
    } else if magic == TRANSFORM_MAGIC {
        Ok(FramedMessage::Encrypted(data.to_vec()))
    } else if magic == COMPRESS_MAGIC {
        Ok(FramedMessage::Compressed(data.to_vec()))
    } else if magic == SMB1_MAGIC {
        Ok(FramedMessage::Smb1Negotiate(data.to_vec()))
    } else {
        Err(WireError::UnknownMagic(magic.to_vec()))
    }
}

/// Maximum number of compound requests per NetBIOS frame (resource policy).
const MAX_COMPOUND_COMMANDS: usize = 20;

/// Byte ranges `[start, end)` of each SMB2 message in a plain payload,
/// following NextCommand. Same validation as `parse_plain_payload`; for a
/// payload that parses, the ranges correspond 1:1 with the decoded requests.
/// Used for per-message signature verification and WRITE data extraction.
pub fn message_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    const HDR: usize = 64;
    let mut out = Vec::new();
    let mut offset = 0usize;
    for _ in 0..MAX_COMPOUND_COMMANDS {
        if offset + HDR > data.len() {
            break;
        }
        let next = u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap()) as usize;
        if next == 0 {
            out.push((offset, data.len()));
            break;
        }
        if next % 8 != 0 || next < HDR || offset + next + HDR > data.len() {
            break;
        }
        out.push((offset, offset + next));
        offset += next;
    }
    out
}

/// Parse a plain SMB2 payload, handling compound (chained) requests.
fn parse_plain_payload(data: &[u8]) -> Result<FramedMessage, WireError> {
    use binrw::BinRead;

    // Decode the first header to check for compound chaining.
    if data.len() < rssmb_proto::header::Header::STRUCT_SIZE {
        return Err(WireError::IncompleteFrame);
    }
    let first_header: rssmb_proto::header::Header = {
        let mut cursor = std::io::Cursor::new(&data[..rssmb_proto::header::Header::STRUCT_SIZE]);
        rssmb_proto::header::Header::read_le(&mut cursor)
            .map_err(|e| WireError::DecodeError(format!("header: {e:?}")))?
    };

    if first_header.next_command == 0 {
        // Single message — decode from the full payload.
        let mut cursor = std::io::Cursor::new(data);
        let request = PlainRequest::read_le(&mut cursor)
            .map_err(|e| WireError::DecodeError(format!("{e:?}")))?;
        return Ok(FramedMessage::Plain(request));
    }

    // Compound: walk the chain, decoding each sub-message from a bounded slice.
    let mut requests = Vec::new();
    let mut offset = 0usize;

    for _ in 0..MAX_COMPOUND_COMMANDS {
        if offset + rssmb_proto::header::Header::STRUCT_SIZE > data.len() {
            return Err(WireError::DecodeError(format!(
                "compound: insufficient bytes for header at offset {offset}"
            )));
        }

        // Decode the header at this offset to find the next boundary.
        let header_slice = &data[offset..offset + rssmb_proto::header::Header::STRUCT_SIZE];
        let header: rssmb_proto::header::Header = {
            let mut cursor = std::io::Cursor::new(header_slice);
            rssmb_proto::header::Header::read_le(&mut cursor)
                .map_err(|e| WireError::DecodeError(format!("header at {offset}: {e:?}")))?
        };

        let next = header.next_command as usize;

        // Determine the end of this sub-message.
        let sub_end = if next == 0 {
            data.len()
        } else {
            // Validate: alignment, minimum, and enough room for the next header.
            if next % 8 != 0 {
                return Err(WireError::DecodeError(format!(
                    "compound: misaligned next_command {next} at offset {offset}"
                )));
            }
            if next < rssmb_proto::header::Header::STRUCT_SIZE {
                return Err(WireError::DecodeError(format!(
                    "compound: next_command {next} < header size at offset {offset}"
                )));
            }
            let boundary = offset + next;
            if boundary + rssmb_proto::header::Header::STRUCT_SIZE > data.len() {
                return Err(WireError::DecodeError(format!(
                    "compound: next_command points past end at offset {offset}"
                )));
            }
            boundary
        };

        // Decode this sub-message from a bounded sub-slice.
        let sub_slice = &data[offset..sub_end];
        let mut cursor = std::io::Cursor::new(sub_slice);
        let request = PlainRequest::read_le(&mut cursor)
            .map_err(|e| WireError::DecodeError(format!("body at {offset}: {e:?}")))?;
        requests.push(request);

        if next == 0 {
            break;
        }
        offset = sub_end;
    }

    // If we exited the loop without hitting next_command == 0, the chain
    // was longer than MAX_COMPOUND_COMMANDS — reject the entire frame.
    let last_next = {
        let last = requests.last().unwrap();
        last.header.next_command
    };
    if last_next != 0 {
        return Err(WireError::DecodeError(format!(
            "compound: chain exceeds {} commands without termination",
            MAX_COMPOUND_COMMANDS
        )));
    }

    if requests.len() == 1 {
        // next_command was set but the chain had only one message after validation.
        Ok(FramedMessage::Plain(requests.into_iter().next().unwrap()))
    } else {
        Ok(FramedMessage::Compound(requests))
    }
}

/// Write a NetBIOS session message frame.
pub fn write_netbios_frame(payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    let len = payload.len();
    buf.put_u8(0x00); // session message
    buf.put_u8((len >> 16) as u8);
    buf.put_u8((len >> 8) as u8);
    buf.put_u8(len as u8);
    buf.extend_from_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netbios_frame_roundtrip() {
        let payload = vec![0xFE, b'S', b'M', b'B', 0x00, 0x00, 0x00, 0x00];
        let frame = write_netbios_frame(&payload);
        let mut cursor: &[u8] = &frame;
        let result = read_netbios_frame(&mut cursor).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_oversized_frame_rejected() {
        // Length field = 0xFFFFFF (16MB) — exceeds MAX_FRAME_SIZE
        let frame = vec![0x00, 0xFF, 0xFF, 0xFF];
        let mut cursor: &[u8] = &frame;
        let result = read_netbios_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::OversizedFrame(_))));
    }

    #[test]
    fn test_unknown_magic_rejected() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let result = parse_payload(&data);
        assert!(matches!(result, Err(WireError::UnknownMagic(_))));
    }

    #[test]
    fn test_smb1_magic_detected() {
        let data = vec![0xFF, b'S', b'M', b'B', 0x00];
        let result = parse_payload(&data);
        assert!(matches!(result, Ok(FramedMessage::Smb1Negotiate(_))));
    }

    #[test]
    fn test_smb2_magic_detected() {
        // Minimal valid SMB2 header (64 bytes, padded)
        let mut data = vec![0xFE, b'S', b'M', b'B'];
        data.extend_from_slice(&[0x00; 60]); // rest of header
        let result = parse_payload(&data);
        // Will likely fail to decode fully, but should attempt Plain parse
        // (the magic detection is what we're testing)
        assert!(matches!(result, Err(WireError::DecodeError(_)) | Ok(FramedMessage::Plain(_))));
    }

    #[test]
    fn test_compound_parse_two_echo() {
        // Build two ECHO requests chained via next_command and parse them.
        use binrw::BinWrite;
        use rssmb_proto::header::{Header, Command, HeaderFlags};
        use rssmb_proto::echo::EchoRequest;
        use rssmb_proto::plain::{PlainRequest, RequestContent};

        fn make_echo(msg_id: u64, next_command: u32) -> PlainRequest {
            PlainRequest {
                header: Header {
                    credit_charge: 0,
                    status: 0,
                    command: Command::Echo,
                    credit_request: 1,
                    flags: HeaderFlags::new(),
                    next_command,
                    message_id: msg_id,
                    tree_id: Some(0),
                    async_id: None,
                    session_id: 0,
                    signature: 0,
                },
                content: RequestContent::Echo(EchoRequest::default()),
            }
        }

        // Encode first echo (with next_command pointing to the second).
        let echo1 = make_echo(1, 0); // next_command will be patched below
        let echo2 = make_echo(2, 0);

        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        echo1.write_le(&mut std::io::Cursor::new(&mut buf1)).unwrap();
        echo2.write_le(&mut std::io::Cursor::new(&mut buf2)).unwrap();

        // Pad buf1 to 8-byte alignment.
        let aligned1 = (buf1.len() + 7) & !7;
        let pad = aligned1 - buf1.len();
        buf1.extend(std::iter::repeat(0u8).take(pad));
        // Patch next_command = aligned1 in buf1 (bytes 20-23).
        let nc = aligned1 as u32;
        buf1[20..24].copy_from_slice(&nc.to_le_bytes());

        let mut frame = Vec::new();
        frame.extend_from_slice(&buf1);
        frame.extend_from_slice(&buf2);

        let result = parse_payload(&frame);
        match result {
            Ok(FramedMessage::Compound(requests)) => {
                assert_eq!(requests.len(), 2);
                assert_eq!(requests[0].header.message_id, 1);
                assert_eq!(requests[1].header.message_id, 2);
            }
            other => panic!("expected Compound with 2 requests, got {:?}", other),
        }
    }

    /// smbclient -m SMB3 (Samba) offers 3.1.1 and appends an
    /// SMB2_POSIX_EXTENSIONS_AVAILABLE context (type 0x0100). MS-SMB2 3.3.5.4:
    /// unknown negotiate contexts are ignored, so the request must decode.
    #[test]
    fn test_negotiate_with_unknown_context_decodes() {
        use binrw::BinWrite;
        use rssmb_proto::Guid;
        use rssmb_proto::header::{Command, Header, HeaderFlags};
        use rssmb_proto::negotiate::*;
        use rssmb_proto::plain::{PlainRequest, RequestContent};

        let posix_ctx_data: Vec<u8> = (0u8..16).collect();
        let neg = NegotiateRequest {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            capabilities: GlobalCapabilities::new(),
            client_guid: Guid::from([7u8; 16]),
            dialects: vec![Dialect::Smb0302, Dialect::Smb0311],
            negotiate_context_list: Some(vec![
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![HashAlgorithm::Sha512],
                    salt: vec![0xab; 32],
                }
                .into(),
                NegotiateContext {
                    context_type: NegotiateContextType::Unknown(0x0100),
                    data: NegotiateContextValue::Unknown {
                        type_id: 0x0100,
                        data: posix_ctx_data.clone(),
                    },
                },
                SigningCapabilities {
                    signing_algorithms: vec![SigningAlgorithmId::AesCmac],
                }
                .into(),
            ]),
        };
        let req = PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Negotiate,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 0,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content: RequestContent::Negotiate(neg),
        };
        let mut buf = Vec::new();
        req.write_le(&mut std::io::Cursor::new(&mut buf)).unwrap();
        // Unknown context is written with its raw type ID (0x0100, LE) and data.
        let mut expect = vec![0x00u8, 0x01, 16, 0, 0, 0, 0, 0];
        expect.extend_from_slice(&posix_ctx_data);
        assert!(buf.windows(expect.len()).any(|w| w == expect.as_slice()));

        let parsed = match parse_payload(&buf) {
            Ok(FramedMessage::Plain(r)) => r,
            other => panic!("expected Plain NEGOTIATE, got {:?}", other),
        };
        let RequestContent::Negotiate(n) = &parsed.content else {
            panic!("expected Negotiate content");
        };
        let ctxs = n.negotiate_context_list.as_ref().unwrap();
        assert_eq!(ctxs.len(), 3);
        assert_eq!(ctxs[1].context_type, NegotiateContextType::Unknown(0x0100));
        assert_eq!(ctxs[1].context_type.id(), 0x0100);
        assert_eq!(ctxs[1].data.get_matching_type(), NegotiateContextType::Unknown(0x0100));
        match &ctxs[1].data {
            NegotiateContextValue::Unknown { type_id, data } => {
                assert_eq!(*type_id, 0x0100);
                assert_eq!(data, &posix_ctx_data);
            }
            other => panic!("expected Unknown context, got {:?}", other),
        }
        // Known contexts before and after the unknown one still decode.
        assert!(n.get_ctx_preauth_integrity_capabilities().is_some());
        assert_eq!(
            n.get_ctx_signing_capabilities().unwrap().signing_algorithms,
            vec![SigningAlgorithmId::AesCmac]
        );
    }

    /// Build a raw SMB2 NEGOTIATE (header + body) with the given raw contexts
    /// (type, data). Contexts are 8-byte aligned per MS-SMB2 2.2.3.1.
    fn raw_negotiate(contexts: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; 64];
        m[..4].copy_from_slice(b"\xfeSMB");
        m[4] = 64; // header StructureSize
        m[14] = 1; // credit request
        let dialects: [u16; 2] = [0x0302, 0x0311];
        let mut body = Vec::new();
        body.extend_from_slice(&36u16.to_le_bytes());
        body.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // security mode
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // capabilities
        body.extend_from_slice(&[7u8; 16]); // client guid
        let ctx_off_pos = body.len();
        body.extend_from_slice(&0u32.to_le_bytes()); // context offset (patched)
        body.extend_from_slice(&(contexts.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        for d in dialects {
            body.extend_from_slice(&d.to_le_bytes());
        }
        m.extend_from_slice(&body);
        for (i, (ty, data)) in contexts.iter().enumerate() {
            while m.len() % 8 != 0 {
                m.push(0);
            }
            if i == 0 {
                let off = m.len() as u32;
                m[64 + ctx_off_pos..64 + ctx_off_pos + 4].copy_from_slice(&off.to_le_bytes());
            }
            m.extend_from_slice(&ty.to_le_bytes());
            m.extend_from_slice(&(data.len() as u16).to_le_bytes());
            m.extend_from_slice(&0u32.to_le_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    fn negotiate_contexts(raw: &[u8]) -> Vec<rssmb_proto::negotiate::NegotiateContext> {
        use rssmb_proto::plain::RequestContent;
        match parse_payload(raw) {
            Ok(FramedMessage::Plain(r)) => match r.content {
                RequestContent::Negotiate(n) => n.negotiate_context_list.unwrap(),
                other => panic!("expected Negotiate, got {:?}", other),
            },
            other => panic!("expected Plain NEGOTIATE, got {:?}", other),
        }
    }

    /// Unknown contexts with lengths that need padding before the next
    /// context (and as the last context) decode, and later contexts land on
    /// the right offsets.
    #[test]
    fn test_negotiate_unknown_context_odd_lengths() {
        use rssmb_proto::negotiate::*;
        let preauth: Vec<u8> = {
            let mut v = vec![1, 0, 32, 0, 1, 0];
            v.extend_from_slice(&[0xab; 32]);
            v
        };
        let signing: &[u8] = &[1, 0, 1, 0]; // 1 algorithm: AES-CMAC
        for len in [0usize, 1, 5, 7, 8, 9, 16] {
            let unk: Vec<u8> = (0..len as u8).collect();
            let raw = raw_negotiate(&[
                (0x0001, &preauth),
                (0x0100, &unk),
                (0x0008, signing),
                (0x7777, &unk),
            ]);
            let ctxs = negotiate_contexts(&raw);
            assert_eq!(ctxs.len(), 4, "len={len}");
            assert_eq!(ctxs[1].context_type, NegotiateContextType::Unknown(0x0100));
            assert_eq!(
                ctxs[1].data,
                NegotiateContextValue::Unknown { type_id: 0x0100, data: unk.clone() },
                "len={len}"
            );
            assert_eq!(
                ctxs[2].data,
                NegotiateContextValue::SigningCapabilities(SigningCapabilities {
                    signing_algorithms: vec![SigningAlgorithmId::AesCmac]
                }),
                "len={len}"
            );
            assert_eq!(ctxs[3].context_type.id(), 0x7777);
        }
    }

    /// A known context whose DataLength declares more bytes than its parser
    /// consumes: the next context must still be found at the declared end.
    #[test]
    fn test_negotiate_known_context_with_trailing_bytes() {
        use rssmb_proto::negotiate::*;
        // SigningCapabilities (1 algo = 4 bytes) + 5 trailing junk bytes.
        let signing: &[u8] = &[1, 0, 1, 0, 0xee, 0xee, 0xee, 0xee, 0xee];
        let enc: &[u8] = &[1, 0, 2, 0]; // 1 cipher: AES-128-GCM
        let raw = raw_negotiate(&[(0x0008, signing), (0x0002, enc)]);
        let ctxs = negotiate_contexts(&raw);
        assert_eq!(ctxs.len(), 2);
        assert_eq!(
            ctxs[1].data,
            NegotiateContextValue::EncryptionCapabilities(EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Gcm]
            })
        );
    }

    /// Unknown cipher, signing algorithm, and hash algorithm IDs inside
    /// negotiate contexts must decode (not fail the whole request).
    #[test]
    fn test_negotiate_unknown_context_values() {
        use rssmb_proto::negotiate::*;

        // Build a raw negotiate with a preauth context containing an unknown
        // hash algorithm (0x02), an encryption context with an unknown cipher
        // (0x00FF), and a signing context with an unknown algorithm (0x00AA).
        let preauth: Vec<u8> = {
            let mut v = vec![1, 0, 32, 0, 2, 0]; // 1 hash, 32 salt, hash_id=0x02 (unknown)
            v.extend_from_slice(&[0xab; 32]);
            v
        };
        let enc: Vec<u8> = {
            let mut v = vec![1, 0]; // 1 cipher
            v.extend_from_slice(&0x00FFu16.to_le_bytes()); // unknown cipher
            v
        };
        let signing: Vec<u8> = {
            let mut v = vec![1, 0]; // 1 algo
            v.extend_from_slice(&0x00AAu16.to_le_bytes()); // unknown algo
            v
        };
        let raw = raw_negotiate(&[
            (0x0001, &preauth),
            (0x0002, &enc),
            (0x0008, &signing),
        ]);
        let ctxs = negotiate_contexts(&raw);
        assert_eq!(ctxs.len(), 3);

        // Preauth: unknown hash algorithm decoded.
        match &ctxs[0].data {
            NegotiateContextValue::PreauthIntegrityCapabilities(c) => {
                assert_eq!(c.hash_algorithms.len(), 1);
                assert_eq!(c.hash_algorithms[0], HashAlgorithm::Unknown(0x02));
            }
            other => panic!("expected PreauthIntegrity, got {:?}", other),
        }

        // Encryption: unknown cipher decoded.
        match &ctxs[1].data {
            NegotiateContextValue::EncryptionCapabilities(c) => {
                assert_eq!(c.ciphers.len(), 1);
                assert_eq!(c.ciphers[0], EncryptionCipher::Unknown(0x00FF));
            }
            other => panic!("expected Encryption, got {:?}", other),
        }

        // Signing: unknown algorithm decoded.
        match &ctxs[2].data {
            NegotiateContextValue::SigningCapabilities(c) => {
                assert_eq!(c.signing_algorithms.len(), 1);
                assert_eq!(c.signing_algorithms[0], SigningAlgorithmId::Unknown(0x00AA));
            }
            other => panic!("expected Signing, got {:?}", other),
        }
    }

    #[test]
    fn test_compound_parse_single_with_next_command() {
        // If next_command is set but points to end, should fail.
        use binrw::BinWrite;
        use rssmb_proto::header::{Header, Command, HeaderFlags};
        use rssmb_proto::echo::EchoRequest;
        use rssmb_proto::plain::{PlainRequest, RequestContent};

        let echo = PlainRequest {
            header: Header {
                credit_charge: 0,
                status: 0,
                command: Command::Echo,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 64, // points to offset 64, but there's no more data
                message_id: 1,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content: RequestContent::Echo(EchoRequest::default()),
        };

        let mut buf = Vec::new();
        echo.write_le(&mut std::io::Cursor::new(&mut buf)).unwrap();

        let result = parse_payload(&buf);
        // Should fail because next_command points past end.
        assert!(matches!(result, Err(WireError::DecodeError(_))));
    }
}
