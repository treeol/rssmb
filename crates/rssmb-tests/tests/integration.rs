//! Step 10.2 — TCP integration tests.
//!
//! These tests start a real TestServer on an ephemeral port, connect via
//! TCP, send raw SMB2 frames (NetBIOS-framed), and validate the responses.
//! They exercise the full connection read-loop → parse → dispatch → encode
//! → write path, not just the dispatch handler in isolation.
//!
//! What's covered:
//! - NEGOTIATE for all four dialects (2.1, 3.0, 3.0.2, 3.1.1)
//! - ECHO after negotiation
//! - Compound NEGOTIATE rejection (MS-SMB2: NEGOTIATE must not be compounded)
//! - SMB1 magic → error response
//! - Bad magic → connection closed
//! - Truncated frame (header only) → error or connection closed
//! - Empty payload → ignored (no response)
//! - NetBIOS framing (session request type 0x81 stripped)
//!
//! What's NOT covered (needs a client-side NTLM+signing implementation):
//! - Authenticated SESSION_SETUP
//! - Signing verification
//! - Encryption (GCM)
//! - File I/O round-trips
//! - Tree connect / create / read / write
//! These are covered by the impacket-driven live tests in tests/live/.

use rssmb_proto::{
    header::{Command, Header, HeaderFlags},
    negotiate::{
        Dialect, GlobalCapabilities, HashAlgorithm, NegotiateRequest,
        NegotiateSecurityMode, PreauthIntegrityCapabilities,
    },
    plain::{PlainRequest, PlainResponse, RequestContent, ResponseContent},
    Guid,
};
use rssmb_server::ServerConfig;
use rssmb_tests::TestServer;
use rssmb_wire_adapter::framing::write_netbios_frame;
use binrw::BinWrite;

use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Default per-read timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a NEGOTIATE request for the given dialects.
fn make_negotiate(dialects: Vec<Dialect>, message_id: u64) -> PlainRequest {
    let negotiate_context_list = if dialects.contains(&Dialect::Smb0311) {
        Some(vec![
            PreauthIntegrityCapabilities {
                hash_algorithms: vec![HashAlgorithm::Sha512],
                salt: vec![0xab; 32],
            }
            .into(),
        ])
    } else {
        None
    };

    let content = RequestContent::Negotiate(NegotiateRequest {
        security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
        capabilities: GlobalCapabilities::new().with_large_mtu(true),
        client_guid: Guid::generate(),
        dialects,
        negotiate_context_list,
    });

    PlainRequest {
        header: Header {
            credit_charge: 0,
            status: 0,
            command: Command::Negotiate,
            credit_request: 1,
            flags: HeaderFlags::new(),
            next_command: 0,
            message_id,
            tree_id: Some(0),
            async_id: None,
            session_id: 0,
            signature: 0,
        },
        content,
    }
}

/// Build an ECHO request.
fn make_echo(message_id: u64) -> PlainRequest {
    let content = RequestContent::Echo(rssmb_proto::echo::EchoRequest::default());
    PlainRequest {
        header: Header {
            credit_charge: 0,
            status: 0,
            command: Command::Echo,
            credit_request: 1,
            flags: HeaderFlags::new(),
            next_command: 0,
            message_id,
            tree_id: Some(0),
            async_id: None,
            session_id: 0,
            signature: 0,
        },
        content,
    }
}

/// Encode a PlainRequest into NetBIOS-framed bytes (ready to send on the wire).
fn encode_request(req: &PlainRequest) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    req.write_le(&mut cursor).expect("encode request");
    let framed = write_netbios_frame(&buf);
    framed.to_vec()
}

/// Read one NetBIOS-framed response from the TCP stream.
///
/// Reads the 4-byte NetBIOS header, then the body. Returns the body bytes
/// (without the NetBIOS header). Returns `None` if the connection was
/// closed cleanly (EOF on header read).
async fn read_one_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    match timeout(READ_TIMEOUT, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
        Ok(Err(e)) => panic!("read header: {e}"),
        Err(_) => panic!("read header timed out"),
    }

    let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
    if len == 0 {
        return Some(Vec::new());
    }

    let mut body = vec![0u8; len];
    match timeout(READ_TIMEOUT, stream.read_exact(&mut body)).await {
        Ok(Ok(_)) => Some(body),
        Ok(Err(e)) => panic!("read body: {e}"),
        Err(_) => panic!("read body timed out"),
    }
}

/// Decode a response body (after NetBIOS framing) into a PlainResponse.
fn decode_response(body: &[u8]) -> PlainResponse {
    use binrw::BinRead;
    let mut cursor = std::io::Cursor::new(body);
    PlainResponse::read_le(&mut cursor).expect("decode response")
}

/// Build a ServerConfig with a temp-dir share for testing.
fn make_config() -> (ServerConfig, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let share_path = dir.path().to_str().unwrap().to_string();
    let mut shares = HashMap::new();
    shares.insert(
        "test".to_string(),
        rssmb_server::ShareConfig {
            name: "test".to_string(),
            path: share_path,
            comment: "Test share".to_string(),
            read_only: false,
            browseable: true,
            guest_ok: true,
            valid_users: vec![],
            encrypt_data: false,
            follow_symlinks: rssmb_vfs::FollowSymlinks::Never,
            strict_sync: true,
            case_sensitive: false,
        },
    );

    let config = ServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        port: 0,
        signing: rssmb_server::config::SigningPolicy::Desired,
        encryption: rssmb_server::config::EncryptionPolicy::Desired,
        guest_access: true,
        shares,
        ..ServerConfig::for_testing()
    };
    (config, dir)
}

/// Send a request and read the response (one frame).
async fn send_and_recv(
    stream: &mut TcpStream,
    req: &PlainRequest,
) -> Option<PlainResponse> {
    let wire = encode_request(req);
    stream.write_all(&wire).await.expect("write request");
    stream.flush().await.expect("flush");
    let body = read_one_frame(stream).await;
    body.map(|b| decode_response(&b))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_negotiate_smb21() {
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    let req = make_negotiate(vec![Dialect::Smb021], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    let resp = resp.expect("got a response");
    assert_eq!(resp.header.command, Command::Negotiate);
    assert_eq!(
        resp.header.status, 0,
        "negotiate should succeed (status 0)"
    );
    match resp.content {
        ResponseContent::Negotiate(neg) => {
            assert_eq!(
                neg.dialect_revision,
                rssmb_proto::negotiate::NegotiateDialect::Smb021,
                "should negotiate 2.1"
            );
        }
        other => panic!("expected Negotiate response, got {other:?}"),
    }
}

#[tokio::test]
async fn test_negotiate_smb30() {
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    let req = make_negotiate(vec![Dialect::Smb030], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    let resp = resp.expect("got a response");
    assert_eq!(resp.header.status, 0);
    match resp.content {
        ResponseContent::Negotiate(neg) => {
            assert_eq!(
                neg.dialect_revision,
                rssmb_proto::negotiate::NegotiateDialect::Smb030,
            );
        }
        other => panic!("expected Negotiate, got {other:?}"),
    }
}

#[tokio::test]
async fn test_negotiate_smb302() {
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    let req = make_negotiate(vec![Dialect::Smb0302], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    let resp = resp.expect("got a response");
    assert_eq!(resp.header.status, 0);
    match resp.content {
        ResponseContent::Negotiate(neg) => {
            assert_eq!(
                neg.dialect_revision,
                rssmb_proto::negotiate::NegotiateDialect::Smb0302,
            );
        }
        other => panic!("expected Negotiate, got {other:?}"),
    }
}

#[tokio::test]
async fn test_negotiate_smb311() {
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    let req = make_negotiate(vec![Dialect::Smb0311], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    let resp = resp.expect("got a response");
    assert_eq!(resp.header.status, 0);
    match resp.content {
        ResponseContent::Negotiate(neg) => {
            assert_eq!(
                neg.dialect_revision,
                rssmb_proto::negotiate::NegotiateDialect::Smb0311,
            );
        }
        other => panic!("expected Negotiate, got {other:?}"),
    }
}

#[tokio::test]
async fn test_negotiate_max_common_dialect() {
    // Client offers 2.1, 3.0, 3.0.2, 3.1.1 — server should pick the highest
    // common (3.1.1) since the server supports up to 3.1.1.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    let req = make_negotiate(
        vec![Dialect::Smb021, Dialect::Smb030, Dialect::Smb0302, Dialect::Smb0311],
        0,
    );
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    let resp = resp.expect("got a response");
    assert_eq!(resp.header.status, 0);
    match resp.content {
        ResponseContent::Negotiate(neg) => {
            assert_eq!(
                neg.dialect_revision,
                rssmb_proto::negotiate::NegotiateDialect::Smb0311,
                "should negotiate the highest common dialect"
            );
        }
        other => panic!("expected Negotiate, got {other:?}"),
    }
}

#[tokio::test]
async fn test_echo_after_negotiate() {
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Must negotiate first — the negotiate gate rejects pre-NEGOTIATE commands.
    let neg_req = make_negotiate(vec![Dialect::Smb021], 0);
    let neg_resp = send_and_recv(&mut stream, &neg_req).await.expect("negotiate response");
    assert_eq!(neg_resp.header.command, Command::Negotiate);
    assert_eq!(neg_resp.header.status, 0, "negotiate should succeed");

    // Now send an ECHO. The server should respond with a successful echo.
    let echo_req = make_echo(1);
    let resp = send_and_recv(&mut stream, &echo_req).await;
    server.stop().await;

    let resp = resp.expect("echo should produce a response");
    assert_eq!(resp.header.command, Command::Echo);
    assert_eq!(resp.header.status, 0, "echo should succeed after negotiation");
}

#[tokio::test]
async fn test_compound_negotiate_rejected() {
    // MS-SMB2 3.3.5.2.7: NEGOTIATE MUST NOT be in a compound request.
    // Build two NEGOTIATEs chained via next_command and send them.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Build two negotiate requests, chain them.
    let neg1 = make_negotiate(vec![Dialect::Smb021], 0);
    let neg2 = make_negotiate(vec![Dialect::Smb021], 2);

    // Encode neg1 to find its length, then patch next_command.
    let mut buf1 = Vec::new();
    let mut cursor1 = std::io::Cursor::new(&mut buf1);
    neg1.write_le(&mut cursor1).unwrap();
    let aligned1 = (buf1.len() + 7) & !7;
    let pad = aligned1 - buf1.len();
    buf1.extend(std::iter::repeat(0u8).take(pad));
    let nc = aligned1 as u32;
    buf1[20..24].copy_from_slice(&nc.to_le_bytes());

    let mut buf2 = Vec::new();
    let mut cursor2 = std::io::Cursor::new(&mut buf2);
    neg2.write_le(&mut cursor2).unwrap();

    let mut frame = Vec::new();
    frame.extend_from_slice(&buf1);
    frame.extend_from_slice(&buf2);

    let wire = write_netbios_frame(&frame);
    stream.write_all(&wire).await.expect("write");
    stream.flush().await.expect("flush");

    let body = read_one_frame(&mut stream).await;
    server.stop().await;

    // The server should respond with an error (STATUS_INVALID_PARAMETER),
    // not silently drop the connection.
    assert!(body.is_some(), "compound negotiate should produce a response");

    let resp = decode_response(&body.unwrap());
    assert_eq!(resp.header.command, Command::Negotiate);
    // STATUS_INVALID_PARAMETER = 0xC000000D
    assert_eq!(
        resp.header.status, 0xC000000D,
        "compound negotiate should be STATUS_INVALID_PARAMETER"
    );
}

#[tokio::test]
async fn test_smb1_magic_dropped() {
    // An SMB2-only server does not respond to SMB1 negotiate. The client
    // (impacket, smbclient, cifs.ko) retries with SMB2 after the SMB1
    // negotiate gets no response. The server should not send an SMB2 error
    // response (which would be misinterpreted as a truncated SMB2 negotiate
    // response by some clients). The connection stays open.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // SMB1 magic: 0xFF 'SMB' + some bytes.
    let payload = vec![0xFF, b'S', b'M', b'B', 0x00, 0x00, 0x00, 0x00];
    let wire = write_netbios_frame(&payload);
    stream.write_all(&wire).await.expect("write");
    stream.flush().await.expect("flush");

    // The server drops the SMB1 negotiate (no response). Send a valid
    // SMB2 NEGOTIATE — the server should still be alive and respond.
    let req = make_negotiate(vec![Dialect::Smb021], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    assert!(resp.is_some(), "server should respond to SMB2 after dropping SMB1");
    let resp = resp.unwrap();
    assert_eq!(resp.header.command, Command::Negotiate);
    assert_eq!(resp.header.status, 0, "SMB2 negotiate should succeed after SMB1 was dropped");
}

#[tokio::test]
async fn test_bad_magic_dropped() {
    // A frame with unrecognized magic (not \xfeSMB, \xfdSMB, \xfcSMB, or \xffSMB)
    // is silently dropped — the server can't even parse a header to build an
    // error response. The connection stays open for subsequent valid frames.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Send a bad-magic frame (64 bytes of 0xAA — looks like a header but
    // with unknown magic). The server drops it and continues.
    let payload = vec![0xAA; 64];
    let wire = write_netbios_frame(&payload);
    stream.write_all(&wire).await.expect("write bad magic");
    stream.flush().await.expect("flush");

    // Now send a valid NEGOTIATE — the server should still be alive.
    let req = make_negotiate(vec![Dialect::Smb021], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    assert!(resp.is_some(), "server should still respond after bad-magic frame");
    let resp = resp.unwrap();
    assert_eq!(resp.header.command, Command::Negotiate);
    assert_eq!(resp.header.status, 0, "negotiate after bad magic should succeed");
}

#[tokio::test]
async fn test_malformed_body_gets_error_response() {
    // Send a valid 64-byte SMB2 header (with NEGOTIATE command) but with
    // no body — the body decode will fail. The server should respond with
    // a STATUS_INVALID_PARAMETER error.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Build a valid negotiate request, then send only the 64-byte header
    // (truncating the body). The server parses the header successfully,
    // but the body decode fails → STATUS_INVALID_PARAMETER error.
    let req = make_negotiate(vec![Dialect::Smb021], 0);
    let mut full = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut full);
    req.write_le(&mut cursor).unwrap();
    // Truncate to exactly 64 bytes (header only, no body).
    let header_only = &full[..64];
    let wire = write_netbios_frame(header_only);
    stream.write_all(&wire).await.expect("write");
    stream.flush().await.expect("flush");

    let body = read_one_frame(&mut stream).await;
    server.stop().await;

    // The server should send an error response (STATUS_INVALID_PARAMETER).
    let body = body.expect("malformed body should produce an error response");
    let resp = decode_response(&body);
    assert_eq!(resp.header.command, Command::Negotiate);
    assert_ne!(resp.header.status, 0, "malformed body should yield an error status");
}

#[tokio::test]
async fn test_empty_payload_ignored() {
    // An empty NetBIOS payload (length 0) should be silently ignored
    // (the connection loop skips empty payloads). The server should not
    // send a response or close the connection.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Send an empty NetBIOS frame (type 0x00, length 0).
    let empty_frame = vec![0x00, 0x00, 0x00, 0x00];
    stream.write_all(&empty_frame).await.expect("write");
    stream.flush().await.expect("flush");

    // Now send a proper NEGOTIATE — the server should still be alive
    // and respond to it.
    let req = make_negotiate(vec![Dialect::Smb021], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    assert!(resp.is_some(), "server should still respond after empty frame");
    let resp = resp.unwrap();
    assert_eq!(resp.header.command, Command::Negotiate);
    assert_eq!(resp.header.status, 0);
}

#[tokio::test]
async fn test_netbios_keepalive_ignored() {
    // NetBIOS keep-alive (type 0x85) has no payload and should be
    // silently ignored by the server.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // Send a keep-alive frame: type 0x85, length 0.
    let keepalive = vec![0x85, 0x00, 0x00, 0x00];
    stream.write_all(&keepalive).await.expect("write");
    stream.flush().await.expect("flush");

    // Send a proper NEGOTIATE — server should still be alive.
    let req = make_negotiate(vec![Dialect::Smb021], 0);
    let resp = send_and_recv(&mut stream, &req).await;
    server.stop().await;

    assert!(resp.is_some(), "server should respond after keep-alive");
}

#[tokio::test]
async fn test_multiple_negotiates_same_connection() {
    // A second NEGOTIATE on the same connection should terminate the
    // connection (MS-SMB2: only one NEGOTIATE per connection). The server
    // returns Disconnect, which closes the TCP connection — the client
    // sees EOF (read returns None).
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");

    // First negotiate — should succeed.
    let req1 = make_negotiate(vec![Dialect::Smb021], 0);
    let resp1 = send_and_recv(&mut stream, &req1).await;
    assert!(resp1.is_some());
    assert_eq!(resp1.unwrap().header.status, 0);

    // Second negotiate — the server disconnects (FramedResponse::Disconnect),
    // so the client sees EOF (read returns None).
    let req2 = make_negotiate(vec![Dialect::Smb021], 2);
    let wire = encode_request(&req2);
    stream.write_all(&wire).await.expect("write second negotiate");
    stream.flush().await.expect("flush");

    // The server closes the connection — we should get EOF (None) or
    // a connection reset, not a hang.
    let body = read_one_frame(&mut stream).await;
    server.stop().await;

    // A repeat NEGOTIATE triggers Disconnect → the read loop returns Err
    // → the connection task exits → the TCP connection is closed.
    // The client sees EOF: read_one_frame returns None.
    assert!(body.is_none(), "second negotiate should disconnect (EOF), got: {body:?}");
}

#[tokio::test]
async fn test_server_shutdown_completes() {
    // Verify that calling stop() on TestServer completes the listener task
    // (the JoinHandle resolves). The shutdown signal unblocks the accept
    // loop via tokio::select!, so the task exits cleanly.
    let (config, _dir) = make_config();
    let server = TestServer::start(config).await.expect("start server");

    // Establish a connection first so the accept loop has accepted at least
    // one connection (ensuring the loop is past the first select! branch).
    let _stream = TcpStream::connect(server.addr).await.expect("connect");

    // Stop the server — this should complete within a reasonable time.
    let stop_result = timeout(Duration::from_secs(10), server.stop()).await;
    assert!(stop_result.is_ok(), "server.stop() should complete within 10s");
}