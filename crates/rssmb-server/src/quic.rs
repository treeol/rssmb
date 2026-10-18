//! SMB over QUIC transport listener (UDP / TLS 1.3, ALPN `smb`).
//!
//! Implements the server side of SMB over QUIC (MS-SMB2 §3.3.5.1.1 / §2.1):
//! - Listens on a UDP socket (default port 443) using `quinn` + `rustls`
//!   with TLS 1.3 only and ALPN protocol identifier `"smb"`.
//! - Enforces connection limits (`ConnectionLimiter::try_admit`) on the
//!   incoming UDP source IP *before* performing the TLS handshake.
//! - Restricts each QUIC connection to a single client-initiated bidirectional
//!   stream (`max_concurrent_bidi_streams = 1`, `max_concurrent_uni_streams = 0`),
//!   feeding its `(RecvStream, SendStream)` halves into
//!   [`crate::connection::Connection::handle_stream`] with [`TransportKind::Quic`].

use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};

use crate::connection::{drain_connections, Connection};
use crate::dispatch::TransportKind;
use crate::ServerState;

/// ALPN protocol identifier required for SMB over QUIC (MS-SMB2 3.3.5.1.1).
pub const SMB_QUIC_ALPN: &[u8] = b"smb";

/// Timeout for completing the QUIC + TLS 1.3 handshake and opening the
/// initial bidirectional SMB stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Load PEM-encoded certificate chain and private key from disk and validate
/// that they can construct a TLS 1.3 `quinn::ServerConfig`.
pub fn validate_tls_files(cert_path: &str, key_path: &str) -> Result<(), String> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    build_quinn_server_config(certs, key, 900, 1_048_576).map(|_| ())
}

/// Load PEM-encoded X.509 certificates from `path`.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("failed to open QUIC certificate file '{path}': {e}"))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse PEM certificates from '{path}': {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "QUIC certificate file '{path}' contains no PEM certificates"
        ));
    }
    Ok(certs)
}

/// Load a PEM-encoded private key (PKCS#8, PKCS#1 RSA, or SEC1 EC) from `path`.
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("failed to open QUIC private key file '{path}': {e}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("failed to parse PEM private key from '{path}': {e}"))?
        .ok_or_else(|| format!("QUIC private key file '{path}' contains no PEM private key"))
}

/// Build a `quinn::ServerConfig` with TLS 1.3 only, ALPN `"smb"`, 0-RTT disabled,
/// and transport limits aligned with the server configuration.
pub fn build_quinn_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    idle_timeout_secs: u64,
    max_frame_size: usize,
) -> Result<quinn::ServerConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("failed to configure TLS 1.3 provider: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid TLS certificate or private key: {e}"))?;

    tls_config.alpn_protocols = vec![SMB_QUIC_ALPN.to_vec()];
    tls_config.max_early_data_size = 0; // Explicitly disable 0-RTT to prevent replay attacks

    let quic_tls = QuicServerConfig::try_from(tls_config)
        .map_err(|e| format!("failed to create QUIC TLS config: {e}"))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));

    let mut transport = quinn::TransportConfig::default();
    // SMB over QUIC uses a single bidirectional stream per connection and no
    // unidirectional streams.
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());

    let idle_secs = idle_timeout_secs.max(1);
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(idle_secs)) {
        transport.max_idle_timeout(Some(idle));
    }

    let window = quinn::VarInt::from_u32(
        crate::limits::max_wire_frame_for(max_frame_size).min(u32::MAX as usize) as u32,
    );
    transport.stream_receive_window(window);
    transport.receive_window(window);

    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Bind a QUIC UDP endpoint on `config.listen_addr:config.quic_port` and run
/// the accept loop until shutdown.
pub async fn listen_quic(state: Arc<ServerState>) -> std::io::Result<()> {
    let certs = load_certs(&state.config.quic_cert_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let key = load_private_key(&state.config.quic_key_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let server_config = build_quinn_server_config(
        certs,
        key,
        state.config.idle_timeout_secs,
        state.config.max_frame_size,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let bind_addr: SocketAddr =
        parse_quic_bind_addr(&state.config.listen_addr, state.config.quic_port)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    let _ = listen_quic_on(endpoint, state).await?;
    Ok(())
}

/// Parse a QUIC bind address from the config `listen_addr` (which may be an
/// IPv4, IPv6, `localhost`, or empty string) and `quic_port`.
fn parse_quic_bind_addr(listen_addr: &str, port: u16) -> Result<SocketAddr, String> {
    if listen_addr.is_empty() {
        return Ok(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port,
        ));
    }
    if listen_addr.eq_ignore_ascii_case("localhost") {
        return Ok(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }
    if let Ok(ip) = listen_addr.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Fall back to hostname resolution (e.g. "example.com").
    let addr_str = format!("{}:{}", listen_addr, port);
    addr_str
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve QUIC bind address '{addr_str}': {e}"))?
        .next()
        .ok_or_else(|| format!("no addresses resolved for '{addr_str}'"))
}

use std::net::ToSocketAddrs;

/// Run the SMB over QUIC accept loop on an already-bound [`quinn::Endpoint`].
pub async fn listen_quic_on(
    endpoint: quinn::Endpoint,
    state: Arc<ServerState>,
) -> std::io::Result<SocketAddr> {
    let addr = endpoint.local_addr()?;
    info!(addr = %addr, "SMB over QUIC listener bound");

    let mut connections = tokio::task::JoinSet::<()>::new();

    loop {
        let incoming = tokio::select! {
            biased;

            _ = state.shutdown.notified() => {
                info!("shutdown signaled; QUIC listener stopping");
                break;
            }

            inc = endpoint.accept() => match inc {
                Some(inc) => inc,
                None => {
                    info!("QUIC endpoint closed; stopping accept loop");
                    break;
                }
            },
        };

        let remote_addr = incoming.remote_address();
        let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);

        // Enforce connection limits (global + per-IP) before TLS handshake.
        let guard = match state.conn_limiter.try_admit(remote_addr.ip()) {
            Some(g) => g,
            None => {
                debug!(conn_id, %remote_addr, "QUIC connection limit exceeded — refusing");
                state
                    .metrics
                    .connections_rejected_limit_total
                    .fetch_add(1, Ordering::Relaxed);
                incoming.refuse();
                continue;
            }
        };

        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(e) => {
                warn!(conn_id, %remote_addr, error = %e, "failed to accept incoming QUIC packet");
                continue;
            }
        };

        state
            .metrics
            .connections_accepted_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .connections_active
            .fetch_add(1, Ordering::Relaxed);

        let state_clone = state.clone();
        connections.spawn(async move {
            let _guard = guard;

            let quic_conn = match tokio::select! {
                biased;
                _ = state_clone.shutdown.notified() => {
                    state_clone
                        .metrics
                        .connections_active
                        .fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                res = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting) => res,
            } {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    warn!(conn_id, %remote_addr, error = %e, "QUIC TLS handshake failed");
                    state_clone
                        .metrics
                        .connections_active
                        .fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => {
                    warn!(conn_id, %remote_addr, "QUIC TLS handshake timed out");
                    state_clone
                        .metrics
                        .connections_active
                        .fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };

            let (send_stream, recv_stream) = match tokio::select! {
                biased;
                _ = state_clone.shutdown.notified() => {
                    quic_conn.close(0u32.into(), b"server shutting down");
                    state_clone
                        .metrics
                        .connections_active
                        .fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                res = tokio::time::timeout(HANDSHAKE_TIMEOUT, quic_conn.accept_bi()) => res,
            } {
                Ok(Ok(streams)) => streams,
                Ok(Err(e)) => {
                    warn!(conn_id, %remote_addr, error = %e, "failed to accept QUIC bidirectional stream");
                    quic_conn.close(1u32.into(), b"stream error");
                    state_clone
                        .metrics
                        .connections_active
                        .fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => {
                    warn!(conn_id, %remote_addr, "timed out waiting for initial QUIC bidirectional stream");
                    quic_conn.close(1u32.into(), b"stream open timeout");
                    state_clone
                        .metrics
                        .connections_active
                        .fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };

            // Keep `quic_conn` alive for the duration of the SMB session and
            // close it cleanly once `handle_stream` finishes.
            //
            // `handle_stream` already waits for the write task to drain and
            // calls `shutdown()` (→ `SendStream::finish()`) on the QUIC
            // SendStream before returning, which sends a STREAM FIN.  We then
            // wait briefly for the peer to acknowledge the FIN (or for the
            // connection to close from the other side) before calling
            // `Connection::close()`.  Quinn's `close()` is *not* graceful —
            // it immediately sends CONNECTION_CLOSE and discards unacked
            // stream data — so this grace window prevents the final SMB
            // response from being lost.
            Connection::handle_stream(
                state_clone,
                recv_stream,
                send_stream,
                remote_addr,
                conn_id,
                TransportKind::Quic,
            )
            .await;

            // Give the peer a brief window to ACK the FIN before we force
            // a CONNECTION_CLOSE.  2 seconds is a conservative bound that
            // covers a typical RTT without delaying shutdown excessively.
            let _ = tokio::time::timeout(Duration::from_secs(2), quic_conn.closed()).await;
            quic_conn.close(0u32.into(), b"done");
        });

        while connections.try_join_next().is_some() {}
    }

    drain_connections(&mut connections, state.config.shutdown_grace_secs).await;
    endpoint.close(0u32.into(), b"server shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionPolicy, ServerConfig, SigningPolicy};
    use binrw::{BinRead, BinWrite};
    use quinn::crypto::rustls::QuicClientConfig;
    use rssmb_proto::echo::EchoRequest;
    use rssmb_proto::header::{Command, Header, HeaderFlags};
    use rssmb_proto::negotiate::{
        Dialect, GlobalCapabilities, HashAlgorithm, NegotiateContextType, NegotiateDialect,
        NegotiateRequest, NegotiateSecurityMode, PreauthIntegrityCapabilities,
        TransportCapabilities,
    };
    use rssmb_proto::plain::{PlainRequest, PlainResponse, RequestContent, ResponseContent};
    use rssmb_proto::Guid;
    use std::io::Cursor;

    fn generate_test_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("valid pkcs8 key");
        (vec![cert_der], key_der)
    }

    fn make_client_endpoint(root_cert: CertificateDer<'static>, alpn: &[u8]) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root_cert).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![alpn.to_vec()];
        let quic_client_cfg = QuicClientConfig::try_from(client_crypto).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_cfg)));
        endpoint
    }

    fn frame_request(req: &PlainRequest) -> Vec<u8> {
        let mut body = Vec::new();
        req.write_le(&mut Cursor::new(&mut body)).unwrap();
        let len = body.len() as u32;
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.push(0x00);
        framed.push((len >> 16) as u8);
        framed.push((len >> 8) as u8);
        framed.push(len as u8);
        framed.extend_from_slice(&body);
        framed
    }

    async fn read_framed_response(recv: &mut quinn::RecvStream) -> std::io::Result<PlainResponse> {
        let mut hdr = [0u8; 4];
        recv.read_exact(&mut hdr)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e.to_string()))?;
        assert_eq!(hdr[0], 0x00);
        let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
        let mut body = vec![0u8; len];
        recv.read_exact(&mut body)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e.to_string()))?;
        let resp = PlainResponse::read_le(&mut Cursor::new(&body))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(resp)
    }

    #[tokio::test]
    async fn test_quic_smb311_negotiate_and_echo_roundtrip() {
        let (certs, key) = generate_test_cert();
        let root_cert = certs[0].clone();
        let server_cfg = build_quinn_server_config(certs, key, 60, 1_048_576).unwrap();
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut cfg = ServerConfig::for_testing();
        cfg.signing = SigningPolicy::Desired;
        cfg.encryption = EncryptionPolicy::Desired;
        let state = Arc::new(ServerState::new(cfg));
        let server_state = state.clone();

        let server_task =
            tokio::spawn(async move { listen_quic_on(server_endpoint, server_state).await });

        let client_ep = make_client_endpoint(root_cert, SMB_QUIC_ALPN);
        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .expect("QUIC handshake should succeed");

        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi should succeed");

        // Send SMB 3.1.1 NEGOTIATE with PreauthIntegrityCapabilities + TransportCapabilities
        let neg_req = PlainRequest {
            header: Header {
                credit_charge: 1,
                status: 0,
                command: Command::Negotiate,
                credit_request: 4,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 0,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content: RequestContent::Negotiate(NegotiateRequest {
                security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
                capabilities: GlobalCapabilities::new().with_large_mtu(true),
                client_guid: Guid::from([0x11; 16]),
                dialects: vec![Dialect::Smb021, Dialect::Smb0311],
                negotiate_context_list: Some(vec![
                    PreauthIntegrityCapabilities {
                        hash_algorithms: vec![HashAlgorithm::Sha512],
                        salt: vec![0xaa; 32],
                    }
                    .into(),
                    TransportCapabilities::new()
                        .with_accept_transport_layer_security(true)
                        .into(),
                ]),
            }),
        };

        send.write_all(&frame_request(&neg_req)).await.unwrap();
        let neg_resp = read_framed_response(&mut recv).await.unwrap();
        assert_eq!(neg_resp.header.status, 0);
        match neg_resp.content {
            ResponseContent::Negotiate(nr) => {
                assert_eq!(nr.dialect_revision, NegotiateDialect::Smb0311);
                let ctxs = nr.negotiate_context_list.expect("3.1.1 contexts");
                assert!(
                    ctxs.iter()
                        .any(|c| c.context_type == NegotiateContextType::TransportCapabilities),
                    "server must echo TransportCapabilities over QUIC"
                );
            }
            other => panic!("unexpected response content: {:?}", other),
        }

        // Send ECHO request over the same QUIC stream
        let echo_req = PlainRequest {
            header: Header {
                credit_charge: 1,
                status: 0,
                command: Command::Echo,
                credit_request: 1,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: 1,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content: RequestContent::Echo(EchoRequest::default()),
        };
        send.write_all(&frame_request(&echo_req)).await.unwrap();
        let echo_resp = read_framed_response(&mut recv).await.unwrap();
        assert_eq!(echo_resp.header.status, 0);
        assert_eq!(echo_resp.header.command, Command::Echo);

        drop(send);
        conn.close(0u32.into(), b"done");
        state.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    }

    #[tokio::test]
    async fn test_quic_rejects_wrong_alpn() {
        let (certs, key) = generate_test_cert();
        let root_cert = certs[0].clone();
        let server_cfg = build_quinn_server_config(certs, key, 60, 1_048_576).unwrap();
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let state = Arc::new(ServerState::new(ServerConfig::for_testing()));
        let server_state = state.clone();
        let server_task =
            tokio::spawn(async move { listen_quic_on(server_endpoint, server_state).await });

        // Client offers ALPN "h3" instead of "smb"
        let client_ep = make_client_endpoint(root_cert, b"h3");
        let res = client_ep.connect(server_addr, "localhost").unwrap().await;
        assert!(res.is_err(), "wrong ALPN must fail TLS handshake");

        state.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    }

    #[tokio::test]
    async fn test_quic_rejects_pre_311_dialect_with_disconnect() {
        let (certs, key) = generate_test_cert();
        let root_cert = certs[0].clone();
        let server_cfg = build_quinn_server_config(certs, key, 60, 1_048_576).unwrap();
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let state = Arc::new(ServerState::new(ServerConfig::for_testing()));
        let server_state = state.clone();
        let server_task =
            tokio::spawn(async move { listen_quic_on(server_endpoint, server_state).await });

        let client_ep = make_client_endpoint(root_cert, SMB_QUIC_ALPN);
        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // Offer only SMB 2.1 over QUIC -> server must disconnect without response
        let neg_req = PlainRequest {
            header: Header {
                credit_charge: 1,
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
            content: RequestContent::Negotiate(NegotiateRequest {
                security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
                capabilities: GlobalCapabilities::new(),
                client_guid: Guid::from([0x22; 16]),
                dialects: vec![Dialect::Smb021],
                negotiate_context_list: None,
            }),
        };
        send.write_all(&frame_request(&neg_req)).await.unwrap();

        let mut buf = [0u8; 4];
        let res = recv.read_exact(&mut buf).await;
        assert!(
            res.is_err(),
            "QUIC connection must be closed when SMB 3.1.1 is not offered"
        );

        state.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    }

    #[test]
    fn test_validate_tls_files_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let res = validate_tls_files(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(res.is_ok(), "validate_tls_files failed: {:?}", res);
    }

    #[tokio::test]
    async fn test_quic_rejects_non_zero_framing_header() {
        let (certs, key) = generate_test_cert();
        let root_cert = certs[0].clone();
        let server_cfg = build_quinn_server_config(certs, key, 60, 1_048_576).unwrap();
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let state = Arc::new(ServerState::new(ServerConfig::for_testing()));
        let server_state = state.clone();
        let server_task =
            tokio::spawn(async move { listen_quic_on(server_endpoint, server_state).await });

        let client_ep = make_client_endpoint(root_cert, SMB_QUIC_ALPN);
        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // Send NetBIOS keep-alive (0x85) which is forbidden on QUIC
        send.write_all(&[0x85, 0x00, 0x00, 0x00]).await.unwrap();
        let mut buf = [0u8; 4];
        assert!(
            recv.read_exact(&mut buf).await.is_err(),
            "non-0x00 framing byte must close QUIC stream"
        );

        state.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    }

    #[tokio::test]
    async fn test_quic_connection_limiter_refuses_when_full() {
        let (certs, key) = generate_test_cert();
        let root_cert = certs[0].clone();
        let server_cfg = build_quinn_server_config(certs, key, 60, 1_048_576).unwrap();
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut cfg = ServerConfig::for_testing();
        cfg.max_connections = 1;
        let state = Arc::new(ServerState::new(cfg));
        // Pre-admit 1 connection to saturate the global limit of 1.
        let _held_guard = state
            .conn_limiter
            .try_admit("10.0.0.1".parse().unwrap())
            .expect("first admit succeeds");

        let server_state = state.clone();
        let server_task =
            tokio::spawn(async move { listen_quic_on(server_endpoint, server_state).await });

        let client_ep = make_client_endpoint(root_cert, SMB_QUIC_ALPN);
        let res = client_ep.connect(server_addr, "localhost").unwrap().await;
        assert!(
            res.is_err(),
            "QUIC connection must be refused when connection limit is reached"
        );
        assert_eq!(
            state
                .metrics
                .connections_rejected_limit_total
                .load(Ordering::Relaxed),
            1
        );

        state.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    }

    #[test]
    fn test_parse_quic_bind_addr_ipv4() {
        let addr = parse_quic_bind_addr("0.0.0.0", 443).unwrap();
        assert_eq!(addr.port(), 443);
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_parse_quic_bind_addr_ipv6() {
        let addr = parse_quic_bind_addr("::", 443).unwrap();
        assert_eq!(addr.port(), 443);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_parse_quic_bind_addr_localhost() {
        let addr = parse_quic_bind_addr("localhost", 443).unwrap();
        assert_eq!(addr.port(), 443);
        assert!(addr.is_ipv4());
    }

    #[test]
    fn test_parse_quic_bind_addr_empty() {
        let addr = parse_quic_bind_addr("", 8443).unwrap();
        assert_eq!(addr.port(), 8443);
        assert!(addr.is_ipv4());
    }
}
