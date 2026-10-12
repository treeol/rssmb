//! Health check endpoint — HTTP on a separate port.
//!
//! Provides liveness (server is running) and readiness (shares/auth initialized)
//! checks for Kubernetes probes.

use std::sync::Arc;
use std::net::SocketAddr;
use rssmb_server::ServerState;
use tracing::{info, error};

/// Serve the health endpoint on the given port.
pub async fn serve(state: Arc<ServerState>, port: u16) -> Result<(), std::io::Error> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Health endpoint listening on {}", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Health listener accept error: {}", e);
                        continue;
                    }
                };

                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_health_request(stream, state).await {
                        tracing::debug!("Health request from {} error: {}", peer, e);
                    }
                });
            }
            _ = state.shutdown.notified() => {
                info!("Health endpoint shutting down");
                return Ok(());
            }
        }
    }
}

async fn handle_health_request(
    mut stream: tokio::net::TcpStream,
    _state: Arc<ServerState>,
) -> Result<(), std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    // Parse the HTTP request line (simplified)
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request.lines().next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, body) = match path {
        "/healthz" | "/liveness" => (200, "ok"),
        "/readyz" | "/ready" => {
            // Check if shares are configured
            if _state.config.shares.is_empty() {
                (503, "not ready: no shares configured")
            } else {
                (200, "ready")
            }
        }
        "/metrics" => {
            // Basic metrics (extensible for Prometheus)
            let sessions = _state.sessions.read().await.len();
            let body = format!(
                "# HELP rssmb_sessions_active Active sessions\n\
                 # TYPE rssmb_sessions_active gauge\n\
                 rssmb_sessions_active {}\n",
                sessions
            );
            return write_response(stream, 200, "text/plain", body.as_bytes()).await;
        }
        _ => (404, "not found"),
    };

    write_response(stream, status, "text/plain", body.as_bytes()).await
}

async fn write_response(
    mut stream: tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;

    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "OK",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        status, status_text, content_type, body.len()
    );

    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
