//! Health check endpoint — HTTP on a separate port.
//!
//! Provides liveness (server is running) and readiness (shares/auth initialized)
//! checks for Kubernetes probes.

use rssmb_server::ServerState;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

/// Serve the health endpoint on the given address and port.
pub async fn serve(
    state: Arc<ServerState>,
    bind_addr: String,
    port: u16,
) -> Result<(), std::io::Error> {
    let ip: std::net::IpAddr = if bind_addr.is_empty() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else if bind_addr == "localhost" {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        bind_addr.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid health bind address '{}': {}", bind_addr, e),
            )
        })?
    };
    let addr = SocketAddr::new(ip, port);
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
    use tokio::io::AsyncReadExt;

    // 5-second read timeout — a slowloris shouldn't hold a health-check thread.
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "health read timeout"))??;

    if n == 0 {
        return Ok(());
    }

    // Parse the HTTP request line (simplified)
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, body) = match path {
        "/healthz" | "/liveness" => (200, "ok"),
        "/readyz" | "/ready" => {
            // Check if shares are configured
            if _state.shares_snapshot().is_empty() {
                (503, "not ready: no shares configured")
            } else {
                (200, "ready")
            }
        }
        "/metrics" => {
            // Prometheus text-format metrics.
            let body = _state.metrics.render_prometheus();
            return write_response(stream, 200, "text/plain; version=0.0.4", body.as_bytes()).await;
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
        status,
        status_text,
        content_type,
        body.len()
    );

    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
