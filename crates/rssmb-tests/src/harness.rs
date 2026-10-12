//! Test harness for starting a test SMB server.

use rssmb_server::{ServerConfig, ServerState, connection};
use std::sync::Arc;

/// A running test server instance.
pub struct TestServer {
    pub state: Arc<ServerState>,
    pub addr: std::net::SocketAddr,
    pub handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Start a test server on an ephemeral port with the given config.
    ///
    /// Binds `127.0.0.1:0` (or the configured address with port 0) and
    /// returns the actual bound address. No sleep needed — the listener
    /// is bound before the accept loop is spawned.
    pub async fn start(config: ServerConfig) -> std::io::Result<Self> {
        let bind_addr = format!("{}:{}", config.listen_addr, config.port);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        let addr = listener.local_addr()?;

        let state = Arc::new(ServerState::new(config));

        let listen_state = state.clone();
        let handle = tokio::spawn(async move {
            let _ = connection::listen_on(listener, listen_state).await;
        });

        Ok(Self { state, addr, handle })
    }

    /// Start with default test config.
    pub async fn default() -> std::io::Result<Self> {
        Self::start(ServerConfig::for_testing()).await
    }

    /// Stop the test server.
    pub async fn stop(self) {
        self.state.shutdown().await;
        let _ = self.handle.await;
    }
}