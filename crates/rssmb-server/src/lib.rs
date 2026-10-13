//! RSSMB server core — connection engine, session state, tree dispatch.
//!
//! The server uses a concurrent connection model:
//! - A **read task** frames incoming messages and dispatches to handlers.
//! - A **write task** serializes outgoing messages through a channel.
//! - Handlers run as spawned tasks, enabling STATUS_PENDING, cancellation,
//!   and unsolicited breaks (oplock/lease) without deadlock.

pub mod connection;
pub mod session;
pub mod tree;
pub mod opens;
pub mod dispatch;
pub mod config;
pub mod crypto;
pub mod fsinfo;
pub mod negotiate_ctx;
pub mod signing;

pub use config::{ServerConfig, ShareConfig};
pub use connection::Connection;
pub use session::Session;
pub use tree::Tree;

use std::sync::Arc;
use thiserror::Error;

/// Server-wide error type.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire error: {0}")]
    Wire(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("vfs error: {0}")]
    Vfs(String),
    #[error("session error: {0}")]
    Session(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("shutdown requested")]
    Shutdown,
}

/// Shared server state across all connections.
pub struct ServerState {
    /// Server configuration.
    pub config: Arc<ServerConfig>,
    /// All active sessions.
    pub sessions: Arc<tokio::sync::RwLock<Vec<Arc<Session>>>>,
    /// Global open table (for share-mode conflict tracking).
    pub open_table: Arc<opens::OpenTable>,
    /// NTLM credential store for user authentication.
    pub credentials: Arc<rssmb_auth::CredentialStore>,
    /// Shutdown signal.
    pub shutdown: Arc<tokio::sync::Notify>,
    /// Stable server GUID (generated once, used for all negotiate responses).
    /// Clients use this for reconnect/multichannel matching.
    pub server_guid: [u8; 16],
}

impl ServerState {
    pub fn new(config: ServerConfig) -> Self {
        use rand::RngCore;
        let mut guid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut guid);

        // Build the credential store from config users.
        let credentials = Arc::new(rssmb_auth::CredentialStore::new());
        for user in &config.users {
            if !user.disabled {
                credentials.add_sync(rssmb_auth::credentials::StoredCredential {
                    username: user.username.clone(),
                    nt_hash: [0u8; 16], // Placeholder — sspi uses the password via AuthIdentity
                    disabled: user.disabled,
                });
            }
        }

        Self {
            config: Arc::new(config),
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            open_table: Arc::new(opens::OpenTable::new()),
            credentials,
            shutdown: Arc::new(tokio::sync::Notify::new()),
            server_guid: guid,
        }
    }

    pub async fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub async fn add_session(&self, session: Arc<Session>) {
        self.sessions.write().await.push(session);
    }

    pub async fn remove_session(&self, session_id: u64) {
        self.sessions.write().await.retain(|s| s.id != session_id);
    }
}
