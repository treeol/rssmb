//! RSSMB server core — connection engine, session state, tree dispatch.
//!
//! The server uses a concurrent connection model:
//! - A **read task** frames incoming messages and dispatches to handlers.
//! - A **write task** serializes outgoing messages through a channel.
//! - Handlers run as spawned tasks, enabling STATUS_PENDING, cancellation,
//!   and unsolicited breaks (oplock/lease) without deadlock.

pub mod auth_limiter;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod dispatch;
pub mod durable;
pub mod fsinfo;
pub mod metrics;
pub mod negotiate_ctx;
pub mod notify;
pub mod opens;
pub mod quic;
pub mod session;
pub mod signing;
pub mod tree;

pub use config::{ServerConfig, ShareConfig};
pub use connection::Connection;
pub use session::Session;
pub use tree::Tree;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use thiserror::Error;

/// Stateful shutdown signal — race-free replacement for bare `Notify`.
///
/// `Notify::notify_waiters` only wakes tasks currently awaiting. A task
/// that calls `notified()` *after* `notify_waiters()` is stuck forever.
/// `ShutdownSignal` closes that race by tracking a `triggered` flag: any
/// `notified()` future checks the flag *after* registering with the
/// `Notify`, so a task that wasn't waiting when `trigger()` was called
/// still sees `triggered == true` and returns immediately.
pub struct ShutdownSignal {
    triggered: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            triggered: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Trigger shutdown — sets the flag and wakes all current waiters.
    /// Idempotent: calling it more than once is a no-op.
    pub fn trigger(&self) {
        self.triggered.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether shutdown has been triggered.
    pub fn is_triggered(&self) -> bool {
        self.triggered.load(Ordering::SeqCst)
    }

    /// Wait for shutdown. Returns immediately if already triggered.
    ///
    /// Race-free: registers the `Notified` future *before* checking the
    /// flag, so a `trigger()` that arrives between the check and the
    /// register is not missed.
    pub async fn notified(&self) {
        // Register before checking the flag — this is the critical
        // ordering. If we checked first, a trigger between the check
        // and the register would be lost.
        let notified = self.notify.notified();
        if self.triggered.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// NTLM identity store — built once at startup from config users.
    /// Each user's NT hash is pre-computed so plaintext passwords are never
    /// stored or rebuilt per session_setup. Reloaded on SIGHUP.
    pub identities: Arc<rssmb_auth::IdentityStore>,
    /// Live-reloadable identities (swapped on SIGHUP). The `identities`
    /// field above is the initial boot-time store; this is the current one.
    /// Use [`identities_snapshot`](Self::identities_snapshot) to get the
    /// current store. We keep both so `ServerState::new` doesn't change
    /// its signature and existing code that uses `state.identities`
    /// directly still works (it gets the boot-time store).
    identities_swap: StdRwLock<Arc<rssmb_auth::IdentityStore>>,
    /// Live-reloadable shares (swapped on SIGHUP).
    shares_swap: StdRwLock<Arc<std::collections::HashMap<String, crate::config::ShareConfig>>>,
    /// Connection limiter (global + per-IP).
    pub conn_limiter: Arc<crate::connection::ConnectionLimiter>,
    /// Auth failure limiter (per-IP token bucket with growing delay + cooldown).
    pub auth_limiter: Arc<crate::auth_limiter::AuthLimiter>,
    /// Durable handle table for SMB 3.x reconnect (DH2Q/DH2C).
    pub durable_table: Arc<crate::durable::DurableTable>,
    /// Server-wide metrics (lock-free atomics).
    pub metrics: Arc<crate::metrics::ServerMetrics>,
    /// Shutdown signal — stateful, race-free.
    pub shutdown: Arc<ShutdownSignal>,
    /// Stable server GUID (generated once, used for all negotiate responses).
    /// Clients use this for reconnect/multichannel matching.
    pub server_guid: [u8; 16],
    /// Global monotonically increasing connection ID counter shared across
    /// TCP and QUIC listeners.
    pub next_conn_id: std::sync::atomic::AtomicU64,
    /// Global registry of session-shared state for multichannel (SessionId → Arc<SessionShared>).
    /// When multichannel is disabled, this is still populated but only one channel
    /// per session exists.
    pub session_registry: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<u64, Arc<crate::dispatch::SessionShared>>>>,
}

impl ServerState {
    pub fn new(config: ServerConfig) -> Self {
        use rand::RngCore;
        let mut guid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut guid);

        // Build the identity store from config users — NT hashes are
        // pre-computed here so the plaintext password is never retained
        // or rebuilt per SESSION_SETUP. Disabled users are excluded.
        let identities = Arc::new(rssmb_auth::IdentityStore::from_users(
            config.users.iter().map(|u| {
                (
                    u.username.clone(),
                    u.password.clone(),
                    u.nt_hash.clone(),
                    u.disabled,
                )
            }),
        ));

        let conn_limiter = Arc::new(crate::connection::ConnectionLimiter::new(
            config.max_connections,
            config.max_connections_per_ip,
        ));

        let auth_limiter = Arc::new(crate::auth_limiter::AuthLimiter::new(
            config.auth_max_failures,
            config.auth_window_secs,
            config.auth_delay_max_ms,
            config.auth_cooldown_secs,
            config.auth_max_failures_per_conn,
        ));

        // Capture the shares for the live-reload store before config is moved.
        let initial_shares = Arc::new(config.shares.clone());

        Self {
            config: Arc::new(config),
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            open_table: Arc::new(opens::OpenTable::new()),
            identities: identities.clone(),
            identities_swap: StdRwLock::new(identities),
            shares_swap: StdRwLock::new(initial_shares),
            conn_limiter,
            auth_limiter,
            durable_table: Arc::new(crate::durable::DurableTable::new()),
            metrics: Arc::new(crate::metrics::ServerMetrics::new()),
            shutdown: Arc::new(ShutdownSignal::new()),
            server_guid: guid,
            next_conn_id: std::sync::atomic::AtomicU64::new(1),
            session_registry: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn shutdown(&self) {
        self.shutdown.trigger();
    }

    pub async fn add_session(&self, session: Arc<Session>) {
        self.sessions.write().await.push(session);
    }

    pub async fn remove_session(&self, session_id: u64) {
        self.sessions.write().await.retain(|s| s.id != session_id);
    }

    /// Get the current (live-reloadable) identity store.
    pub fn identities_snapshot(&self) -> Arc<rssmb_auth::IdentityStore> {
        self.identities_swap.read().unwrap().clone()
    }

    /// Get the current (live-reloadable) shares map.
    pub fn shares_snapshot(
        &self,
    ) -> Arc<std::collections::HashMap<String, crate::config::ShareConfig>> {
        self.shares_swap.read().unwrap().clone()
    }

    /// Reload users and share definitions from a new config.
    ///
    /// Existing sessions keep their state (session keys, signing, encryption).
    /// New TREE_CONNECTs see the new shares. Removed shares' trees are
    /// disconnected on next access (the share lookup will fail).
    ///
    /// Server-level settings (listen addr, signing policy, encryption policy,
    /// dialects, timeouts, limits) are NOT reloaded — they require a restart.
    /// This matches the Samba model: server-level settings need a restart;
    /// users and shares are live-reloadable.
    pub fn reload(&self, new_config: ServerConfig) {
        // Build a new identity store from the reloaded users.
        let new_identities = Arc::new(rssmb_auth::IdentityStore::from_users(
            new_config.users.iter().map(|u| {
                (
                    u.username.clone(),
                    u.password.clone(),
                    u.nt_hash.clone(),
                    u.disabled,
                )
            }),
        ));

        // Swap identities and shares atomically (each behind StdRwLock).
        // Server-level settings (listen, signing, encryption, dialects,
        // timeouts, limits) are NOT reloaded — they require a restart.
        *std::sync::RwLock::write(&self.identities_swap).unwrap() = new_identities;
        *std::sync::RwLock::write(&self.shares_swap).unwrap() = Arc::new(new_config.shares.clone());

        tracing::info!(
            shares = new_config.shares.len(),
            users = new_config.users.len(),
            "config reloaded — new shares and identities are live"
        );
    }
}
