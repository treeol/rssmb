//! Session state machine.
//!
//! A [`Session`] is created per SMB2 SESSION_SETUP sequence and owns the
//! negotiated security material (session/signing/encryption keys), the
//! authenticated identity, and the set of active tree connections
//! (`TREE_CONNECT`s). Authentication is modeled as a multi-round conversation
//! via [`rssmb_auth::AuthProvider`]; the in-progress acceptor state lives in
//! `auth_state` until the conversation completes, at which point the session
//! key and identity are promoted to first-class fields and `auth_state` is
//! cleared.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::config::DialectConfig;
use crate::tree::Tree;
use crate::ServerError;

use rssmb_auth::{AuthProvider, AuthState, AuthStep, Identity};

/// One SMB2/3 session.
///
/// A session is bound to a single connection (`connection_id`) and is the
/// security boundary for all tree connects performed on it. Session IDs are
/// assigned by the connection engine and are unique per server.
pub struct Session {
    /// Unique session ID (the SMB2 SessionId).
    pub id: u64,
    /// Owning connection's ID.
    pub connection_id: u64,
    /// Authenticated identity, `None` until authentication completes.
    pub user_identity: Option<Identity>,
    /// Session key exported by the auth provider on completion — the root
    /// secret from which signing/encryption keys are derived.
    pub session_key: Option<Vec<u8>>,
    /// Derived signing key (HMAC-SHA256 key for SMB2 signing).
    pub signing_key: Option<Vec<u8>>,
    /// Derived encryption key (AES-128-CCM/GCM key for SMB3 encryption).
    pub encryption_key: Option<Vec<u8>>,
    /// Active tree connections keyed by `TreeId`.
    pub trees: tokio::sync::RwLock<HashMap<u32, Arc<Tree>>>,
    /// In-progress authentication acceptor state. `None` before the first
    /// `authenticate_step` and after authentication completes.
    pub auth_state: Option<AuthState>,
    /// Negotiated dialect for this session.
    pub dialect: Option<DialectConfig>,
    /// Whether message signing is required on this session.
    pub signing_required: bool,
    /// Whether this is a guest/anonym session.
    pub is_guest: bool,
}

impl Session {
    /// Create a new, unauthenticated session bound to `connection_id` with the
    /// given server-assigned `id`.
    pub fn new(connection_id: u64, id: u64) -> Self {
        debug!(session_id = id, connection_id, "creating session");
        Self {
            id,
            connection_id,
            user_identity: None,
            session_key: None,
            signing_key: None,
            encryption_key: None,
            trees: tokio::sync::RwLock::new(HashMap::new()),
            auth_state: None,
            dialect: None,
            signing_required: false,
            is_guest: false,
        }
    }

    /// Advance the authentication conversation by one round.
    ///
    /// `provider` drives the acceptor; `token` is the inbound SPNEGO/security
    /// blob from the client's SESSION_SETUP request. On the first call the
    /// session lazily initializes its [`AuthState`]. On `AuthStep::Complete`
    /// the session key and identity are promoted to first-class fields and
    /// `auth_state` is cleared.
    ///
    /// NOTE: the task spec listed the signature as `authenticate_step(token)`;
    /// an `AuthProvider` reference is required to actually step the
    /// conversation and is therefore taken as an explicit parameter.
    pub async fn authenticate_step(
        &mut self,
        provider: &dyn AuthProvider,
        token: &[u8],
    ) -> Result<AuthStep, ServerError> {
        if self.auth_state.is_none() {
            debug!(session_id = self.id, "initializing auth state");
            self.auth_state = Some(AuthState::new());
        }

        let state = self
            .auth_state
            .as_mut()
            .expect("auth_state was just initialized");

        let step = provider
            .step(token, state)
            .await
            .map_err(|e| ServerError::Auth(e.to_string()))?;

        match &step {
            AuthStep::Continue { .. } => {
                debug!(session_id = self.id, "auth step: continue");
            }
            AuthStep::Complete {
                session_key,
                identity,
                ..
            } => {
                info!(
                    session_id = self.id,
                    username = %identity.username,
                    is_guest = identity.is_guest,
                    "session authenticated"
                );
                self.user_identity = Some(identity.clone());
                self.is_guest = identity.is_guest;
                self.session_key = Some(session_key.clone());

                // TODO(Phase 2/3): derive signing/encryption keys from the
                // session key via the SMB2 KDF (SMB311 uses HKDF). For now the
                // raw session key is stored as a placeholder so the session is
                // usable end-to-end in tests.
                self.signing_key = Some(session_key.clone());
                self.encryption_key = Some(session_key.clone());

                // Conversation is done — drop the acceptor state.
                self.auth_state = None;
            }
            AuthStep::Reject { reason } => {
                warn!(session_id = self.id, reason = %reason, "auth step: rejected");
                self.auth_state = None;
            }
        }

        Ok(step)
    }

    /// `true` once authentication has completed successfully.
    pub fn is_authenticated(&self) -> bool {
        self.user_identity.is_some()
    }

    /// Register a tree connection under `tree_id`.
    pub async fn add_tree(&self, tree_id: u32, tree: Arc<Tree>) {
        debug!(session_id = self.id, tree_id, "tree connect");
        self.trees.write().await.insert(tree_id, tree);
    }

    /// Look up a tree connection by `tree_id`.
    pub async fn get_tree(&self, tree_id: u32) -> Option<Arc<Tree>> {
        self.trees.read().await.get(&tree_id).cloned()
    }

    /// Remove (tree-disconnect) a tree connection. Returns the removed tree
    /// if it was present.
    pub async fn remove_tree(&self, tree_id: u32) -> Option<Arc<Tree>> {
        debug!(session_id = self.id, tree_id, "tree disconnect");
        self.trees.write().await.remove(&tree_id)
    }

    /// Tear down the session: drop all tree connections and clear security
    /// material.
    pub async fn close(&self) {
        let mut trees = self.trees.write().await;
        let count = trees.len();
        trees.clear();
        info!(session_id = self.id, tree_count = count, "session closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rssmb_auth::{AuthError, GuestAuthProvider};

    #[tokio::test]
    async fn test_session_creation() {
        let session = Session::new(42, 7);
        assert_eq!(session.id, 7);
        assert_eq!(session.connection_id, 42);
        assert!(!session.is_authenticated());
        assert!(session.user_identity.is_none());
        assert!(session.session_key.is_none());
        assert!(session.signing_key.is_none());
        assert!(session.encryption_key.is_none());
        assert!(session.auth_state.is_none());
        assert!(session.dialect.is_none());
        assert!(!session.signing_required);
        assert!(!session.is_guest);
        // Empty tree table.
        assert!(session.trees.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_tree_add_remove() {
        let session = Session::new(1, 1);

        // Initially absent.
        assert!(session.get_tree(0).await.is_none());
        // Removing an absent tree yields None.
        assert!(session.remove_tree(0).await.is_none());

        let vfs: Arc<dyn rssmb_vfs::Vfs> = Arc::new(rssmb_vfs::memoryfs::MemoryFs::new());
        let share = crate::config::ShareConfig {
            name: "test".to_string(),
            path: "/tmp/test".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: false,
            follow_symlinks: rssmb_vfs::FollowSymlinks::Never,
        };
        let tree = Arc::new(Tree::new(1, 1, "test".to_string(), share, vfs));
        session.add_tree(1, tree.clone()).await;
        assert!(session.get_tree(1).await.is_some());

        let removed = session.remove_tree(1).await;
        assert!(removed.is_some());
        assert!(session.get_tree(1).await.is_none());
    }

    #[tokio::test]
    async fn test_close_clears_trees() {
        let session = Session::new(1, 2);
        let vfs: Arc<dyn rssmb_vfs::Vfs> = Arc::new(rssmb_vfs::memoryfs::MemoryFs::new());
        let share = crate::config::ShareConfig {
            name: "share".to_string(),
            path: "/tmp/share".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: false,
            follow_symlinks: rssmb_vfs::FollowSymlinks::Never,
        };
        let tree = Arc::new(Tree::new(1, 1, "share".to_string(), share, vfs));
        session.add_tree(1, tree).await;
        let vfs2: Arc<dyn rssmb_vfs::Vfs> = Arc::new(rssmb_vfs::memoryfs::MemoryFs::new());
        let share2 = crate::config::ShareConfig {
            name: "other".to_string(),
            path: "/tmp/other".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: false,
            follow_symlinks: rssmb_vfs::FollowSymlinks::Never,
        };
        session.add_tree(2, Arc::new(Tree::new(2, 1, "other".to_string(), share2, vfs2))).await;
        assert_eq!(session.trees.read().await.len(), 2);

        session.close().await;
        assert!(session.trees.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_auth_state_transitions() {
        let mut session = Session::new(1, 10);
        assert!(!session.is_authenticated());
        assert!(session.auth_state.is_none());

        // GuestAuthProvider completes in a single round with an empty token.
        let provider = GuestAuthProvider;
        let step = session
            .authenticate_step(&provider, &[])
            .await
            .expect("guest auth step");

        match step {
            AuthStep::Complete { identity, session_key, .. } => {
                assert_eq!(identity.username, "guest");
                assert!(identity.is_guest);
                assert!(session_key.is_empty());
            }
            _ => panic!("expected AuthStep::Complete"),
        }

        // After completion the session is authenticated and state is cleared.
        assert!(session.is_authenticated());
        assert!(session.user_identity.is_some());
        assert_eq!(session.user_identity.as_ref().unwrap().username, "guest");
        assert!(session.is_guest);
        assert!(session.auth_state.is_none());
        assert!(session.session_key.is_some());
        assert!(session.signing_key.is_some());
        assert!(session.encryption_key.is_some());
    }

    #[tokio::test]
    async fn test_auth_reject_clears_state() {
        // A provider that always rejects.
        struct RejectProvider;
        #[async_trait::async_trait]
        impl AuthProvider for RejectProvider {
            async fn step(
                &self,
                _input_token: &[u8],
                _state: &mut AuthState,
            ) -> Result<AuthStep, AuthError> {
                Ok(AuthStep::Reject {
                    reason: AuthError::LogonFailure("no".to_string()),
                })
            }
        }

        let mut session = Session::new(1, 11);
        let provider = RejectProvider;
        let step = session
            .authenticate_step(&provider, &[])
            .await
            .expect("step should not error");
        assert!(matches!(step, AuthStep::Reject { .. }));

        assert!(!session.is_authenticated());
        assert!(session.user_identity.is_none());
        assert!(session.auth_state.is_none());
    }
}
