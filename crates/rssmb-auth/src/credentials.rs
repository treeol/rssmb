//! Credential store — username + NT hash database.
//!
//! NT hashes are password-equivalent secrets. In production, these should
//! be loaded from k8s Secrets or a properly protected file, never from
//! ConfigMaps or environment variables.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A stored credential (username + NT hash).
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub username: String,
    /// The NT hash (MD4 of UTF-16LE password) as 16 bytes.
    pub nt_hash: [u8; 16],
    /// Whether the account is disabled.
    pub disabled: bool,
}

/// Thread-safe credential store.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    credentials: Arc<RwLock<HashMap<String, StoredCredential>>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add(&self, cred: StoredCredential) {
        self.credentials.write().await.insert(cred.username.to_lowercase(), cred);
    }

    /// Synchronous add for use outside async contexts (e.g. ServerState::new).
    /// Panics if the lock is held by the current thread (shouldn't happen at startup).
    pub fn add_sync(&self, cred: StoredCredential) {
        self.credentials.blocking_write().insert(cred.username.to_lowercase(), cred);
    }

    pub async fn lookup(&self, username: &str) -> Option<StoredCredential> {
        self.credentials.read().await.get(&username.to_lowercase()).cloned()
    }

    pub async fn verify(&self, username: &str, _nt_proof: &[u8]) -> bool {
        if let Some(cred) = self.lookup(username).await {
            if cred.disabled {
                return false;
            }
            // For MVP: we don't implement the full NTLMv2 proof verification here.
            // That's handled by the sspi acceptor which has access to the NT hash.
            // This method is a placeholder for credential lookup validation.
            true
        } else {
            false
        }
    }

    pub async fn user_exists(&self, username: &str) -> bool {
        self.lookup(username).await.is_some()
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_credential_lookup() {
        let store = CredentialStore::new();
        store.add(StoredCredential {
            username: "admin".to_string(),
            nt_hash: [0u8; 16],
            disabled: false,
        }).await;

        assert!(store.user_exists("admin").await);
        assert!(store.user_exists("ADMIN").await); // case-insensitive
        assert!(!store.user_exists("nobody").await);
    }

    #[tokio::test]
    async fn test_disabled_account() {
        let store = CredentialStore::new();
        store.add(StoredCredential {
            username: "disabled".to_string(),
            nt_hash: [0u8; 16],
            disabled: true,
        }).await;

        let cred = store.lookup("disabled").await.unwrap();
        assert!(cred.disabled);
    }
}
