//! Credential store — username + NT hash database.
//!
//! NT hashes are password-equivalent secrets. In production, these should
//! be loaded from k8s Secrets or a properly protected file, never from
//! ConfigMaps or environment variables.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ntlmv2;

/// A stored identity for NTLM authentication.
///
/// Stores the pre-computed NT hash (MD4 of UTF-16LE password) so the
/// plaintext password is never retained after config parsing. The NT hash
/// is sufficient for NTLMv2 proof verification and session key computation.
#[derive(Clone)]
pub struct StoredIdentity {
    pub username: String,
    /// NT hash (MD4 of UTF-16LE password) — 16 bytes.
    pub nt_hash: [u8; 16],
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredIdentity")
            .field("username", &self.username)
            .field("nt_hash", &"<redacted>")
            .finish()
    }
}

/// Thread-safe identity store — the set of configured NTLM users.
///
/// Built once at server startup from the config. Each identity's NT hash is
/// pre-computed at construction time so plaintext passwords are never stored
/// or rebuilt per SESSION_SETUP. Lookups are case-insensitive on username.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    identities: Arc<HashMap<String, StoredIdentity>>,
}

impl IdentityStore {
    /// An empty identity store (no configured users — guest/anonymous only).
    pub fn empty() -> Self {
        Self {
            identities: Arc::new(HashMap::new()),
        }
    }

    /// Build an identity store from sspi AuthIdentity entries (legacy
    /// constructor — computes NT hashes from plaintext passwords).
    pub fn from_identities(identities: &[sspi::AuthIdentity]) -> Self {
        let mut map = HashMap::new();
        for id in identities {
            let username = id.username.account_name().to_string();
            let nt_hash = ntlmv2::nt_hash(id.password.as_ref());
            map.insert(
                username.to_lowercase(),
                StoredIdentity { username, nt_hash },
            );
        }
        Self {
            identities: Arc::new(map),
        }
    }

    /// Build an identity store from a list of (username, password, nt_hash_hex, disabled) tuples.
    ///
    /// For each non-disabled user:
    /// - If `nt_hash` is provided (hex), parse it directly.
    /// - Otherwise, compute `nt_hash(password)`.
    ///
    /// Disabled users are excluded. Invalid hex hashes log a warning and
    /// are skipped.
    pub fn from_users(users: impl IntoIterator<Item = (String, String, String, bool)>) -> Self {
        let mut map = HashMap::new();
        for (username, password, nt_hash_hex, disabled) in users {
            if disabled {
                continue;
            }
            let nt_hash = if !nt_hash_hex.is_empty() {
                match hex::decode(&nt_hash_hex) {
                    Ok(bytes) if bytes.len() == 16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    Ok(_) => {
                        tracing::warn!(
                            username = %username,
                            "nt_hash is not 16 bytes — skipping user"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            username = %username,
                            error = %e,
                            "invalid nt_hash hex — skipping user"
                        );
                        continue;
                    }
                }
            } else if !password.is_empty() {
                ntlmv2::nt_hash(&password)
            } else {
                tracing::warn!(
                    username = %username,
                    "no password or nt_hash — skipping user"
                );
                continue;
            };
            map.insert(
                username.to_lowercase(),
                StoredIdentity {
                    username,
                    nt_hash,
                },
            );
        }
        Self {
            identities: Arc::new(map),
        }
    }

    /// Look up an identity by username (case-insensitive).
    pub fn lookup(&self, username: &str) -> Option<StoredIdentity> {
        self.identities.get(&username.to_lowercase()).cloned()
    }

    /// Number of configured identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

/// A stored credential (username + NT hash).
///
/// Deprecated: use [`StoredIdentity`] and [`IdentityStore`] instead.
#[derive(Debug, Clone)]
#[deprecated(note = "Use StoredIdentity / IdentityStore instead")]
pub struct StoredCredential {
    pub username: String,
    /// The NT hash (MD4 of UTF-16LE password) as 16 bytes.
    pub nt_hash: [u8; 16],
    /// Whether the account is disabled.
    pub disabled: bool,
}

/// Thread-safe credential store.
///
/// Deprecated: use [`IdentityStore`] instead — it pre-computes NT hashes
/// at startup and doesn't need async locking for lookups.
#[derive(Debug, Clone)]
#[deprecated(note = "Use IdentityStore instead")]
#[allow(deprecated)]
pub struct CredentialStore {
    credentials: std::sync::Arc<tokio::sync::RwLock<HashMap<String, StoredCredential>>>,
}

#[allow(deprecated)]
impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn add(&self, cred: StoredCredential) {
        self.credentials.write().await.insert(cred.username.to_lowercase(), cred);
    }

    /// Synchronous add for use outside async contexts (e.g. ServerState::new).
    /// Uses `try_write` with a busy loop — safe because at startup no async
    /// task holds the lock.
    pub fn add_sync(&self, cred: StoredCredential) {
        // Use blocking_write via std::thread::sleep fallback — at startup
        // the tokio runtime hasn't started its worker threads yet, so
        // blocking_write panics. Use a standard lock instead.
        // The RwLock is only ever held briefly; a spin loop is safe here.
        loop {
            match self.credentials.try_write() {
                Ok(mut guard) => {
                    guard.insert(cred.username.to_lowercase(), cred);
                    return;
                }
                Err(_) => {
                    // Lock contended — yield briefly and retry.
                    std::thread::sleep(std::time::Duration::from_micros(10));
                }
            }
        }
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

#[allow(deprecated)]
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
