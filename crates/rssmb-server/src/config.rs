//! Server and share configuration.

use std::collections::HashMap;
use serde::Deserialize;

/// Top-level server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Listen address (default: 0.0.0.0)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// TCP port (default: 445)
    #[serde(default = "default_smb_port")]
    pub port: u16,

    /// Minimum SMB dialect to support
    #[serde(default)]
    pub min_dialect: DialectConfig,

    /// Maximum SMB dialect to support
    #[serde(default = "default_max_dialect")]
    pub max_dialect: DialectConfig,

    /// Signing policy
    #[serde(default)]
    pub signing: SigningPolicy,

    /// Encryption policy
    #[serde(default)]
    pub encryption: EncryptionPolicy,

    /// Maximum connections per IP (0 = unlimited)
    #[serde(default)]
    pub max_connections_per_ip: u32,

    /// Maximum frame size (bytes)
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: usize,

    /// Share definitions
    #[serde(default)]
    pub shares: HashMap<String, ShareConfig>,

    /// Guest access
    #[serde(default)]
    pub guest_access: bool,

    /// Health endpoint port (separate from SMB port)
    #[serde(default = "default_health_port")]
    pub health_port: u16,

    /// Maximum credits to grant per connection
    #[serde(default = "default_max_credits")]
    pub max_credits: u32,

    /// Server name (for SrvSvc NetrServerGetInfo). Defaults to "rssmb" if empty.
    #[serde(default)]
    pub server_name: String,

    /// User accounts for authentication.
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

/// User account configuration for NTLM authentication.
///
/// For MVP, passwords are stored in plaintext. In production, use an external
/// auth file mounted as a Secret (k8s) or environment variable — never commit
/// real credentials to version control.
#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub disabled: bool,
}

fn default_listen_addr() -> String { "0.0.0.0".to_string() }
fn default_smb_port() -> u16 { 445 }
fn default_max_frame_size() -> usize { 1_048_576 }
fn default_health_port() -> u16 { 8080 }
fn default_max_credits() -> u32 { 1024 }
fn default_max_dialect() -> DialectConfig { DialectConfig::Smb311 }

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum DialectConfig {
    Smb2002,
    Smb21,
    Smb30,
    Smb302,
    Smb311,
}

impl Default for DialectConfig {
    fn default() -> Self {
        DialectConfig::Smb21
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SigningPolicy {
    /// Signing is not offered
    Disabled,
    /// Signing is offered but not required
    Desired,
    /// Signing is required
    Required,
}

impl Default for SigningPolicy {
    fn default() -> Self {
        SigningPolicy::Required
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionPolicy {
    /// Encryption is not offered
    Disabled,
    /// Encryption is offered but not required
    Desired,
    /// Encryption is required
    Required,
}

impl Default for EncryptionPolicy {
    fn default() -> Self {
        EncryptionPolicy::Desired
    }
}

/// Per-share configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ShareConfig {
    /// Share name
    pub name: String,

    /// Filesystem path (for LocalFs backend)
    pub path: String,

    /// Comment/description
    #[serde(default)]
    pub comment: String,

    /// Read-only share
    #[serde(default)]
    pub read_only: bool,

    /// Browseable in network listing
    #[serde(default = "default_true")]
    pub browseable: bool,

    /// Guest access allowed
    #[serde(default)]
    pub guest_ok: bool,

    /// Allowed users (empty = all authenticated users)
    #[serde(default)]
    pub valid_users: Vec<String>,

    /// Require encryption for all traffic on this share (SMB 3.x).
    /// Only effective for 3.x dialects; ignored for 2.x.
    #[serde(default)]
    pub encrypt_data: bool,
}

fn default_true() -> bool { true }

impl ServerConfig {
    /// Load from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Validate config consistency: a share with `encrypt_data = true` under
    /// `encryption = "disabled"` is a startup error (MS-SMB2: encryption
    /// cannot be required on a share if the server doesn't support encryption).
    pub fn validate(&self) -> Result<(), String> {
        if self.encryption == EncryptionPolicy::Disabled {
            for share in self.shares.values() {
                if share.encrypt_data {
                    return Err(format!(
                        "share '{}' has encrypt_data = true but encryption is disabled \
                         — cannot require per-share encryption without server support",
                        share.name
                    ));
                }
            }
        }
        // IPC$ is a reserved share name (the named-pipe share). A configured
        // share with that name would shadow the built-in IPC$ tree and break
        // share enumeration.
        if self.shares.iter().any(|(k, _)| k.eq_ignore_ascii_case("IPC$")) {
            return Err("share named 'IPC$' is reserved — cannot configure a disk share with that name".to_string());
        }
        Ok(())
    }

    /// Default config for testing.
    pub fn for_testing() -> Self {
        let mut shares = HashMap::new();
        shares.insert("test".to_string(), ShareConfig {
            name: "test".to_string(),
            path: "/tmp/rssmb-test".to_string(),
            comment: "Test share".to_string(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: false,
        });

        Self {
            listen_addr: "127.0.0.1".to_string(),
            port: 0,
            min_dialect: DialectConfig::Smb21,
            max_dialect: DialectConfig::Smb311,
            signing: SigningPolicy::Required,
            encryption: EncryptionPolicy::Desired,
            max_connections_per_ip: 100,
            max_frame_size: 1_048_576,
            shares,
            guest_access: false,
            health_port: 8080,
            max_credits: 1024,
            server_name: "rssmb".to_string(),
            users: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::for_testing();
        assert_eq!(config.port, 0);
        assert_eq!(config.signing, SigningPolicy::Required);
        assert_eq!(config.max_dialect, DialectConfig::Smb311);
        assert!(config.shares.contains_key("test"));
    }

    #[test]
    fn test_toml_parsing() {
        let toml_str = r#"
listen_addr = "0.0.0.0"
port = 445
min_dialect = "smb21"
max_dialect = "smb311"
signing = "required"
encryption = "desired"
max_connections_per_ip = 100
max_frame_size = 1048576
guest_access = false
health_port = 8080
max_credits = 1024

[shares.public]
name = "public"
path = "/data/public"
comment = "Public share"
read_only = false
browseable = true
guest_ok = true
valid_users = []
"#;
        let config = ServerConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.port, 445);
        assert_eq!(config.max_dialect, DialectConfig::Smb311);
        assert!(config.shares.contains_key("public"));
        let share = &config.shares["public"];
        assert_eq!(share.path, "/data/public");
        assert!(share.guest_ok);
    }

    #[test]
    fn test_toml_parsing_with_users() {
        let toml_str = r#"
listen_addr = "0.0.0.0"
port = 445
guest_access = true
health_port = 8080
max_credits = 1024

[shares.public]
name = "public"
path = "/data/public"
guest_ok = true

[[users]]
username = "admin"
password = "secret"
disabled = false

[[users]]
username = "guest_user"
password = "pass123"
disabled = true
"#;
        let config = ServerConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.users.len(), 2);
        assert_eq!(config.users[0].username, "admin");
        assert_eq!(config.users[0].password, "secret");
        assert!(!config.users[0].disabled);
        assert_eq!(config.users[1].username, "guest_user");
        assert!(config.users[1].disabled);
    }

    #[test]
    fn test_validate_rejects_encrypt_data_under_disabled() {
        let mut config = ServerConfig::for_testing();
        config.encryption = EncryptionPolicy::Disabled;
        config.shares.insert("enc_share".to_string(), ShareConfig {
            name: "enc_share".to_string(),
            path: "/tmp/rssmb-enc".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: true,
        });
        assert!(config.validate().is_err(), "encrypt_data under disabled must be rejected");
    }

    #[test]
    fn test_validate_ok_encrypt_data_under_desired() {
        let mut config = ServerConfig::for_testing();
        config.encryption = EncryptionPolicy::Desired;
        config.shares.insert("enc_share".to_string(), ShareConfig {
            name: "enc_share".to_string(),
            path: "/tmp/rssmb-enc".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: true,
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_ipc_share_name() {
        let mut config = ServerConfig::for_testing();
        config.shares.insert("IPC$".to_string(), ShareConfig {
            name: "IPC$".to_string(),
            path: "/tmp/ipc".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: false,
        });
        assert!(config.validate().is_err(), "IPC$ share name must be rejected");
    }

    #[test]
    fn test_validate_rejects_ipc_case_insensitive() {
        let mut config = ServerConfig::for_testing();
        config.shares.insert("ipc$".to_string(), ShareConfig {
            name: "ipc$".to_string(),
            path: "/tmp/ipc".to_string(),
            comment: String::new(),
            read_only: false,
            browseable: true,
            guest_ok: false,
            valid_users: vec![],
            encrypt_data: false,
        });
        assert!(config.validate().is_err(), "ipc$ share name must be rejected (case-insensitive)");
    }
}
