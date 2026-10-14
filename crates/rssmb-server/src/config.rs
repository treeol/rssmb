//! Server and share configuration.

use std::collections::HashMap;
use serde::Deserialize;
use rssmb_vfs::FollowSymlinks;

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

    /// Maximum simultaneous connections (0 = unlimited)
    #[serde(default)]
    pub max_connections: u32,

    /// Idle timeout in seconds — a connection with no activity for this
    /// long is closed. Default: 900 (15 min).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

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

    /// Health endpoint bind address (default: 127.0.0.1 for security).
    /// Set to 0.0.0.0 to allow remote access — ensure the port is otherwise
    /// protected (firewall, network policy) if you do.
    #[serde(default = "default_health_bind_addr")]
    pub health_bind_addr: String,

    /// Maximum credits to grant per connection
    #[serde(default = "default_max_credits")]
    pub max_credits: u32,

    /// Maximum auth failures per IP within the rolling window before delay
    /// and cooldown kick in. 0 = disabled (no throttling).
    #[serde(default = "default_auth_max_failures")]
    pub auth_max_failures: u32,

    /// Rolling window (seconds) for auth failure counting per IP.
    #[serde(default = "default_auth_window_secs")]
    pub auth_window_secs: u64,

    /// Maximum delay (milliseconds) before sending LOGON_FAILURE after the
    /// failure threshold is exceeded. When the growing delay would exceed this,
    /// the IP enters cooldown instead.
    #[serde(default = "default_auth_delay_max_ms")]
    pub auth_delay_max_ms: u64,

    /// Cooldown duration (seconds) during which SESSION_SETUP from a
    /// throttled IP is refused immediately.
    #[serde(default = "default_auth_cooldown_secs")]
    pub auth_cooldown_secs: u64,

    /// Maximum auth failures per TCP connection before the connection is
    /// dropped. 0 = disabled (no per-connection cap).
    #[serde(default = "default_auth_max_failures_per_conn")]
    pub auth_max_failures_per_conn: u32,

    /// Server name (for SrvSvc NetrServerGetInfo). Defaults to "rssmb" if empty.
    #[serde(default)]
    pub server_name: String,

    /// User accounts for authentication.
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

/// User account configuration for NTLM authentication.
///
/// Either `password` (plaintext) or `nt_hash` (hex-encoded NT hash) may be
/// used. NT hashes are preferred for production — they are password-equivalent
/// but never expose the plaintext. Use `rssmb hash-password <password>` to
/// generate an `nt_hash` value.
///
/// Passwords and hashes are secrets. The config file's permissions should be
/// restricted (e.g. `chmod 600`) and it should be mounted as a secret, not
/// committed to version control.
#[derive(Clone, Deserialize)]
pub struct UserConfig {
    pub username: String,
    /// Plaintext password (optional if `nt_hash` is provided).
    #[serde(default)]
    pub password: String,
    /// NT hash as hex (alternative to plaintext password). When set, the
    /// plaintext `password` field is ignored and never needed.
    #[serde(default)]
    pub nt_hash: String,
    #[serde(default)]
    pub disabled: bool,
}

impl std::fmt::Debug for UserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserConfig")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("nt_hash", &self.nt_hash.as_str().is_empty().then(|| "<unset>").unwrap_or("<redacted>"))
            .field("disabled", &self.disabled)
            .finish()
    }
}

fn default_listen_addr() -> String { "0.0.0.0".to_string() }
fn default_smb_port() -> u16 { 445 }
fn default_max_frame_size() -> usize { 1_048_576 }
fn default_health_port() -> u16 { 8080 }
fn default_max_credits() -> u32 { 1024 }
fn default_auth_max_failures() -> u32 { 5 }
fn default_auth_window_secs() -> u64 { 60 }
fn default_auth_delay_max_ms() -> u64 { 5000 }
fn default_auth_cooldown_secs() -> u64 { 60 }
fn default_auth_max_failures_per_conn() -> u32 { 10 }
fn default_max_dialect() -> DialectConfig { DialectConfig::Smb311 }
fn default_idle_timeout() -> u64 { 900 }
fn default_health_bind_addr() -> String { "127.0.0.1".to_string() }

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

    /// Symlink policy for this share:
    /// - `never` (default): never follow symlinks; report them as reparse points
    /// - `within`: follow symlinks only if their target is within the share root
    #[serde(default)]
    pub follow_symlinks: FollowSymlinks,
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
        // Auth throttle validation: when throttling is enabled, the window,
        // delay cap, and cooldown must be positive and non-trivial.
        if self.auth_max_failures > 0 {
            if self.auth_window_secs == 0 {
                return Err("auth_window_secs must be > 0 when auth_max_failures > 0".to_string());
            }
            if self.auth_delay_max_ms == 0 {
                return Err("auth_delay_max_ms must be > 0 when auth_max_failures > 0".to_string());
            }
            if self.auth_cooldown_secs == 0 {
                return Err("auth_cooldown_secs must be > 0 when auth_max_failures > 0".to_string());
            }
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
            follow_symlinks: FollowSymlinks::Never,
        });

        Self {
            listen_addr: "127.0.0.1".to_string(),
            port: 0,
            min_dialect: DialectConfig::Smb21,
            max_dialect: DialectConfig::Smb311,
            signing: SigningPolicy::Required,
            encryption: EncryptionPolicy::Desired,
            max_connections_per_ip: 100,
            max_connections: 1024,
            idle_timeout_secs: 900,
            max_frame_size: 1_048_576,
            shares,
            guest_access: false,
            health_port: 8080,
            health_bind_addr: "127.0.0.1".to_string(),
            max_credits: 1024,
            auth_max_failures: 5,
            auth_window_secs: 60,
            auth_delay_max_ms: 5000,
            auth_cooldown_secs: 60,
            auth_max_failures_per_conn: 10,
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
    fn test_debug_redacts_password() {
        let user = UserConfig {
            username: "alice".to_string(),
            password: "secret123".to_string(),
            nt_hash: String::new(),
            disabled: false,
        };
        let debug = format!("{:?}", user);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret123"));
    }

    #[test]
    fn test_debug_redacts_nt_hash() {
        let user = UserConfig {
            username: "alice".to_string(),
            password: String::new(),
            nt_hash: "deadbeef".to_string(),
            disabled: false,
        };
        let debug = format!("{:?}", user);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("deadbeef"));
    }

    #[test]
    fn test_nt_hash_field_parsed() {
        let toml_str = r#"
guest_access = true
health_port = 8080
max_credits = 1024

[[users]]
username = "alice"
nt_hash = "0123abcd"
disabled = false
"#;
        let config = ServerConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.users[0].nt_hash, "0123abcd");
        assert_eq!(config.users[0].password, "");
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
            follow_symlinks: FollowSymlinks::Never,
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
            follow_symlinks: FollowSymlinks::Never,
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
            follow_symlinks: FollowSymlinks::Never,
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
            follow_symlinks: FollowSymlinks::Never,
        });
        assert!(config.validate().is_err(), "ipc$ share name must be rejected (case-insensitive)");
    }
}
