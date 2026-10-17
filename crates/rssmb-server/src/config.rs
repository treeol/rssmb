//! Server and share configuration.

use rssmb_vfs::FollowSymlinks;
use serde::Deserialize;
use std::collections::HashMap;

/// Top-level server configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Whether to require MsvAvTimestamp in the NTLMv2 blob (anti-replay).
    /// When true, AUTHENTICATE messages without a timestamp AV_PAIR are
    /// rejected. Does not affect guest/anonymous auth.
    #[serde(default)]
    pub ntlm_require_timestamp: bool,

    /// Durable handle timeout in seconds. When a client opens a file with a
    /// DH2Q (durable handle v2) create context and the connection drops, the
    /// server keeps the open alive for this many seconds so the client can
    /// reconnect (DH2C) and re-attach without a "network path lost" error.
    /// Default: 900 (15 min). 0 = durable handles disabled.
    #[serde(default = "default_durable_timeout_secs")]
    pub durable_timeout_secs: u64,

    /// Whether SMB 2.1+ file leases and traditional oplocks are enabled.
    /// Default: true.
    #[serde(default = "default_true")]
    pub leases: bool,

    /// Server name (for SrvSvc NetrServerGetInfo). Defaults to "rssmb" if empty.
    #[serde(default)]
    pub server_name: String,

    /// Grace period (seconds) for draining active connections on shutdown.
    /// After this, remaining connections are aborted. Default: 10.
    #[serde(default = "default_shutdown_grace_secs")]
    pub shutdown_grace_secs: u64,

    /// Whether SMB 3.x multichannel is enabled. Default: true.
    #[serde(default = "default_true")]
    pub multichannel: bool,

    /// User accounts for authentication.
    #[serde(default)]
    pub users: Vec<UserConfig>,

    /// Whether SMB over QUIC (UDP / TLS 1.3, SMB 3.1.1) is enabled.
    /// Default: false.
    #[serde(default)]
    pub quic_enabled: bool,

    /// UDP port for SMB over QUIC (default: 443).
    /// Note: binding ports < 1024 on Linux requires root or `CAP_NET_BIND_SERVICE`.
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,

    /// Path to PEM-encoded TLS certificate chain for SMB over QUIC.
    /// Required when `quic_enabled = true`.
    #[serde(default)]
    pub quic_cert_path: String,

    /// Path to PEM-encoded TLS private key for SMB over QUIC.
    /// Required when `quic_enabled = true`.
    #[serde(default)]
    pub quic_key_path: String,
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
#[serde(deny_unknown_fields)]
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
            .field(
                "nt_hash",
                &if self.nt_hash.is_empty() {
                    "<unset>"
                } else {
                    "<redacted>"
                },
            )
            .field("disabled", &self.disabled)
            .finish()
    }
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}
fn default_smb_port() -> u16 {
    445
}
fn default_quic_port() -> u16 {
    443
}
fn default_max_frame_size() -> usize {
    1_048_576
}
fn default_health_port() -> u16 {
    8080
}
fn default_max_credits() -> u32 {
    1024
}
fn default_auth_max_failures() -> u32 {
    5
}
fn default_auth_window_secs() -> u64 {
    60
}
fn default_auth_delay_max_ms() -> u64 {
    5000
}
fn default_auth_cooldown_secs() -> u64 {
    60
}
fn default_auth_max_failures_per_conn() -> u32 {
    10
}
fn default_durable_timeout_secs() -> u64 {
    900
}
fn default_shutdown_grace_secs() -> u64 {
    10
}
fn default_max_dialect() -> DialectConfig {
    DialectConfig::Smb311
}
fn default_idle_timeout() -> u64 {
    900
}
fn default_health_bind_addr() -> String {
    "127.0.0.1".to_string()
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DialectConfig {
    Smb2002,
    #[default]
    Smb21,
    Smb30,
    Smb302,
    Smb311,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SigningPolicy {
    /// Signing is not offered
    Disabled,
    /// Signing is offered but not required
    Desired,
    /// Signing is required
    #[default]
    Required,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum EncryptionPolicy {
    /// Encryption is not offered
    Disabled,
    /// Encryption is offered but not required
    #[default]
    Desired,
    /// Encryption is required
    Required,
}

/// Per-share configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Users with read access (empty = all authenticated users in
    /// `valid_users` may read). When non-empty, only users listed here
    /// (and in `valid_users`) may open files for reading.
    #[serde(default)]
    pub read_users: Vec<String>,

    /// Users with write access (empty = all authenticated users in
    /// `valid_users` may write, unless `read_only = true`). When
    /// non-empty, only users listed here may open files for writing;
    /// all others get read-only access on a read-write share.
    #[serde(default)]
    pub write_users: Vec<String>,

    /// Require encryption for all traffic on this share (SMB 3.x).
    /// Only effective for 3.x dialects; ignored for 2.x.
    #[serde(default)]
    pub encrypt_data: bool,

    /// Symlink policy for this share:
    /// - `never` (default): never follow symlinks; report them as reparse points
    /// - `within`: follow symlinks only if their target is within the share root
    #[serde(default)]
    pub follow_symlinks: FollowSymlinks,

    /// Whether to fsync on FLUSH and close (default: true). When false, FLUSH
    /// returns success without syncing to disk — faster but less durable.
    /// Samba has the same knob (`strict sync`).
    #[serde(default = "default_true")]
    pub strict_sync: bool,

    /// Whether file name lookup is case-sensitive (default: false).
    /// Windows and macOS clients expect case-insensitive lookup. Set to
    /// true only if all clients are cifs.ko on a case-sensitive filesystem.
    #[serde(default = "default_false")]
    pub case_sensitive: bool,
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}

impl ServerConfig {
    /// Load from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Validate config consistency: a share with `encrypt_data = true` under
    /// `encryption = "disabled"` is a startup error (MS-SMB2: encryption
    /// cannot be required on a share if the server doesn't support encryption).
    pub fn validate(&self) -> Result<(), String> {
        // Dialect range: min ≤ max.
        if self.min_dialect > self.max_dialect {
            return Err(format!(
                "min_dialect ({:?}) must be <= max_dialect ({:?})",
                self.min_dialect, self.max_dialect
            ));
        }
        // Port collision: SMB and health must not share a port (when both > 0).
        if self.port > 0 && self.health_port > 0 && self.port == self.health_port {
            return Err(format!(
                "port ({}) and health_port ({}) must not be the same",
                self.port, self.health_port
            ));
        }
        // Validate bind addresses when non-empty and not "localhost".
        if !self.listen_addr.is_empty()
            && self.listen_addr != "localhost"
            && self.listen_addr.parse::<std::net::IpAddr>().is_err()
        {
            return Err(format!(
                "listen_addr '{}' is not a valid IP address",
                self.listen_addr
            ));
        }
        if !self.health_bind_addr.is_empty()
            && self.health_bind_addr != "localhost"
            && self.health_bind_addr.parse::<std::net::IpAddr>().is_err()
        {
            return Err(format!(
                "health_bind_addr '{}' is not a valid IP address",
                self.health_bind_addr
            ));
        }
        // Frame size: at least 64 KiB (SMB2 minimum).
        if self.max_frame_size < 65536 {
            return Err(format!(
                "max_frame_size ({}) must be >= 65536 (64 KiB)",
                self.max_frame_size
            ));
        }
        // Credits: must be > 0.
        if self.max_credits == 0 {
            return Err("max_credits must be > 0".to_string());
        }
        // User validation: each non-disabled user needs a username and
        // at least one credential (password or nt_hash).
        for (i, user) in self.users.iter().enumerate() {
            if !user.disabled {
                if user.username.trim().is_empty() {
                    return Err(format!("user #{} has an empty username", i + 1));
                }
                if user.password.is_empty() && user.nt_hash.is_empty() {
                    return Err(format!(
                        "user '{}' has neither password nor nt_hash set (and is not disabled)",
                        user.username
                    ));
                }
                // Validate nt_hash is valid hex if present.
                if !user.nt_hash.is_empty()
                    && (user.nt_hash.len() != 32
                        || !user.nt_hash.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return Err(format!(
                        "user '{}': nt_hash must be 32 hex characters (16 bytes), got {} chars",
                        user.username,
                        user.nt_hash.len()
                    ));
                }
            }
        }
        // Encryption required with a dialect below 3.0 — encryption is only
        // available in SMB 3.x, so requiring it with 2.x is a contradiction.
        if self.encryption == EncryptionPolicy::Required && self.max_dialect < DialectConfig::Smb30
        {
            return Err(format!(
                "encryption = 'required' but max_dialect ({:?}) < smb30 — \
                 encryption is only available in SMB 3.x",
                self.max_dialect
            ));
        }
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
        if self
            .shares
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("IPC$"))
        {
            return Err(
                "share named 'IPC$' is reserved — cannot configure a disk share with that name"
                    .to_string(),
            );
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
        // Share access-list validation: `write_users` on a `read_only = true`
        // share is contradictory — read_only already denies all writes.
        for share in self.shares.values() {
            if share.read_only && !share.write_users.is_empty() {
                return Err(format!(
                    "share '{}' has read_only = true but write_users is non-empty \
                     — read-only shares deny all writes regardless of write_users",
                    share.name
                ));
            }
        }
        // SMB over QUIC validation: requires cert/key paths and SMB 3.1.1.
        if self.quic_enabled {
            if self.quic_cert_path.trim().is_empty() {
                return Err("quic_cert_path must be set when quic_enabled = true".to_string());
            }
            if self.quic_key_path.trim().is_empty() {
                return Err("quic_key_path must be set when quic_enabled = true".to_string());
            }
            if self.max_dialect < DialectConfig::Smb311 {
                return Err(format!(
                    "quic_enabled = true requires max_dialect = 'smb311' (got {:?}) — \
                     SMB over QUIC only supports SMB 3.1.1",
                    self.max_dialect
                ));
            }
        }
        Ok(())
    }

    /// Validate that share paths (and QUIC TLS cert/key files when enabled)
    /// exist and are valid. Called by `rssmb check-config` and server startup
    /// (not by `validate()`, which is also used by in-memory unit tests with
    /// synthetic paths).
    pub fn validate_paths(&self) -> Result<(), String> {
        for share in self.shares.values() {
            if share.path.is_empty() {
                continue;
            }
            let meta = std::fs::metadata(&share.path).map_err(|e| {
                format!(
                    "share '{}': path '{}' is not accessible: {}",
                    share.name, share.path, e
                )
            })?;
            if !meta.is_dir() {
                return Err(format!(
                    "share '{}': path '{}' is not a directory",
                    share.name, share.path
                ));
            }
        }
        if self.quic_enabled {
            crate::quic::validate_tls_files(&self.quic_cert_path, &self.quic_key_path)?;
        }
        Ok(())
    }

    /// Non-fatal configuration warnings (logged at startup, not errors).
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Signing not required on a non-loopback address — exposed to
        // network attackers who could downgrade or tamper.
        let is_loopback = self.listen_addr == "127.0.0.1"
            || self.listen_addr == "::1"
            || self.listen_addr == "localhost"
            || self.listen_addr.is_empty();
        if self.signing != SigningPolicy::Required && !is_loopback {
            warnings.push(format!(
                "signing is not 'required' but listen_addr '{}' is not loopback — \
                 unauthenticated tampering and downgrade attacks are possible",
                self.listen_addr
            ));
        }

        // Share with guest_ok = true but server-level guest_access = false —
        // the share-level flag is ineffective.
        if !self.guest_access {
            for share in self.shares.values() {
                if share.guest_ok {
                    warnings.push(format!(
                        "share '{}' has guest_ok = true but server guest_access = false \
                         — guest access on this share is ineffective",
                        share.name
                    ));
                }
            }
        }

        // Share with guest_ok = true on a signing=required server — guests
        // can never be signed, so guest_ok is ineffective here too.
        if self.signing == SigningPolicy::Required {
            for share in self.shares.values() {
                if share.guest_ok {
                    warnings.push(format!(
                        "share '{}' has guest_ok = true but signing = 'required' — \
                         guest sessions are never signed, so guest access is ineffective",
                        share.name
                    ));
                }
            }
        }

        warnings
    }

    /// Default config for testing.
    pub fn for_testing() -> Self {
        let mut shares = HashMap::new();
        shares.insert(
            "test".to_string(),
            ShareConfig {
                name: "test".to_string(),
                path: "/tmp/rssmb-test".to_string(),
                comment: "Test share".to_string(),
                read_only: false,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec![],
                encrypt_data: false,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );

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
            ntlm_require_timestamp: false,
            durable_timeout_secs: 900,
            leases: true,
            multichannel: true,
            server_name: "rssmb".to_string(),
            shutdown_grace_secs: 10,
            users: vec![],
            quic_enabled: false,
            quic_port: 0,
            quic_cert_path: String::new(),
            quic_key_path: String::new(),
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
        config.shares.insert(
            "enc_share".to_string(),
            ShareConfig {
                name: "enc_share".to_string(),
                path: "/tmp/rssmb-enc".to_string(),
                comment: String::new(),
                read_only: false,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec![],
                encrypt_data: true,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        assert!(
            config.validate().is_err(),
            "encrypt_data under disabled must be rejected"
        );
    }

    #[test]
    fn test_validate_ok_encrypt_data_under_desired() {
        let mut config = ServerConfig::for_testing();
        config.encryption = EncryptionPolicy::Desired;
        config.shares.insert(
            "enc_share".to_string(),
            ShareConfig {
                name: "enc_share".to_string(),
                path: "/tmp/rssmb-enc".to_string(),
                comment: String::new(),
                read_only: false,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec![],
                encrypt_data: true,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_ipc_share_name() {
        let mut config = ServerConfig::for_testing();
        config.shares.insert(
            "IPC$".to_string(),
            ShareConfig {
                name: "IPC$".to_string(),
                path: "/tmp/ipc".to_string(),
                comment: String::new(),
                read_only: false,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec![],
                encrypt_data: false,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        assert!(
            config.validate().is_err(),
            "IPC$ share name must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_ipc_case_insensitive() {
        let mut config = ServerConfig::for_testing();
        config.shares.insert(
            "ipc$".to_string(),
            ShareConfig {
                name: "ipc$".to_string(),
                path: "/tmp/ipc".to_string(),
                comment: String::new(),
                read_only: false,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec![],
                encrypt_data: false,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        assert!(
            config.validate().is_err(),
            "ipc$ share name must be rejected (case-insensitive)"
        );
    }

    #[test]
    fn test_validate_rejects_write_users_on_read_only_share() {
        let mut config = ServerConfig::for_testing();
        config.shares.insert(
            "ro_share".to_string(),
            ShareConfig {
                name: "ro_share".to_string(),
                path: "/tmp/ro".to_string(),
                comment: String::new(),
                read_only: true,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec!["alice".to_string()],
                encrypt_data: false,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        assert!(
            config.validate().is_err(),
            "write_users on read_only share must be rejected"
        );
    }

    #[test]
    fn test_validate_ok_write_users_on_read_write_share() {
        let mut config = ServerConfig::for_testing();
        config.shares.insert(
            "rw_share".to_string(),
            ShareConfig {
                name: "rw_share".to_string(),
                path: "/tmp/rw".to_string(),
                comment: String::new(),
                read_only: false,
                browseable: true,
                guest_ok: false,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec!["alice".to_string()],
                encrypt_data: false,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        assert!(
            config.validate().is_ok(),
            "write_users on read-write share should be accepted"
        );
    }

    #[test]
    fn test_validate_rejects_dialect_range_inverted() {
        let mut config = ServerConfig::for_testing();
        config.min_dialect = DialectConfig::Smb311;
        config.max_dialect = DialectConfig::Smb21;
        assert!(
            config.validate().is_err(),
            "min > max dialect must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_port_collision() {
        let mut config = ServerConfig::for_testing();
        config.port = 8080;
        config.health_port = 8080;
        assert!(
            config.validate().is_err(),
            "port == health_port must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_small_frame_size() {
        let mut config = ServerConfig::for_testing();
        config.max_frame_size = 1024;
        assert!(
            config.validate().is_err(),
            "max_frame_size < 65536 must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_zero_credits() {
        let mut config = ServerConfig::for_testing();
        config.max_credits = 0;
        assert!(
            config.validate().is_err(),
            "max_credits = 0 must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_user_without_credentials() {
        let mut config = ServerConfig::for_testing();
        config.users = vec![UserConfig {
            username: "alice".to_string(),
            password: String::new(),
            nt_hash: String::new(),
            disabled: false,
        }];
        assert!(
            config.validate().is_err(),
            "non-disabled user without credentials must be rejected"
        );
    }

    #[test]
    fn test_validate_allows_disabled_user_without_credentials() {
        let mut config = ServerConfig::for_testing();
        config.users = vec![UserConfig {
            username: "alice".to_string(),
            password: String::new(),
            nt_hash: String::new(),
            disabled: true,
        }];
        assert!(
            config.validate().is_ok(),
            "disabled user without credentials should be accepted"
        );
    }

    #[test]
    fn test_warnings_signing_not_required_non_loopback() {
        let mut config = ServerConfig::for_testing();
        config.listen_addr = "0.0.0.0".to_string();
        config.signing = SigningPolicy::Desired;
        let warnings = config.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("signing is not 'required'")),
            "should warn about signing on non-loopback: {:?}",
            warnings
        );
    }

    #[test]
    fn test_warnings_no_signing_warning_on_loopback() {
        let config = ServerConfig::for_testing();
        // for_testing uses 127.0.0.1 + signing=Required — no signing warning.
        let warnings = config.warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("signing")),
            "should not warn about signing on loopback with required: {:?}",
            warnings
        );
    }

    #[test]
    fn test_warnings_guest_ok_with_server_guest_disabled() {
        let mut config = ServerConfig::for_testing();
        config.guest_access = false;
        config.shares.insert(
            "guest_share".to_string(),
            ShareConfig {
                name: "guest_share".to_string(),
                path: "/tmp/guest".to_string(),
                comment: String::new(),
                read_only: false,
                browseable: true,
                guest_ok: true,
                valid_users: vec![],
                read_users: vec![],
                write_users: vec![],
                encrypt_data: false,
                follow_symlinks: FollowSymlinks::Never,
                strict_sync: true,
                case_sensitive: false,
            },
        );
        let warnings = config.warnings();
        assert!(
            warnings.iter().any(|w| w.contains("guest_access = false")),
            "should warn about guest_ok with server guest disabled: {:?}",
            warnings
        );
    }

    #[test]
    fn test_deny_unknown_fields_rejects_extra_key() {
        let toml_str = r#"
listen_addr = "127.0.0.1"
port = 445
unknown_field = "should be rejected"
"#;
        let result = ServerConfig::from_toml(toml_str);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown keys"
        );
    }

    #[test]
    fn test_validate_rejects_invalid_nt_hash_length() {
        let mut config = ServerConfig::for_testing();
        config.users = vec![UserConfig {
            username: "alice".to_string(),
            password: String::new(),
            nt_hash: "short".to_string(),
            disabled: false,
        }];
        assert!(
            config.validate().is_err(),
            "nt_hash with wrong length must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_non_hex_nt_hash() {
        let mut config = ServerConfig::for_testing();
        config.users = vec![UserConfig {
            username: "alice".to_string(),
            password: String::new(),
            nt_hash: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(), // 32 chars but not hex
            disabled: false,
        }];
        assert!(
            config.validate().is_err(),
            "nt_hash with non-hex chars must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_encryption_required_below_smb30() {
        let mut config = ServerConfig::for_testing();
        config.encryption = EncryptionPolicy::Required;
        config.max_dialect = DialectConfig::Smb21;
        assert!(
            config.validate().is_err(),
            "encryption=required with max_dialect < smb30 must be rejected"
        );
    }

    #[test]
    fn test_validate_allows_encryption_desired_below_smb30() {
        let mut config = ServerConfig::for_testing();
        config.encryption = EncryptionPolicy::Desired;
        config.max_dialect = DialectConfig::Smb21;
        assert!(
            config.validate().is_ok(),
            "encryption=desired with smb21 should be accepted"
        );
    }

    #[test]
    fn test_deny_unknown_fields_on_share() {
        let toml_str = r#"
listen_addr = "127.0.0.1"
port = 445
max_credits = 1024

[shares.public]
name = "public"
path = "/data/public"
bogus_field = true
"#;
        let result = ServerConfig::from_toml(toml_str);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown share keys"
        );
    }

    #[test]
    fn test_deny_unknown_fields_on_user() {
        let toml_str = r#"
listen_addr = "127.0.0.1"
port = 445
max_credits = 1024

[[users]]
username = "alice"
password = "secret"
bogus_field = true
"#;
        let result = ServerConfig::from_toml(toml_str);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown user keys"
        );
    }

    #[test]
    fn test_validate_quic_requires_cert_and_key_and_smb311() {
        let mut config = ServerConfig::for_testing();
        config.quic_enabled = true;
        // Missing cert and key
        assert!(config.validate().is_err());

        config.quic_cert_path = "/tmp/cert.pem".to_string();
        assert!(config.validate().is_err());

        config.quic_key_path = "/tmp/key.pem".to_string();
        assert!(config.validate().is_ok());

        // max_dialect < Smb311 rejected when quic_enabled = true
        config.max_dialect = DialectConfig::Smb302;
        assert!(config.validate().is_err());
    }
}
