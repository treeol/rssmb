//! Server metrics — atomic counters rendered as Prometheus text format.
//!
//! Counters are lock-free (atomics) so they can be incremented from hot
//! paths without contention. The `/metrics` endpoint renders them on demand.

use std::sync::atomic::{AtomicU64, Ordering};

/// Server-wide metrics (all lock-free atomics).
pub struct ServerMetrics {
    // Connections
    pub connections_active: AtomicU64,
    pub connections_accepted_total: AtomicU64,
    pub connections_rejected_limit_total: AtomicU64,

    // Sessions
    pub sessions_active: AtomicU64,
    pub sessions_by_dialect_smb2xx: AtomicU64,
    pub sessions_by_dialect_smb21: AtomicU64,
    pub sessions_by_dialect_smb30: AtomicU64,
    pub sessions_by_dialect_smb302: AtomicU64,
    pub sessions_by_dialect_smb311: AtomicU64,
    pub sessions_signed: AtomicU64,
    pub sessions_encrypted: AtomicU64,

    // Auth
    pub auth_success_total: AtomicU64,
    pub auth_failures_total: AtomicU64,
    pub auth_throttled_total: AtomicU64,

    // I/O
    pub bytes_read_total: AtomicU64,
    pub bytes_written_total: AtomicU64,

    // Handles
    pub open_handles_active: AtomicU64,
    pub durable_handles_active: AtomicU64,

    // Per-command request count (indexed by command ordinal).
    // We use a fixed array sized to the number of SMB2 commands.
    pub requests_total: [AtomicU64; 20],
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            connections_active: AtomicU64::new(0),
            connections_accepted_total: AtomicU64::new(0),
            connections_rejected_limit_total: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            sessions_by_dialect_smb2xx: AtomicU64::new(0),
            sessions_by_dialect_smb21: AtomicU64::new(0),
            sessions_by_dialect_smb30: AtomicU64::new(0),
            sessions_by_dialect_smb302: AtomicU64::new(0),
            sessions_by_dialect_smb311: AtomicU64::new(0),
            sessions_signed: AtomicU64::new(0),
            sessions_encrypted: AtomicU64::new(0),
            auth_success_total: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            auth_throttled_total: AtomicU64::new(0),
            bytes_read_total: AtomicU64::new(0),
            bytes_written_total: AtomicU64::new(0),
            open_handles_active: AtomicU64::new(0),
            durable_handles_active: AtomicU64::new(0),
            requests_total: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Record a request for a given command ordinal.
    pub fn record_request(&self, command_ordinal: usize) {
        if command_ordinal < self.requests_total.len() {
            self.requests_total[command_ordinal].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record bytes read.
    pub fn record_bytes_read(&self, n: u64) {
        self.bytes_read_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Record bytes written.
    pub fn record_bytes_written(&self, n: u64) {
        self.bytes_written_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Render metrics as Prometheus text format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        // Connections
        metric(
            &mut out,
            "rssmb_connections_active",
            "gauge",
            "Active connections",
            self.connections_active.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_connections_accepted_total",
            "counter",
            "Total accepted connections",
            self.connections_accepted_total.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_connections_rejected_limit_total",
            "counter",
            "Connections rejected by limit",
            self.connections_rejected_limit_total
                .load(Ordering::Relaxed),
        );

        // Sessions
        metric(
            &mut out,
            "rssmb_sessions_active",
            "gauge",
            "Active sessions",
            self.sessions_active.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_sessions_signed",
            "gauge",
            "Signed sessions",
            self.sessions_signed.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_sessions_encrypted",
            "gauge",
            "Encrypted sessions",
            self.sessions_encrypted.load(Ordering::Relaxed),
        );

        // Auth
        metric(
            &mut out,
            "rssmb_auth_success_total",
            "counter",
            "Total successful authentications",
            self.auth_success_total.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_auth_failures_total",
            "counter",
            "Total failed authentications",
            self.auth_failures_total.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_auth_throttled_total",
            "counter",
            "Total throttled auth attempts",
            self.auth_throttled_total.load(Ordering::Relaxed),
        );

        // I/O
        metric(
            &mut out,
            "rssmb_bytes_read_total",
            "counter",
            "Total bytes read from VFS",
            self.bytes_read_total.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_bytes_written_total",
            "counter",
            "Total bytes written to VFS",
            self.bytes_written_total.load(Ordering::Relaxed),
        );

        // Handles
        metric(
            &mut out,
            "rssmb_open_handles_active",
            "gauge",
            "Active open handles",
            self.open_handles_active.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "rssmb_durable_handles_active",
            "gauge",
            "Active durable handles",
            self.durable_handles_active.load(Ordering::Relaxed),
        );

        // Per-command requests — emit HELP/TYPE once, then one line per command.
        out.push_str("# HELP rssmb_requests_total Total requests by command\n");
        out.push_str("# TYPE rssmb_requests_total counter\n");
        let command_names = [
            "negotiate",
            "session_setup",
            "logoff",
            "tree_connect",
            "tree_disconnect",
            "create",
            "close",
            "flush",
            "read",
            "write",
            "lock",
            "ioctl",
            "cancel",
            "echo",
            "query_directory",
            "change_notify",
            "query_info",
            "set_info",
            "oplock_break",
            "lease_break",
        ];
        for (i, name) in command_names.iter().enumerate() {
            let val = self.requests_total[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "rssmb_requests_total{{command=\"{}\"}} {}\n",
                name, val
            ));
        }

        out
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn metric(out: &mut String, name: &str, type_: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {} {}\n", name, help));
    out.push_str(&format!("# TYPE {} {}\n", name, type_));
    out.push_str(&format!("{} {}\n", name, value));
}
