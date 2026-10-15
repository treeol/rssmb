//! RSSMB server binary — config loading, CLI args, signal handling, health endpoint.

use clap::{Parser, Subcommand};
use rssmb_server::{ServerConfig, ServerState};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
mod health;

/// RSSMB — A pure-Rust SMB2/3 server for dynamic container environments.
#[derive(Parser, Debug)]
#[command(name = "rssmb", version, about)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to config file (TOML) — used when no subcommand is given.
    #[arg(short, long, default_value = "rssmb.toml")]
    config: PathBuf,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,

    /// Override port
    #[arg(short, long)]
    port: Option<u16>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Log format: "text" (default) or "json"
    #[arg(long, default_value = "text")]
    log_format: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compute the NT hash (MD4 of UTF-16LE) for a password.
    ///
    /// The hash can be used in the config as `nt_hash = "..."` instead of
    /// storing the plaintext password.
    HashPassword {
        /// The password to hash.
        password: String,
    },

    /// Validate the config file without starting the server.
    CheckConfig {
        /// Path to config file (TOML).
        #[arg(short, long, default_value = "rssmb.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Handle subcommands first.
    if let Some(command) = &args.command {
        match command {
            Command::HashPassword { password } => {
                let hash = rssmb_auth::nt_hash(password);
                println!("{}", hex::encode(hash));
                return Ok(());
            }
            Command::CheckConfig { config } => {
                // Initialize logging for the check-config subcommand.
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                    )
                    .init();

                let config_str = std::fs::read_to_string(config).map_err(|e| {
                    error!("Failed to read config file {}: {}", config.display(), e);
                    e
                })?;
                let config = ServerConfig::from_toml(&config_str).map_err(|e| {
                    error!("Failed to parse config: {}", e);
                    e
                })?;
                if let Err(msg) = config.validate() {
                    error!("Config validation error: {}", msg);
                    return Err(msg.into());
                }
                if let Err(msg) = config.validate_paths() {
                    error!("Config path validation error: {}", msg);
                    return Err(msg.into());
                }
                for warning in config.warnings() {
                    warn!("{}", warning);
                }
                info!(
                    "Config OK: {} shares, {} users",
                    config.shares.len(),
                    config.users.len()
                );
                return Ok(());
            }
        }
    }

    // Default: run the server.
    run_server(args).await
}

async fn run_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging — respect RUST_LOG env var, fallback to "info"
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if args.verbose {
            tracing_subscriber::EnvFilter::new("debug")
        } else {
            tracing_subscriber::EnvFilter::new("info")
        }
    });

    match args.log_format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    info!("RSSMB server starting");

    // Install a panic hook that routes panics through tracing instead of
    // dumping the raw backtrace to stderr. Keeps the default hook in tests
    // (cfg(test)) for debugging.
    #[cfg(not(test))]
    {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown>".to_string());
            if let Some(payload) = info.payload().downcast_ref::<&str>() {
                error!(location, panic = payload, "thread panicked");
            } else if let Some(payload) = info.payload().downcast_ref::<String>() {
                error!(location, panic = payload.as_str(), "thread panicked");
            } else {
                error!(location, "thread panicked");
            }
            default_hook(info);
        }));
    }

    // Load config
    let config_str = std::fs::read_to_string(&args.config).map_err(|e| {
        error!(
            "Failed to read config file {}: {}",
            args.config.display(),
            e
        );
        e
    })?;

    // Warn if the config file is too permissive (it may contain passwords or
    // NT hashes). On Unix, 0o640 or stricter is recommended.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&args.config) {
            let mode = meta.permissions().mode();
            if mode & 0o007 != 0 {
                warn!(
                    path = %args.config.display(),
                    mode = format!("{:o}", mode),
                    "config file is world-readable — it may contain passwords or NT hashes. \
                     Restrict with: chmod 640 {}",
                    args.config.display()
                );
            } else if mode & 0o070 != 0 {
                warn!(
                    path = %args.config.display(),
                    mode = format!("{:o}", mode),
                    "config file is group-readable — it may contain passwords or NT hashes. \
                     Consider restricting with: chmod 600 {}",
                    args.config.display()
                );
            }
        }
    }

    let mut config = ServerConfig::from_toml(&config_str).map_err(|e| {
        error!("Failed to parse config: {}", e);
        e
    })?;

    // Apply CLI overrides
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
    }
    if let Some(port) = args.port {
        config.port = port;
    }

    info!(
        "Config loaded: {} shares, listen {}:{}",
        config.shares.len(),
        config.listen_addr,
        config.port
    );

    // Validate config consistency (e.g. encrypt_data under encryption=disabled).
    if let Err(msg) = config.validate() {
        error!("Config validation error: {}", msg);
        return Err(msg.into());
    }

    // Validate share paths exist and are directories.
    if let Err(msg) = config.validate_paths() {
        error!("Config path validation error: {}", msg);
        return Err(msg.into());
    }

    // Log non-fatal config warnings.
    for warning in config.warnings() {
        warn!("{}", warning);
    }

    // Create server state
    let state = Arc::new(ServerState::new(config.clone()));

    // Start the durable handle sweeper — periodically cleans up expired
    // durable opens whose VFS handles need to be closed.
    let sweeper_state = state.clone();
    let sweeper_interval = if config.durable_timeout_secs > 0 {
        std::time::Duration::from_secs(config.durable_timeout_secs.min(60))
    } else {
        std::time::Duration::from_secs(60)
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(sweeper_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = sweeper_state.shutdown.notified() => break,
            }
            let swept = sweeper_state.durable_table.sweep().await;
            if swept > 0 {
                tracing::info!(
                    expired = swept,
                    "durable handle sweeper: cleaned up expired entries"
                );
            }
        }
    });

    // Start health endpoint
    let health_state = state.clone();
    let health_port = config.health_port;
    let health_bind_addr = config.health_bind_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = health::serve(health_state, health_bind_addr, health_port).await {
            error!("Health endpoint error: {}", e);
        }
    });

    // Start SMB listener
    let smb_state = state.clone();
    let listen_addr = config.listen_addr.clone();
    let port = config.port;

    // Signal handling — SIGINT/SIGTERM for shutdown, SIGHUP for config reload.
    let shutdown_state = state.clone();
    let reload_config_path = args.config.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            // SIGINT
            let mut sig_int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Failed to install SIGINT handler: {} — Ctrl+C will not trigger shutdown",
                        e
                    );
                    return;
                }
            };
            // SIGTERM
            let mut sig_term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Failed to install SIGTERM handler: {} — SIGTERM will not trigger shutdown",
                        e
                    );
                    return;
                }
            };
            // SIGHUP — reload config. If we can't install the handler,
            // just skip reload capability (log and continue).
            let mut sig_hup = match signal(SignalKind::hangup()) {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(
                        "Failed to install SIGHUP handler: {} — config will not be reloadable",
                        e
                    );
                    None
                }
            };

            loop {
                tokio::select! {
                    _ = sig_int.recv() => {
                        warn!("Received SIGINT, initiating graceful shutdown");
                        shutdown_state.shutdown().await;
                        return;
                    }
                    _ = sig_term.recv() => {
                        warn!("Received SIGTERM, initiating graceful shutdown");
                        shutdown_state.shutdown().await;
                        return;
                    }
                    _ = async {
                        if let Some(ref mut hup) = sig_hup {
                            hup.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("Received SIGHUP — reloading config from {}", reload_config_path.display());
                        match std::fs::read_to_string(&reload_config_path) {
                            Ok(config_str) => {
                                match ServerConfig::from_toml(&config_str) {
                                    Ok(new_config) => {
                                        if let Err(msg) = new_config.validate() {
                                            error!("Config reload validation error: {} — keeping current config", msg);
                                            continue;
                                        }
                                        if let Err(msg) = new_config.validate_paths() {
                                            error!("Config reload path validation error: {} — keeping current config", msg);
                                            continue;
                                        }
                                        for warning in new_config.warnings() {
                                            warn!("{}", warning);
                                        }
                                        info!("Config reloaded: {} shares, {} users — applying",
                                              new_config.shares.len(), new_config.users.len());
                                        shutdown_state.reload(new_config);
                                    }
                                    Err(e) => {
                                        error!("Failed to parse config during reload: {} — keeping current config", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to read config file during reload: {} — keeping current config", e);
                            }
                        }
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            // Non-unix: Ctrl+C for shutdown, no SIGHUP.
            loop {
                tokio::signal::ctrl_c().await.ok();
                warn!("Received Ctrl+C, initiating graceful shutdown");
                shutdown_state.shutdown().await;
                return;
            }
        }
    });

    info!("SMB listener starting on {}:{}", listen_addr, port);
    rssmb_server::connection::listen_with_state(config, move |_| smb_state)
        .await
        .map_err(|e| {
            error!("SMB listener error: {}", e);
            e
        })?;

    info!("Server shutdown complete");
    Ok(())
}
