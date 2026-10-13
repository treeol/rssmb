//! RSSMB server binary — config loading, CLI args, signal handling, health endpoint.

use clap::Parser;
use rssmb_server::{ServerConfig, ServerState};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, error};

mod health;

/// RSSMB — A pure-Rust SMB2/3 server for dynamic container environments.
#[derive(Parser, Debug)]
#[command(name = "rssmb", version, about)]
struct Args {
    /// Path to config file (TOML)
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging — respect RUST_LOG env var, fallback to "info"
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if args.verbose {
                tracing_subscriber::EnvFilter::new("debug")
            } else {
                tracing_subscriber::EnvFilter::new("info")
            }
        });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("RSSMB server starting");

    // Install a panic hook that routes panics through tracing instead of
    // dumping the raw backtrace to stderr. Keeps the default hook in tests
    // (cfg(test)) for debugging.
    #[cfg(not(test))]
    {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info.location()
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
    let config_str = std::fs::read_to_string(&args.config)
        .map_err(|e| {
            error!("Failed to read config file {}: {}", args.config.display(), e);
            e
        })?;

    let mut config = ServerConfig::from_toml(&config_str)
        .map_err(|e| {
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

    info!("Config loaded: {} shares, listen {}:{}", config.shares.len(), config.listen_addr, config.port);

    // Validate config consistency (e.g. encrypt_data under encryption=disabled).
    if let Err(msg) = config.validate() {
        error!("Config validation error: {}", msg);
        return Err(msg.into());
    }

    // Create server state
    let state = Arc::new(ServerState::new(config.clone()));

    // Start health endpoint
    let health_state = state.clone();
    let health_port = config.health_port;
    tokio::spawn(async move {
        if let Err(e) = health::serve(health_state, health_port).await {
            error!("Health endpoint error: {}", e);
        }
    });

    // Start SMB listener
    let smb_state = state.clone();
    let listen_addr = config.listen_addr.clone();
    let port = config.port;

    // Signal handling
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        let sigterm = async {
            use tokio::signal::unix::{signal, SignalKind};
            let mut stream = signal(SignalKind::terminate()).unwrap();
            stream.recv().await;
        };
        #[cfg(not(unix))]
        let sigterm = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                warn!("Received SIGINT, initiating graceful shutdown");
            }
            _ = sigterm => {
                warn!("Received SIGTERM, initiating graceful shutdown");
            }
        }

        shutdown_state.shutdown().await;
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
