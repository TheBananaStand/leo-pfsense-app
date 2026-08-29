//! Leo pfSense app subprocess — the Network package's backend, running as a
//! standalone binary that the hub builds, launches, and reverse-proxies.
//!
//! The hub mounts this at `/p/pfsense/*`, stripping the prefix before forwarding.
//! Auth is delegated: the hub injects `X-Leo-User-Id` and `x-leo-is-admin` on
//! every request; this binary trusts those headers and never holds a session store.

use std::sync::Arc;

use axum::Router;
use tracing::info;

mod auth;
mod bandwidth;
mod config;
mod error;
mod pfsense;
mod routes;
mod sampler;
mod ui;

/// Shared state threaded through every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub pfsense: Arc<pfsense::PfSenseService>,
    pub monitor: Arc<bandwidth::BandwidthMonitor>,
}

#[tokio::main]
async fn main() {
    // Respect RUST_LOG; default to info so the operator can see SSH activity
    // without drowning in debug output.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::from_env();

    let pf = Arc::new(pfsense::PfSenseService::new(
        cfg.pfsense_host.clone(),
        cfg.pfsense_port,
        cfg.pfsense_username.clone(),
        cfg.pfsense_password.clone(),
        cfg.pfsense_key.clone(),
    ));

    let monitor = Arc::new(bandwidth::BandwidthMonitor::new());

    // Spawn the background sampler — it runs forever, feeding the monitor.
    sampler::spawn(pf.clone(), monitor.clone());

    let state = AppState {
        pfsense: pf,
        monitor,
    };

    // The hub strips /p/pfsense before forwarding, so we mount everything at /.
    // The /leo/* prefix is Leo's convention for internal app-package endpoints
    // (descriptor and data); the rest mirrors the hub's /api/network/* surface.
    let app = Router::new()
        .nest("/", routes::router())
        .route("/leo/ui/descriptor", axum::routing::get(ui::descriptor_handler))
        .route("/leo/ui/data", axum::routing::get(ui::data_handler))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", cfg.listen_port);
    info!("leo-pfsense-app listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind {addr}: {e}");
            std::process::exit(1);
        });

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    });
}
