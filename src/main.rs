//! Leo pfSense app subprocess — the Network package's backend, running as a
//! standalone binary that the hub builds, launches, and reverse-proxies.
//!
//! The hub mounts this at `/p/pfsense/*`, stripping the prefix before forwarding.
//! Auth is delegated: the hub injects `X-Leo-User-Id` and `x-leo-is-admin` on
//! every request; this binary trusts those headers and never holds a session store.
//!
//! ## Subcommands
//!
//! `leo-pfsense-app mcp`   — speak MCP over stdio instead of serving HTTP
//! `leo-pfsense-app start` — HTTP server (the default when no arg is given)
//!
//! Both modes read settings from the same env vars. The reason they share one
//! binary is explained in `mcp.rs`.

use std::sync::Arc;

use axum::Router;
use tracing::info;

mod auth;
mod bandwidth;
mod config;
mod error;
mod mcp;
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

/// The whole HTTP surface, assembled.
///
/// Its own function so a test can build it. axum decides a good deal of routing
/// legality at *runtime* — a root `nest` panics on construction, and compiles
/// perfectly on the way there — so "does this router assemble" is a real
/// question that only running the code answers.
pub fn build_router(state: AppState) -> Router {
    // `merge`, not `nest("/", …)`: axum 0.8 panics on a root nest, which is a
    // runtime failure from code that type-checks. The two differ only at the
    // root — merge folds the routes in as though declared here, which is what
    // mounting at `/` always meant.
    Router::new()
        .merge(routes::router())
        .route(
            "/leo/ui/descriptor",
            axum::routing::get(ui::descriptor_handler),
        )
        .route("/leo/ui/data", axum::routing::get(ui::data_handler))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    // Logs go to stderr in both modes — in MCP mode the host reads stdout as
    // protocol; mixing logs there would corrupt the stream.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
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

    // Dispatch on the first argument. "mcp" runs the MCP stdio loop; anything
    // else (including no argument) runs the HTTP server as before.
    //
    // The reason MCP mode lives in this binary rather than a separate package:
    // the hub injects entitled settings as env vars when launching an MCP
    // subprocess, but those vars do not include the app's hub-assigned port.
    // A separate binary could not discover the HTTP server to call it. Sharing
    // the binary gives MCP mode direct access to PfSenseService — no HTTP hop,
    // no port discovery needed. See src/mcp.rs for the protocol details.
    match std::env::args().nth(1).as_deref() {
        Some("mcp") => {
            eprintln!("leo-pfsense-app: MCP stdio mode");
            mcp::run(pf).await;
        }
        _ => {
            run_http_server(pf, cfg).await;
        }
    }
}

async fn run_http_server(pf: Arc<pfsense::PfSenseService>, cfg: config::Config) {
    let monitor = Arc::new(bandwidth::BandwidthMonitor::new());

    // Spawn the background sampler — it runs forever, feeding the monitor.
    sampler::spawn(pf.clone(), monitor.clone());

    let state = AppState {
        pfsense: pf,
        monitor,
    };

    // The hub strips /p/pfsense before forwarding, so everything mounts at /.
    let app = build_router(state);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The router assembles.
    ///
    /// This exists because it already failed once in the way that costs most:
    /// `nest("/", …)` compiled, installed, cloned, built, launched — and
    /// panicked on the first line of `main`, so the package was rejected after
    /// a full cold build on the hub. A compile check cannot see it; only
    /// building the router can.
    #[test]
    fn the_router_assembles() {
        let state = AppState {
            pfsense: std::sync::Arc::new(pfsense::PfSenseService::new(
                "192.0.2.1", 22, "admin", None, None,
            )),
            monitor: std::sync::Arc::new(bandwidth::BandwidthMonitor::new()),
        };
        // Construction is the assertion — a bad route shape panics here, and no
        // request is ever made, so the unroutable address is never dialled.
        let _ = build_router(state);
    }
}
