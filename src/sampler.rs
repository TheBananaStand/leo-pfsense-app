//! Background task that feeds `BandwidthMonitor` with router counters.
//!
//! Derived from `sample_router` in `crates/leo-api/src/routes/network.rs`.
//! Interface names (WAN/LAN) are resolved once at startup from `config.xml`
//! and re-resolved only after a failure — SSH round trips are expensive enough
//! that paying for a re-read on every tick would be noticeable.
//!
//! The hub-NIC sampler (`sample_hub` in the original) is not here: it reads
//! `/proc/net/dev` from the hub machine, not the firewall. That half stays in
//! the hub process.

use std::sync::Arc;
use std::time::Duration;

use crate::bandwidth::BandwidthMonitor;
use crate::pfsense::PfSenseService;

/// Cap on a single router round trip — same value as the hub's `ROUTER_TIMEOUT`.
///
/// Shorter than the OS connect timeout on purpose: an unreachable firewall
/// otherwise wedges the loop for over two minutes, so the reported figures
/// would keep claiming to be current long after they stopped being sampled.
const ROUTER_TIMEOUT: Duration = Duration::from_secs(8);

/// Spawn the background sampler. Returns immediately; the task runs forever.
pub fn spawn(pfsense: Arc<PfSenseService>, monitor: Arc<BandwidthMonitor>) {
    tokio::spawn(run(pfsense, monitor));
}

async fn run(pfsense: Arc<PfSenseService>, monitor: Arc<BandwidthMonitor>) {
    let mut tick = tokio::time::interval(crate::bandwidth::ROUTER_INTERVAL);
    // Resolved once; re-resolved only after a transport failure, which is the
    // signal that config.xml may have been rewritten (e.g. a pfSense upgrade).
    let mut interfaces: Option<(String, String)> = None;

    loop {
        tick.tick().await;

        if interfaces.is_none() {
            match with_timeout(pfsense.wan_lan_interface_names()).await {
                Ok(names) => interfaces = Some(names),
                Err(e) => {
                    monitor.record_router_error(e);
                    continue;
                }
            }
        }
        let Some((wan, lan)) = interfaces.clone() else {
            continue;
        };

        match with_timeout(pfsense.interface_counters_raw()).await {
            Ok(text) => monitor.record_router(&text, &wan, &lan),
            Err(e) => {
                monitor.record_router_error(e);
                // The names may be what went stale — re-resolve on the next tick.
                interfaces = None;
            }
        }
    }
}

async fn with_timeout<T, E: std::fmt::Display>(
    fut: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match tokio::time::timeout(ROUTER_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "router did not respond within {}s",
            ROUTER_TIMEOUT.as_secs()
        )),
    }
}
