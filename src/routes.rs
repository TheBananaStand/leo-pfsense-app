//! Axum router mirroring the hub's `/api/network/*` surface.
//!
//! Routes are rooted here at "/" — the hub strips the `/p/pfsense` mount prefix
//! before forwarding, so we never see it. Auth levels match exactly what the hub
//! enforced: reads are session-level (any `Caller`), writes are `AdminCaller`.
//!
//! The only structural deviation from the original: `/dhcp/leases` is added here
//! because the descriptor's data function calls `get_dhcp_leases()` directly and
//! there was no REST route for it in the hub (the tool used the service method).
//! Making it reachable over HTTP lets the hub proxy it consistently.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::routing::{delete, get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;
use crate::auth::{AdminCaller, Caller};
use crate::error::Error;
use crate::pfsense::{DhcpLease, DnsOverride, HaProxyConfig, NetworkDevice, StaticMapping, VpnServer};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route("/dashboard", get(dashboard))
        .route("/devices", get(devices))
        .route(
            "/dhcp/static",
            get(list_dhcp_static)
                .post(add_dhcp_static)
                .delete(delete_dhcp_static),
        )
        .route("/dhcp/leases", get(dhcp_leases))
        .route("/vpn", get(vpn_status))
        .route("/haproxy", get(haproxy_status))
        .route(
            "/dns/overrides",
            get(list_dns)
                .post(add_dns)
                .put(update_dns)
                .delete(delete_dns),
        )
        // Legacy aliases kept for backwards compatibility with the hub's original paths.
        .route("/dns", get(list_dns).post(add_dns))
        .route("/dns/delete", delete(delete_dns))
        .route("/pfsense/php", post(exec_php))
        .route("/bandwidth", get(bandwidth))
}

// ---------------------------------------------------------------------------
// Body structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AddDnsBody {
    host: String,
    domain: String,
    ip: String,
    description: Option<String>,
}

#[derive(Deserialize)]
struct DeleteDnsBody {
    host: String,
    // A domain-less override is valid — pfSense parses it with unwrap_or_default().
    // The descriptor client drops blank body fields, so a domain-less delete omits
    // `domain` entirely; default it to "" rather than 422 on the missing field.
    #[serde(default)]
    domain: String,
}

#[derive(Deserialize)]
struct AddDhcpBody {
    mac: String,
    ip: String,
    hostname: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct DeleteDhcpBody {
    mac: String,
}

#[derive(Deserialize)]
struct PhpExecBody {
    code: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_pfsense(state: &AppState) -> Arc<crate::pfsense::PfSenseService> {
    state.pfsense.clone()
}

fn ok_json() -> Json<Value> {
    Json(serde_json::json!({"ok": true}))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Always returns `{"configured": true}` — the process only starts when
/// PFSENSE_HOST is set, so reaching this endpoint proves it's configured.
async fn status(_caller: Caller, _state: State<AppState>) -> Json<Value> {
    Json(serde_json::json!({"configured": true}))
}

async fn dashboard(_caller: Caller, State(state): State<AppState>) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    let data = pf.get_dashboard().await?;
    Ok(Json(data))
}

async fn devices(
    _caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<Vec<NetworkDevice>>, Error> {
    let pf = require_pfsense(&state);
    let devs = pf.get_devices().await?;
    Ok(Json(devs))
}

async fn list_dhcp_static(
    _caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<Vec<StaticMapping>>, Error> {
    let pf = require_pfsense(&state);
    let leases = pf.get_dhcp_static_mappings().await?;
    Ok(Json(leases))
}

async fn dhcp_leases(
    _caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<Vec<DhcpLease>>, Error> {
    let pf = require_pfsense(&state);
    let leases = pf.get_dhcp_leases().await?;
    Ok(Json(leases))
}

/// Writing a DHCP reservation reconfigures the network *every other machine
/// on the LAN* depends on — admin only. See the same comment in network.rs.
async fn add_dhcp_static(
    _caller: AdminCaller,
    State(state): State<AppState>,
    Json(body): Json<AddDhcpBody>,
) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    let hostname = body.hostname.as_deref().unwrap_or("");
    pf.add_dhcp_static_mapping(&body.mac, &body.ip, hostname, body.description.as_deref())
        .await?;
    Ok(ok_json())
}

/// Admin-only — see `add_dhcp_static`.
async fn delete_dhcp_static(
    _caller: AdminCaller,
    State(state): State<AppState>,
    Json(body): Json<DeleteDhcpBody>,
) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    pf.delete_dhcp_static_mapping(&body.mac).await?;
    Ok(ok_json())
}

async fn vpn_status(
    _caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<Vec<VpnServer>>, Error> {
    let pf = require_pfsense(&state);
    let vpn = pf.get_vpn_status().await?;
    Ok(Json(vpn))
}

async fn haproxy_status(
    _caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<HaProxyConfig>, Error> {
    let pf = require_pfsense(&state);
    let ha = pf.get_haproxy_config().await?;
    Ok(Json(ha))
}

async fn list_dns(
    _caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<Vec<DnsOverride>>, Error> {
    let pf = require_pfsense(&state);
    let overrides = pf.get_dns_overrides().await?;
    Ok(Json(overrides))
}

/// Admin-only — see `add_dhcp_static`.
async fn add_dns(
    _caller: AdminCaller,
    State(state): State<AppState>,
    Json(body): Json<AddDnsBody>,
) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    pf.add_dns_override(
        &body.host,
        &body.domain,
        &body.ip,
        body.description.as_deref(),
    )
    .await?;
    Ok(ok_json())
}

/// Admin-only — see `add_dhcp_static`. Delete + re-add is the pfSense pattern
/// for an update because the XML list has no stable key to update in place.
async fn update_dns(
    _caller: AdminCaller,
    State(state): State<AppState>,
    Json(body): Json<AddDnsBody>,
) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    // Ignore delete failure: the old entry may not exist (first-time PUT).
    let _ = pf.delete_dns_override(&body.host, &body.domain).await;
    pf.add_dns_override(
        &body.host,
        &body.domain,
        &body.ip,
        body.description.as_deref(),
    )
    .await?;
    Ok(ok_json())
}

/// Admin-only — see `add_dhcp_static`.
async fn delete_dns(
    _caller: AdminCaller,
    State(state): State<AppState>,
    Json(body): Json<DeleteDnsBody>,
) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    let deleted = pf.delete_dns_override(&body.host, &body.domain).await?;
    if deleted {
        Ok(ok_json())
    } else {
        Err(Error::Other(format!(
            "DNS override {}.{} not found",
            body.host, body.domain
        )))
    }
}

/// Raw PHP execution on the router — admin only.
async fn exec_php(
    _caller: AdminCaller,
    State(state): State<AppState>,
    Json(body): Json<PhpExecBody>,
) -> Result<Json<Value>, Error> {
    let pf = require_pfsense(&state);
    let output = pf.php_exec_raw(&body.code).await?;
    Ok(Json(serde_json::json!({"output": output})))
}

/// Current up/down rates for WAN and LAN.
///
/// Reads whatever the background sampler last computed — it never samples
/// inline, because one reading of a cumulative counter is not a rate and the
/// router reading costs an SSH round trip.
async fn bandwidth(_caller: Caller, State(state): State<AppState>) -> Json<Value> {
    Json(serde_json::to_value(state.monitor.snapshot()).unwrap_or(Value::Null))
}
