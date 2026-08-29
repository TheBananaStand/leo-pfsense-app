//! Descriptor UI endpoints: `GET /leo/ui/descriptor` and `GET /leo/ui/data`.
//!
//! This is a faithful translation of `packages/leo-pfsense/src/ui.rs`. Two
//! things changed:
//!
//! 1. **No leo-package DSL.** The hub's `leo-package` crate provides a builder
//!    API (`Node::new(…).prop(…).build()`) that compiles to serde_json::Value.
//!    This binary has no access to that crate, so the descriptor tree is written
//!    directly as `serde_json::json!{…}` literals. The output shape is identical.
//!
//! 2. **`delete_path` retargeted.** The original hardcodes `/api/network/dhcp/static`
//!    and `/api/network/dns/overrides` — paths that go to the hub. Here they become
//!    `/p/pfsense/dhcp/static` and `/p/pfsense/dns/overrides`, which the hub proxy
//!    forwards to us. The clients never speak to this process directly, so the path
//!    must be one the hub's proxy recognizes.
//!
//! The data function signature matches what the hub's package data machinery calls:
//! `GET /leo/ui/data?page=network` → `{ rows, device_count, … }`.

use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Caller;
use crate::error::Error;

// Status + kind palette — kept byte-for-byte from the original.
const GREEN: &str = "#30d158";
const BLUE: &str = "#0a84ff";
const PURPLE: &str = "#bf5af2";
const TEAL: &str = "#64d2ff";
const RED: &str = "#ff453a";
const GRAY: &str = "#98989d";

const IFACE_PALETTE: [&str; 8] = [
    "#0a84ff", "#64d2ff", "#bf5af2", "#ff9f0a",
    "#5e5ce6", "#66d4cf", "#ff375f", "#ffd60a",
];

fn iface_color(iface: &str) -> &'static str {
    if iface.is_empty() {
        return GRAY;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in iface.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    IFACE_PALETTE[(h % IFACE_PALETTE.len() as u64) as usize]
}

// ---------------------------------------------------------------------------
// Axum handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DataQuery {
    page: Option<String>,
}

/// `GET /leo/ui/descriptor` — the static descriptor tree.
pub async fn descriptor_handler(
    _caller: Caller,
    _state: State<AppState>,
) -> Json<Value> {
    Json(json!({ "network": network_page() }))
}

/// `GET /leo/ui/data?page=network` — live bind data for the Network page.
pub async fn data_handler(
    _caller: Caller,
    State(state): State<AppState>,
    Query(params): Query<DataQuery>,
) -> Result<Json<Value>, Error> {
    let page = params.page.as_deref().unwrap_or("");
    match page {
        "network" => {
            let data = network_data(&state.pfsense).await?;
            Ok(Json(data))
        }
        other => Err(Error::Other(format!("pfsense ui page '{other}' has no data"))),
    }
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

async fn network_data(pf: &Arc<crate::pfsense::PfSenseService>) -> Result<Value, Error> {
    // Devices are the core dataset — fail the page if they can't load.
    // Everything else degrades to empty so one broken subsystem doesn't blank
    // the whole surface.
    let mut devices = pf.get_devices().await?;
    let statics = pf.get_dhcp_static_mappings().await.unwrap_or_default();
    let dns = pf.get_dns_overrides().await.unwrap_or_default();
    let vpn = pf.get_vpn_status().await.unwrap_or_default();
    let wan = pf.get_wan_info().await.ok();
    let lan = pf.get_lan_info().await.ok();

    // Numeric IP sort so the list reads like a subnet map.
    devices.sort_by_key(|d| d.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX));

    let mut rows: Vec<Value> = Vec::new();

    for d in &devices {
        let title = d
            .hostname
            .clone()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| d.ip.clone());
        let iface = d.interface.clone().unwrap_or_default();
        let desc = d.description.clone().unwrap_or_default();
        let color = iface_color(&iface);
        rows.push(json!({
            "id": format!("dev-{}", d.mac),
            "tab": "devices",
            "tab_label": "Device",
            "kind_color": color,
            "title": title,
            "subtitle": join_dot(&[&d.mac, &desc]),
            "trailing": d.ip,
            "badge": iface,
            "badge_color": color,
            "sections": sections(vec![
                section("Identity", &[
                    ("Hostname", d.hostname.as_deref().unwrap_or("")),
                    ("MAC address", &d.mac),
                    ("Description", &desc),
                ]),
                section("Network", &[
                    ("IP address", &d.ip),
                    ("Interface", &iface),
                    ("Source", &source_label(&d.source)),
                ]),
            ]),
            "actions": [],
        }));
    }

    for s in &statics {
        let title = if s.hostname.is_empty() {
            s.ip.clone()
        } else {
            s.hostname.clone()
        };
        let desc = s.description.clone().unwrap_or_default();
        let id = format!("dhcp-{}", s.mac);
        rows.push(json!({
            "id": id,
            "tab": "dhcp",
            "tab_label": "Static mapping",
            "kind_color": BLUE,
            "title": title,
            "subtitle": join_dot(&[&s.mac, &desc]),
            "trailing": s.ip,
            "badge": "",
            "badge_color": BLUE,
            "sections": sections(vec![
                section("Reservation", &[
                    ("Hostname", &s.hostname),
                    ("IP address", &s.ip),
                    ("MAC address", &s.mac),
                ]),
                section("Notes", &[("Description", &desc)]),
            ]),
            "actions": [{
                "id": id,
                "kind": "dhcp",
                "name": title,
                // Retargeted: was /api/network/dhcp/static (hub-direct).
                // Now /p/pfsense/dhcp/static so the hub proxy forwards it here.
                "delete_path": "/p/pfsense/dhcp/static",
                "mac": s.mac,
            }],
        }));
    }

    for o in &dns {
        let fqdn = if o.domain.is_empty() {
            o.host.clone()
        } else {
            format!("{}.{}", o.host, o.domain)
        };
        let desc = o.description.clone().unwrap_or_default();
        let id = format!("dns-{}-{}", o.host, o.domain);
        rows.push(json!({
            "id": id,
            "tab": "dns",
            "tab_label": "DNS override",
            "kind_color": PURPLE,
            "title": fqdn,
            "subtitle": desc,
            "trailing": o.ip,
            "badge": "",
            "badge_color": PURPLE,
            "sections": sections(vec![
                section("Record", &[
                    ("Host", &o.host),
                    ("Domain", &o.domain),
                    ("Resolves to", &o.ip),
                ]),
                section("Notes", &[("Description", &desc)]),
            ]),
            "actions": [{
                "id": id,
                "kind": "dns",
                "name": fqdn,
                // Retargeted: was /api/network/dns/overrides (hub-direct).
                // Now /p/pfsense/dns/overrides so the hub proxy forwards it here.
                "delete_path": "/p/pfsense/dns/overrides",
                "host": o.host,
                "domain": o.domain,
            }],
        }));
    }

    let mut vpn_client_count = 0usize;
    for srv in &vpn {
        vpn_client_count += srv.clients.len();
        let title = if srv.description.is_empty() {
            format!("OpenVPN server {}", srv.vpnid)
        } else {
            srv.description.clone()
        };
        let endpoint = format!("{}:{}", srv.protocol.to_uppercase(), srv.port);
        let clients_label = match srv.clients.len() {
            0 => "no clients".to_string(),
            1 => "1 client connected".to_string(),
            n => format!("{n} clients connected"),
        };
        rows.push(json!({
            "id": format!("vpn-server-{}", srv.vpnid),
            "tab": "vpn",
            "tab_label": "VPN server",
            "kind_color": TEAL,
            "title": title,
            "subtitle": join_dot(&[&srv.mode, &clients_label]),
            "trailing": endpoint,
            "badge": "server",
            "badge_color": TEAL,
            "sections": sections(vec![
                section("Endpoint", &[
                    ("Mode", &srv.mode),
                    ("Listen", &endpoint),
                    ("Tunnel network", &srv.tunnel_network),
                ]),
                section("Sessions", &[
                    ("Connected clients", &srv.clients.len().to_string()),
                ]),
            ]),
            "actions": [],
        }));

        for c in &srv.clients {
            let virtual_ip = c.virtual_address.clone().unwrap_or_default();
            let (since_abs, uptime) = friendly_since(&c.connected_since);
            let down = format!("{} ↓", fmt_bytes(c.bytes_received));
            let up = format!("{} ↑", fmt_bytes(c.bytes_sent));
            let uptime_label = if uptime.is_empty() {
                String::new()
            } else {
                format!("up {uptime}")
            };
            rows.push(json!({
                "id": format!("vpn-client-{}-{}", srv.vpnid, c.common_name),
                "tab": "vpn",
                "tab_label": "VPN client",
                "kind_color": GREEN,
                "title": c.common_name,
                "subtitle": join_dot(&[&down, &up, &uptime_label]),
                "trailing": virtual_ip,
                "badge": "connected",
                "badge_color": GREEN,
                "sections": sections(vec![
                    section("Connection", &[
                        ("Remote address", &c.real_address),
                        ("Virtual IP", &virtual_ip),
                        ("Connected since", &since_abs),
                        ("Online for", &uptime),
                    ]),
                    section("Traffic", &[
                        ("Received", &down),
                        ("Sent", &up),
                    ]),
                ]),
                "actions": [],
            }));
        }
    }

    let (wan_label, wan_color) = match wan.as_ref() {
        Some(w) if w.status == "up" => ("Online", GREEN),
        Some(_) => ("Offline", RED),
        None => ("Unreachable", GRAY),
    };

    Ok(json!({
        "rows": rows,
        "device_count": devices.len(),
        "dhcp_count": statics.len(),
        "dns_count": dns.len(),
        "vpn_count": vpn_client_count,
        "wan_status_label": wan_label,
        "wan_status_color": wan_color,
        "wan_ip": wan.as_ref().and_then(|w| w.ip.clone()).unwrap_or_default(),
        "gateway": wan.as_ref().and_then(|w| w.gateway.clone()).unwrap_or_default(),
        "lan_ip": lan.as_ref().and_then(|l| l.ip.clone()).unwrap_or_default(),
        "dns_servers": wan
            .as_ref()
            .map(|w| w.dns_servers.join(", "))
            .unwrap_or_default(),
    }))
}

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------

/// A labeled detail section: `{title, fields:[{label, value}]}`. Empty values
/// are dropped; a section with no surviving fields disappears.
fn section(title: &str, fields: &[(&str, &str)]) -> Option<Value> {
    let items: Vec<Value> = fields
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(l, v)| json!({ "id": l, "label": l, "value": v }))
        .collect();
    if items.is_empty() {
        None
    } else {
        Some(json!({ "id": title, "title": title, "fields": items }))
    }
}

fn sections(list: Vec<Option<Value>>) -> Vec<Value> {
    list.into_iter().flatten().collect()
}

fn join_dot(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" · ")
}

fn source_label(source: &str) -> String {
    match source {
        "static" => "Static mapping".into(),
        "dhcp" => "DHCP lease".into(),
        "arp" => "ARP".into(),
        other => other.to_string(),
    }
}

fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let n = n as f64;
    if n >= KB * KB * KB {
        format!("{:.1} GB", n / (KB * KB * KB))
    } else if n >= KB * KB {
        format!("{:.1} MB", n / (KB * KB))
    } else if n >= KB {
        format!("{:.0} KB", n / KB)
    } else {
        format!("{n:.0} B")
    }
}

fn friendly_since(raw: &str) -> (String, String) {
    let raw = raw.trim();
    let Ok(dt) = chrono::NaiveDateTime::parse_from_str(raw, "%a %b %e %H:%M:%S %Y") else {
        return (raw.to_string(), String::new());
    };
    let abs = dt.format("%b %-d, %-I:%M %p").to_string();
    let mins = (chrono::Local::now().naive_local() - dt).num_minutes();
    let uptime = if mins < 0 {
        String::new()
    } else if mins < 1 {
        "moments".to_string()
    } else if mins < 60 {
        format!("{mins}m")
    } else if mins < 60 * 24 {
        format!("{}h {}m", mins / 60, mins % 60)
    } else {
        format!("{}d {}h", mins / (60 * 24), (mins / 60) % 24)
    };
    (abs, uptime)
}

// ---------------------------------------------------------------------------
// Descriptor tree
// ---------------------------------------------------------------------------
//
// This section translates the leo-package DSL builder calls from the original
// ui.rs into equivalent serde_json::json!{} literals. The output JSON is
// identical; only the Rust API used to produce it differs.

fn network_page() -> Value {
    json!({
        "kind": "screen",
        "title": "Network",
        "route": "/network",
        "state": { "tab": "devices", "query": "", "selectedId": "" },
        "addressableState": ["tab", "selectedId"],
        "assistant": {
            "app": "Network",
            "placeholder": "Ask about your network…",
            "suggestions": [
                "Who's on my network right now?",
                "Is anyone connected to the VPN?",
                "Give my NAS a static IP",
                "Add a DNS override for nas.home"
            ]
        },
        "children": [{
            "kind": "masterDetail",
            "selectionKey": "selectedId",
            "dividers": true,
            "dividerInset": 22,
            "sidebarWidth": 220,
            "detailWidth": 320,
            "sidebar": sidebar(),
            "list": {
                "kind": "list",
                "bind": "rows",
                "filter": {
                    "field": "tab", "equalsState": "tab",
                    "search": "query", "searchFields": ["title", "subtitle", "trailing"]
                },
                "empty": empty_states(),
                "children": [row()]
            },
            "detail": detail()
        }]
    })
}

fn sidebar() -> Value {
    json!({
        "kind": "vstack",
        "spacing": 2,
        "children": [
            status_hero(),
            quiet_row("Gateway", "gateway"),
            quiet_row("LAN", "lan_ip"),
            quiet_row("DNS", "dns_servers"),
            section_label("Network", 16),
            {
                "kind": "searchField",
                "stateKey": "query",
                "placeholder": "Search",
                "width": 196
            },
            tab_row("devices", "Devices", "desktopcomputer", "device_count"),
            tab_row("dhcp", "DHCP", "pin", "dhcp_count"),
            tab_row("dns", "DNS", "globe", "dns_count"),
            tab_row("vpn", "VPN", "lock.shield", "vpn_count"),
        ]
    })
}

fn status_hero() -> Value {
    json!({
        "kind": "vstack",
        "spacing": 5,
        "align": "leading",
        "paddingH": 10,
        "paddingV": 6,
        "children": [
            { "kind": "text", "style": "section-label", "value": "WAN" },
            {
                "kind": "hstack",
                "spacing": 8,
                "align": "center",
                "children": [
                    { "kind": "dot", "colorFrom": "wan_status_color", "size": 8 },
                    { "kind": "text", "bind": "wan_status_label", "style": "headline" }
                ]
            },
            {
                "kind": "text",
                "bind": "wan_ip",
                "style": "mono",
                "color": "secondary",
                "lines": 1,
                "hideWhenEmpty": true
            }
        ]
    })
}

fn section_label(label: &str, padding_top: u32) -> Value {
    json!({
        "kind": "hstack",
        "paddingH": 10,
        "paddingTop": padding_top,
        "children": [{
            "kind": "text",
            "style": "section-label",
            "value": label
        }]
    })
}

fn tab_row(value: &str, label: &str, icon: &str, count_bind: &str) -> Value {
    json!({
        "kind": "selectRow",
        "stateKey": "tab",
        "value": value,
        "label": label,
        "icon": icon,
        "countBind": count_bind
    })
}

fn quiet_row(label: &str, bind: &str) -> Value {
    json!({
        "kind": "hstack",
        "spacing": 6,
        "align": "center",
        "paddingH": 10,
        "paddingV": 2,
        "children": [
            { "kind": "text", "style": "caption", "value": label },
            { "kind": "spacer" },
            {
                "kind": "text",
                "bind": bind,
                "style": "mono",
                "color": "secondary",
                "lines": 1,
                "hideWhenEmpty": true
            }
        ]
    })
}

fn row() -> Value {
    json!({
        "kind": "hstack",
        "spacing": 11,
        "align": "center",
        "paddingH": 22,
        "paddingV": 12,
        "children": [
            {
                "kind": "vstack",
                "spacing": 3,
                "align": "leading",
                "children": [
                    {
                        "kind": "hstack",
                        "spacing": 7,
                        "align": "center",
                        "children": [
                            { "kind": "text", "bind": "title", "style": "headline", "lines": 1 },
                            { "kind": "badge", "bind": "badge", "tintFrom": "badge_color", "hideWhenEmpty": true }
                        ]
                    },
                    { "kind": "text", "bind": "subtitle", "style": "caption", "lines": 1, "hideWhenEmpty": true }
                ]
            },
            { "kind": "spacer" },
            { "kind": "text", "bind": "trailing", "style": "mono", "color": "secondary", "hideWhenEmpty": true }
        ]
    })
}

fn empty_states() -> Value {
    json!({
        "kind": "vstack",
        "children": [
            tab_empty("devices", "desktopcomputer", "No devices found",
                "The firewall's ARP table and DHCP leases came back empty."),
            tab_empty("dhcp", "pin", "No static mappings",
                "Reserve an IP so a device always gets the same address — just ask Leo."),
            tab_empty("dns", "globe", "No DNS overrides",
                "Point a local hostname at any IP — try \u{201c}add a DNS override for nas.home\u{201d}."),
            tab_empty("vpn", "lock.shield", "VPN is quiet",
                "No OpenVPN servers or connected clients right now."),
        ]
    })
}

fn tab_empty(tab: &str, icon: &str, title: &str, message: &str) -> Value {
    json!({
        "kind": "emptyState",
        "icon": icon,
        "title": title,
        "message": message,
        "visibleWhen": { "state": "tab", "equals": tab }
    })
}

fn detail() -> Value {
    json!({
        "kind": "vstack",
        "spacing": 12,
        "align": "leading",
        "children": [
            { "kind": "badge", "bind": "tab_label", "tintFrom": "kind_color" },
            { "kind": "text", "bind": "title", "style": "title", "wrap": true },
            { "kind": "text", "bind": "subtitle", "style": "subtle", "wrap": true, "hideWhenEmpty": true },
            { "kind": "divider" },
            {
                "kind": "list",
                "bind": "sections",
                "spacing": 14,
                "children": [{
                    "kind": "vstack",
                    "spacing": 8,
                    "align": "leading",
                    "children": [
                        { "kind": "text", "bind": "title", "style": "section-label" },
                        {
                            "kind": "list",
                            "bind": "fields",
                            "spacing": 8,
                            "children": [{
                                "kind": "hstack",
                                "spacing": 8,
                                "align": "center",
                                "children": [
                                    { "kind": "text", "bind": "label", "style": "caption" },
                                    { "kind": "spacer" },
                                    { "kind": "text", "bind": "value", "style": "mono", "lines": 1 }
                                ]
                            }]
                        }
                    ]
                }]
            },
            {
                "kind": "list",
                "bind": "actions",
                "spacing": 6,
                "children": [{
                    "kind": "hstack",
                    "paddingTop": 8,
                    "children": [
                        delete_button("Remove reservation", "dhcp"),
                        delete_button("Remove override", "dns"),
                    ]
                }]
            }
        ]
    })
}

fn delete_button(label: &str, kind: &str) -> Value {
    json!({
        "kind": "button",
        "variant": "destructive",
        "label": label,
        "visibleWhen": { "field": "kind", "equals": kind },
        "action": {
            "kind": "confirm",
            "title": "Delete \u{201c}{name}\u{201d}?",
            "confirmLabel": "Delete",
            "destructive": true,
            "confirm": {
                "method": "DELETE",
                "path": "{delete_path}",
                "body": { "mac": "{mac}", "host": "{host}", "domain": "{domain}" },
                "optimistic": "remove",
                "refresh": "reload"
            }
        }
    })
}
