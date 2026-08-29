//! MCP stdio server for `leo-pfsense-app mcp`.
//!
//! Why this lives in the binary rather than a separate MCP package: the hub
//! launches an MCP subprocess with only its entitled settings injected as env
//! vars. That env does not include the app's hub-assigned port, so a separate
//! MCP server could not discover and call the HTTP server. Sharing the process
//! image lets MCP mode construct its own `PfSenseService` from those same env
//! vars and reuse every parser and method — no network round-trip in the path,
//! no port to look up.
//!
//! Wire format: JSON-RPC 2.0, newline-delimited, over stdin/stdout. Only
//! stdout carries protocol; all log output goes to stderr so the host can
//! distinguish them without parsing.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::pfsense::PfSenseService;

// ── Tool schemas ──────────────────────────────────────────────────────────────

/// The `network` tool schema, reproduced verbatim from
/// `packages/leo-network/src/lib.rs` `NetworkTool::definition()`.
///
/// The action enum, property descriptions and `required` field are the
/// contract the tool-caller sends; any drift here means the model builds
/// arguments that a caller accepting the hub's schema would accept, but that
/// this server would not recognise — a silent capability split.
fn network_tool_schema() -> Value {
    json!({
        "name": "network",
        "description": "Manage the live pfSense network \u{2014} dashboard, devices, DHCP, DNS overrides, VPN, HAProxy, interfaces.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "get_dashboard",
                        "get_devices",
                        "get_dhcp_leases",
                        "get_dhcp_static_mappings",
                        "add_dhcp_static_mapping",
                        "delete_dhcp_static_mapping",
                        "get_dns_overrides",
                        "add_dns_override",
                        "delete_dns_override",
                        "get_vpn_status",
                        "get_wan_info",
                        "get_lan_info",
                        "get_haproxy_config"
                    ],
                    "description": "Action"
                },
                "mac": { "type": "string", "description": "MAC address (for DHCP static mapping add/delete)" },
                "ip": { "type": "string", "description": "IP address (for DHCP static mapping or DNS override)" },
                "hostname": { "type": "string", "description": "Hostname (for DHCP static mapping)" },
                "description": { "type": "string", "description": "Description (for DHCP static mapping or DNS override)" },
                "host": { "type": "string", "description": "Host part of DNS override, e.g. 'app'" },
                "domain": { "type": "string", "description": "Domain part of DNS override, e.g. 'example.com'" }
            },
            "required": ["action"]
        }
    })
}

/// The `pfsense_ssh` tool schema, reproduced verbatim from
/// `packages/leo-pfsense/src/tool.rs` `PfSenseSshTool::definition()`.
fn pfsense_ssh_tool_schema() -> Value {
    json!({
        "name": "pfsense_ssh",
        "description": "Run arbitrary shell or PHP, or read config.xml, on the live pfSense firewall. Requires approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["ssh_command", "php_exec", "read_config"],
                    "description": "Action"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command (for ssh_command)"
                },
                "code": {
                    "type": "string",
                    "description": "PHP code (for php_exec). config.inc, util.inc, services.inc are auto-included."
                }
            },
            "required": ["action"]
        }
    })
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Check that every required field for the named (tool, action) pair is
/// present in `args`, returning a descriptive message for the first missing
/// one. Pure: no I/O, no SSH — so tests can cover this without a pfSense box.
///
/// The required-field logic mirrors `leo_tools::require_str!` — that macro
/// returns an error result when a field is absent or not a string; here we
/// surface the same failure as an MCP `isError` response before making any
/// network call.
pub fn validate(tool: &str, action: &str, args: &Value) -> Result<(), String> {
    let required: &[&str] = match (tool, action) {
        ("network", "add_dhcp_static_mapping") => &["mac", "ip", "hostname"],
        ("network", "delete_dhcp_static_mapping") => &["mac"],
        ("network", "add_dns_override") => &["host", "domain", "ip"],
        ("network", "delete_dns_override") => &["host", "domain"],
        ("pfsense_ssh", "ssh_command") => &["command"],
        ("pfsense_ssh", "php_exec") => &["code"],
        // All other actions are zero-argument reads.
        _ => &[],
    };

    for &field in required {
        match args.get(field) {
            None | Some(Value::Null) => {
                return Err(format!("action '{action}' requires field '{field}'"));
            }
            Some(Value::String(s)) if s.is_empty() => {
                return Err(format!("action '{action}' requires a non-empty '{field}'"));
            }
            _ => {}
        }
    }
    Ok(())
}

// ── JSON-RPC helpers ─────────────────────────────────────────────────────────

fn ok_response(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn error_response(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn tool_ok(text: impl Into<String>) -> Value {
    json!({"content":[{"type":"text","text":text.into()}]})
}

fn tool_err(text: impl Into<String>) -> Value {
    json!({"content":[{"type":"text","text":text.into()}],"isError":true})
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/// Route a `tools/call` to `PfSenseService`, returning the MCP result value.
///
/// Returns `Ok(value)` — the value is placed in `result` when the call
/// succeeded and in `result` with `isError: true` when the service returned an
/// error. An `Err` here means the request itself was malformed (unknown tool,
/// missing required field), which the caller maps to a JSON-RPC error instead.
async fn dispatch(
    pfsense: &PfSenseService,
    tool: &str,
    args: &Value,
) -> Result<Value, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required field 'action'".to_string())?;

    // Validate required fields before touching the network. A missing field
    // here produces a clear isError message rather than a confusing SSH error.
    validate(tool, action, args)?;

    let opt_str = |key: &str| -> Option<&str> { args.get(key).and_then(|v| v.as_str()) };
    let get_str = |key: &str| -> &str { opt_str(key).unwrap_or("") };

    match (tool, action) {
        // ── network actions ────────────────────────────────────────────────
        ("network", "get_dashboard") => match pfsense.get_dashboard().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "get_devices") => match pfsense.get_devices().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "get_dhcp_leases") => match pfsense.get_dhcp_leases().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "get_dhcp_static_mappings") => match pfsense.get_dhcp_static_mappings().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "add_dhcp_static_mapping") => {
            let mac = get_str("mac");
            let ip = get_str("ip");
            let hostname = get_str("hostname");
            let description = opt_str("description");
            match pfsense.add_dhcp_static_mapping(mac, ip, hostname, description).await {
                Ok(()) => Ok(tool_ok(format!("Static DHCP mapping added: {mac} -> {ip} ({hostname})"))),
                Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
            }
        }
        ("network", "delete_dhcp_static_mapping") => {
            let mac = get_str("mac");
            match pfsense.delete_dhcp_static_mapping(mac).await {
                Ok(true) => Ok(tool_ok(format!("Static DHCP mapping deleted for MAC: {mac}"))),
                Ok(false) => Ok(tool_err(format!("No static mapping found for MAC: {mac}"))),
                Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
            }
        }
        ("network", "get_dns_overrides") => match pfsense.get_dns_overrides().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "add_dns_override") => {
            let host = get_str("host");
            let domain = get_str("domain");
            let ip = get_str("ip");
            let description = opt_str("description");
            match pfsense.add_dns_override(host, domain, ip, description).await {
                Ok(()) => Ok(tool_ok(format!("DNS override added: {host}.{domain} -> {ip}"))),
                Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
            }
        }
        ("network", "delete_dns_override") => {
            let host = get_str("host");
            let domain = get_str("domain");
            match pfsense.delete_dns_override(host, domain).await {
                Ok(true) => Ok(tool_ok(format!("DNS override deleted: {host}.{domain}"))),
                Ok(false) => Ok(tool_err(format!("No DNS override found for {host}.{domain}"))),
                Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
            }
        }
        ("network", "get_vpn_status") => match pfsense.get_vpn_status().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "get_wan_info") => match pfsense.get_wan_info().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "get_lan_info") => match pfsense.get_lan_info().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },
        ("network", "get_haproxy_config") => match pfsense.get_haproxy_config().await {
            Ok(v) => Ok(tool_ok(serde_json::to_string(&v).unwrap_or_default())),
            Err(e) => Ok(tool_err(format!("pfSense error: {e}"))),
        },

        // ── pfsense_ssh actions ────────────────────────────────────────────
        ("pfsense_ssh", "ssh_command") => {
            let command = get_str("command");
            match pfsense.ssh_command(command).await {
                Ok(output) => Ok(tool_ok(output)),
                Err(e) => Ok(tool_err(format!("SSH error: {e}"))),
            }
        }
        ("pfsense_ssh", "php_exec") => {
            let code = get_str("code");
            match pfsense.php_exec_raw(code).await {
                Ok(output) => Ok(tool_ok(output)),
                Err(e) => Ok(tool_err(format!("PHP exec error: {e}"))),
            }
        }
        ("pfsense_ssh", "read_config") => match pfsense.read_config().await {
            Ok(xml) => Ok(tool_ok(xml)),
            Err(e) => Ok(tool_err(format!("Config read error: {e}"))),
        },

        // ── unknown action for a known tool ────────────────────────────────
        _ => Err(format!("unknown action '{action}' for tool '{tool}'")),
    }
}

// ── Main loop ─────────────────────────────────────────────────────────────────

/// Run the MCP stdio loop until stdin closes.
///
/// One JSON object per line in, one JSON object per line out. Notifications
/// (requests with no `id`) are silently dropped — the protocol says servers
/// must not respond to them, and there is nothing to act on here.
///
/// Async IO throughout: blocking on stdin would hold the tokio thread and
/// prevent the SSH calls inside `dispatch` from progressing on the same
/// executor. The `io-util` tokio feature (already a dependency) provides
/// `AsyncBufReadExt::lines`.
pub async fn run(pfsense: Arc<PfSenseService>) {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) if l.trim().is_empty() => continue,
            Ok(Some(l)) => l,
            Ok(None) => break, // stdin closed
            Err(e) => {
                eprintln!("mcp: stdin read error: {e}");
                break;
            }
        };

        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                // A parse error before we have an id: respond with id=null per spec.
                let resp = error_response(&Value::Null, -32700, &format!("parse error: {e}"));
                let s = format!("{resp}\n");
                let _ = stdout.write_all(s.as_bytes()).await;
                continue;
            }
        };

        // Notifications have no `id`; the spec requires no response.
        let id = match msg.get("id") {
            Some(id) if !id.is_null() => id.clone(),
            _ => continue,
        };

        let method = msg
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let resp = handle_request(&pfsense, &id, method, &msg).await;
        let s = format!("{resp}\n");
        let _ = stdout.write_all(s.as_bytes()).await;
    }
}

/// Dispatch one request, returning the complete JSON-RPC response object.
async fn handle_request(pfsense: &PfSenseService, id: &Value, method: &str, msg: &Value) -> Value {
    match method {
        "initialize" => ok_response(id, json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "leo-pfsense-mcp", "version": "1.0.0"}
        })),

        "tools/list" => ok_response(id, json!({
            "tools": [network_tool_schema(), pfsense_ssh_tool_schema()]
        })),

        "tools/call" => {
            let params = msg.get("params").unwrap_or(&Value::Null);
            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = params.get("arguments").unwrap_or(&Value::Null);

            if tool_name != "network" && tool_name != "pfsense_ssh" {
                return ok_response(id, tool_err(format!("unknown tool: '{tool_name}'")));
            }

            match dispatch(pfsense, tool_name, args).await {
                Ok(result) => ok_response(id, result),
                // dispatch returns Err only for malformed requests (missing
                // action, unknown action) — not for SSH failures, which come
                // back as Ok(tool_err(...)). Map these to isError results
                // rather than JSON-RPC errors so the host sees them as tool
                // output, not as a protocol failure.
                Err(msg) => ok_response(id, tool_err(msg)),
            }
        }

        _ => error_response(id, -32601, &format!("method not found: '{method}'")),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── tools/list ────────────────────────────────────────────────────────────

    /// The tools/list payload names both tools and exposes the action enums that
    /// a well-behaved MCP host uses to build its tool-call UI. A missing tool
    /// is a silent capability drop — the host never learns it exists.
    #[test]
    fn tools_list_contains_both_tools_with_correct_action_enums() {
        let network = network_tool_schema();
        let pfsense_ssh = pfsense_ssh_tool_schema();

        // Network tool names
        assert_eq!(network["name"], "network");
        let network_actions: Vec<&str> = network["inputSchema"]["properties"]["action"]["enum"]
            .as_array()
            .expect("network action enum must be an array")
            .iter()
            .map(|v| v.as_str().expect("action must be a string"))
            .collect();

        let expected_network = [
            "get_dashboard", "get_devices", "get_dhcp_leases", "get_dhcp_static_mappings",
            "add_dhcp_static_mapping", "delete_dhcp_static_mapping", "get_dns_overrides",
            "add_dns_override", "delete_dns_override", "get_vpn_status", "get_wan_info",
            "get_lan_info", "get_haproxy_config",
        ];
        assert_eq!(network_actions.len(), expected_network.len());
        for action in &expected_network {
            assert!(network_actions.contains(action), "missing network action: {action}");
        }

        // pfsense_ssh tool names
        assert_eq!(pfsense_ssh["name"], "pfsense_ssh");
        let ssh_actions: Vec<&str> = pfsense_ssh["inputSchema"]["properties"]["action"]["enum"]
            .as_array()
            .expect("pfsense_ssh action enum must be an array")
            .iter()
            .map(|v| v.as_str().expect("action must be a string"))
            .collect();

        let expected_ssh = ["ssh_command", "php_exec", "read_config"];
        assert_eq!(ssh_actions.len(), expected_ssh.len());
        for action in &expected_ssh {
            assert!(ssh_actions.contains(action), "missing pfsense_ssh action: {action}");
        }
    }

    // ── unknown tool ─────────────────────────────────────────────────────────

    /// An unknown tool name must produce an isError result, not a panic.
    /// The host distinguishes isError from a successful empty response: a panic
    /// or a silent `{}` would look like the tool ran and returned nothing.
    #[tokio::test]
    async fn unknown_tool_returns_is_error_not_panic() {
        let pfsense = Arc::new(PfSenseService::new(
            "192.0.2.1", 22, "admin", None, None,
        ));
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "does_not_exist",
                "arguments": {"action": "something"}
            }
        });
        let resp = handle_request(&pfsense, &json!(1), "tools/call", &msg).await;

        // Result must be isError=true, not a JSON-RPC error code.
        assert!(
            resp["result"]["isError"].as_bool().unwrap_or(false),
            "unknown tool should set isError: true; got: {resp}"
        );
        let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
        assert!(
            text.contains("does_not_exist"),
            "error text should name the unknown tool; got: {text}"
        );
    }

    // ── missing required field ─────────────────────────────────────────────

    /// A missing required field for a write action must produce an isError that
    /// names the field, before any SSH connection is attempted.
    ///
    /// Testing `validate` directly keeps this fast and SSH-free: the test
    /// exercises the same logic dispatch uses, because dispatch calls validate
    /// before touching the network.
    #[test]
    fn missing_required_field_returns_is_error_naming_the_field() {
        // add_dhcp_static_mapping requires mac, ip, hostname.
        // Supply only mac — the first missing field should be named.
        let args = json!({"action": "add_dhcp_static_mapping", "mac": "aa:bb:cc:dd:ee:ff"});
        let err = validate("network", "add_dhcp_static_mapping", &args)
            .expect_err("should fail with missing ip and hostname");
        assert!(
            err.contains("ip") || err.contains("hostname"),
            "error should name a missing field; got: {err}"
        );

        // ssh_command requires command.
        let args = json!({"action": "ssh_command"});
        let err = validate("pfsense_ssh", "ssh_command", &args)
            .expect_err("should fail with missing command");
        assert!(err.contains("command"), "error should name 'command'; got: {err}");

        // A zero-argument read passes without any extra fields.
        let args = json!({"action": "get_dashboard"});
        assert!(
            validate("network", "get_dashboard", &args).is_ok(),
            "get_dashboard takes no extra fields and should always pass"
        );
    }

    // ── method not found ──────────────────────────────────────────────────────

    /// An unrecognised method must produce a JSON-RPC error (not an isError
    /// result), because the host may gate retries on the error code.
    #[tokio::test]
    async fn unknown_method_returns_json_rpc_method_not_found() {
        let pfsense = Arc::new(PfSenseService::new(
            "192.0.2.1", 22, "admin", None, None,
        ));
        let msg = json!({"jsonrpc":"2.0","id":42,"method":"not/a/method","params":{}});
        let resp = handle_request(&pfsense, &json!(42), "not/a/method", &msg).await;

        assert_eq!(resp["error"]["code"], -32601, "expected method-not-found code; got: {resp}");
    }
}
