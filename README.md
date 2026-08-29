# leo-pfsense-app

A Leo app package — a standalone Rust binary the hub builds, launches, and
reverse-proxies at `/p/pfsense/*`. It is the pfSense network management
backend, extracted from the compiled `leo-pfsense` package into a subprocess
that the hub can run without recompiling itself.

## Subcommands

```
leo-pfsense-app start   # HTTP server (default when no argument is given)
leo-pfsense-app mcp     # MCP stdio server
```

Both modes read the same env vars — one binary, two personalities.

### HTTP mode (`start` or no argument)

- Connects to pfSense over SSH (key-based or password auth)
- Serves the Network page descriptor and live data at `/leo/ui/*`
- Mirrors the hub's `/api/network/*` REST surface at the same relative paths
- Runs a background sampler that measures WAN/LAN throughput every 10s

### MCP mode (`mcp`)

Speaks the [Model Context Protocol](https://modelcontextprotocol.io) over
stdio: newline-delimited JSON-RPC 2.0 on stdin, responses on stdout. The host
(Claude, LeoCode, or any MCP-aware client) registers this binary as an MCP
server and calls its two tools:

| Tool | Actions |
|---|---|
| `network` | `get_dashboard`, `get_devices`, `get_dhcp_leases`, `get_dhcp_static_mappings`, `add_dhcp_static_mapping`, `delete_dhcp_static_mapping`, `get_dns_overrides`, `add_dns_override`, `delete_dns_override`, `get_vpn_status`, `get_wan_info`, `get_lan_info`, `get_haproxy_config` |
| `pfsense_ssh` | `ssh_command`, `php_exec`, `read_config` |

The tool schemas are reproduced verbatim from `packages/leo-network` and
`packages/leo-pfsense` so the MCP surface and the compiled-package surface
stay in sync.

**Why one binary, not a separate MCP package:** when the hub launches an MCP
subprocess it injects entitled settings as env vars — but it does not inject
the app's hub-assigned port. A separate binary could not discover the HTTP
server to proxy through it. Sharing the binary gives MCP mode direct access to
`PfSenseService` with no HTTP hop and no port discovery.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PFSENSE_HOST` | **Yes** | — | Hostname or IP of the pfSense box |
| `PFSENSE_PORT` | No | `22` | SSH port |
| `PFSENSE_USERNAME` | No | `admin` | SSH username |
| `PFSENSE_PASSWORD` | No | — | SSH password (optional if key is set) |
| `PFSENSE_KEY` | No | — | Path to SSH private key (`~` is expanded) |
| `LEO_APP_PORT` | No | `8500` | Port to listen on (also checked as `PORT`) |

## How the hub runs it

The hub:
1. Builds it with `cargo build --release -p leo-pfsense-app`
2. Sets the env vars from the pfSense package's settings
3. Launches it as a subprocess
4. Reverse-proxies `/p/pfsense/*` → `localhost:$LEO_APP_PORT/*` (stripping
   the prefix) and injects `X-Leo-User-Id` and `x-leo-is-admin` headers

## Auth model

This binary never holds a session store. The hub's proxy injects two headers
on every request:

- `X-Leo-User-Id` — the authenticated user's ID (absence → 401)
- `x-leo-is-admin` — `"1"` for admin, `"0"` or absent → not admin

A missing `x-leo-is-admin` is treated as non-admin. This is the safe default:
older hub builds may not send it, and the consequence is read-only access, not
elevated privileges.

## Route auth levels

| Routes | Level |
|---|---|
| GET /status, /dashboard, /devices, /dhcp/static, /dhcp/leases, /vpn, /haproxy, /dns/overrides, /wan, /lan, /bandwidth | Session (any logged-in user) |
| POST/DELETE /dhcp/static, POST/PUT/DELETE /dns/overrides, POST /php | Admin only |
| GET /leo/ui/descriptor, GET /leo/ui/data | Session |

## Deviations from the hub's compiled package

- `delete_path` in the descriptor now points to `/p/pfsense/dhcp/static` and
  `/p/pfsense/dns/overrides` instead of `/api/network/…` — the action goes
  through the hub proxy, not directly to the hub's own API.
- The hub-NIC bandwidth sampler (`/proc/net/dev`) is absent. It measures the
  hub machine, which is the hub's own business. The `Snapshot` returned from
  `/bandwidth` omits the `hub` field; the hub fills that in from its own
  monitor before returning to the client.
- `GET /dhcp/leases` is added as a REST route (it existed only as a service
  method in the hub, called directly from the UI data function).
