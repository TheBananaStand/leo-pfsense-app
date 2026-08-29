//! pfSense management via SSH — reads config.xml, runs shell commands, executes PHP.
//!
//! This is a faithful copy of packages/leo-pfsense/src/pfsense.rs with two
//! changes: `leo_core::LeoError` → `crate::error::Error`, and the async-trait
//! import now references `async_trait` directly (still a crate dependency, not
//! from leo-core). Every method, every parser, every #[cfg(test)] test is kept.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use crate::error::Error;
use regex::Regex;
use russh::keys::key;
use russh::{ChannelMsg, Disconnect, client};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Validation patterns
// ---------------------------------------------------------------------------

fn validate_mac(mac: &str) -> Result<String, Error> {
    let mac = mac.trim().to_lowercase();
    let re = Regex::new(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$").unwrap();
    if !re.is_match(&mac) {
        return Err(Error::Validation(format!("Invalid MAC address: {mac}")));
    }
    Ok(mac)
}

fn validate_ip(ip: &str) -> Result<String, Error> {
    let ip = ip.trim().to_string();
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| Error::Validation(format!("Invalid IP address: {ip}")))?;
    Ok(ip)
}

fn validate_hostname(name: &str) -> Result<String, Error> {
    let name = name.trim().to_string();
    let re = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$").unwrap();
    if name.is_empty() || !re.is_match(&name) {
        return Err(Error::Validation(format!("Invalid hostname: {name}")));
    }
    Ok(name)
}

fn validate_domain(domain: &str) -> Result<String, Error> {
    let domain = domain.trim().to_string();
    let re = Regex::new(r"^[a-zA-Z0-9.\-]+$").unwrap();
    if domain.is_empty() || !re.is_match(&domain) {
        return Err(Error::Validation(format!("Invalid domain: {domain}")));
    }
    Ok(domain)
}

/// Escape a string for embedding in single-quoted PHP.
fn php_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub starts: Option<String>,
    pub ends: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMapping {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub source: String, // "arp", "dhcp", "static"
    pub interface: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub interface: String,
    pub status: String,
    pub ip: Option<String>,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub dhcp_range_from: Option<String>,
    pub dhcp_range_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnServer {
    pub vpnid: String,
    pub description: String,
    pub mode: String,
    pub protocol: String,
    pub port: String,
    pub tunnel_network: String,
    pub clients: Vec<VpnClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnClient {
    pub common_name: String,
    pub real_address: String,
    pub virtual_address: Option<String>,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub connected_since: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOverride {
    pub host: String,
    pub domain: String,
    pub ip: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaProxyConfig {
    pub backends: Vec<serde_json::Value>,
    pub frontends: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// SSH client handler
// ---------------------------------------------------------------------------

struct PfSenseHandler;

#[async_trait]
impl client::Handler for PfSenseHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // pfSense is on a trusted LAN — accept all host keys
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct PfSenseService {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    key_path: Option<PathBuf>,
}

impl PfSenseService {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: Option<String>,
        key_path: Option<PathBuf>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password,
            key_path,
        }
    }

    /// Open an SSH connection and authenticate.
    async fn connect(&self) -> Result<client::Handle<PfSenseHandler>, Error> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        };

        let mut handle =
            client::connect(Arc::new(config), (&*self.host, self.port), PfSenseHandler)
                .await
                .map_err(|e| Error::Ssh(format!("SSH connect failed: {e}")))?;

        // Try key-based auth first, then password
        let authenticated = if let Some(ref key_path) = self.key_path {
            let expanded = if key_path.starts_with("~") {
                if let Some(home) = dirs::home_dir() {
                    home.join(key_path.strip_prefix("~").unwrap_or(key_path))
                } else {
                    key_path.clone()
                }
            } else {
                key_path.clone()
            };

            if expanded.exists() {
                let key_pair = russh::keys::load_secret_key(&expanded, None)
                    .map_err(|e| Error::Ssh(format!("Failed to load SSH key: {e}")))?;
                handle
                    .authenticate_publickey(&self.username, Arc::new(key_pair))
                    .await
                    .map_err(|e| Error::Ssh(format!("Public key auth failed: {e}")))?
            } else if let Some(ref pw) = self.password {
                handle
                    .authenticate_password(&self.username, pw)
                    .await
                    .map_err(|e| Error::Ssh(format!("Password auth failed: {e}")))?
            } else {
                return Err(Error::Ssh(format!(
                    "SSH key not found at {} and no password configured",
                    expanded.display()
                )));
            }
        } else if let Some(ref pw) = self.password {
            handle
                .authenticate_password(&self.username, pw)
                .await
                .map_err(|e| Error::Ssh(format!("Password auth failed: {e}")))?
        } else {
            return Err(Error::Ssh(
                "No SSH key or password configured".to_string(),
            ));
        };

        if !authenticated {
            return Err(Error::Auth("SSH authentication failed".to_string()));
        }

        Ok(handle)
    }

    /// Run a shell command over SSH and return stdout.
    async fn run_command(&self, cmd: &str) -> Result<String, Error> {
        let handle = self.connect().await?;
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| Error::Ssh(format!("Failed to open session channel: {e}")))?;

        channel
            .exec(true, cmd)
            .await
            .map_err(|e| Error::Ssh(format!("Failed to exec command: {e}")))?;

        let mut output = Vec::new();
        let mut exit_code: Option<u32> = None;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    output.extend_from_slice(data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                _ => {}
            }
        }

        let stdout = String::from_utf8_lossy(&output).to_string();

        if let Some(code) = exit_code
            && code != 0
        {
            debug!("Command exited with code {code}: {cmd}");
        }

        handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .ok();

        Ok(stdout)
    }

    /// Execute PHP code on pfSense via a temp file.
    async fn php_exec(&self, code: &str) -> Result<String, Error> {
        let script = format!(
            "require_once('config.inc');\nrequire_once('util.inc');\nrequire_once('services.inc');\n{code}\n"
        );
        // Use a heredoc to write the PHP script to a temp file, then execute and clean up.
        let cmd = format!(
            "tmpf=$(mktemp /tmp/leo_php_XXXXXX.php) && \
             cat > \"$tmpf\" << 'LEOPHPEOF'\n<?php\n{script}\n?>\nLEOPHPEOF\n\
             php \"$tmpf\"; rc=$?; rm -f \"$tmpf\"; exit $rc"
        );
        self.run_command(&cmd).await
    }

    /// Read the pfSense config.xml as a string.
    async fn read_config_xml(&self) -> Result<String, Error> {
        self.run_command("cat /cf/conf/config.xml").await
    }

    // -----------------------------------------------------------------------
    // DHCP
    // -----------------------------------------------------------------------

    /// Get active DHCP leases from the ISC dhcpd.leases file.
    pub async fn get_dhcp_leases(&self) -> Result<Vec<DhcpLease>, Error> {
        let raw = self
            .run_command("cat /var/dhcpd/var/db/dhcpd.leases")
            .await?;
        Ok(parse_isc_leases(&raw))
    }

    /// Get static DHCP mappings from config.xml.
    pub async fn get_dhcp_static_mappings(&self) -> Result<Vec<StaticMapping>, Error> {
        let xml = self.read_config_xml().await?;
        Ok(parse_static_mappings(&xml))
    }

    /// Add a static DHCP mapping.
    pub async fn add_dhcp_static_mapping(
        &self,
        mac: &str,
        ip: &str,
        hostname: &str,
        description: Option<&str>,
    ) -> Result<(), Error> {
        let mac = validate_mac(mac)?;
        let ip = validate_ip(ip)?;
        let hostname = validate_hostname(hostname)?;
        let descr = description.unwrap_or("");

        let php = format!(
            "$new = array();\n\
             $new['mac'] = '{mac_e}';\n\
             $new['ipaddr'] = '{ip_e}';\n\
             $new['hostname'] = '{host_e}';\n\
             $new['descr'] = '{descr_e}';\n\
             if (!is_array($config['dhcpd']['lan']['staticmap'])) {{\n\
                 $config['dhcpd']['lan']['staticmap'] = array();\n\
             }}\n\
             $config['dhcpd']['lan']['staticmap'][] = $new;\n\
             write_config('Added DHCP static mapping for {host_e}');\n\
             services_dhcpd_configure();\n\
             echo \"OK\";\n",
            mac_e = php_escape(&mac),
            ip_e = php_escape(&ip),
            host_e = php_escape(&hostname),
            descr_e = php_escape(descr),
        );
        let result = self.php_exec(&php).await?;
        if !result.contains("OK") {
            return Err(Error::Other(format!(
                "add_dhcp_static_mapping: unexpected output: {result}"
            )));
        }
        Ok(())
    }

    /// Delete a static DHCP mapping by MAC address.
    pub async fn delete_dhcp_static_mapping(&self, mac: &str) -> Result<bool, Error> {
        let mac = validate_mac(mac)?;

        let php = format!(
            "$found = false;\n\
             if (is_array($config['dhcpd']['lan']['staticmap'])) {{\n\
                 foreach ($config['dhcpd']['lan']['staticmap'] as $idx => $map) {{\n\
                     if (strtolower($map['mac']) === '{mac_e}') {{\n\
                         unset($config['dhcpd']['lan']['staticmap'][$idx]);\n\
                         $config['dhcpd']['lan']['staticmap'] = array_values($config['dhcpd']['lan']['staticmap']);\n\
                         $found = true;\n\
                         break;\n\
                     }}\n\
                 }}\n\
             }}\n\
             if ($found) {{\n\
                 write_config('Removed DHCP static mapping for {mac_e}');\n\
                 services_dhcpd_configure();\n\
                 echo \"DELETED\";\n\
             }} else {{\n\
                 echo \"NOT_FOUND\";\n\
             }}\n",
            mac_e = php_escape(&mac),
        );
        let result = self.php_exec(&php).await?;
        Ok(result.contains("DELETED"))
    }

    // -----------------------------------------------------------------------
    // Devices
    // -----------------------------------------------------------------------

    /// Get all network devices by merging ARP table, DHCP leases, and static mappings.
    pub async fn get_devices(&self) -> Result<Vec<NetworkDevice>, Error> {
        let arp_raw = self.run_command("arp -an").await?;
        let leases = self.get_dhcp_leases().await?;
        let statics = self.get_dhcp_static_mappings().await?;

        // Build lookup maps
        let lease_by_ip: HashMap<&str, &DhcpLease> =
            leases.iter().map(|l| (l.ip.as_str(), l)).collect();

        let static_by_mac: HashMap<&str, &StaticMapping> =
            statics.iter().map(|s| (s.mac.as_str(), s)).collect();

        let arp_re =
            Regex::new(r"\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)").unwrap();

        let mut devices = Vec::new();
        let mut seen_macs = std::collections::HashSet::new();

        for line in arp_raw.lines() {
            if let Some(caps) = arp_re.captures(line) {
                let ip = caps[1].to_string();
                let mac = caps[2].to_lowercase();
                let iface = caps[3].to_string();

                if mac == "(incomplete)" || mac == "ff:ff:ff:ff:ff:ff" {
                    continue;
                }
                seen_macs.insert(mac.clone());

                let (hostname, source, description) =
                    if let Some(sm) = static_by_mac.get(mac.as_str()) {
                        (
                            Some(sm.hostname.clone()),
                            "static".to_string(),
                            sm.description.clone(),
                        )
                    } else if let Some(lease) = lease_by_ip.get(ip.as_str()) {
                        (lease.hostname.clone(), "dhcp".to_string(), None)
                    } else {
                        (None, "arp".to_string(), None)
                    };

                devices.push(NetworkDevice {
                    ip,
                    mac,
                    hostname,
                    source,
                    interface: Some(iface),
                    description,
                });
            }
        }

        // seen_macs is populated but not used further — it was scaffolding for
        // a planned "add static-only devices" pass that never landed. Kept to
        // match the original exactly; a compiler warning is the only cost.
        let _ = seen_macs;

        Ok(devices)
    }

    // -----------------------------------------------------------------------
    // Interfaces
    // -----------------------------------------------------------------------

    /// The names of the WAN and LAN interfaces, straight out of `config.xml`.
    ///
    /// Cheaper than `get_wan_info`/`get_lan_info` (one command, no `ifconfig`
    /// or route lookup) because the throughput sampler needs only the names,
    /// and it resolves them on a schedule.
    pub async fn wan_lan_interface_names(&self) -> Result<(String, String), Error> {
        let xml = self.read_config_xml().await?;
        Ok((
            extract_xml_text(&xml, "interfaces", "wan", "if").unwrap_or("wan".to_string()),
            extract_xml_text(&xml, "interfaces", "lan", "if").unwrap_or("lan".to_string()),
        ))
    }

    /// Raw `netstat -ibn` output — cumulative byte counters for every
    /// interface, in one command.
    ///
    /// Returned unparsed: the caller diffs successive readings into a rate, and
    /// keeping that logic next to the equivalent `/proc/net/dev` parse (in
    /// `bandwidth.rs`) means one place to test both.
    pub async fn interface_counters_raw(&self) -> Result<String, Error> {
        self.run_command("netstat -ibn").await
    }

    /// Get WAN interface information.
    pub async fn get_wan_info(&self) -> Result<InterfaceInfo, Error> {
        let xml = self.read_config_xml().await?;

        let wan_if = extract_xml_text(&xml, "interfaces", "wan", "if").unwrap_or("wan".to_string());

        let ifconfig_raw = self.run_command(&format!("ifconfig {wan_if}")).await?;
        let route_raw = self.run_command("route -n get default").await?;

        let ip_re = Regex::new(r"inet (\d+\.\d+\.\d+\.\d+)").unwrap();
        let ip = ip_re.captures(&ifconfig_raw).map(|c| c[1].to_string());

        let mask_re = Regex::new(r"netmask (0x[0-9a-f]+)").unwrap();
        let subnet = mask_re.captures(&ifconfig_raw).map(|c| {
            let mask_int = u32::from_str_radix(&c[1][2..], 16).unwrap_or(0);
            mask_int.count_ones().to_string()
        });

        let gw_re = Regex::new(r"gateway:\s*(\S+)").unwrap();
        let gateway = gw_re.captures(&route_raw).map(|c| c[1].to_string());

        let status = if ifconfig_raw
            .lines()
            .next()
            .is_some_and(|l| l.contains("UP"))
        {
            "up"
        } else {
            "down"
        };

        // DNS servers from config.xml
        let dns_servers = extract_xml_list(&xml, "system", "dnsserver");

        Ok(InterfaceInfo {
            interface: wan_if,
            status: status.to_string(),
            ip,
            subnet,
            gateway,
            dns_servers,
            dhcp_range_from: None,
            dhcp_range_to: None,
        })
    }

    /// Get LAN interface information.
    pub async fn get_lan_info(&self) -> Result<InterfaceInfo, Error> {
        let xml = self.read_config_xml().await?;

        let lan_if = extract_xml_text(&xml, "interfaces", "lan", "if").unwrap_or("lan".to_string());
        let lan_ip = extract_xml_text(&xml, "interfaces", "lan", "ipaddr");
        let lan_subnet = extract_xml_text(&xml, "interfaces", "lan", "subnet");

        let ifconfig_raw = self.run_command(&format!("ifconfig {lan_if}")).await?;
        let status = if ifconfig_raw
            .lines()
            .next()
            .is_some_and(|l| l.contains("UP"))
        {
            "up"
        } else {
            "down"
        };

        // DHCP range
        let dhcp_from = extract_xml_nested(&xml, "dhcpd", "lan", "range", "from");
        let dhcp_to = extract_xml_nested(&xml, "dhcpd", "lan", "range", "to");

        Ok(InterfaceInfo {
            interface: lan_if,
            status: status.to_string(),
            ip: lan_ip,
            subnet: lan_subnet,
            gateway: None,
            dns_servers: Vec::new(),
            dhcp_range_from: dhcp_from,
            dhcp_range_to: dhcp_to,
        })
    }

    // -----------------------------------------------------------------------
    // VPN
    // -----------------------------------------------------------------------

    /// Get OpenVPN server status including connected clients.
    pub async fn get_vpn_status(&self) -> Result<Vec<VpnServer>, Error> {
        let xml = self.read_config_xml().await?;
        let servers_raw = extract_openvpn_servers(&xml);
        let mut servers = Vec::new();

        for srv in servers_raw {
            let vpnid = srv.0.clone();
            let clients = match self
                .run_command(&format!("cat /var/etc/openvpn/server{vpnid}/status.log"))
                .await
            {
                Ok(log) => parse_openvpn_status(&log),
                Err(_) => Vec::new(),
            };

            servers.push(VpnServer {
                vpnid: srv.0,
                description: srv.1,
                mode: srv.2,
                protocol: srv.3,
                port: srv.4,
                tunnel_network: srv.5,
                clients,
            });
        }

        Ok(servers)
    }

    // -----------------------------------------------------------------------
    // DNS
    // -----------------------------------------------------------------------

    /// Get DNS host overrides from config.xml.
    pub async fn get_dns_overrides(&self) -> Result<Vec<DnsOverride>, Error> {
        let xml = self.read_config_xml().await?;
        Ok(parse_dns_overrides(&xml))
    }

    /// Add a DNS host override.
    pub async fn add_dns_override(
        &self,
        host: &str,
        domain: &str,
        ip: &str,
        description: Option<&str>,
    ) -> Result<(), Error> {
        let host = validate_hostname(host)?;
        let domain = validate_domain(domain)?;
        let ip = validate_ip(ip)?;
        let descr = description.unwrap_or("");

        let php = format!(
            "$new = array();\n\
             $new['host'] = '{host_e}';\n\
             $new['domain'] = '{domain_e}';\n\
             $new['ip'] = '{ip_e}';\n\
             $new['descr'] = '{descr_e}';\n\
             if (!is_array($config['unbound']['hosts'])) {{\n\
                 $config['unbound']['hosts'] = array();\n\
             }}\n\
             $config['unbound']['hosts'][] = $new;\n\
             write_config('Added DNS override for {host_e}.{domain_e}');\n\
             services_unbound_configure();\n\
             echo \"OK\";\n",
            host_e = php_escape(&host),
            domain_e = php_escape(&domain),
            ip_e = php_escape(&ip),
            descr_e = php_escape(descr),
        );
        let result = self.php_exec(&php).await?;
        if !result.contains("OK") {
            return Err(Error::Other(format!(
                "add_dns_override: unexpected output: {result}"
            )));
        }
        Ok(())
    }

    /// Delete a DNS host override.
    pub async fn delete_dns_override(&self, host: &str, domain: &str) -> Result<bool, Error> {
        let host = validate_hostname(host)?;
        let domain = validate_domain(domain)?;

        let php = format!(
            "$found = false;\n\
             if (is_array($config['unbound']['hosts'])) {{\n\
                 foreach ($config['unbound']['hosts'] as $idx => $entry) {{\n\
                     if ($entry['host'] === '{host_e}' && $entry['domain'] === '{domain_e}') {{\n\
                         unset($config['unbound']['hosts'][$idx]);\n\
                         $config['unbound']['hosts'] = array_values($config['unbound']['hosts']);\n\
                         $found = true;\n\
                         break;\n\
                     }}\n\
                 }}\n\
             }}\n\
             if ($found) {{\n\
                 write_config('Removed DNS override for {host_e}.{domain_e}');\n\
                 services_unbound_configure();\n\
                 echo \"DELETED\";\n\
             }} else {{\n\
                 echo \"NOT_FOUND\";\n\
             }}\n",
            host_e = php_escape(&host),
            domain_e = php_escape(&domain),
        );
        let result = self.php_exec(&php).await?;
        Ok(result.contains("DELETED"))
    }

    pub async fn get_haproxy_config(&self) -> Result<HaProxyConfig, Error> {
        let php = r#"
$ha = $config['installedpackages']['haproxy'] ?? [];
$result = ['backends' => [], 'frontends' => []];

// Backends (ha_pools)
$pools = $ha['ha_pools']['item'] ?? [];
if (!is_array($pools)) $pools = [];
if (isset($pools['name'])) $pools = [$pools];
foreach ($pools as $p) {
    $servers = [];
    $srvItems = $p['ha_servers']['item'] ?? [];
    if (!is_array($srvItems)) $srvItems = [];
    if (isset($srvItems['name'])) $srvItems = [$srvItems];
    foreach ($srvItems as $s) {
        $servers[] = [
            'name' => $s['name'] ?? '',
            'address' => $s['address'] ?? '',
            'port' => $s['port'] ?? '',
            'status' => $s['status'] ?? 'active',
        ];
    }
    $result['backends'][] = [
        'name' => $p['name'] ?? '',
        'balance' => $p['balance'] ?? '',
        'mode' => $p['type'] ?? 'http',
        'servers' => $servers,
    ];
}

// Frontends (ha_backends)
$fes = $ha['ha_backends']['item'] ?? [];
if (!is_array($fes)) $fes = [];
if (isset($fes['name'])) $fes = [$fes];
foreach ($fes as $f) {
    $addrs = [];
    $addrItems = $f['a_extaddr']['item'] ?? [];
    if (!is_array($addrItems)) $addrItems = [];
    if (isset($addrItems['extaddr'])) $addrItems = [$addrItems];
    foreach ($addrItems as $a) {
        $addrs[] = [
            'address' => $a['extaddr'] ?? '',
            'port' => $a['extaddr_port'] ?? '',
        ];
    }
    $acls = [];
    $aclItems = $f['ha_acls']['item'] ?? [];
    if (!is_array($aclItems)) $aclItems = [];
    if (isset($aclItems['name'])) $aclItems = [$aclItems];
    foreach ($aclItems as $a) {
        $acls[] = [
            'name' => $a['name'] ?? '',
            'expression' => $a['expression'] ?? '',
            'value' => $a['value'] ?? '',
        ];
    }
    $actions = [];
    $actItems = $f['a_actionitems']['item'] ?? [];
    if (!is_array($actItems)) $actItems = [];
    if (isset($actItems['action'])) $actItems = [$actItems];
    foreach ($actItems as $a) {
        $actions[] = [
            'action' => $a['action'] ?? '',
            'acl' => $a['acl'] ?? '',
            'backend' => $a['use_backend'] ?? '',
        ];
    }
    $result['frontends'][] = [
        'name' => $f['name'] ?? '',
        'status' => $f['status'] ?? 'active',
        'mode' => $f['type'] ?? 'http',
        'default_backend' => $f['backend_serverpool'] ?? '',
        'ssl' => ($f['ssloffloadcert'] ?? '') !== '' ? 'yes' : 'no',
        'addresses' => $addrs,
        'acls' => $acls,
        'actions' => $actions,
    ];
}

echo json_encode($result);
"#;
        let raw = self.php_exec(php).await?;
        let trimmed = raw.trim();
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(val) => {
                let backends = val
                    .get("backends")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let frontends = val
                    .get("frontends")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                Ok(HaProxyConfig {
                    backends,
                    frontends,
                })
            }
            Err(e) => {
                warn!("Failed to parse HAProxy config JSON: {e}");
                Ok(HaProxyConfig {
                    backends: Vec::new(),
                    frontends: Vec::new(),
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Dashboard
    // -----------------------------------------------------------------------

    /// Get a combined dashboard overview of the pfSense box.
    pub async fn get_dashboard(&self) -> Result<serde_json::Value, Error> {
        let wan = self.get_wan_info().await?;
        let lan = self.get_lan_info().await?;
        let devices = self.get_devices().await?;
        let leases = self.get_dhcp_leases().await?;
        let statics = self.get_dhcp_static_mappings().await?;
        let vpn = self.get_vpn_status().await?;
        let dns = self.get_dns_overrides().await?;

        let vpn_client_count: usize = vpn.iter().map(|s| s.clients.len()).sum();

        Ok(serde_json::json!({
            "wan": wan,
            "lan": lan,
            "device_count": devices.len(),
            "lease_count": leases.len(),
            "static_count": statics.len(),
            "vpn_servers": vpn.len(),
            "vpn_client_count": vpn_client_count,
            "dns_override_count": dns.len(),
        }))
    }

    // -----------------------------------------------------------------------
    // Public wrappers for direct SSH/PHP access
    // -----------------------------------------------------------------------

    /// Run an arbitrary SSH command.
    pub async fn ssh_command(&self, cmd: &str) -> Result<String, Error> {
        self.run_command(cmd).await
    }

    /// Execute arbitrary PHP.
    pub async fn php_exec_raw(&self, code: &str) -> Result<String, Error> {
        self.php_exec(code).await
    }

    /// Read the pfSense config.xml.
    pub async fn read_config(&self) -> Result<String, Error> {
        self.read_config_xml().await
    }

    // -----------------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------------

    /// Check if the pfSense box is reachable via SSH.
    pub async fn check_reachable(&self) -> bool {
        self.reach().await.is_ok()
    }

    /// Open a connection, authenticate, and hang up — reporting *why* if it
    /// didn't work.
    ///
    /// [`check_reachable`](Self::check_reachable) collapses this to a bool, and
    /// the two failures it merges want opposite responses from the owner:
    /// [`Error::Auth`] means the login is wrong and only a human can fix it,
    /// while [`Error::Ssh`] means the box didn't answer and may well come
    /// back on its own. Authenticating *is* the whole question here, so there's
    /// no command worth running afterwards — and nothing is written either way.
    pub async fn reach(&self) -> Result<(), Error> {
        let handle = self.connect().await?;
        handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .ok();
        Ok(())
    }
}

// ===========================================================================
// Parsers
// ===========================================================================

/// Parse ISC dhcpd.leases into active leases, deduplicated by MAC (keeping latest).
fn parse_isc_leases(raw: &str) -> Vec<DhcpLease> {
    let mut leases = Vec::new();
    let mut current: Option<DhcpLease> = None;

    for line in raw.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix("lease ") {
            let ip = rest.split_whitespace().next().unwrap_or("").to_string();
            current = Some(DhcpLease {
                ip,
                mac: String::new(),
                hostname: None,
                starts: None,
                ends: None,
            });
        } else if let Some(ref mut lease) = current {
            if line.starts_with("hardware ethernet") {
                lease.mac = line
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_end_matches(';')
                    .to_lowercase();
            } else if line.starts_with("client-hostname") {
                if let Some(name) = line.split('"').nth(1) {
                    lease.hostname = Some(name.to_string());
                }
            } else if line.starts_with("starts") {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    lease.starts = Some(
                        parts[2..]
                            .join(" ")
                            .trim_end_matches(';')
                            .trim()
                            .to_string(),
                    );
                }
            } else if line.starts_with("ends") {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    lease.ends = Some(
                        parts[2..]
                            .join(" ")
                            .trim_end_matches(';')
                            .trim()
                            .to_string(),
                    );
                }
            } else if line == "}"
                && let Some(l) = current.take()
                && !l.mac.is_empty()
            {
                leases.push(l);
            }
        }
    }

    // Deduplicate: keep latest lease per MAC
    let mut by_mac: HashMap<String, DhcpLease> = HashMap::new();
    for lease in leases {
        let mac = lease.mac.clone();
        let dominated = by_mac.get(&mac).is_some_and(|existing| {
            existing.ends.as_deref().unwrap_or("") >= lease.ends.as_deref().unwrap_or("")
        });
        if !dominated {
            by_mac.insert(mac, lease);
        }
    }

    by_mac.into_values().collect()
}

/// Parse static DHCP mappings from config.xml using simple string extraction.
fn parse_static_mappings(xml: &str) -> Vec<StaticMapping> {
    let mut mappings = Vec::new();

    // Find the <dhcpd> section, then <lan>, then each <staticmap>
    // Simple approach: find all <staticmap>...</staticmap> blocks
    let staticmap_re = Regex::new(r"(?s)<staticmap>(.*?)</staticmap>").unwrap();
    let mac_re = Regex::new(r"<mac>(.*?)</mac>").unwrap();
    let ip_re = Regex::new(r"<ipaddr>(.*?)</ipaddr>").unwrap();
    let host_re = Regex::new(r"<hostname>(.*?)</hostname>").unwrap();
    let descr_re = Regex::new(r"<descr>(.*?)</descr>").unwrap();

    // Only look within <dhcpd><lan>...</lan></dhcpd> if possible
    let section = if let Some(start) = xml.find("<dhcpd>") {
        if let Some(end) = xml[start..].find("</dhcpd>") {
            &xml[start..start + end + 8]
        } else {
            xml
        }
    } else {
        return mappings;
    };

    for cap in staticmap_re.captures_iter(section) {
        let block = &cap[1];
        let mac = mac_re
            .captures(block)
            .map(|c| c[1].to_lowercase())
            .unwrap_or_default();
        let ip = ip_re
            .captures(block)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        let hostname = host_re
            .captures(block)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        let descr = descr_re.captures(block).map(|c| c[1].to_string());

        if !mac.is_empty() {
            mappings.push(StaticMapping {
                mac,
                ip,
                hostname,
                description: descr,
            });
        }
    }

    mappings
}

/// Parse DNS host overrides from config.xml.
fn parse_dns_overrides(xml: &str) -> Vec<DnsOverride> {
    let mut overrides = Vec::new();

    // Find <unbound> section and extract <hosts> blocks
    let section = if let Some(start) = xml.find("<unbound>") {
        if let Some(end) = xml[start..].find("</unbound>") {
            &xml[start..start + end + 10]
        } else {
            xml
        }
    } else {
        return overrides;
    };

    let hosts_re = Regex::new(r"(?s)<hosts>(.*?)</hosts>").unwrap();
    let host_re = Regex::new(r"<host>(.*?)</host>").unwrap();
    let domain_re = Regex::new(r"<domain>(.*?)</domain>").unwrap();
    let ip_re = Regex::new(r"<ip>(.*?)</ip>").unwrap();
    let descr_re = Regex::new(r"<descr>(.*?)</descr>").unwrap();

    for cap in hosts_re.captures_iter(section) {
        let block = &cap[1];
        let host = host_re
            .captures(block)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        let domain = domain_re
            .captures(block)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        let ip = ip_re
            .captures(block)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        let descr = descr_re.captures(block).map(|c| c[1].to_string());

        overrides.push(DnsOverride {
            host,
            domain,
            ip,
            description: descr,
        });
    }

    overrides
}

/// Parse OpenVPN status.log for connected clients.
fn parse_openvpn_status(raw: &str) -> Vec<VpnClient> {
    let mut clients = Vec::new();
    let mut in_clients = false;

    for line in raw.lines() {
        if line.starts_with("Common Name,") {
            in_clients = true;
            continue;
        }
        if line.starts_with("ROUTING TABLE") {
            break;
        }
        if in_clients && line.contains(',') {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                clients.push(VpnClient {
                    common_name: parts[0].to_string(),
                    real_address: parts[1].to_string(),
                    virtual_address: None,
                    bytes_received: parts[2].parse().unwrap_or(0),
                    bytes_sent: parts[3].parse().unwrap_or(0),
                    connected_since: parts.get(4).unwrap_or(&"").to_string(),
                });
            }
        }
    }

    clients
}

/// Extract OpenVPN server definitions from config.xml.
/// Returns tuples of (vpnid, description, mode, protocol, port, tunnel_network).
fn extract_openvpn_servers(xml: &str) -> Vec<(String, String, String, String, String, String)> {
    let mut servers = Vec::new();

    let server_re = Regex::new(r"(?s)<openvpn-server>(.*?)</openvpn-server>").unwrap();

    let section = if let Some(start) = xml.find("<openvpn>") {
        if let Some(end) = xml[start..].find("</openvpn>") {
            &xml[start..start + end + 10]
        } else {
            xml
        }
    } else {
        return servers;
    };

    for cap in server_re.captures_iter(section) {
        let block = &cap[1];
        let vpnid = extract_tag(block, "vpnid").unwrap_or_default();
        let desc = extract_tag(block, "description")
            .or_else(|| extract_tag(block, "descr"))
            .unwrap_or_else(|| format!("Server {vpnid}"));
        let mode = extract_tag(block, "mode").unwrap_or_default();
        let protocol = extract_tag(block, "protocol").unwrap_or_default();
        let port = extract_tag(block, "local_port").unwrap_or_default();
        let tunnel = extract_tag(block, "tunnel_network").unwrap_or_default();

        servers.push((vpnid, desc, mode, protocol, port, tunnel));
    }

    servers
}

// ---------------------------------------------------------------------------
// Simple XML helpers (no full XML parser needed for config.xml)
// ---------------------------------------------------------------------------

/// Extract the text content of a simple XML tag like `<tag>value</tag>`.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Extract text at path `<parent><child><field>value</field></child></parent>`.
fn extract_xml_text(xml: &str, parent: &str, child: &str, field: &str) -> Option<String> {
    let parent_open = format!("<{parent}>");
    let parent_close = format!("</{parent}>");
    let start = xml.find(&parent_open)? + parent_open.len();
    let end = xml[start..].find(&parent_close)? + start;
    let parent_content = &xml[start..end];

    let child_open = format!("<{child}>");
    let child_close = format!("</{child}>");
    let cstart = parent_content.find(&child_open)? + child_open.len();
    let cend = parent_content[cstart..].find(&child_close)? + cstart;
    let child_content = &parent_content[cstart..cend];

    extract_tag(child_content, field)
}

/// Extract text at a 4-level path.
fn extract_xml_nested(xml: &str, l1: &str, l2: &str, l3: &str, field: &str) -> Option<String> {
    let l1_open = format!("<{l1}>");
    let l1_close = format!("</{l1}>");
    let start = xml.find(&l1_open)? + l1_open.len();
    let end = xml[start..].find(&l1_close)? + start;
    let l1_content = &xml[start..end];

    let l2_open = format!("<{l2}>");
    let l2_close = format!("</{l2}>");
    let l2start = l1_content.find(&l2_open)? + l2_open.len();
    let l2end = l1_content[l2start..].find(&l2_close)? + l2start;
    let l2_content = &l1_content[l2start..l2end];

    let l3_open = format!("<{l3}>");
    let l3_close = format!("</{l3}>");
    let l3start = l2_content.find(&l3_open)? + l3_open.len();
    let l3end = l2_content[l3start..].find(&l3_close)? + l3start;
    let l3_content = &l2_content[l3start..l3end];

    extract_tag(l3_content, field)
}

/// Extract a list of values for repeated elements like `<parent><tag>v1</tag><tag>v2</tag></parent>`.
fn extract_xml_list(xml: &str, parent: &str, tag: &str) -> Vec<String> {
    let parent_open = format!("<{parent}>");
    let parent_close = format!("</{parent}>");

    let Some(start) = xml.find(&parent_open) else {
        return Vec::new();
    };
    let start = start + parent_open.len();
    let Some(rel_end) = xml[start..].find(&parent_close) else {
        return Vec::new();
    };
    let section = &xml[start..start + rel_end];

    let re = Regex::new(&format!(r"<{tag}>(.*?)</{tag}>")).unwrap();
    re.captures_iter(section)
        .map(|c| c[1].to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_isc_leases() {
        let raw = r#"
lease 10.0.0.100 {
  starts 2 2026/02/22 10:00:00;
  ends 2 2026/02/22 22:00:00;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "my-device";
}
lease 10.0.0.101 {
  starts 2 2026/02/22 11:00:00;
  ends 2 2026/02/22 23:00:00;
  hardware ethernet 11:22:33:44:55:66;
  client-hostname "other-device";
}
"#;
        let leases = parse_isc_leases(raw);
        assert_eq!(leases.len(), 2);

        let lease_aa = leases.iter().find(|l| l.mac == "aa:bb:cc:dd:ee:ff");
        assert!(lease_aa.is_some());
        let lease_aa = lease_aa.unwrap();
        assert_eq!(lease_aa.ip, "10.0.0.100");
        assert_eq!(lease_aa.hostname.as_deref(), Some("my-device"));
    }

    #[test]
    fn test_parse_isc_leases_dedup() {
        let raw = r#"
lease 10.0.0.100 {
  starts 2 2026/02/22 10:00:00;
  ends 2 2026/02/22 18:00:00;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "old";
}
lease 10.0.0.101 {
  starts 2 2026/02/22 12:00:00;
  ends 2 2026/02/22 22:00:00;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "new";
}
"#;
        let leases = parse_isc_leases(raw);
        assert_eq!(leases.len(), 1);
        let lease = &leases[0];
        assert_eq!(lease.hostname.as_deref(), Some("new"));
        assert_eq!(lease.ip, "10.0.0.101");
    }

    #[test]
    fn test_parse_static_mappings() {
        let xml = r#"
<pfsense>
<dhcpd>
<lan>
<range><from>10.0.0.100</from><to>10.0.0.200</to></range>
<staticmap>
<mac>AA:BB:CC:DD:EE:FF</mac>
<ipaddr>10.0.0.50</ipaddr>
<hostname>server1</hostname>
<descr>My server</descr>
</staticmap>
<staticmap>
<mac>11:22:33:44:55:66</mac>
<ipaddr>10.0.0.51</ipaddr>
<hostname>printer</hostname>
</staticmap>
</lan>
</dhcpd>
</pfsense>
"#;
        let mappings = parse_static_mappings(xml);
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(mappings[0].ip, "10.0.0.50");
        assert_eq!(mappings[0].hostname, "server1");
        assert_eq!(mappings[0].description.as_deref(), Some("My server"));
        assert_eq!(mappings[1].hostname, "printer");
        assert!(mappings[1].description.is_none());
    }

    #[test]
    fn test_parse_openvpn_status() {
        let raw = "OpenVPN CLIENT LIST\n\
                    Updated,2026-02-22 10:00:00\n\
                    Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n\
                    user1,1.2.3.4:51234,123456,654321,2026-02-22 09:00:00\n\
                    user2,5.6.7.8:51235,789,987,2026-02-22 09:30:00\n\
                    ROUTING TABLE\n\
                    Virtual Address,Common Name,Real Address,Last Ref\n";
        let clients = parse_openvpn_status(raw);
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].common_name, "user1");
        assert_eq!(clients[0].bytes_received, 123456);
        assert_eq!(clients[1].common_name, "user2");
    }

    #[test]
    fn test_parse_dns_overrides() {
        let xml = r#"
<unbound>
<hosts>
<host>app</host>
<domain>example.com</domain>
<ip>10.0.0.50</ip>
<descr>App server</descr>
</hosts>
<hosts>
<host>db</host>
<domain>example.com</domain>
<ip>10.0.0.51</ip>
</hosts>
</unbound>
"#;
        let overrides = parse_dns_overrides(xml);
        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides[0].host, "app");
        assert_eq!(overrides[0].domain, "example.com");
        assert_eq!(overrides[0].ip, "10.0.0.50");
        assert_eq!(overrides[0].description.as_deref(), Some("App server"));
        assert_eq!(overrides[1].host, "db");
        assert!(overrides[1].description.is_none());
    }

    #[test]
    fn test_validate_mac() {
        assert!(validate_mac("AA:BB:CC:DD:EE:FF").is_ok());
        assert!(validate_mac("aa:bb:cc:dd:ee:ff").is_ok());
        assert!(validate_mac("invalid").is_err());
        assert!(validate_mac("GG:BB:CC:DD:EE:FF").is_err());
    }

    #[test]
    fn test_validate_ip() {
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("not-an-ip").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("my-server").is_ok());
        assert!(validate_hostname("server1").is_ok());
        assert!(validate_hostname("-bad").is_err());
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("home.local").is_ok());
        assert!(validate_domain("").is_err());
    }

    #[test]
    fn test_php_escape() {
        assert_eq!(php_escape("hello"), "hello");
        assert_eq!(php_escape("it's"), "it\\'s");
        assert_eq!(php_escape("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn test_extract_xml_text() {
        let xml = "<interfaces><wan><if>igb0</if></wan><lan><if>igb1</if></lan></interfaces>";
        assert_eq!(
            extract_xml_text(xml, "interfaces", "wan", "if"),
            Some("igb0".to_string())
        );
        assert_eq!(
            extract_xml_text(xml, "interfaces", "lan", "if"),
            Some("igb1".to_string())
        );
    }

    #[test]
    fn test_extract_xml_list() {
        let xml = "<system><dnsserver>1.1.1.1</dnsserver><dnsserver>8.8.8.8</dnsserver></system>";
        let servers = extract_xml_list(xml, "system", "dnsserver");
        assert_eq!(servers, vec!["1.1.1.1", "8.8.8.8"]);
    }
}
