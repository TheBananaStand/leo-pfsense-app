//! Runtime configuration read from environment variables.
//!
//! The hub launches this binary with env vars set from the pfSense package's
//! settings. Nothing is read from disk; there is no config file. This is a
//! deliberate constraint: the hub owns the credential store, and giving this
//! process its own config would create a second source of truth.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// Hostname or IP of the pfSense box. Required — the process exits cleanly
    /// if absent rather than starting and failing on every request.
    pub pfsense_host: String,

    /// SSH port. Defaults to 22 (pfSense's default; most installs leave it there).
    pub pfsense_port: u16,

    /// SSH username. Defaults to "admin" (pfSense's default admin account).
    pub pfsense_username: String,

    /// SSH password. Optional — key-based auth is preferred, but many pfSense
    /// installs use password auth and this binary should support both.
    pub pfsense_password: Option<String>,

    /// Path to an SSH private key. Optional. ~ is expanded to $HOME.
    pub pfsense_key: Option<PathBuf>,

    /// Port this process should listen on. The hub sets this; clients never
    /// talk to us directly, so any free port works. Checked in order:
    /// LEO_APP_PORT, PORT, default 8500.
    pub listen_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        let pfsense_host = std::env::var("PFSENSE_HOST").unwrap_or_else(|_| {
            eprintln!(
                "PFSENSE_HOST is required — set it to the hostname or IP of the pfSense box"
            );
            std::process::exit(1);
        });

        let pfsense_port = std::env::var("PFSENSE_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(22);

        let pfsense_username = std::env::var("PFSENSE_USERNAME")
            .unwrap_or_else(|_| "admin".to_string());

        let pfsense_password = std::env::var("PFSENSE_PASSWORD").ok();

        let pfsense_key = std::env::var("PFSENSE_KEY").ok().map(|p| {
            // Expand a leading ~ to the home directory so the operator can use
            // the familiar "~/.ssh/id_rsa" form without the shell doing it first.
            if p.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(&p[2..]);
                }
            }
            PathBuf::from(p)
        });

        let listen_port = std::env::var("LEO_APP_PORT")
            .or_else(|_| std::env::var("PORT"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8500);

        Self {
            pfsense_host,
            pfsense_port,
            pfsense_username,
            pfsense_password,
            pfsense_key,
            listen_port,
        }
    }
}
