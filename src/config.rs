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

/// A setting handed down by the hub, or the same name shouted for a hand run.
///
/// The hub passes entitled settings to a subprocess as environment variables
/// named by the settings key **verbatim** — `resolve_secrets` inserts
/// `key.clone()` — so what actually arrives is `pfsense_host`, lowercase. Env
/// var names are case-sensitive on Linux, so reading only `PFSENSE_HOST` finds
/// nothing: the package installs, builds, launches and exits one line later
/// complaining that a setting the owner definitely filled in is missing.
///
/// The uppercase form is the fallback rather than the primary, for running this
/// by hand outside the hub, where shouting is the convention.
fn setting(key: &str) -> Option<String> {
    std::env::var(key)
        .or_else(|_| std::env::var(key.to_ascii_uppercase()))
        .ok()
        .filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Self {
        let pfsense_host = setting("pfsense_host").unwrap_or_else(|| {
            eprintln!(
                "pfsense_host is required — set it to the hostname or IP of the pfSense box. \
                 The hub supplies it from the package's entitled settings; if this is a hand \
                 run, export pfsense_host or PFSENSE_HOST."
            );
            std::process::exit(1);
        });

        let pfsense_port = setting("pfsense_port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(22);

        let pfsense_username = setting("pfsense_username").unwrap_or_else(|| "admin".to_string());

        let pfsense_password = setting("pfsense_password");

        let pfsense_key = setting("pfsense_key").map(|p| {
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

#[cfg(test)]
mod tests {
    use super::setting;

    /// The bug this guards is silent and total: the hub sends `pfsense_host`
    /// and a package reading `PFSENSE_HOST` finds nothing, so it installs,
    /// builds, launches and exits one line later insisting a setting the owner
    /// filled in is missing. Env var names are case-sensitive on Linux.
    #[test]
    fn a_setting_is_read_under_the_name_the_hub_actually_sends() {
        // SAFETY: single-threaded test, and the keys are unique to it.
        unsafe {
            std::env::set_var("pfsense_probe_lower", "from-hub");
            std::env::set_var("PFSENSE_PROBE_UPPER", "from-hand");
            std::env::set_var("pfsense_probe_empty", "");
        }
        assert_eq!(setting("pfsense_probe_lower").as_deref(), Some("from-hub"));
        assert_eq!(
            setting("pfsense_probe_upper").as_deref(),
            Some("from-hand"),
            "the shouted form must still work for a hand run"
        );
        assert_eq!(
            setting("pfsense_probe_empty"),
            None,
            "an empty value is not a value — the hub omits keys with no value, \
             and a blank host would fail far later than it needs to"
        );
        assert_eq!(setting("pfsense_probe_absent"), None);
    }
}
