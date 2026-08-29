//! Local error type, mirroring the LeoError variants that pfsense.rs constructs.
//!
//! The hub's `LeoError` is a much larger enum covering DB failures, auth, chat,
//! and dozens of other concerns this binary will never have. We mirror only the
//! three variants pfsense.rs actually constructs — `Ssh`, `Auth`, `Validation`,
//! and `Other` — so the rest of the file compiles without the entire leo-core
//! dependency tree.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum Error {
    /// SSH transport failure: the box didn't answer, the channel didn't open,
    /// or a command couldn't be sent. Often transient — the firewall may come
    /// back on its own.
    Ssh(String),

    /// SSH authentication failed with credentials that reached the server.
    /// Distinct from Ssh because the owner needs to rotate the key or password;
    /// waiting won't help.
    Auth(String),

    /// The caller supplied input that failed validation (MAC address, IP,
    /// hostname, domain). A 400: the server is fine, the input is wrong.
    Validation(String),

    /// Anything that doesn't fit the above: unexpected PHP output, JSON parse
    /// failures inside the pfSense response, etc.
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssh(msg) => write!(f, "SSH error: {msg}"),
            Self::Auth(msg) => write!(f, "Auth error: {msg}"),
            Self::Validation(msg) => write!(f, "Validation error: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            // Validation errors are the caller's fault.
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            // Auth failures are worth distinguishing from transport failures:
            // a 401 here means "the app's credentials are wrong", not "the
            // caller's session expired" (the hub already handles that).
            Self::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            // SSH and unknown failures are upstream problems, not client errors.
            Self::Ssh(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Self::Other(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
        };
        (status, message).into_response()
    }
}
