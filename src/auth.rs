//! Axum extractor pair for the hub-forwarded identity headers.
//!
//! The hub's reverse proxy injects exactly two headers on every request before
//! forwarding to this subprocess:
//!
//!   X-Leo-User-Id      — the authenticated user's ID (always present)
//!   x-leo-is-admin     — "1" if the user is an admin, "0" if not
//!
//! These headers are never visible to the original caller — the hub strips them
//! from inbound requests and re-adds them from the session. An attacker who
//! could forge them would already have LAN access and an open TCP connection to
//! this port, which is a worse problem than anything they could do through here.
//!
//! The rule on absence: a missing `x-leo-is-admin` header means NOT admin, never
//! unknown-therefore-assume-yes. Older hub builds may not send it; until they do,
//! every write operation requires an explicit "1". Missing `X-Leo-User-Id` is a
//! 401 — the hub guarantees it for every authenticated request, so its absence
//! means the request didn't come through the hub's auth layer.

use axum::extract::FromRequestParts;
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};

/// Any caller the hub has authenticated, regardless of admin status.
#[derive(Debug, Clone)]
pub struct Caller {
    pub user_id: String,
    pub is_admin: bool,
}

/// A caller who is also an admin. Extracting this type rejects with 403 when
/// `x-leo-is-admin` is absent or anything other than "1".
#[derive(Debug, Clone)]
pub struct AdminCaller {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for Caller
where
    S: Send + Sync,
{
    type Rejection = CallerRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user_id = parts
            .headers
            .get("x-leo-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or(CallerRejection::Unauthenticated)?;

        // Absence means "hub didn't say" — treat as non-admin. "1" is the only
        // truthy value; anything else (including "true", "yes", "admin") is not.
        let is_admin = parts
            .headers
            .get("x-leo-is-admin")
            .and_then(|v| v.to_str().ok())
            == Some("1");

        Ok(Caller { user_id, is_admin })
    }
}

impl<S> FromRequestParts<S> for AdminCaller
where
    S: Send + Sync,
{
    type Rejection = CallerRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let caller = Caller::from_request_parts(parts, state).await?;
        if !caller.is_admin {
            return Err(CallerRejection::Forbidden);
        }
        Ok(AdminCaller {
            user_id: caller.user_id,
        })
    }
}

#[derive(Debug)]
pub enum CallerRejection {
    /// `X-Leo-User-Id` was absent — the request didn't come through the hub's
    /// auth layer, or the hub is too old to forward the header.
    Unauthenticated,
    /// The user is authenticated but not an admin.
    Forbidden,
}

impl IntoResponse for CallerRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "not authenticated").into_response(),
            Self::Forbidden => (StatusCode::FORBIDDEN, "admin required").into_response(),
        }
    }
}
