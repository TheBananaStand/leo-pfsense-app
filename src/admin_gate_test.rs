//! Can a non-admin account repoint the network Leo serves DNS for?
//!
//! This is the app-package half of a check that used to live in the hub:
//! `d1c4480096` moved pfSense and Network out of `leo-api` into this
//! out-of-process binary, deleting `network_admin_test.rs` along with the
//! routes it drove — but Leo's own Autopilot verifier still names the old
//! test, which selects nothing under `--exact` and is reported as a pass.
//! See the comment left at the old call site in
//! `crates/leo-api/src/lib.rs`.
//!
//! The rule this guards has not moved: `/dhcp/static`, `/dns/overrides` and
//! their legacy aliases mutate the network Leo's dnsmasq answers for, so a
//! plain account must not reach them. `auth.rs` already enforces it via the
//! `AdminCaller` extractor — this test is what was missing, not the fix.
//!
//! This drives the real [`crate::build_router`] end to end, with the two
//! header shapes the hub actually sends (`x-leo-user-id` /
//! `x-leo-is-admin`). A `403` here can only have come from the extractor's
//! own gate; the admin and read-only cases are the control, so the test
//! would also fail if the routes had simply stopped answering.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::bandwidth::BandwidthMonitor;
use crate::pfsense::PfSenseService;
use crate::{AppState, build_router};

/// A hostname takeover: `leo.aurum.academy` — the hub's own name — aimed at
/// an address the caller controls.
const HIJACK_DNS: &str = r#"{"host":"leo","domain":"aurum.academy","ip":"10.66.66.66"}"#;
const DROP_DNS: &str = r#"{"host":"leo","domain":"aurum.academy"}"#;

/// Every route that rewrites DNS or DHCP, each with a body valid enough to
/// reach the handler — so an admin is stopped by the (unreachable) upstream
/// and not by a deserialization error, which would make the two refusals
/// indistinguishable.
///
/// The legacy aliases are listed separately on purpose: `POST /dns` and
/// `DELETE /dns/delete` are their own route entries, and a gate applied per
/// path rather than per handler would leave them open.
const WRITES: &[(&str, &str, &str)] = &[
    (
        "POST",
        "/dhcp/static",
        r#"{"mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.50","hostname":"impostor"}"#,
    ),
    ("DELETE", "/dhcp/static", r#"{"mac":"aa:bb:cc:dd:ee:ff"}"#),
    ("POST", "/dns/overrides", HIJACK_DNS),
    ("PUT", "/dns/overrides", HIJACK_DNS),
    ("DELETE", "/dns/overrides", DROP_DNS),
    ("POST", "/dns", HIJACK_DNS),
    ("DELETE", "/dns/delete", DROP_DNS),
    ("POST", "/pfsense/php", r#"{"code":"echo 1;"}"#),
];

/// The status pane beside those writes. It must stay open to everyone, or the
/// fix is a package-wide lockout wearing a narrower name.
const READS: &[&str] = &["/status", "/dns/overrides", "/dhcp/static", "/bandwidth"];

async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    body: &str,
    user_id: Option<&str>,
    is_admin: Option<&str>,
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(uid) = user_id {
        req = req.header("x-leo-user-id", uid);
    }
    if let Some(admin) = is_admin {
        req = req.header("x-leo-is-admin", admin);
    }
    let res = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .expect("router call");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn test_router() -> Router {
    // Port 1 on loopback: nothing listens there, so the connect fails fast
    // (immediate ECONNREFUSED) instead of hanging on a black-holed address —
    // this test only needs to reach the SSH layer, never actually talk to it.
    let state = AppState {
        pfsense: std::sync::Arc::new(PfSenseService::new("127.0.0.1", 1, "admin", None, None)),
        monitor: std::sync::Arc::new(BandwidthMonitor::new()),
    };
    build_router(state)
}

/// The body lives here rather than under a bare `#[tokio::test]` so the crate
/// root can expose the test under its own bare name (see `main.rs`) — a name
/// declared inside this module answers to `admin_gate_test::…` under
/// `--exact`, which is exactly the trap the deleted `leo-api` test fell into.
pub(crate) async fn run() {
    let router = test_router();

    for (method, uri, body) in WRITES {
        // 1. A plain account is refused — every route, including the legacy
        //    aliases that reach the same handlers by another name.
        let (status, out) = call(&router, method, uri, body, Some("resident"), Some("0")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} accepted a non-admin caller: {out}"
        );

        // 2. The refusal happens during extraction, before the body is
        //    read — so a non-admin can't even learn the payload shape by
        //    probing for a 422.
        let (status, out) = call(
            &router,
            method,
            uri,
            "}not json{",
            Some("resident"),
            Some("0"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} parsed a non-admin's body before checking who they were: {out}"
        );

        // 3. Same refusal when the hub simply omits the header, which is
        //    what an older hub build does — absence must mean "not admin",
        //    never "unknown, so allow it".
        let (status, out) = call(&router, method, uri, body, Some("resident"), None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} treated a missing x-leo-is-admin header as admin: {out}"
        );

        // 4. No caller identity at all still stops at 401 — authentication
        //    before authorization, so the 403s above aren't hiding a broken
        //    auth layer.
        let (status, out) = call(&router, method, uri, body, None, None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} is reachable with no caller identity: {out}"
        );

        // 5. An admin gets through both gates and into the handler, which
        //    then fails trying to reach the (nonexistent) router. Any
        //    401/403 here would mean the fix closed the endpoint rather
        //    than narrowed it.
        let (status, out) = call(&router, method, uri, body, Some("owner"), Some("1")).await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "{method} {uri} didn't admit an admin — expected the handler's \
             SSH failure, got: {out}"
        );
    }

    // 6. Reading network state is unchanged for a non-admin: they still
    //    reach the handler.
    for uri in READS {
        let (status, out) = call(&router, "GET", uri, "", Some("resident"), Some("0")).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "GET {uri} became admin-only — the writes were meant to move, not the reads: {out}"
        );
    }
}
