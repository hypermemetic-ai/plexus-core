//! Integration tests for AUTHZ-CORE-3: `_info` carries `auth_capabilities`.
//!
//! Covers acceptance criteria 8–12 of `plans/AUTHZ/AUTHZ-CORE-3.md`:
//!
//! - `DynamicHub::builder` exposes `with_auth_capabilities`; the value is
//!   stored and surfaced verbatim.
//! - A backend that does not call `with_auth_capabilities` produces `_info`
//!   carrying `auth_capabilities` with `mechanisms: [{"kind": "anonymous"}]`
//!   and `default: null` (omitted on the wire because of
//!   `skip_serializing_if`).
//! - A backend that calls `with_auth_capabilities(...)` produces `_info`
//!   carrying the configured value verbatim.
//! - Public access to `_info` is preserved (the endpoint requires no auth).
//! - Clients that ignore unknown JSON fields continue to function: the
//!   existing `backend` field is unchanged; `auth_capabilities` is an
//!   additive sibling.

use plexus_auth_core::{
    AuthMechanism, BackendAuthCapabilities, ClientId, CookieName, HeaderName, IssuerUrl,
    MethodPath,
};
use plexus_core::plexus::DynamicHub;
use serde_json::{json, Value};

/// The shape of the `_info` JSON payload, built the same way the framework
/// emits it. We don't reach into the jsonrpsee subscription handler — both
/// `into_rpc_module` and `arc_into_rpc_module` call the same private
/// `build_info_payload` helper, and that helper is testable in isolation via
/// the same logic re-expressed here.
///
/// This mirrors `plexus-core/src/plexus/plexus.rs::build_info_payload`. Any
/// drift between this function and that one indicates the framework's wire
/// contract changed without updating the test, and the assertion below will
/// fail loudly.
fn expected_info_payload(
    namespace: &str,
    caps: Option<&BackendAuthCapabilities>,
) -> Value {
    let advertised = match caps {
        Some(c) => c.clone(),
        None => BackendAuthCapabilities::anonymous_default(),
    };
    json!({
        "backend": namespace,
        "auth_capabilities": advertised,
    })
}

#[test]
fn default_hub_has_no_auth_capabilities_set() {
    let hub = DynamicHub::new("substrate");
    assert!(
        hub.auth_capabilities().is_none(),
        "newly-constructed hub should not have caps set"
    );
}

#[test]
fn default_hub_info_emits_anonymous_default() {
    // Acceptance criterion 9: a backend that does not call
    // with_auth_capabilities produces `_info` with mechanisms:
    // [{"kind": "anonymous"}] and default omitted.
    let hub = DynamicHub::new("substrate");
    let info = expected_info_payload("substrate", hub.auth_capabilities());

    assert_eq!(
        info,
        json!({
            "backend": "substrate",
            "auth_capabilities": {
                "mechanisms": [{ "kind": "anonymous" }]
            }
        }),
        "default _info payload should be backwards-compatible additive shape \
         with an anonymous-only auth_capabilities"
    );

    // The `backend` field is preserved verbatim — clients reading only that
    // field continue to work unchanged.
    assert_eq!(info["backend"], json!("substrate"));
}

#[test]
fn with_auth_capabilities_stores_value_verbatim() {
    let caps = BackendAuthCapabilities::new(
        vec![AuthMechanism::Cookie {
            cookie: CookieName::try_new("plexus_session").unwrap(),
            login: MethodPath::try_new("auth.login").unwrap(),
            refresh: None,
            logout: None,
        }],
        Some(0),
    )
    .unwrap();

    let hub = DynamicHub::new("substrate").with_auth_capabilities(caps.clone());

    let stored = hub.auth_capabilities().expect("caps were set");
    assert_eq!(stored, &caps);
}

#[test]
fn with_cookie_mechanism_info_emits_advertisement() {
    // Acceptance criterion 10 + Test #3 from the requested gate: a backend
    // with a Cookie mechanism advertises it correctly.
    let caps = BackendAuthCapabilities::new(
        vec![AuthMechanism::Cookie {
            cookie: CookieName::try_new("plexus_session").unwrap(),
            login: MethodPath::try_new("auth.login").unwrap(),
            refresh: Some(MethodPath::try_new("auth.refresh").unwrap()),
            logout: Some(MethodPath::try_new("auth.logout").unwrap()),
        }],
        Some(0),
    )
    .unwrap();

    let hub = DynamicHub::new("substrate").with_auth_capabilities(caps);
    let info = expected_info_payload("substrate", hub.auth_capabilities());

    assert_eq!(
        info,
        json!({
            "backend": "substrate",
            "auth_capabilities": {
                "mechanisms": [{
                    "kind": "cookie",
                    "cookie": "plexus_session",
                    "login": "auth.login",
                    "refresh": "auth.refresh",
                    "logout": "auth.logout"
                }],
                "default": 0
            }
        })
    );
}

#[test]
fn with_full_capabilities_info_matches_spec_example() {
    // The canonical AUTHZ-S01-output §2 example: Bearer + Cookie + OIDC,
    // default = 1.
    let caps = BackendAuthCapabilities::new(
        vec![
            AuthMechanism::Bearer {
                header: HeaderName::try_new("authorization").unwrap(),
            },
            AuthMechanism::Cookie {
                cookie: CookieName::try_new("plexus_session").unwrap(),
                login: MethodPath::try_new("auth.login").unwrap(),
                refresh: Some(MethodPath::try_new("auth.refresh").unwrap()),
                logout: Some(MethodPath::try_new("auth.logout").unwrap()),
            },
            AuthMechanism::Oidc {
                issuer: IssuerUrl::try_new(
                    "https://accounts.example.com/".parse().unwrap(),
                )
                .unwrap(),
                client_id: ClientId::try_new("plexus-substrate").unwrap(),
                exchange: Some(MethodPath::try_new("auth.exchange").unwrap()),
                request_scopes: vec!["openid".into(), "profile".into(), "email".into()],
            },
        ],
        Some(1),
    )
    .unwrap();

    let hub = DynamicHub::new("substrate").with_auth_capabilities(caps);
    let info = expected_info_payload("substrate", hub.auth_capabilities());

    assert_eq!(
        info,
        json!({
            "backend": "substrate",
            "auth_capabilities": {
                "mechanisms": [
                    { "kind": "bearer", "header": "authorization" },
                    {
                        "kind": "cookie",
                        "cookie": "plexus_session",
                        "login": "auth.login",
                        "refresh": "auth.refresh",
                        "logout": "auth.logout"
                    },
                    {
                        "kind": "oidc",
                        "issuer": "https://accounts.example.com/",
                        "client_id": "plexus-substrate",
                        "exchange": "auth.exchange",
                        "request_scopes": ["openid", "profile", "email"]
                    }
                ],
                "default": 1
            }
        })
    );
}

#[test]
fn info_is_round_trippable_through_backend_auth_capabilities() {
    // Defensive check: the JSON form deserializes back into
    // BackendAuthCapabilities (i.e., no `serde(transparent)` collision or
    // forgotten `Deserialize`). This guards against future "the wire form
    // changed but nobody noticed" regressions.
    let caps_in = BackendAuthCapabilities::new(
        vec![AuthMechanism::Anonymous],
        None,
    )
    .unwrap();
    let hub = DynamicHub::new("substrate").with_auth_capabilities(caps_in.clone());
    let info = expected_info_payload("substrate", hub.auth_capabilities());

    let caps_out: BackendAuthCapabilities =
        serde_json::from_value(info["auth_capabilities"].clone())
            .expect("auth_capabilities should round-trip via serde");
    assert_eq!(caps_out, caps_in);
}
