//! CA-1 — `site_hint` gets a sender (trak facet
//! `ccc924ad-0e78-4d4b-b71f-0018d249d0bf`).
//!
//! Backends emit where credentials attach: at schema-assembly time the
//! [`DynamicHub`] fills `requires_credential.site_hint` on every method
//! schema leaving the hub, deriving the site from the backend's advertised
//! auth capabilities (`with_auth_capabilities` — AUTHZ-CORE-3). Service
//! authors write nothing new; AUTHZ-CRED-CORE-3's "no explicit per-method
//! requires_credential blob" call stands.
//!
//! Derivation table (`AuthMechanism::implied_attachment_site`):
//!
//! | Advertised mechanism | Derived site                      |
//! |----------------------|-----------------------------------|
//! | `Bearer { header }`  | `header:<header>`                 |
//! | `Cookie { cookie }`  | `cookie:<cookie>`                 |
//! | `Oidc { .. }`        | `header:authorization` (bearer)   |
//! | `Anonymous`          | none                              |
//!
//! Back-compat pinned both ways:
//! - capabilities that imply a site → `site_hint` populated on the wire;
//! - no capabilities (or anonymous-only) → `site_hint` stays absent,
//!   byte-identical to pre-CA-1 emissions.

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_auth_core::{
    AuthMechanism, BackendAuthCapabilities, CookieName, HeaderName, MethodPath,
};
use plexus_core::plexus::DynamicHub;
use plexus_core::plexus::types::PlexusStreamItem;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Fixture activation: one scoped method, one public, one unannotated.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Vault;

#[plexus_macros::activation(
    namespace = "vault",
    version = "1.0.0",
    description = "CA-1 site-hint fixture",
    crate_path = "plexus_core"
)]
impl Vault {
    /// Scope-gated — carries a `requires_credential` with no macro-set
    /// site_hint (`from_method_scope` constructs `None`).
    #[plexus_macros::method(scope = "vault.write")]
    async fn write(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "wrote".to_string(); }
    }

    /// Explicitly public — never carries a requirement.
    #[plexus_macros::method(public)]
    async fn ping(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "pong".to_string(); }
    }

    /// Unannotated — no requirement either.
    #[plexus_macros::method]
    async fn plain(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "plain".to_string(); }
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn bearer_caps() -> BackendAuthCapabilities {
    BackendAuthCapabilities::new(
        vec![AuthMechanism::Bearer {
            header: HeaderName::try_new("authorization").unwrap(),
        }],
        Some(0),
    )
    .unwrap()
}

fn cookie_caps() -> BackendAuthCapabilities {
    BackendAuthCapabilities::new(
        vec![AuthMechanism::Cookie {
            cookie: CookieName::try_new("access_token").unwrap(),
            login: MethodPath::try_new("auth.login").unwrap(),
            refresh: None,
            logout: None,
        }],
        Some(0),
    )
    .unwrap()
}

fn hub_with(caps: Option<BackendAuthCapabilities>) -> DynamicHub {
    let hub = DynamicHub::new("testhub").register(Vault);
    match caps {
        Some(caps) => hub.with_auth_capabilities(caps),
        None => hub,
    }
}

/// Route a schema query through the hub and return the (single) schema
/// payload from the response stream.
async fn fetch_schema_json(hub: &DynamicHub, method: &str, params: Value) -> Value {
    let stream = hub
        .route(method, params, None)
        .await
        .unwrap_or_else(|e| panic!("{method} must dispatch: {e}"));
    let items: Vec<PlexusStreamItem> = stream.collect().await;
    items
        .iter()
        .find_map(|item| match item {
            PlexusStreamItem::Data {
                content_type,
                content,
                ..
            } if content_type.ends_with(".schema")
                || content_type.ends_with(".method_schema") =>
            {
                Some(content.clone())
            }
            _ => None,
        })
        .expect("schema query must yield a schema Data item")
}

/// Find a method object by name within a plugin-schema JSON payload.
fn method_json<'a>(plugin: &'a Value, name: &str) -> &'a Value {
    plugin["methods"]
        .as_array()
        .expect("plugin schema carries methods")
        .iter()
        .find(|m| m["name"] == name)
        .unwrap_or_else(|| panic!("method {name} present in schema"))
}

// ---------------------------------------------------------------------------
// 1. Capabilities imply a site → site_hint populated on the wire.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bearer_caps_fill_site_hint_on_routed_activation_schema() {
    let hub = hub_with(Some(bearer_caps()));
    let plugin = fetch_schema_json(&hub, "vault.schema", serde_json::json!({})).await;

    let write = method_json(&plugin, "write");
    assert_eq!(
        write["requires_credential"]["site_hint"],
        serde_json::json!({ "site": "header", "name": "authorization" }),
        "bearer capability must derive header:authorization onto the gated method"
    );
    // Scopes are untouched by the fill.
    assert_eq!(
        write["requires_credential"]["scopes"],
        serde_json::json!(["vault.write"])
    );

    // Derivation never CREATES a requirement: public + unannotated methods
    // keep their pre-CA-1 wire shape.
    for name in ["ping", "plain"] {
        assert!(
            method_json(&plugin, name).get("requires_credential").is_none(),
            "{name} must not grow a requires_credential from the fill"
        );
    }
}

#[tokio::test]
async fn cookie_caps_derive_cookie_site() {
    let hub = hub_with(Some(cookie_caps()));
    let plugin = fetch_schema_json(&hub, "vault.schema", serde_json::json!({})).await;

    assert_eq!(
        method_json(&plugin, "write")["requires_credential"]["site_hint"],
        serde_json::json!({ "site": "cookie", "name": "access_token" }),
    );
}

#[tokio::test]
async fn method_query_fills_single_method_schema() {
    // The `{"method": "..."}` query path returns SchemaResult::Method —
    // the fill applies there too.
    let hub = hub_with(Some(bearer_caps()));
    let method = fetch_schema_json(
        &hub,
        "vault.schema",
        serde_json::json!({ "method": "write" }),
    )
    .await;

    assert_eq!(method["name"], "write");
    assert_eq!(
        method["requires_credential"]["site_hint"],
        serde_json::json!({ "site": "header", "name": "authorization" }),
    );
}

// ---------------------------------------------------------------------------
// 2. Back-compat: absent capabilities → wire byte-identical to pre-CA-1.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_caps_leave_site_hint_absent() {
    let hub = hub_with(None);
    let plugin = fetch_schema_json(&hub, "vault.schema", serde_json::json!({})).await;

    let req = &method_json(&plugin, "write")["requires_credential"];
    assert_eq!(req["scopes"], serde_json::json!(["vault.write"]));
    assert!(
        req.get("site_hint").is_none(),
        "no advertised capabilities → site_hint key must stay off the wire"
    );
}

#[tokio::test]
async fn anonymous_only_caps_leave_site_hint_absent() {
    let hub = hub_with(Some(BackendAuthCapabilities::anonymous_default()));
    let plugin = fetch_schema_json(&hub, "vault.schema", serde_json::json!({})).await;

    assert!(
        method_json(&plugin, "write")["requires_credential"]
            .get("site_hint")
            .is_none(),
        "anonymous-only capabilities imply no site → site_hint stays absent"
    );
}

// ---------------------------------------------------------------------------
// 3. Non-schema dispatch is untouched by the interception.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_schema_dispatch_passes_through() {
    let hub = hub_with(Some(bearer_caps()));
    let stream = hub
        .route("vault.plain", serde_json::json!({}), None)
        .await
        .expect("plain dispatch works");
    let items: Vec<PlexusStreamItem> = stream.collect().await;
    let data: Vec<&Value> = items
        .iter()
        .filter_map(|i| match i {
            PlexusStreamItem::Data { content, .. } => Some(content),
            _ => None,
        })
        .collect();
    assert_eq!(data, vec![&serde_json::json!("plain")]);
}
