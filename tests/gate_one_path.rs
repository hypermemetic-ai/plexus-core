//! A call is decided on the path it is routed by, and `auth.grant` /
//! `auth.revoke` hold their own scope check whatever routed them.
//!
//! A gated service with the `auth` activation and the reference in-memory
//! stores; callers: an admin of one scope, a session capped to one scope, a
//! viewer everywhere, and the admin of everything. Every spelling a caller
//! can send for a method is one call: decided and routed alike.

use std::sync::Arc;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{
    with_reach, AuthContext, AuthSetup, ChildRouter, Gate, Grant, MemoryAuthBackend, MemoryMemberships, MemoryRoles,
    PlexusStream, PlexusStreamItem, Reach, Resolve, ScopeRef,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::{json, Value};

#[derive(Clone)]
struct TicketsActivation;

#[plexus_macros::activation(
    version = "0.1.0",
    description = "Tickets",
    roles(viewer = ["get", "list"]),
)]
impl TicketsActivation {
    /// One ticket by id.
    #[plexus_macros::method(target = "id", description = "One ticket by id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// Where the caller holds `tickets.list`.
    #[plexus_macros::method(description = "Where the caller reads")]
    async fn list(&self, reach: Reach) -> impl Stream<Item = String> + Send + 'static {
        let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        stream! { yield held.join(","); }
    }
}

/// `CODE-n` → `[CODE-n, CODE, *]`; `CODE` → `[CODE, *]`; anything else: no scope.
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return None;
        }
        let mut chain = Vec::new();
        if target.contains('-') {
            chain.push(ScopeRef::named(target));
        }
        chain.push(ScopeRef::named(code));
        chain.push(ScopeRef::Everywhere);
        Some(chain)
    }
}

const KILN_ADMIN: &str = "key:4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";
const ADMIN: &str = "key:adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad";
const VIEWER: &str = "key:7676767676767676767676767676767676767676767676767676767676767676";
const TARGET: &str = "key:7474747474747474747474747474747474747474747474747474747474747474";

struct World {
    hub: Arc<DynamicHub>,
    members: Arc<MemoryMemberships>,
    gate: Gate,
}

fn world() -> World {
    let roles = Arc::new(MemoryRoles::default());
    let members = Arc::new(
        MemoryMemberships::new()
            .with(KILN_ADMIN, "admin", "KILN")
            .with(ADMIN, "admin", "*")
            .with(VIEWER, "viewer", "*"),
    );
    let hub = DynamicHub::new("svc")
        .register(TicketsActivation)
        .with_auth(AuthSetup::new(Arc::new(MemoryAuthBackend::new("http://x/login")), roles.clone(), members.clone(), Arc::new(Shortcodes)));
    roles.seed(&hub.declared_roles());
    // A gate over the same stores, to make the reaches a route would hand.
    let gate = Gate::new(members.clone(), roles, Arc::new(Shortcodes));
    World { hub: Arc::new(hub), members, gate }
}

fn who(p: &str, ceiling: Option<&[&str]>) -> AuthContext {
    let meta = ceiling.map_or(json!({}), |c| json!({ "ceiling": c }));
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], meta)
}

/// The callers who hold `admin` somewhere short of `*`.
fn scoped() -> Vec<(&'static str, AuthContext)> {
    vec![("admin of KILN", who(KILN_ADMIN, None)), ("admin capped admin@KILN", who(ADMIN, Some(&["admin@KILN"])))]
}

async fn items(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
                PlexusStreamItem::Error { message, .. } => Some(json!({ "type": "error", "message": message })),
                _ => None,
            }
        })
        .collect()
        .await
}

async fn call(w: &World, method: &str, params: Value, ctx: &AuthContext) -> Result<Vec<Value>, PlexusError> {
    match w.hub.route(method, params, Some(ctx)).await {
        Ok(s) => Ok(items(s).await),
        Err(e) => Err(e),
    }
}

fn granted(answer: &Result<Vec<Value>, PlexusError>) -> bool {
    matches!(answer, Ok(items) if items.iter().any(|i| i["type"] == "granted" || i["type"] == "revoked" && !i["roles"].as_array().is_some_and(Vec::is_empty)))
}

fn holds_everywhere(w: &World, principal: &str) -> bool {
    w.members.all().iter().any(|m| m.principal.to_string() == principal && m.scope.is_everywhere())
}

/// Every spelling of `method` a caller can send.
fn spellings(method: &str) -> Vec<String> {
    vec![
        method.to_string(),
        format!("svc.{method}"),
        format!("svc.svc.{method}"),
        format!("svc.call.{method}"),
        format!("svc.{method}.schema"),
    ]
}

#[tokio::test]
async fn an_admin_of_one_scope_never_grants_beyond_it_by_any_spelling() {
    let w = world();
    for (name, ctx) in scoped() {
        for path in spellings("auth.grant") {
            for scope in ["*", " *", "ACME"] {
                let answer = call(&w, &path, json!({ "principal": TARGET, "role": "admin", "scope": scope }), &ctx).await;
                assert!(!granted(&answer), "{name} {path} on {scope:?}: {answer:?}");
            }
            assert!(!holds_everywhere(&w, TARGET), "{name} {path}");
        }
        for path in spellings("auth.revoke") {
            let answer = call(&w, &path, json!({ "principal": ADMIN, "scope": "*" }), &ctx).await;
            assert!(!granted(&answer), "{name} {path}: {answer:?}");
            assert!(holds_everywhere(&w, ADMIN), "{name} {path}: nothing was taken");
        }
    }
}

#[tokio::test]
async fn a_rightful_grant_inside_the_scope_still_works_by_either_form() {
    let w = world();
    for (name, ctx) in scoped() {
        for path in ["auth.grant", "svc.auth.grant"] {
            let answer = call(&w, path, json!({ "principal": TARGET, "role": "viewer", "scope": "KILN-3" }), &ctx).await;
            assert!(granted(&answer), "{name} {path}: {answer:?}");
            let answer = call(&w, path.replace("grant", "revoke").as_str(), json!({ "principal": TARGET, "scope": "KILN-3" }), &ctx).await;
            assert!(granted(&answer), "{name} {path}: {answer:?}");
        }
    }
    // The admin of everything grants on `*`, as before.
    let answer = call(&w, "auth.grant", json!({ "principal": TARGET, "role": "admin", "scope": "*" }), &who(ADMIN, None)).await;
    assert!(granted(&answer) && holds_everywhere(&w, TARGET), "{answer:?}");
}

/// A whole-service method of the platform, by every spelling.
#[tokio::test]
async fn whole_service_auth_methods_want_everywhere_by_any_spelling() {
    let w = world();
    for (name, ctx) in scoped() {
        for method in ["auth.role_set", "auth.waiting"] {
            // (`<method>.schema` answers the method's schema: introspection.)
            for path in spellings(method).into_iter().filter(|p| !p.ends_with(".schema")) {
                let answer = call(&w, &path, json!({ "role": "viewer", "grants": ["tickets.get", "tickets.list", "auth.grant"] }), &ctx).await;
                let refused = match &answer {
                    Err(_) => true,
                    Ok(items) => items.iter().any(|i| i["type"] == "error") && !items.iter().any(|i| i["type"] == "role"),
                };
                assert!(refused, "{name} {path}: {answer:?}");
            }
        }
    }
}

/// A path no schema describes is decided on `*` alone: the admin of one
/// scope, a capped session and a viewer are refused before routing; the
/// admin of everything is routed (and finds nothing there).
#[tokio::test]
async fn a_path_no_schema_describes_is_held_on_everywhere_alone() {
    let w = world();
    for path in ["tickets.nothing", "svc.tickets.nothing.here", "svc.call.auth.grant", "svc.svc.auth.grant"] {
        for (name, ctx) in scoped().into_iter().chain([("viewer", who(VIEWER, None))]) {
            let answer = call(&w, path, json!({}), &ctx).await;
            assert!(matches!(answer, Err(PlexusError::Forbidden { .. })), "{name} {path}: {answer:?}");
        }
        let answer = call(&w, path, json!({}), &who(ADMIN, None)).await;
        assert!(!matches!(answer, Err(PlexusError::Forbidden { .. })), "admin {path}: {answer:?}");
    }
}

/// The service's own-namespace form is the bare form: the same answer for
/// the same caller, introspection included; the service's own methods stay.
#[tokio::test]
async fn the_prefixed_form_is_the_bare_form() {
    let w = world();
    for ctx in [who(KILN_ADMIN, None), who(VIEWER, None), who(ADMIN, Some(&["admin@KILN"]))] {
        for (bare, prefixed, params) in [
            ("tickets.list", "svc.tickets.list", json!({})),
            ("tickets.get", "svc.tickets.get", json!({ "id": "KILN-1" })),
            ("tickets.get", "svc.tickets.get", json!({ "id": "ACME-1" })),
            ("tickets.schema", "svc.tickets.schema", json!({})),
            ("tickets.get.schema", "svc.tickets.get.schema", json!({})),
            ("auth.whoami", "svc.auth.whoami", json!({})),
        ] {
            let a = call(&w, bare, params.clone(), &ctx).await.map_err(|e| e.to_string());
            let b = call(&w, prefixed, params, &ctx).await.map_err(|e| e.to_string());
            assert_eq!(a, b, "{bare} / {prefixed}");
        }
        for own in ["svc.schema", "svc.hash", "svc.hashes"] {
            assert!(call(&w, own, json!({}), &ctx).await.is_ok(), "{own}");
        }
    }
}

/// Reached with no gate in front of it (a route that skips the gate), or
/// with a reach for any other grant, `auth.grant` checks for itself: the
/// reach is its own, and the caller holds it on the scope written.
#[tokio::test]
async fn auth_grant_checks_its_own_scope_whatever_routed_it() {
    let w = world();
    let auth = w.hub.get_child("auth").await.expect("auth is mounted");
    let run = |ctx: AuthContext, reach: Option<Reach>, method: &'static str, params: Value| {
        let auth = &auth;
        async move {
            let call = async { items(auth.router_call(method, params, Some(&ctx), None).await.expect("dispatched")).await };
            match reach {
                Some(r) => with_reach(r, call).await,
                None => call.await,
            }
        }
    };
    let everything = json!({ "principal": TARGET, "role": "admin", "scope": "*" });
    let kiln = who(KILN_ADMIN, None);
    // No reach at all: refused, even for the admin of everything.
    let said = run(who(ADMIN, None), None, "grant", everything.clone()).await;
    assert_eq!(said[0]["error_kind"], "forbidden", "{said:?}");
    // A reach for another grant, held where the caller holds it.
    for other in ["svc.auth.grant", "auth.revoke", "tickets.list"] {
        let reach = w.gate.check(Some(&kiln), &Grant::new(other), None).unwrap();
        let said = run(kiln.clone(), Some(reach), "grant", everything.clone()).await;
        assert_eq!(said[0]["error_kind"], "forbidden", "{other}: {said:?}");
    }
    // Its own reach, on KILN: `*` refused, KILN granted.
    let reach = w.gate.check(Some(&kiln), &Grant::new("auth.grant"), Some("KILN")).unwrap();
    let said = run(kiln.clone(), Some(reach.clone()), "grant", everything.clone()).await;
    assert_eq!(said[0]["error_kind"], "forbidden", "{said:?}");
    assert!(!holds_everywhere(&w, TARGET));
    let said = run(kiln.clone(), Some(reach), "grant", json!({ "principal": TARGET, "role": "viewer", "scope": "KILN" })).await;
    assert_eq!(said[0]["type"], "granted", "{said:?}");
    // revoke: the same rule.
    let reach = w.gate.check(Some(&kiln), &Grant::new("auth.revoke"), Some("KILN")).unwrap();
    let said = run(kiln.clone(), Some(reach), "revoke", json!({ "principal": ADMIN, "scope": "*" })).await;
    assert_eq!(said[0]["error_kind"], "forbidden", "{said:?}");
    assert!(holds_everywhere(&w, ADMIN));
    // A capped session, with the reach the gate gives it on KILN.
    let capped = who(ADMIN, Some(&["admin@KILN"]));
    let reach = w.gate.check(Some(&capped), &Grant::new("auth.grant"), Some("KILN")).unwrap();
    let said = run(capped, Some(reach), "grant", everything).await;
    assert_eq!(said[0]["error_kind"], "forbidden", "{said:?}");
    assert!(!holds_everywhere(&w, TARGET));
}
