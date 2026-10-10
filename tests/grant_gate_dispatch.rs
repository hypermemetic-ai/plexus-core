//! AUTH-2 — the grant gate in [`DynamicHub`] dispatch, end to end: a small
//! activation declaring `target` and `roles(...)` (AUTH-3), a fake service
//! (memberships, roles from the schema's defaults, a shortcode resolver),
//! and calls through `route` showing allow, deny, the reach a method
//! receives, and the refusal as it goes on the wire.

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{
    error_item, AuthContext, ForbiddenItem, Gate, Membership, Memberships, PlexusStream, PlexusStreamItem,
    Reach, Resolve, RoleTable, ScopeRef,
};
use plexus_core::{AuthzDenyReason, DynamicHub, PlexusError};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Tickets;

#[plexus_macros::activation(
    namespace = "tickets",
    version = "1.0.0",
    description = "AUTH-2 gate fixture",
    crate_path = "plexus_core",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl Tickets {
    /// One ticket.
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield id; }
    }

    /// Every ticket the caller reaches: the reach, as the method sees it.
    #[plexus_macros::method]
    async fn list(&self, reach: Reach) -> impl Stream<Item = String> + Send + 'static {
        let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        stream! { yield held.join(","); }
    }

    /// A stream that re-asks the gate per event (IDENTITY-37): each id it
    /// would emit is checked against the reach as it stands.
    #[plexus_macros::method(streaming)]
    async fn watch(&self, reach: Reach, ids: Vec<String>) -> impl Stream<Item = String> + Send + 'static {
        stream! {
            for id in ids {
                if reach.allows(&id) { yield id; }
            }
        }
    }

    /// Change a ticket's status.
    #[plexus_macros::method(target = "id")]
    async fn set_status(&self, auth: &AuthContext, id: String, status: String) -> impl Stream<Item = String> + Send + 'static {
        let who = auth.user_id.clone();
        stream! { yield format!("{who}: {id} -> {status}"); }
    }

    /// Close several tickets — a list target, each element checked.
    #[plexus_macros::method(target = "ids")]
    async fn close(&self, ids: Vec<String>) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield ids.join(","); }
    }

    /// The door: anyone.
    #[plexus_macros::method(public)]
    async fn providers(&self, reach: Reach) -> impl Stream<Item = String> + Send + 'static {
        let empty = reach.is_empty();
        stream! { yield format!("key empty={empty}"); }
    }
}

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Default)]
struct Members(Mutex<Vec<Membership>>);
impl Members {
    fn add(&self, who: &str, role: &str, scope: &str) {
        self.0.lock().unwrap().push(Membership {
            principal: who.parse().unwrap(),
            role: plexus_auth_core::RoleName::new(role),
            scope: ScopeRef::parse(scope),
        });
    }
    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}
impl Memberships for Members {
    fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
        self.0.lock().unwrap().iter().filter(|m| &m.principal == who).cloned().collect()
    }
}

/// `CODE-n` → `[CODE, *]`; a bare shortcode → `[CODE, *]`.
struct Shortcodes;
impl Resolve for Shortcodes {
    fn chain(&self, target: &str) -> Option<Vec<ScopeRef>> {
        let code = target.split_once('-').map(|(c, _)| c).unwrap_or(target);
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return None;
        }
        Some(vec![ScopeRef::named(code), ScopeRef::Everywhere])
    }
}

fn hub(members: &Arc<Members>) -> DynamicHub {
    // Roles seeded from the activation's declared defaults.
    let declared = DynamicHub::new("menger").register(Tickets).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let gate = Gate::new(members.clone(), Arc::new(roles), Arc::new(Shortcodes));
    DynamicHub::new("menger").register(Tickets).with_gate(Arc::new(gate))
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], serde_json::Value::Null)
}

async fn data(stream: PlexusStream) -> Vec<serde_json::Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content),
                _ => None,
            }
        })
        .collect()
        .await
}

/// `<ns>.call`'s params object.
fn call(method: &str, params: serde_json::Value) -> jsonrpsee::core::params::ObjectParams {
    let mut p = jsonrpsee::core::params::ObjectParams::new();
    p.insert("method", method).unwrap();
    p.insert("params", params).unwrap();
    p
}

fn members() -> Arc<Members> {
    let m = Arc::new(Members::default());
    m.add(ADA, "editor", "MENGER");
    m.add(BOB, "viewer", "*");
    m.add(ROOT, "admin", "*");
    m
}

#[tokio::test]
async fn a_hub_without_a_gate_dispatches_as_before() {
    let hub = DynamicHub::new("menger").register(Tickets);
    let out = data(hub.route("tickets.set_status", serde_json::json!({"id": "X-1", "status": "Ready"}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(out, vec![serde_json::json!(format!("{}: X-1 -> Ready", who(ADA).user_id))]);
    // Anonymous, too — and `reach` is everywhere.
    let out = data(hub.route("tickets.list", serde_json::json!({}), None).await.unwrap()).await;
    assert_eq!(out, vec![serde_json::json!("*")]);
}

#[tokio::test]
async fn held_on_menger_allows_a_menger_target_not_an_identity_one() {
    let m = members();
    let hub = hub(&m);
    let ok = hub.route("tickets.set_status", serde_json::json!({"id": "MENGER-12", "status": "Ready"}), Some(&who(ADA))).await;
    assert!(ok.is_ok());
    let err = hub
        .route("tickets.set_status", serde_json::json!({"id": "IDENTITY-1", "status": "Ready"}), Some(&who(ADA)))
        .await
        .err()
        .unwrap();
    match &err {
        PlexusError::Forbidden { reason: AuthzDenyReason::MissingGrant { grant, scope, roles, held_on } } => {
            assert_eq!(grant.as_str(), "tickets.set_status");
            assert_eq!(scope, &ScopeRef::named("IDENTITY"));
            assert_eq!(roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(), vec!["editor", "admin"]);
            assert_eq!(held_on, &vec![ScopeRef::named("MENGER")]);
        }
        other => panic!("expected MissingGrant, got {other:?}"),
    }
    assert_eq!(err.to_string(), "needs tickets.set_status on IDENTITY");
}

#[tokio::test]
async fn the_refusal_on_the_wire() {
    let m = members();
    let hub = hub(&m);
    let err = hub
        .route("tickets.set_status", serde_json::json!({"id": "IDENTITY-1", "status": "Ready"}), Some(&who(ADA)))
        .await
        .err()
        .unwrap();
    let mut item = error_item("menger", &err);
    item.as_object_mut().unwrap().remove("metadata");
    assert_eq!(
        item,
        serde_json::json!({
            "type": "error",
            "error_kind": "forbidden",
            "grant": "tickets.set_status",
            "scope": "IDENTITY",
            "roles": ["editor", "admin"],
            "held_on": ["MENGER"],
            "message": "needs tickets.set_status on IDENTITY",
            "code": "-32003",
            "recoverable": false,
        })
    );
    // A client reads it back typed, and an old client still parses the item.
    let item = error_item("menger", &err);
    let typed = ForbiddenItem::from_item(&item).unwrap();
    assert_eq!(typed.grant, "tickets.set_status");
    assert_eq!(typed.held_on, vec!["MENGER"]);
    assert!(matches!(serde_json::from_value::<PlexusStreamItem>(item).unwrap(), PlexusStreamItem::Error { .. }));
}

#[tokio::test]
async fn the_wire_through_the_rpc_module_anonymous() {
    // into_rpc_module dispatches `<ns>.call` without a connection identity:
    // anonymous, so a non-public method is refused as unauthenticated…
    let m = members();
    let module = hub(&m).into_rpc_module().unwrap();
    let mut sub = module
        .subscribe_unbounded("menger.call", call("tickets.get", serde_json::json!({"id": "MENGER-1"})))
        .await
        .unwrap();
    let (item, _) = sub.next::<serde_json::Value>().await.unwrap().unwrap();
    assert_eq!(item["type"], "error");
    assert_eq!(item["error_kind"], "unauthenticated");
    assert_eq!(item["code"], "-32001");
    // …and a public one runs. The activations' direct methods are not
    // merged under a gate: `tickets.providers` is reached only via call.
    let mut sub = module
        .subscribe_unbounded("menger.call", call("tickets.providers", serde_json::json!({})))
        .await
        .unwrap();
    let (item, _) = sub.next::<serde_json::Value>().await.unwrap().unwrap();
    assert_eq!(item["content"], "key empty=true");
    assert!(!module.method_names().any(|n| n.starts_with("tickets.")));
}

#[tokio::test]
async fn no_role_lists_it_refused_except_admin() {
    let m = members();
    let hub = hub(&m);
    // `close` is listed by no role.
    let err = hub.route("tickets.close", serde_json::json!({"ids": ["MENGER-1"]}), Some(&who(ADA))).await.err().unwrap();
    assert!(matches!(
        err,
        PlexusError::Forbidden { reason: AuthzDenyReason::MissingGrant { ref roles, .. } } if roles.len() == 1 && roles[0].as_str() == "admin"
    ));
    assert!(hub.route("tickets.close", serde_json::json!({"ids": ["MENGER-1", "IDENTITY-2"]}), Some(&who(ROOT))).await.is_ok());
}

#[tokio::test]
async fn a_list_target_needs_every_element() {
    let m = members();
    m.add(ADA, "closer", "MENGER");
    let roles = RoleTable::new().define("closer", ["tickets.close"]).unwrap();
    let gate = Gate::new(m.clone(), Arc::new(roles), Arc::new(Shortcodes));
    let hub = DynamicHub::new("menger").register(Tickets).with_gate(Arc::new(gate));
    assert!(hub.route("tickets.close", serde_json::json!({"ids": ["MENGER-1", "MENGER-2"]}), Some(&who(ADA))).await.is_ok());
    assert!(hub.route("tickets.close", serde_json::json!({"ids": ["MENGER-1", "IDENTITY-2"]}), Some(&who(ADA))).await.is_err());
}

#[tokio::test]
async fn anonymous_is_unauthenticated_public_passes() {
    let m = members();
    let hub = hub(&m);
    let err = hub.route("tickets.get", serde_json::json!({"id": "MENGER-1"}), None).await.err().unwrap();
    assert!(matches!(err, PlexusError::Unauthenticated(_)));
    let out = data(hub.route("tickets.providers", serde_json::json!({}), None).await.unwrap()).await;
    assert_eq!(out, vec![serde_json::json!("key empty=true")]);
    // Introspection stays open (per-caller views are AUTH-4's).
    assert!(hub.route("tickets.schema", serde_json::json!({}), None).await.is_ok());
    assert!(hub.route("menger.hash", serde_json::json!({}), None).await.is_ok());
}

#[tokio::test]
async fn a_method_receives_its_reach() {
    let m = members();
    let hub = hub(&m);
    let out = data(hub.route("tickets.list", serde_json::json!({}), Some(&who(ADA))).await.unwrap()).await;
    assert_eq!(out, vec![serde_json::json!("MENGER")]);
    let out = data(hub.route("tickets.list", serde_json::json!({}), Some(&who(BOB))).await.unwrap()).await;
    assert_eq!(out, vec![serde_json::json!("*")]);
    // A ceiling narrows it: ADA's session within MENGER-12.
    let narrowed = AuthContext::for_principal(
        &ADA.parse().unwrap(),
        "s2",
        vec![],
        serde_json::json!({ "ceiling": ["editor@MENGER-12"] }),
    );
    struct Tickety;
    impl Resolve for Tickety {
        fn chain(&self, t: &str) -> Option<Vec<ScopeRef>> {
            let code = t.split_once('-').map(|(c, _)| c).unwrap_or(t);
            let mut v = Vec::new();
            if t.contains('-') {
                v.push(ScopeRef::named(t));
            }
            v.push(ScopeRef::named(code));
            v.push(ScopeRef::Everywhere);
            Some(v)
        }
    }
    let declared = DynamicHub::new("x").register(Tickets).declared_roles();
    let roles = RoleTable::from_lists(declared.iter().map(|(r, g)| (r.as_str(), g.iter().map(String::as_str))));
    let hub2 = DynamicHub::new("menger").register(Tickets).with_gate(Arc::new(Gate::new(m.clone(), Arc::new(roles), Arc::new(Tickety))));
    let out = data(hub2.route("tickets.list", serde_json::json!({}), Some(&narrowed)).await.unwrap()).await;
    assert_eq!(out, vec![serde_json::json!("MENGER-12")]);
    assert!(hub2.route("tickets.set_status", serde_json::json!({"id": "MENGER-12", "status": "x"}), Some(&narrowed)).await.is_ok());
    assert!(hub2.route("tickets.set_status", serde_json::json!({"id": "MENGER-13", "status": "x"}), Some(&narrowed)).await.is_err());
    // Unknown methods are denied (default deny), even to a viewer everywhere.
    assert!(hub.route("tickets.nope", serde_json::json!({}), Some(&who(BOB))).await.is_err());
}

#[tokio::test]
async fn a_stream_follows_grants_as_they_stand() {
    let m = members();
    let hub = hub(&m);
    // `watch` is listed by no role: admin holds it; its membership is then
    // revoked mid-stream.
    let mut stream = hub
        .route("tickets.watch", serde_json::json!({"ids": ["MENGER-1", "IDENTITY-1"]}), Some(&who(ROOT)))
        .await
        .unwrap();
    // The first event is checked against the memberships as they stand…
    let first = loop {
        match stream.next().await.unwrap() {
            PlexusStreamItem::Data { content, .. } => break content,
            _ => continue,
        }
    };
    assert_eq!(first, "MENGER-1");
    // …the membership goes, and the next event is dropped.
    m.clear();
    let rest: Vec<_> = data(stream).await;
    assert!(rest.is_empty(), "{rest:?}");
}

#[test]
fn the_hubs_own_methods_are_granted_under_its_runtime_namespace() {
    use plexus_core::plexus::Activation;
    let hub = DynamicHub::new("menger").register(Tickets);
    let schema = Activation::plugin_schema(&hub);
    let call = schema.methods.iter().find(|m| m.name == "call").unwrap();
    assert_eq!(call.grant.as_deref(), Some("menger.call"));
    assert_eq!(
        hub.declared_roles()["editor"],
        vec!["tickets.get", "tickets.list", "tickets.set_status"]
    );
}
