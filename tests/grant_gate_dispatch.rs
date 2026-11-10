//! AUTH-2 — the grant gate in [`DynamicHub`] dispatch, end to end: a small
//! activation declaring `target` and `roles(...)` (AUTH-3), a fake service
//! (memberships, roles from the schema's defaults, a shortcode resolver),
//! and calls through the gate showing allow, deny, the reach a method
//! receives, and the refusal as it goes on the wire.

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{error_item, AuthContext, ForbiddenItem, PlexusStreamItem, Reach, Resolve, RoleTable, ScopeRef};
use plexus_core::DynamicHub;
use plexus_testkit::parts::{who, Shortcodes};
use plexus_testkit::{Caller, Forbidden, HostBuilder, Outcome, Unauthenticated, World};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct TicketsActivation;

#[plexus_macros::activation(
    version = "1.0.0",
    description = "AUTH-2 gate fixture",
    roles(viewer = ["get", "list"], editor = [viewer, "set_status"]),
)]
impl TicketsActivation {
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
    #[plexus_macros::method]
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

/// The service `menger`, its roles seeded from the activation's declared
/// defaults, a ticket living in its shortcode (`CODE-n` → `[CODE, *]`).
fn menger() -> HostBuilder {
    World::new().host().named("menger").with(TicketsActivation).resolving(Shortcodes).without_named_callers()
}

/// `<ns>.call`'s params object.
fn call(method: &str, params: serde_json::Value) -> jsonrpsee::core::params::ObjectParams {
    let mut p = jsonrpsee::core::params::ObjectParams::new();
    p.insert("method", method).unwrap();
    p.insert("params", params).unwrap();
    p
}

/// ADA edits MENGER, BOB views everywhere, ROOT is admin.
fn members() -> HostBuilder {
    menger().member_at(ADA, "editor", "MENGER").member(BOB, "viewer").member(ROOT, "admin")
}

/// What a `<ns>.call` subscription sent, to its last item (`done`, or an
/// error), as an outcome of `method` called by no one signed in.
async fn heard(mut sub: jsonrpsee::core::server::Subscription, method: &str) -> Outcome {
    let mut items = Vec::new();
    while let Some(Ok((item, _))) = sub.next::<PlexusStreamItem>().await {
        let last = matches!(item, PlexusStreamItem::Done { .. } | PlexusStreamItem::Error { .. });
        items.push(item);
        if last {
            break;
        }
    }
    Outcome::of(method, "anonymous", items)
}

#[tokio::test]
async fn a_hub_without_a_gate_dispatches_as_before() {
    let hub = Arc::new(DynamicHub::new("menger").register(TicketsActivation));
    let ada = Caller::new(hub.clone(), Some(who(ADA)));
    let out = ada.call("tickets.set_status", json!({"id": "X-1", "status": "Ready"})).await.answer::<String>();
    assert_eq!(out, format!("{}: X-1 -> Ready", who(ADA).user_id));
    // Anonymous, too — and `reach` is everywhere.
    assert_eq!(Caller::new(hub, None).call("tickets.list", json!({})).await.answer::<String>(), "*");
}

#[tokio::test]
async fn held_on_menger_allows_a_menger_target_not_an_identity_one() {
    let host = members().await;
    host.as_(ADA).call("tickets.set_status", json!({"id": "MENGER-12", "status": "Ready"})).await.answers(1);
    let refusal = host.as_(ADA).call("tickets.set_status", json!({"id": "IDENTITY-1", "status": "Ready"})).await.refused(Forbidden);
    let refusal = refusal.naming("tickets.set_status").at("IDENTITY").listed_by(["editor", "admin"]).held_on(["MENGER"]);
    assert_eq!(refusal.message(), "needs tickets.set_status on IDENTITY");
}

#[tokio::test]
async fn the_refusal_on_the_wire() {
    let host = members().await;
    let refusal = host.as_(ADA).call("tickets.set_status", json!({"id": "IDENTITY-1", "status": "Ready"})).await.refused(Forbidden);
    let err = refusal.plexus_error().expect("refused before it opened");
    let mut item = error_item("menger", err);
    item.as_object_mut().unwrap().remove("metadata");
    assert_eq!(
        item,
        json!({
            "type": "error",
            "error_kind": "forbidden",
            "grant": "tickets.set_status",
            "scope": "IDENTITY",
            "roles": ["editor", "admin"],
            "held_on": ["MENGER"],
            "message": "needs tickets.set_status on IDENTITY",
            "code": "-32003",
            "recoverable": false,
            // RETURNS-36: RETURNS-6's typed error beside spec/05's fields.
            "error": {
                "kind": "forbidden",
                "reason": "missing_grant",
                "grant": "tickets.set_status",
                "scope": "IDENTITY",
                "roles": ["editor", "admin"],
                "held_on": ["MENGER"],
            },
        })
    );
    // A client reads it back typed, and an old client still parses the item.
    let item = error_item("menger", err);
    let typed = ForbiddenItem::from_item(&item).unwrap();
    assert_eq!(typed.grant, "tickets.set_status");
    assert_eq!(typed.held_on, vec!["MENGER"]);
    assert!(matches!(serde_json::from_value::<PlexusStreamItem>(item).unwrap(), PlexusStreamItem::Error { .. }));
}

#[tokio::test]
async fn the_wire_through_the_rpc_module_anonymous() {
    // into_rpc_module dispatches `<ns>.call` without a connection identity:
    // anonymous, so a non-public method is refused as unauthenticated…
    let host = members().await;
    let module = host.service().as_ref().clone().into_rpc_module().unwrap();
    let sub = module.subscribe_unbounded("menger.call", call("tickets.get", json!({"id": "MENGER-1"}))).await.unwrap();
    let got = heard(sub, "tickets.get").await;
    got.refused_in_band(Unauthenticated);
    assert_eq!(got.raw()[0]["code"], "-32001");
    // …and a public one runs. The activations' direct methods are not
    // merged under a gate: `tickets.providers` is reached only via call.
    let sub = module.subscribe_unbounded("menger.call", call("tickets.providers", json!({}))).await.unwrap();
    assert_eq!(heard(sub, "tickets.providers").await.answer::<String>(), "key empty=true");
    assert!(!module.method_names().any(|n| n.starts_with("tickets.")));
}

#[tokio::test]
async fn no_role_lists_it_refused_except_admin() {
    let host = members().await;
    // `close` is listed by no role.
    host.as_(ADA).call("tickets.close", json!({"ids": ["MENGER-1"]})).await.refused(Forbidden).listed_by(["admin"]);
    host.as_(ROOT).call("tickets.close", json!({"ids": ["MENGER-1", "IDENTITY-2"]})).await.answers(1);
}

#[tokio::test]
async fn a_list_target_needs_every_element() {
    // The gate reads one role alone, `closer`: none of the declared ones.
    let closer = RoleTable::new().define("closer", ["tickets.close"]).unwrap();
    let host = members().member_at(ADA, "closer", "MENGER").roles_through(move |_declared| Arc::new(closer)).await;
    host.as_(ADA).call("tickets.close", json!({"ids": ["MENGER-1", "MENGER-2"]})).await.answers(1);
    host.as_(ADA).call("tickets.close", json!({"ids": ["MENGER-1", "IDENTITY-2"]})).await.refused(Forbidden).at("IDENTITY");
}

#[tokio::test]
async fn anonymous_is_unauthenticated_public_passes() {
    let host = members().await;
    let anonymous = host.anonymous();
    anonymous.call("tickets.get", json!({"id": "MENGER-1"})).await.refused(Unauthenticated);
    assert_eq!(anonymous.call("tickets.providers", json!({})).await.answer::<String>(), "key empty=true");
    // Introspection stays open (per-caller views are AUTH-4's).
    anonymous.call("tickets.schema", json!({})).await.answers(1);
    anonymous.call("menger.hash", json!({})).await.answers(1);
}

#[tokio::test]
async fn a_method_receives_its_reach() {
    let host = members().await;
    assert_eq!(host.as_(ADA).call("tickets.list", json!({})).await.answer::<String>(), "MENGER");
    assert_eq!(host.as_(BOB).call("tickets.list", json!({})).await.answer::<String>(), "*");
    // A ceiling narrows it: ADA's session within MENGER-12.
    let narrowed = AuthContext::for_principal(
        &ADA.parse().unwrap(),
        "s2",
        vec![],
        json!({ "ceiling": ["editor@MENGER-12"] }),
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
    let host2 = members().resolving(Tickety).await;
    let narrowed = Caller::new(host2.service().clone(), Some(narrowed));
    assert_eq!(narrowed.call("tickets.list", json!({})).await.answer::<String>(), "MENGER-12");
    narrowed.call("tickets.set_status", json!({"id": "MENGER-12", "status": "x"})).await.answers(1);
    narrowed.call("tickets.set_status", json!({"id": "MENGER-13", "status": "x"})).await.refused(Forbidden).at("MENGER-13");
    // Unknown methods are denied (default deny), even to a viewer everywhere.
    host.as_(BOB).call("tickets.nope", json!({})).await.refused(Forbidden).naming("tickets.nope");
}

#[tokio::test]
async fn a_stream_follows_grants_as_they_stand() {
    let host = members().await;
    // `watch` is listed by no role: admin holds it; its membership is then
    // revoked mid-stream.
    let mut stream = host.as_(ROOT).stream("tickets.watch", json!({"ids": ["MENGER-1", "IDENTITY-1"]})).await.unwrap();
    // The first event is checked against the memberships as they stand…
    let first = loop {
        match stream.next().await.unwrap() {
            PlexusStreamItem::Data { content, .. } => break content.into_value(),
            _ => continue,
        }
    };
    assert_eq!(first, "MENGER-1");
    // …the membership goes, and the next event is dropped.
    host.members().0.lock().unwrap().clear();
    Outcome::of("tickets.watch", "ROOT, its membership gone", stream.collect().await).answers(0);
}

#[test]
fn the_hubs_own_methods_are_granted_under_its_runtime_namespace() {
    use plexus_core::plexus::Activation;
    let hub = DynamicHub::new("menger").register(TicketsActivation);
    let schema = Activation::plugin_schema(&hub);
    let call = schema.methods.iter().find(|m| m.name == "call").unwrap();
    assert_eq!(call.grant.as_deref(), Some("menger.call"));
    assert_eq!(
        hub.declared_roles()["editor"],
        vec!["tickets.get", "tickets.list", "tickets.set_status"]
    );
}
