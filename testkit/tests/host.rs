//! KEEL-9: the kit's own rows — a host admits by role, refuses without, and
//! `roles(..)` adds to the declared ones. KEEL-10: a membership on a scope,
//! targets resolved by shortcode, a host without the named callers, and a
//! member forgotten; each caller in a session of its own.

use async_stream::stream;
use futures::stream::Stream;
use plexus_core::plexus::AuthEvent;
use plexus_testkit::parts::{every_item, items, session_of, who, Shortcodes};
use plexus_testkit::{Forbidden, Unauthenticated, World, ADMIN, EDITOR, NOBODY, USER, VIEWER};
use serde_json::json;

#[derive(Clone)]
struct ShopActivation;

/// A shop: the viewer reads the shelves, the editor restocks.
#[plexus_macros::activation(namespace = "shop", roles(viewer = ["items"], editor = ["items", "restock"]))]
impl ShopActivation {
    /// What is on the shelves.
    #[plexus_macros::method]
    async fn items(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "flour".to_string(); yield "salt".to_string(); }
    }
    /// Put more on them.
    #[plexus_macros::method]
    async fn restock(&self, what: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield format!("restocked {what}"); }
    }
    /// The till: no role the shop declares lists it.
    #[plexus_macros::method]
    async fn till(&self) -> impl Stream<Item = u64> + Send + 'static {
        stream! { yield 42; }
    }
}

const CLERK: &str = "key:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

#[tokio::test]
async fn a_host_admits_by_role() {
    let world = World::new();
    let host = world.host().with(ShopActivation).await;
    assert_eq!(host.as_(VIEWER).call("shop.items", json!({})).await.answers(2), [json!("flour"), json!("salt")]);
    assert_eq!(host.as_(EDITOR).call("shop.restock", json!({ "what": "rye" })).await.answer::<String>(), "restocked rye");
    // admin holds every grant, listed or not.
    assert_eq!(host.as_(ADMIN).call("shop.till", json!({})).await.answer::<u64>(), 42);
}

#[tokio::test]
async fn a_host_refuses_without_the_grant() {
    let world = World::new();
    let host = world.host().with(ShopActivation).await;
    // The refusal names the grant and the roles that list it.
    host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await.refused(Forbidden).naming("shop.restock").listed_by(["editor", "admin"]);
    host.as_(NOBODY).call("shop.items", json!({})).await.refused(Forbidden).naming("shop.items");
    // `user` is held by USER, but no activation declares it.
    host.as_(USER).call("shop.items", json!({})).await.refused(Forbidden).naming("shop.items");
    host.anonymous().call("shop.items", json!({})).await.refused(Unauthenticated);
}

#[tokio::test]
async fn roles_add_to_the_declared_ones() {
    let world = World::new();
    let host = world.host().with(ShopActivation).roles([("viewer", ["shop.till"]), ("user", ["shop.items"])]).await;
    // Added: the viewer reaches the till, the user the shelves…
    assert_eq!(host.as_(VIEWER).call("shop.till", json!({})).await.answer::<u64>(), 42);
    host.as_(USER).call("shop.items", json!({})).await.answers(2);
    // …and the declared grants stay.
    host.as_(VIEWER).call("shop.items", json!({})).await.answers(2);
    host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await.refused(Forbidden).naming("shop.restock");
}

#[tokio::test]
async fn a_caller_the_test_names_holds_the_role_it_is_given() {
    let world = World::new();
    let host = world.host().with(ShopActivation).role("clerk", ["shop.till"]).member(CLERK, "clerk").await;
    assert_eq!(host.as_(CLERK).call("shop.till", json!({})).await.answer::<u64>(), 42);
    host.as_(CLERK).call("shop.items", json!({})).await.refused(Forbidden).naming("shop.items");
}

#[tokio::test]
async fn with_auth_the_auth_activation_answers_and_decides() {
    let world = World::new();
    let host = world.host().named("store").with(ShopActivation).role("clerk", ["shop.till"]).member(CLERK, "clerk").with_auth().await;
    let req = host.as_(VIEWER).call("auth.requires", json!({ "method": "shop.items" })).await.answer::<AuthEvent>();
    let AuthEvent::Requires { grant, roles, .. } = req else { panic!("auth.requires answered {req:?}") };
    assert_eq!(grant, "shop.items");
    assert!(roles.iter().any(|r| r == "viewer"), "{roles:?}");
    assert_eq!(host.as_(CLERK).call("shop.till", json!({})).await.answer::<u64>(), 42);
    host.as_(VIEWER).call("shop.till", json!({})).await.refused(Forbidden).naming("shop.till");
}

#[tokio::test]
async fn the_service_is_handed_over_and_is_the_one_called() {
    let world = World::new();
    let host = world.host().named("store").with(ShopActivation).await;
    assert_eq!(host.service().runtime_namespace(), "store");
    assert!(host.service().declared_roles()["viewer"].contains(&"shop.items".to_string()));
    // A membership taken away while the host serves, said to the gate.
    host.members().0.lock().unwrap().clear();
    host.gate().moved(plexus_auth_core::grants::GrantsMove::Revoke);
    host.as_(VIEWER).call("shop.items", json!({})).await.refused(Forbidden).naming("shop.items");
}

#[derive(Clone)]
struct AislesActivation;

/// A shop's aisles, each a ticket of its department (`BAKERY-3`).
#[plexus_macros::activation(namespace = "aisles", roles(viewer = ["stock"]))]
impl AislesActivation {
    /// What an aisle holds.
    #[plexus_macros::method(target = "aisle")]
    async fn stock(&self, aisle: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield aisle; }
    }
}

#[tokio::test]
async fn a_member_on_a_shortcode_reaches_its_targets_alone() {
    let world = World::new();
    let host = world.host().with(AislesActivation).resolving(Shortcodes).member_at(CLERK, "viewer", "BAKERY").await;
    let stock = |aisle: &str| json!({ "aisle": aisle });
    assert_eq!(host.as_(CLERK).call("aisles.stock", stock("BAKERY-3")).await.answer::<String>(), "BAKERY-3");
    assert_eq!(host.as_(CLERK).call("aisles.stock", stock("BAKERY")).await.answer::<String>(), "BAKERY");
    host.as_(CLERK).call("aisles.stock", stock("DAIRY-1")).await.refused(Forbidden).naming("aisles.stock").at("DAIRY").held_on(["BAKERY"]);
    // No shortcode: it locates nothing, refused even to a viewer everywhere.
    host.as_(VIEWER).call("aisles.stock", stock("bakery-3")).await.refused(Forbidden).naming("aisles.stock");
    // The named viewer holds viewer on `*`: every shortcode.
    assert_eq!(host.as_(VIEWER).call("aisles.stock", stock("DAIRY-1")).await.answer::<String>(), "DAIRY-1");
}

#[tokio::test]
async fn without_the_named_callers_only_the_tests_members_hold_anything() {
    let world = World::new();
    let host = world.host().with(AislesActivation).resolving(Shortcodes).without_named_callers().member(CLERK, "viewer").await;
    assert_eq!(host.as_(CLERK).call("aisles.stock", json!({ "aisle": "DAIRY-1" })).await.answer::<String>(), "DAIRY-1");
    for named in [VIEWER, EDITOR, ADMIN, USER] {
        host.as_(named).call("aisles.stock", json!({ "aisle": "DAIRY-1" })).await.refused(Forbidden).naming("aisles.stock");
    }
    assert_eq!(host.members().0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_member_forgotten_holds_nothing() {
    let world = World::new();
    let host = world.host().with(AislesActivation).member_at(CLERK, "viewer", "*").member(CLERK, "editor").await;
    assert_eq!(host.as_(CLERK).call("aisles.stock", json!({ "aisle": "x" })).await.answer::<String>(), "x");
    host.members().forget(CLERK);
    host.as_(CLERK).call("aisles.stock", json!({ "aisle": "x" })).await.refused(Forbidden).naming("aisles.stock");
    // The others keep what they hold.
    assert_eq!(host.as_(VIEWER).call("aisles.stock", json!({ "aisle": "x" })).await.answer::<String>(), "x");
}

/// What a method saw of its caller's session.
#[derive(Clone)]
struct SessionActivation;

#[plexus_macros::activation(namespace = "session", roles(viewer = ["mine"]))]
impl SessionActivation {
    /// The caller's session id.
    #[plexus_macros::method]
    async fn mine(&self, auth: &plexus_core::plexus::AuthContext) -> impl Stream<Item = String> + Send + 'static {
        let id = auth.session_id.clone();
        stream! { yield id; }
    }
}

#[tokio::test]
async fn each_caller_has_a_session_of_its_own_and_keeps_it() {
    assert_ne!(who(VIEWER).session_id, who(EDITOR).session_id);
    assert_eq!(who(VIEWER).session_id, who(VIEWER).session_id);
    assert_eq!(who(VIEWER).session_id, session_of(VIEWER));
    let world = World::new();
    let host = world.host().with(SessionActivation).member(EDITOR, "viewer").await;
    let viewer = host.as_(VIEWER).call("session.mine", json!({})).await.answer::<String>();
    let editor = host.as_(EDITOR).call("session.mine", json!({})).await.answer::<String>();
    assert_eq!(viewer, session_of(VIEWER));
    assert_eq!(editor, session_of(EDITOR));
    assert_ne!(viewer, editor);
    assert_eq!(host.as_(VIEWER).call("session.mine", json!({})).await.answer::<String>(), viewer, "the same session on the next call");
}

#[tokio::test]
async fn every_item_keeps_the_closing_done_that_items_leaves_out() {
    let world = World::new();
    let host = world.host().with(ShopActivation).await;
    let all = every_item(host.as_(VIEWER).stream("shop.items", json!({})).await).await;
    assert_eq!(all.len(), 3, "{all:?}");
    assert_eq!(&all[..2], [json!("flour"), json!("salt")]);
    assert_eq!(all[2]["type"], "done", "{all:?}");
    assert_eq!(items(host.as_(VIEWER).stream("shop.items", json!({})).await).await, all[..2]);
    // The outcome's raw() is every_item's shape.
    assert_eq!(host.as_(VIEWER).call("shop.items", json!({})).await.raw(), all);
    // A call not routed: one item, as `items` gives it.
    let refused = every_item(host.as_(NOBODY).stream("shop.items", json!({})).await).await;
    assert!(refused.len() == 1 && refused[0]["route_error"].as_str().is_some_and(|e| e.contains("Forbidden") && e.contains("shop.items")), "{refused:?}");
}
