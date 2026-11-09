//! KEEL-9: the kit's own rows — a host admits by role, refuses without, and
//! `roles(..)` adds to the declared ones.

use async_stream::stream;
use futures::stream::Stream;
use plexus_testkit::{World, ADMIN, EDITOR, NOBODY, USER, VIEWER};
use serde_json::{json, Value};

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

fn refused_naming(got: &[Value], grant: &str) -> bool {
    got.len() == 1 && got[0]["route_error"].as_str().is_some_and(|e| e.contains("Forbidden") && e.contains(grant))
}

#[tokio::test]
async fn a_host_admits_by_role() {
    let world = World::new();
    let host = world.host().with(ShopActivation).await;
    assert_eq!(host.as_(VIEWER).call("shop.items", json!({})).await, [json!("flour"), json!("salt")]);
    assert_eq!(host.as_(EDITOR).call("shop.restock", json!({ "what": "rye" })).await, [json!("restocked rye")]);
    // admin holds every grant, listed or not.
    assert_eq!(host.as_(ADMIN).call("shop.till", json!({})).await, [json!(42)]);
}

#[tokio::test]
async fn a_host_refuses_without_the_grant() {
    let world = World::new();
    let host = world.host().with(ShopActivation).await;
    let got = host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await;
    assert!(refused_naming(&got, "shop.restock"), "{got:?}");
    // The refusal names the roles that list the grant.
    assert!(got[0]["route_error"].as_str().unwrap().contains("editor"), "{got:?}");
    let got = host.as_(NOBODY).call("shop.items", json!({})).await;
    assert!(refused_naming(&got, "shop.items"), "{got:?}");
    // `user` is held by USER, but no activation declares it.
    let got = host.as_(USER).call("shop.items", json!({})).await;
    assert!(refused_naming(&got, "shop.items"), "{got:?}");
    let got = host.anonymous().call("shop.items", json!({})).await;
    assert!(got[0]["route_error"].as_str().is_some_and(|e| e.contains("Unauthenticated")), "{got:?}");
}

#[tokio::test]
async fn roles_add_to_the_declared_ones() {
    let world = World::new();
    let host = world.host().with(ShopActivation).roles([("viewer", ["shop.till"]), ("user", ["shop.items"])]).await;
    // Added: the viewer reaches the till, the user the shelves…
    assert_eq!(host.as_(VIEWER).call("shop.till", json!({})).await, [json!(42)]);
    assert_eq!(host.as_(USER).call("shop.items", json!({})).await.len(), 2);
    // …and the declared grants stay.
    assert_eq!(host.as_(VIEWER).call("shop.items", json!({})).await.len(), 2);
    let got = host.as_(VIEWER).call("shop.restock", json!({ "what": "rye" })).await;
    assert!(refused_naming(&got, "shop.restock"), "{got:?}");
}

#[tokio::test]
async fn a_caller_the_test_names_holds_the_role_it_is_given() {
    let world = World::new();
    let host = world.host().with(ShopActivation).role("clerk", ["shop.till"]).member(CLERK, "clerk").await;
    assert_eq!(host.as_(CLERK).call("shop.till", json!({})).await, [json!(42)]);
    let got = host.as_(CLERK).call("shop.items", json!({})).await;
    assert!(refused_naming(&got, "shop.items"), "{got:?}");
}

#[tokio::test]
async fn with_auth_the_auth_activation_answers_and_decides() {
    let world = World::new();
    let host = world.host().named("store").with(ShopActivation).role("clerk", ["shop.till"]).member(CLERK, "clerk").with_auth().await;
    let req = host.as_(VIEWER).call("auth.requires", json!({ "method": "shop.items" })).await;
    assert_eq!(req[0]["grant"], "shop.items", "{req:?}");
    assert!(req[0]["roles"].as_array().unwrap().iter().any(|r| r == "viewer"), "{req:?}");
    assert_eq!(host.as_(CLERK).call("shop.till", json!({})).await, [json!(42)]);
    let got = host.as_(VIEWER).call("shop.till", json!({})).await;
    assert!(refused_naming(&got, "shop.till"), "{got:?}");
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
    let got = host.as_(VIEWER).call("shop.items", json!({})).await;
    assert!(refused_naming(&got, "shop.items"), "{got:?}");
}
