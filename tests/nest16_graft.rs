//! NEST-16's gate: a graft that knows its parent — NEST-1's shop sketch.
//!
//! `restock` is written against its parent's interface,
//! `#[activation(parent = ShopClient)]`, and calls `parent.items()`; the
//! macro infers `needs: [shop.items]` and publishes it in the schema.
//!
//! - grafted onto `shop`'s service (behind a mount, on stdio, and in
//!   process), `restock.low` calls `shop.items` inward **as the caller**;
//! - grafting it onto a service without `items` is refused naming it — at
//!   runtime (`ServiceRoot::insert`) and at a static start
//!   (`check_grafts`), and a `shop` whose `items` changed shape is refused
//!   naming it as changed;
//! - its call to any other shop method (`shop.secret`, made by hand on the
//!   raw connection back) is refused by the host, `forbidden` /
//!   `not_needed`, though the caller holds `shop.secret`;
//! - a child with no needs (`plain`) calls the standard four
//!   (`host.schema`, `host.whoami`, `host.log`, `host.notify`) and nothing
//!   else — unless the host keeps NEST-11's rule for it
//!   (`legacy_upcalls`).
//!
//! No test harness: this binary is the host and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the child on stdio.

use futures::StreamExt;
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::remote_child::host;
use plexus_core::plexus::{ChildOptions, ChildSpec, Need, Parent, ParentTransport, RemoteChild};
use plexus_core::DynamicHub;
use plexus_testkit::parts::who;
use plexus_testkit::{HostBuilder, World, EDITOR, VIEWER};
use serde_json::{json, Value};

// ------------------------------------------------------------------ the parent

pub mod shop {
    use super::*;

    #[derive(Clone)]
    pub struct Shop;

    /// The shop: what it stocks.
    #[plexus_macros::activation(crate_path = "plexus_core")]
    impl Shop {
        /// What is on the shelves, and for whom it was asked.
        #[plexus_macros::method]
        pub async fn items(&self) -> Value {
            let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
            json!({ "items": ["flour", "salt"], "caller": caller })
        }
        /// The till: no child needs it.
        #[plexus_macros::method]
        pub async fn secret(&self) -> Value {
            json!({ "till": 42 })
        }
    }
}

/// Another service's `shop`: no `items`.
pub mod bare {
    use super::*;

    /// A shop with nothing on the shelves.
    #[plexus_macros::activation(namespace = "shop", crate_path = "plexus_core")]
    impl BareActivation {
        /// The till.
        #[plexus_macros::method]
        pub async fn secret(&self) -> Value {
            json!({ "till": 0 })
        }
    }
    #[derive(Clone)]
    pub struct BareActivation;
}

/// A `shop` whose `items` takes a parameter: the same name, another shape.
pub mod moved {
    use super::*;

    #[derive(Clone)]
    pub struct MovedActivation;

    /// A shop, rebuilt.
    #[plexus_macros::activation(namespace = "shop", crate_path = "plexus_core")]
    impl MovedActivation {
        /// Items in one aisle.
        #[plexus_macros::method]
        pub async fn items(&self, aisle: u32) -> Value {
            json!({ "aisle": aisle })
        }
    }
}

use shop::ShopClient;

// ------------------------------------------------------------------ the grafts

#[derive(Clone)]
pub struct Restock;

/// Knows its parent: written against the shop's client.
#[plexus_macros::activation(parent = ShopClient, crate_path = "plexus_core")]
impl Restock {
    /// What is running low: the parent's `items`, called inward.
    #[plexus_macros::method]
    pub async fn low(&self, parent: Parent<ShopClient>) -> Value {
        match parent.items().await {
            Ok(v) => json!({ "low": v }),
            Err(e) => json!({ "error": e.to_string() }),
        }
    }
    /// Whom the call is for, from the standard interface.
    #[plexus_macros::method]
    pub async fn who(&self, parent: Parent<ShopClient>) -> Value {
        let who = parent.host().whoami().await.map_err(|e| e.to_string());
        let _ = parent.host().log("info", "restock asked who").await;
        json!({ "who": who.unwrap_or_else(|e| json!({ "error": e })) })
    }
    /// Reaches past its needs, by hand, on the raw connection back.
    #[plexus_macros::method]
    pub async fn sneak(&self) -> Value {
        match host() {
            Ok(t) => first(&t, MethodRef::new("shop", "secret")).await,
            Err(e) => json!({ "no_host": e.to_string() }),
        }
    }
}

#[derive(Clone)]
pub struct Plain;

/// Knows no parent: the standard interface alone.
#[plexus_macros::activation(crate_path = "plexus_core")]
impl Plain {
    /// Calls `host.<name>` (or any method) up, by hand.
    #[plexus_macros::method]
    pub async fn up(&self, method: String) -> Value {
        let (path, name) = method.rsplit_once('.').unwrap_or(("host", "whoami"));
        let params = match name {
            "log" => json!({ "level": "info", "message": "plain says hello" }),
            "notify" => json!({ "topic": "restocked", "data": { "flour": 3 } }),
            _ => json!({}),
        };
        match host() {
            Ok(t) => {
                let items: Vec<_> = t.call(MethodRef::named(path.to_string(), name.to_string()), params).collect().await;
                match items.into_iter().next() {
                    Some(Ok(StreamItem::Data { content, .. })) => content,
                    Some(Ok(StreamItem::Error { error, message, .. })) => json!({ "refused": serde_json::to_value(&error).unwrap(), "message": message }),
                    other => json!({ "other": format!("{other:?}") }),
                }
            }
            Err(e) => json!({ "no_host": e.to_string() }),
        }
    }
}

async fn first(t: &impl Transport, m: MethodRef) -> Value {
    let items: Vec<_> = t.call(m, json!({})).collect().await;
    match items.into_iter().next() {
        Some(Ok(StreamItem::Data { content, .. })) => content,
        Some(Ok(StreamItem::Error { error, message, .. })) => json!({ "refused": serde_json::to_value(&error).unwrap(), "message": message }),
        other => json!({ "other": format!("{other:?}") }),
    }
}

// ------------------------------------------------------------------ the host

/// `svc`, serving the shop. VIEWER: the grafts and `shop.items`; EDITOR:
/// everything, `shop.secret` too.
fn shop_host() -> HostBuilder {
    let grafts = ["restock.low", "restock.who", "restock.sneak", "plain.up"];
    let viewer: Vec<&str> = grafts.iter().copied().chain(["shop.items"]).collect();
    let editor: Vec<&str> = viewer.iter().copied().chain(["shop.secret"]).collect();
    World::new().host().named("svc").with(shop::Shop).roles([("viewer", viewer), ("editor", editor)])
}

async fn mount(name: &str, service: &DynamicHub, legacy: bool) -> RemoteChild {
    let spec: ChildSpec = format!("{name}=stdio:{}", std::env::current_exe().unwrap().display()).parse().unwrap();
    RemoteChild::connect(spec, ChildOptions::for_service("svc").with_host(service).with_legacy_upcalls(legacy)).await.expect("the child mounts")
}

// ------------------------------------------------------------------ the rows

/// The schema says what `restock` needs, inferred from `parent.items()`,
/// with the shape hash it was built against.
async fn restock_needs_shop_items_inferred() {
    use plexus_core::plexus::Activation;
    let needs = Restock.plugin_schema().needs.expect("restock declares needs");
    assert_eq!(needs.iter().map(|n| n.method.as_str()).collect::<Vec<_>>(), ["shop.items"], "{needs:?}");
    let served = DynamicHub::new("svc").register(shop::Shop).method_at("shop.items").unwrap();
    assert_eq!(needs[0].hash, served.0, "built against today's shape");
    assert_eq!(Plain.plugin_schema().needs, None, "a child that names no parent declares nothing");
    let wire = serde_json::to_value(Plain.plugin_schema()).unwrap();
    assert!(wire.get("needs").is_none(), "absent on the wire: {wire}");
}

/// Grafted behind a mount: `low` calls `shop.items` inward as the caller.
async fn grafted_it_calls_items_as_the_caller() {
    let host = shop_host().await;
    let service = host.service();
    let child = mount("restock", service, false).await;
    assert_eq!(child.needs().unwrap(), [Need::new("shop.items", child.needs().unwrap()[0].hash.clone())]);
    service.root().insert(child).expect("shop serves what restock needs");
    let got = host.as_(VIEWER).call("restock.low", json!({})).await;
    assert_eq!(got[0]["low"], json!({ "items": ["flour", "salt"], "caller": VIEWER }), "{got:?}");
    let got = host.as_(EDITOR).call("restock.who", json!({})).await;
    assert_eq!(got[0]["who"]["for"], EDITOR, "{got:?}");
    assert_eq!(got[0]["who"]["child"], "restock", "{got:?}");
}

/// Its call to anything else of the shop is refused by the host — even for
/// a caller who holds it.
async fn its_call_past_its_needs_is_refused_by_the_host() {
    let host = shop_host().await;
    let service = host.service();
    let child = mount("restock", service, false).await;
    service.root().insert(child).unwrap();
    let got = host.as_(EDITOR).call("restock.sneak", json!({})).await;
    assert_eq!(got[0]["refused"]["kind"], "forbidden", "{got:?}");
    assert_eq!(got[0]["refused"]["reason"], "not_needed", "{got:?}");
    assert_eq!(got[0]["refused"]["method"], "shop.secret", "{got:?}");
    // The editor does hold it, straight.
    let straight = host.as_(EDITOR).call("shop.secret", json!({})).await;
    assert_eq!(straight[0], json!({ "till": 42 }));
}

/// Onto a service without `items`: refused, naming it — at runtime and at a
/// static start; and onto a `shop` whose `items` moved, named as changed.
async fn refused_onto_a_service_without_items() {
    let host = shop_host().await;
    let child = mount("restock", host.service(), false).await;
    let bare = DynamicHub::new("svc").register(bare::BareActivation);
    match bare.root().insert(child.clone()) {
        Err(plexus_core::plexus::service_root::RootError::Needs(miss)) => {
            assert_eq!(miss.missing, ["shop.items"]);
            assert!(miss.to_string().contains("shop.items"), "{miss}");
        }
        other => panic!("{other:?}"),
    }
    assert!(!bare.root().contains("restock"));
    let statically = DynamicHub::new("svc").register(bare::BareActivation).register(child.clone());
    let misses = statically.check_grafts().unwrap_err();
    assert_eq!(misses[0].missing, ["shop.items"], "{misses:?}");
    let serve = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| statically.clone().into_rpc_module().map(|_| ())));
    let why = serve.expect_err("not served");
    let why = why.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(why.contains("shop.items"), "{why}");
    let moved = DynamicHub::new("svc").register(moved::MovedActivation);
    match moved.root().insert(child) {
        Err(plexus_core::plexus::service_root::RootError::Needs(miss)) => assert_eq!((miss.missing.len(), miss.changed.clone()), (0, vec!["shop.items".to_string()])),
        other => panic!("{other:?}"),
    }
    // In process, the same check: the static start refuses it.
    let local = DynamicHub::new("svc").register(bare::BareActivation).register(Restock);
    assert_eq!(local.check_grafts().unwrap_err()[0].missing, ["shop.items"]);
}

/// Registered in the same process: the parent is the service's own routing.
async fn in_process_it_calls_items_as_the_caller() {
    let host = shop_host().with(Restock).await;
    let service = host.service();
    service.check_grafts().unwrap();
    let got = host.as_(VIEWER).call("restock.low", json!({})).await;
    assert_eq!(got[0]["low"]["caller"], VIEWER, "{got:?}");
    let got = host.as_(VIEWER).call("restock.who", json!({})).await;
    assert_eq!(got[0]["who"]["for"], VIEWER, "{got:?}");
    // The transport holds to the needs before sending anything.
    let t = ParentTransport::local(service.clone(), Some(who(EDITOR)), "restock", Restock::__plexus_parent_needs());
    let got = first(&t, MethodRef::new("shop", "secret")).await;
    assert_eq!(got["refused"]["reason"], "not_needed", "{got:?}");
    let p = Parent::new(t, ShopClient::new);
    assert_eq!(p.items().await.unwrap()["caller"], EDITOR);
}

/// A child with no needs: the standard four, nothing else — unless the host
/// keeps NEST-11's rule for it.
async fn a_child_with_no_needs_calls_the_standard_four_only() {
    let host = shop_host().await;
    let service = host.service();
    let mut heard = service.notices();
    let child = mount("plain", service, false).await;
    assert_eq!(child.needs(), None);
    service.root().insert(child).unwrap();
    let up = |m: &'static str| {
        let host = host.clone();
        async move { host.as_(EDITOR).call("plain.up", json!({ "method": m })).await.remove(0) }
    };
    assert_eq!(up("host.whoami").await["for"], EDITOR);
    assert_eq!(up("host.log").await, json!({ "logged": true }));
    assert_eq!(up("host.notify").await["heard"], 1);
    let notice = heard.recv().await.unwrap();
    assert_eq!((notice.child.as_str(), notice.topic.as_str(), notice.data.clone(), notice.for_.as_deref()), ("plain", "restocked", json!({ "flour": 3 }), Some(EDITOR)));
    assert_eq!(up("host.schema").await["namespace"], "svc");
    let refused = up("shop.items").await;
    assert_eq!((refused["refused"]["reason"].as_str(), refused["refused"]["method"].as_str()), (Some("not_needed"), Some("shop.items")), "{refused:?}");
    // Under the legacy option, NEST-11's rule.
    let legacy = shop_host().await;
    let child = mount("plain", legacy.service(), true).await;
    legacy.service().root().insert(child).unwrap();
    let got = legacy.as_(EDITOR).call("plain.up", json!({ "method": "shop.items" })).await;
    assert_eq!(got[0]["caller"], EDITOR, "{got:?}");
}

fn main() {
    match std::env::var("PLEXUS_CHILD_NAME").ok().as_deref() {
        Some("restock") => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(Restock)).unwrap();
            return;
        }
        Some(_) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(plexus_core::plexus::remote_child::serve_child_stdio(Plain)).unwrap();
            return;
        }
        None => {}
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        macro_rules! run {
            ($($t:ident),*) => {{ let mut n = 0; $( $t().await; println!("test {} ... ok", stringify!($t)); n += 1; )* n }};
        }
        let n = run!(
            restock_needs_shop_items_inferred,
            grafted_it_calls_items_as_the_caller,
            its_call_past_its_needs_is_refused_by_the_host,
            refused_onto_a_service_without_items,
            in_process_it_calls_items_as_the_caller,
            a_child_with_no_needs_calls_the_standard_four_only
        );
        println!("\ntest result: ok. {n} passed; 0 failed");
    });
}
