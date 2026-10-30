//! PERF-21: two starts of the same service describe it the same. A service
//! lists its activations by namespace — a function of what it serves — so its
//! schema's `children`, its `hash` (the `plexus_hash` every item it sends
//! carries) and each caller's `_info` (`view_hash`), `hash`, `hashes` and
//! `schema` are the same at every start of the same build.
//!
//! A start here is the service built again of the same activations: each
//! `DynamicHub` keeps its maps under a `RandomState` of its own, seeded anew,
//! as another process's is. Before PERF-21 a service listed its activations
//! in that map's order: two starts of this two-activation service disagreed
//! often, two starts of menger (twelve activations) nearly always — four
//! starts, four hashes — and a client keeping a schema by hash fetched it
//! again after a restart.

mod describe_support;

use std::collections::BTreeSet;

use describe_support::*;
use plexus_core::plexus::{Activation, AuthContext};
use plexus_core::DynamicHub;
use serde_json::Value;

/// Starts of AUTH-5's service (tickets and the auth activation): enough that,
/// listed in a map's order, they show both orders all but always (at main:
/// sixteen starts, both orders, two hashes).
const STARTS: usize = 16;

/// The namespaces a schema lists as its children, in its order.
#[allow(deprecated)]
fn children(schema: &plexus_core::plexus::schema::PluginSchema) -> Vec<String> {
    schema.children.as_ref().map(|kids| kids.iter().map(|c| c.namespace.clone()).collect()).unwrap_or_default()
}

/// The distinct values `f` takes over the starts — one, when they agree.
fn across<T: Ord>(starts: &[World], f: impl Fn(&World) -> T) -> BTreeSet<T> {
    starts.iter().map(f).collect()
}

#[tokio::test]
async fn the_children_are_listed_by_namespace() {
    let starts: Vec<World> = (0..STARTS).map(|_| auth_world()).collect();
    let root = key(ROOT, "root");
    let listed = across(&starts, |w| w.service.plugin_children().into_iter().map(|c| c.namespace).collect::<Vec<_>>());
    assert_eq!(listed, BTreeSet::from([vec!["auth".to_string(), "tickets".into()]]), "{STARTS} starts: the children as the service lists them");
    let schema = across(&starts, |w| children(&Activation::plugin_schema(&*w.service)));
    assert_eq!(schema, listed, "{STARTS} starts: the children of the service's schema");
    let view = across(&starts, |w| children(&w.service.view(Some(&root)).schema));
    assert_eq!(view, listed, "{STARTS} starts: the children of root's view");
}

#[tokio::test]
async fn two_starts_answer_the_same() {
    let starts: Vec<World> = (0..STARTS).map(|_| auth_world()).collect();
    let hashes = across(&starts, |w| w.service.compute_hash());
    assert_eq!(hashes.len(), 1, "{STARTS} starts, {} hashes (each start's plexus_hash): {hashes:?}", hashes.len());
    for (name, who) in callers() {
        let infos = across(&starts, |w| w.service.info(who.as_ref()).to_string());
        assert_eq!(infos.len(), 1, "{name}: {STARTS} starts, {} _info answers: {infos:#?}", infos.len());
    }
    // Every self-description answer, for every caller, at every start.
    for (name, who) in callers() {
        let first = all(&starts[0], who.as_ref()).await;
        for (n, w) in starts.iter().enumerate().skip(1) {
            for ((got, want), ask) in all(w, who.as_ref()).await.iter().zip(&first).zip(asks()) {
                assert_eq!(got, want, "{name}: {} at start {n} is not start 0's", ask.label());
            }
        }
    }
}

#[tokio::test]
async fn the_order_registered_in_is_not_the_answer() {
    // What the service is, not how it was built: the same activations
    // registered in either order describe the same service.
    let one = DynamicHub::new("menger").register(TicketsActivation).register(NotesActivation);
    let other = DynamicHub::new("menger").register(NotesActivation).register(TicketsActivation);
    assert_eq!(children(&Activation::plugin_schema(&one)), ["notes", "tickets"]);
    assert_eq!(children(&Activation::plugin_schema(&other)), ["notes", "tickets"]);
    assert_eq!(one.compute_hash(), other.compute_hash());
    let schema = |s: &DynamicHub| serde_json::to_string(&Activation::plugin_schema(s)).unwrap();
    assert_eq!(schema(&one), schema(&other), "the service's schema, byte for byte");
}

/// Every ask in `asks()`, for `who`, on its own connection.
async fn all(w: &World, who: Option<&AuthContext>) -> Vec<Value> {
    let module = module_for(w, who);
    let mut out = Vec::new();
    for ask in asks() {
        out.push(ask.answer(w, &module, who).await);
    }
    out
}
