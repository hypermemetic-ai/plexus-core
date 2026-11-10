//! KEEL-33 — `<ns>.list_children` and `<ns>.search_children` are not served
//! by a gated service: they ran the activation's list or search method with
//! no gate, beside `<ns>.call`. On a gated service the list or search
//! method is reached as any method is, through `<ns>.call` and the gate, by
//! its own grant. A service without a gate serves them as before.
//!
//! The review's probe (`list_door.rs`, KEEL-28): anonymously, `peers.names`
//! was refused through `route`, and `peers.list_children` streamed the names.

use std::sync::{Arc, Mutex};

use futures::stream::Stream;
use plexus_core::DynamicHub;
use plexus_testkit::{Unauthenticated, World, VIEWER};
use serde_json::{json, Value};

/// Every time a listing method ran.
type Ran = Arc<Mutex<Vec<&'static str>>>;

#[derive(Clone)]
struct PeersActivation {
    ran: Ran,
}

/// Like dyn: a slot whose names a method lists.
#[plexus_macros::activation(namespace = "peers", version = "1.0.0", roles(viewer = ["ping"]))]
impl PeersActivation {
    /// Ping.
    #[plexus_macros::method]
    async fn ping(&self) -> Value {
        json!("pong")
    }

    /// Every peer's name: no role lists it.
    #[plexus_macros::method]
    async fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        self.ran.lock().unwrap().push("names");
        futures::stream::iter(vec!["secret-peer-a".to_string(), "secret-peer-b".to_string()])
    }

    /// Peers whose name has `query` in it: no method at all, so no grant
    /// of its own — the slot's search alone.
    fn find(&self, query: &str) -> impl Stream<Item = String> + Send + 'static {
        self.ran.lock().unwrap().push("find");
        futures::stream::iter(vec![format!("secret-{query}")])
    }

    /// A peer by name.
    #[plexus_macros::child(list = "names", search = "find")]
    fn item(&self, name: &str) -> Option<PeersActivation> {
        let _ = name;
        None
    }
}

/// What the module answers `method` (params `params`), as the connection
/// with no credential: each item's text, or the error it was refused with.
async fn ask(module: &jsonrpsee::RpcModule<()>, method: &str, params: Value) -> Vec<String> {
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let (resp, mut rx) = module.raw_json_request(&req, 1024).await.unwrap();
    let mut seen = vec![resp.get().to_string()];
    if resp.get().contains("\"error\"") {
        return seen;
    }
    while let Ok(Some(item)) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await {
        let t = item.get().to_string();
        let done = t.contains(r#""type":"done""#) || t.contains(r#""type":"error""#);
        seen.push(t);
        if done {
            break;
        }
    }
    seen
}

#[tokio::test]
async fn a_gated_service_serves_no_listing_beside_its_gate() {
    let ran: Ran = Arc::default();
    let host = World::new().host().named("svc").with(PeersActivation { ran: ran.clone() }).await;
    let module = DynamicHub::arc_into_rpc_module(host.service().clone()).unwrap();
    for (method, params) in [("peers.list_children", json!({})), ("peers.search_children", json!({ "query": "a" }))] {
        let said = ask(&module, method, params).await.join("\n");
        assert!(!said.contains("secret-"), "{method} answered anonymously: {said}");
        assert!(said.contains("-32601") || said.contains("not found"), "{method}: {said}");
    }
    let names: Vec<&str> = module.method_names().collect();
    assert!(!names.iter().any(|n| n.ends_with("_children")), "served beside the gate: {names:?}");
    assert!(ran.lock().unwrap().is_empty(), "a listing method ran ungated: {:?}", ran.lock().unwrap());
    // The listing method is a method: decided by the gate, by its own grant.
    host.anonymous().call("peers.names", json!({})).await.refused(Unauthenticated);
    host.as_(VIEWER).call("peers.names", json!({})).await.refused(plexus_testkit::Forbidden).naming("peers.names");
}

#[tokio::test]
async fn a_service_without_a_gate_lists_as_before() {
    let ran: Ran = Arc::default();
    let module = DynamicHub::new("svc").register(PeersActivation { ran: ran.clone() }).into_rpc_module().unwrap();
    let said = ask(&module, "peers.list_children", json!({})).await.join("\n");
    assert!(said.contains("secret-peer-a") && said.contains("secret-peer-b"), "{said}");
    let said = ask(&module, "peers.search_children", json!({ "query": "x" })).await.join("\n");
    assert!(said.contains("secret-x"), "{said}");
}
