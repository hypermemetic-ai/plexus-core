//! ASK-1 — the in-call question stays removed: a service's module has no
//! `{ns}.respond`, and a method's schema says nothing of `bidirectional`,
//! `request_type` or `response_type`. Plexus has no in-call or
//! protocol-wide confirmation; a service builds its own if it wants one.

use std::sync::Arc;

use futures::StreamExt;
use plexus_core::activations::health::Health;
use plexus_core::plexus::PlexusStreamItem;
use plexus_core::DynamicHub;
use serde_json::{json, Value};

fn hub() -> DynamicHub {
    DynamicHub::new("svc").register(Health::new())
}

#[tokio::test]
async fn the_module_has_no_respond() {
    let module = DynamicHub::arc_into_rpc_module(Arc::new(hub())).unwrap();
    assert!(module.method("svc.respond").is_none(), "svc.respond is registered");
    let frame = r#"{"jsonrpc":"2.0","id":1,"method":"svc.respond","params":{"request_id":"r-1","response_data":{}}}"#;
    let (resp, _rx) = module.raw_json_request(frame, 4).await.unwrap();
    let v: Value = serde_json::from_str(resp.get()).unwrap();
    assert_eq!(v["error"]["code"], -32601, "{v}");
}

#[tokio::test]
async fn a_schema_says_nothing_of_bidirectional() {
    let items: Vec<PlexusStreamItem> = hub().route("health.schema", json!({}), None).await.unwrap().collect().await;
    let text = serde_json::to_string(&items).unwrap();
    for gone in ["\"bidirectional\"", "\"request_type\"", "\"response_type\"", "\"asks\""] {
        assert!(!text.contains(gone), "{gone} in {text}");
    }
}
