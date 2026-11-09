//! PLEXUS-45 — plexus-core runs on `wasm32-unknown-unknown`, not only
//! compiles: a `DynamicHub` with activations, dispatched in wasm.
//!
//! A plain call, a streaming call whose items are spaced by a timer, the
//! health activation (its `Instant`) and the schema read, all on the JS
//! event loop with no tokio runtime.
//!
//! Run under Node (no browser needed: everything here is JS's timers and
//! clock, which Node has, and Node is what plexus-client's wasm tests use):
//! `scripts/wasm-test.sh`, which finds (or installs, once) the
//! `wasm-bindgen-test-runner` matching the lock's wasm-bindgen and runs
//! `cargo test --target wasm32-unknown-unknown --no-default-features --test wasm_dispatch`.
#![cfg(target_arch = "wasm32")]

use std::time::Duration;

use async_stream::stream;
use futures::{Stream, StreamExt};
use plexus_core::plexus::{DynamicHub, PlexusStreamItem};
use plexus_core::activations::health::Health;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen_test::wasm_bindgen_test;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClockEvent {
    Pong { msg: String },
    Tick { i: u64, after_ms: u64 },
    Error { message: String },
}

impl plexus_client::FromClientError for ClockEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        ClockEvent::Error { message: error.to_string() }
    }
}

#[derive(Clone)]
pub struct Clock;

#[plexus_macros::activation(version = "1.0.0", description = "PLEXUS-45: a wasm dispatch")]
impl Clock {
    /// One item back.
    #[plexus_macros::method]
    pub async fn ping(&self, msg: String) -> impl Stream<Item = ClockEvent> + Send + 'static {
        futures::stream::iter(vec![ClockEvent::Pong { msg }])
    }

    /// `n` items, `gap_ms` apart.
    #[plexus_macros::method]
    pub async fn ticks(&self, n: u64, gap_ms: u64) -> impl Stream<Item = ClockEvent> + Send + 'static {
        stream! {
            let start = web_time::Instant::now();
            for i in 0..n {
                futures_timer::Delay::new(Duration::from_millis(gap_ms)).await;
                yield ClockEvent::Tick { i, after_ms: start.elapsed().as_millis() as u64 };
            }
        }
    }
}

fn hub() -> DynamicHub {
    DynamicHub::new("wasm").register(Clock).register(Health::new())
}

/// Every item of a call, as JSON.
async fn call(hub: &DynamicHub, method: &str, params: Value) -> Vec<Value> {
    let stream = hub.route(method, params, None).await.unwrap_or_else(|e| panic!("{method}: {e:?}"));
    stream.map(|item: PlexusStreamItem| serde_json::to_value(item).unwrap()).collect().await
}

/// The data items' content.
fn data(items: &[Value]) -> Vec<Value> {
    items.iter().filter(|i| i["type"] == "data").map(|i| i["content"].clone()).collect()
}

#[wasm_bindgen_test]
async fn a_plain_call() {
    let items = call(&hub(), "clock.ping", json!({"msg": "hi"})).await;
    assert_eq!(data(&items), vec![json!({"type": "pong", "msg": "hi"})], "{items:?}");
    assert_eq!(items.last().unwrap()["type"], "done", "{items:?}");
}

#[wasm_bindgen_test]
async fn a_streaming_call_on_the_event_loop() {
    let items = call(&hub(), "clock.ticks", json!({"n": 3, "gap_ms": 20})).await;
    let ticks = data(&items);
    assert_eq!(ticks.len(), 3, "{items:?}");
    for (i, t) in ticks.iter().enumerate() {
        assert_eq!(t["i"], i as u64);
    }
    assert!(ticks[2]["after_ms"].as_u64().unwrap() >= 55, "timers really waited: {ticks:?}");
}

#[wasm_bindgen_test]
async fn health_answers() {
    let items = call(&hub(), "health.check", json!({})).await;
    let d = data(&items);
    assert_eq!(d.len(), 1, "{items:?}");
    assert_eq!(d[0]["status"], "healthy");
    assert!(d[0]["timestamp"].as_i64().unwrap() > 1_700_000_000, "the JS clock: {d:?}");
}

#[wasm_bindgen_test]
async fn the_schema_reads() {
    let hub = hub();
    let items = call(&hub, "wasm.schema", json!({})).await;
    let d = data(&items);
    assert_eq!(d.len(), 1, "{items:?}");
    let children: Vec<&str> = d[0]["children"].as_array().expect("children").iter().filter_map(|c| c["namespace"].as_str()).collect();
    assert!(children.contains(&"clock") && children.contains(&"health"), "{children:?}");
    let items = call(&hub, "clock.schema", json!({"method": "ticks"})).await;
    let d = data(&items);
    assert_eq!(d.len(), 1, "{items:?}");
    assert_eq!(d[0]["name"], "ticks", "{d:?}");
}
