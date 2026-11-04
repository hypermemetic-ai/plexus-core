//! BIDIR-13 — the stopgap on today's in-stream question (`Request {
//! requestId }` out, `{ns}.respond { request_id, response_data }` back),
//! over a real jsonrpsee WebSocket with two connections and the way
//! `serve_stdio` drives the module. BIDIR-3's `question_matrix` (tag `archive/BIDIR-3`),
//! inverted: an answer from another connection is `not_this_call`, and a
//! call dropped mid-question leaves no pending entry.
//!
//! The asking method is a real `#[method(bidirectional)]` activation on a
//! `DynamicHub`, called through the hub's own `{ns}.call`, so the stream
//! goes out through the hub's pipe exactly as a backend's would.
//! BIDIR-9 (questions as items) retires this path.
//!
//! Run: `cargo test --test question_matrix -- --nocapture --test-threads=1`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_stream::stream;
use futures::Stream;
use jsonrpsee::core::client::{ClientT, Error as ClientError, Subscription, SubscriptionClientT};
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use jsonrpsee::RpcModule;
use plexus_core::plexus::bidirectional::registry::{is_request_pending, pending_count};
use plexus_core::plexus::bidirectional::StandardBidirChannel;
use plexus_core::plexus::{DynamicHub, StandardRequest, StandardResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// `pending_count` is process-wide: one question test at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AskEvent {
    Answer { i: u64, answer: Value },
    Error { message: String },
}

impl plexus_client::FromClientError for AskEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        AskEvent::Error { message: error.to_string() }
    }
}

#[derive(Clone)]
pub struct AskActivation;

#[plexus_macros::activation(version = "1.0.0", description = "BIDIR-13: asks confirms")]
impl AskActivation {
    /// Asks `n` confirms in turn, each waiting `timeout_ms`, and says each answer.
    #[plexus_macros::method(bidirectional)]
    pub async fn ask(&self, ctx: &Arc<StandardBidirChannel>, n: u64, timeout_ms: u64) -> impl Stream<Item = AskEvent> + Send + 'static {
        let ctx = ctx.clone();
        let t = Duration::from_millis(timeout_ms);
        stream! {
            for i in 0..n {
                let r = ctx.request_with_timeout(StandardRequest::Confirm { message: format!("q{i}?"), default: None }, t).await;
                let answer = match r {
                    Ok(StandardResponse::Confirmed { value }) => json!(value),
                    other => json!(format!("{other:?}")),
                };
                yield AskEvent::Answer { i, answer };
            }
        }
    }
}

fn module() -> RpcModule<()> {
    let hub = Arc::new(DynamicHub::new("q").register(AskActivation));
    DynamicHub::arc_into_rpc_module(hub).unwrap()
}

async fn ws_server() -> String {
    let server = jsonrpsee::server::Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    std::mem::forget(server.start(module()));
    format!("ws://{addr}")
}

/// One socket of its own; `who` names it in the test, nothing more — the
/// stopgap keys an answer by connection, not by principal.
async fn connect(url: &str, _who: &str) -> WsClient {
    WsClientBuilder::default().build(url).await.unwrap()
}

fn yes() -> Value {
    serde_json::to_value(StandardResponse::<Value>::Confirmed { value: true }).unwrap()
}

fn respond(id: &str) -> ObjectParams {
    let mut p = ObjectParams::new();
    p.insert("request_id", id).unwrap();
    p.insert("response_data", yes()).unwrap();
    p
}

fn ask(n: u64, timeout_ms: u64) -> ObjectParams {
    let mut p = ObjectParams::new();
    p.insert("method", "ask.ask").unwrap();
    p.insert("params", json!({"n": n, "timeout_ms": timeout_ms})).unwrap();
    p
}

async fn next(sub: &mut Subscription<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(5), sub.next()).await.expect("an item in 5 s").unwrap().unwrap()
}

/// The next item that is not the stream's own bookkeeping.
async fn next_of(sub: &mut Subscription<Value>, ty: &str) -> Value {
    loop {
        let v = next(sub).await;
        if v["type"] == ty {
            return v;
        }
        assert_ne!(v["type"], "error", "{v}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_question_round_trip() {
    let _s = SERIAL.lock().await;
    let url = ws_server().await;
    let alice = connect(&url, "alice").await;
    let mut sub: Subscription<Value> = alice.subscribe("q.call", ask(200, 30_000), "q.call_unsub").await.unwrap();
    let mut rt = Vec::new();
    for i in 0..200 {
        let q = next_of(&mut sub, "request").await;
        assert!(q["requestId"].is_string() && q["timeoutMs"] == 30_000, "{q}");
        let t0 = Instant::now();
        let ok: Value = alice.request("q.respond", respond(q["requestId"].as_str().unwrap())).await.unwrap();
        assert_eq!(ok, json!({"success": true}));
        let a = next_of(&mut sub, "data").await;
        rt.push(t0.elapsed().as_nanos() as u64);
        assert_eq!(a["content"], json!({"type": "answer", "i": i, "answer": true}));
    }
    rt.sort();
    println!(
        "WS question round trip (respond sent → next item), 200: p50 {:.3} ms p99 {:.3} ms",
        rt[100] as f64 / 1e6,
        rt[198] as f64 / 1e6
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_second_connection_is_not_this_call() {
    let _s = SERIAL.lock().await;
    let url = ws_server().await;
    let alice = connect(&url, "alice").await;
    let bob = connect(&url, "bob").await;
    let mut sub: Subscription<Value> = alice.subscribe("q.call", ask(1, 30_000), "q.call_unsub").await.unwrap();
    let q = next_of(&mut sub, "request").await;
    let id = q["requestId"].as_str().unwrap().to_string();

    // bob's socket, alice's question: refused, typed.
    let r: Result<Value, _> = bob.request("q.respond", respond(&id)).await;
    println!("WS wrong peer: bob answered alice's question → {r:?}");
    let ClientError::Call(e) = r.expect_err("bob's answer must be refused") else { panic!("not a call error") };
    assert_eq!(e.code(), -32003, "{e:?}");
    let data: Value = serde_json::from_str(e.data().expect("typed data").get()).unwrap();
    assert_eq!(data["error_kind"], "not_this_call", "{data}");
    assert_eq!(data["request_id"], id.as_str(), "{data}");
    // The question is still alice's, and her method has not moved.
    assert!(is_request_pending(&id), "a refused answer must leave the question pending");
    assert!(tokio::time::timeout(Duration::from_millis(200), sub.next()).await.is_err(), "the method moved on bob's answer");

    // alice's own connection still answers.
    let ok: Value = alice.request("q.respond", respond(&id)).await.unwrap();
    assert_eq!(ok, json!({"success": true}));
    let a = next_of(&mut sub, "data").await;
    assert_eq!(a["content"]["answer"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_dropped_stream_leaves_no_entry() {
    let _s = SERIAL.lock().await;
    let url = ws_server().await;
    let alice = connect(&url, "alice").await;
    let base = pending_count();
    let mut sub: Subscription<Value> = alice.subscribe("q.call", ask(1, 30_000), "q.call_unsub").await.unwrap();
    let q = next_of(&mut sub, "request").await;
    let id = q["requestId"].as_str().unwrap().to_string();
    assert!(is_request_pending(&id));
    let t0 = Instant::now();
    sub.unsubscribe().await.unwrap();
    let gone = loop {
        if !is_request_pending(&id) {
            break t0.elapsed();
        }
        assert!(t0.elapsed() < Duration::from_millis(300), "the entry outlived its call by 300 ms");
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    println!("WS dropped mid-question: entry gone {gone:?} after the unsubscribe (its timeout 30 s); {} left", pending_count().saturating_sub(base));
    assert_eq!(pending_count().saturating_sub(base), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_question_round_trip() {
    let _s = SERIAL.lock().await;
    // `serve_stdio` is this loop: one line → `raw_json_request` → the
    // response line, then the subscription's notifications as lines. Every
    // call is `ConnectionId(0)`: one pipe, one caller.
    let m = module();
    let (resp, mut rx) = m
        .raw_json_request(r#"{"jsonrpc":"2.0","id":1,"method":"q.call","params":{"method":"ask.ask","params":{"n":1,"timeout_ms":30000}}}"#, 64)
        .await
        .unwrap();
    assert!(resp.get().contains("\"result\""), "{}", resp.get());
    let q = loop {
        let line: Value = serde_json::from_str(rx.recv().await.unwrap().get()).unwrap();
        if line["params"]["result"]["type"] == "request" {
            break line["params"]["result"].clone();
        }
    };
    let answer = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"q.respond","params":{{"request_id":"{}","response_data":{}}}}}"#,
        q["requestId"].as_str().unwrap(),
        yes()
    );
    let (r, _) = m.raw_json_request(&answer, 64).await.unwrap();
    assert!(r.get().contains("success"), "{}", r.get());
    let a = loop {
        let line: Value = serde_json::from_str(rx.recv().await.unwrap().get()).unwrap();
        if line["params"]["result"]["type"] == "data" {
            break line;
        }
    };
    assert_eq!(a["params"]["result"]["content"]["answer"], true);
}

