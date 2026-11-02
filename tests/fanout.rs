//! PERF-7's fan-out: one change, sent to 200 watchers over the WebSocket,
//! is encoded once — `Shared` carries it, and its encoding is made by the
//! first socket that sends it and written by every other. Counted by the
//! change's own `Serialize`: red before the build (one encode per watcher,
//! 200), green after (1). Every watcher reads the same JSON, which is the
//! change's own.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use futures::stream::Stream;
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use plexus_core::plexus::Shared;
use plexus_core::DynamicHub;
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use tokio::sync::broadcast;

/// How many times a [`Change`] was serialized, by anything.
static ENCODES: AtomicUsize = AtomicUsize::new(0);

/// The tests here read `ENCODES` one at a time.
static ALONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One change, as menger's `watch` relays one: a ticket and what moved.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
struct Change {
    id: String,
    title: String,
    status: String,
    labels: Vec<String>,
    body: String,
}

/// The change's own `Serialize`, counted.
impl Serialize for Change {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        ENCODES.fetch_add(1, Ordering::SeqCst);
        let mut st = s.serialize_struct("Change", 5)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("title", &self.title)?;
        st.serialize_field("status", &self.status)?;
        st.serialize_field("labels", &self.labels)?;
        st.serialize_field("body", &self.body)?;
        st.end()
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FeedEvent {
    /// The watch is open: every change from here on reaches it.
    Ready,
    Error { message: String },
    /// A change, shared by every watcher.
    #[serde(untagged)]
    Changed(Shared<Change>),
}

impl plexus_client::FromClientError for FeedEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        FeedEvent::Error { message: error.to_string() }
    }
}

#[derive(Clone)]
struct FeedActivation {
    changes: broadcast::Sender<Shared<Change>>,
}

#[plexus_macros::activation(version = "1.0.0", description = "One change, many watchers")]
impl FeedActivation {
    /// Every change, from now on.
    #[plexus_macros::method(streaming)]
    async fn watch(&self) -> impl Stream<Item = FeedEvent> + Send + 'static {
        let mut rx = self.changes.subscribe();
        stream! {
            yield FeedEvent::Ready;
            while let Ok(change) = rx.recv().await {
                yield FeedEvent::Changed(change);
            }
        }
    }
}

async fn socket(url: &str) -> WsClient {
    WsClientBuilder::default().max_concurrent_requests(4).build(url).await.unwrap()
}

async fn next_data(sub: &mut Subscription<Value>) -> Value {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(10), sub.next()).await.expect("an item in 10 s").expect("open").unwrap();
        if item["type"] == "data" {
            return item["content"].clone();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_change_to_200_watchers_is_encoded_once() {
    const WATCHERS: usize = 200;
    let _alone = ALONE.lock().await;
    let (changes, _keep) = broadcast::channel(16);
    let hub = Arc::new(DynamicHub::new("feeds").register(FeedActivation { changes: changes.clone() }));
    let module = DynamicHub::arc_into_rpc_module(hub).unwrap();
    let opts = plexus_transport::websocket::UpgradeOptions::default();
    let (_server, addr) = plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(0), None, opts).await.unwrap();
    let url = format!("ws://{addr}");

    let mut watchers = Vec::new();
    for _ in 0..WATCHERS {
        let ws = socket(&url).await;
        let mut p = ObjectParams::new();
        p.insert("method", "feed.watch").unwrap();
        p.insert("params", json!({})).unwrap();
        let mut sub: Subscription<Value> = ws.subscribe("feeds.call", p, "feeds.call_unsub").await.unwrap();
        assert_eq!(next_data(&mut sub).await, json!({"type": "ready"}));
        watchers.push((ws, sub));
    }

    let change = Change {
        id: "MENGER-7".into(),
        title: "the zero-allocation item path".into(),
        status: "Coding".into(),
        labels: vec!["perf".into(), "needs-you".into()],
        body: "x".repeat(4096),
    };
    let want = serde_json::to_value(&change).unwrap();
    ENCODES.store(0, Ordering::SeqCst);
    changes.send(Shared::new(change)).unwrap();
    for (_, sub) in watchers.iter_mut() {
        assert_eq!(next_data(sub).await, want, "every watcher reads the change as it is");
    }
    let encodes = ENCODES.load(Ordering::SeqCst);
    println!("{WATCHERS} watchers, one change: {encodes} encode(s)");
    assert_eq!(encodes, 1, "one change to {WATCHERS} watchers is encoded once, not once a watcher");
}

/// PERF-9: the same on sockets in both encodings — one encode for each
/// encoding, however many watchers, and each reads its own. `ENCODES` is the
/// process's, so this test takes the count alone (`one_change_to_200…` has
/// finished or not begun: they are serialized by `ALONE`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_change_is_encoded_once_for_each_encoding() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;
    const WATCHERS: usize = 20;
    let _alone = ALONE.lock().await;
    let (changes, _keep) = broadcast::channel(16);
    let hub = Arc::new(DynamicHub::new("feeds").register(FeedActivation { changes: changes.clone() }));
    let module = DynamicHub::arc_into_rpc_module(hub).unwrap();
    let opts = plexus_transport::websocket::UpgradeOptions::default();
    let (_server, addr) = plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(0), None, opts).await.unwrap();
    let url = format!("ws://{addr}");
    // Half on JSON (jsonrpsee's client), half on msgpack.
    let mut json_clients = Vec::new();
    let mut json_watchers = Vec::new();
    for _ in 0..WATCHERS / 2 {
        let c = socket(&url).await;
        let mut p = ObjectParams::new();
        p.insert("method", "feed.watch").unwrap();
        p.insert("params", json!({})).unwrap();
        let mut sub: Subscription<Value> = c.subscribe("feeds.call", p, "feeds.call_unsub").await.unwrap();
        assert_eq!(next_data(&mut sub).await["type"], "ready");
        json_clients.push(c);
        json_watchers.push(sub);
    }
    let mut packed = Vec::new();
    for _ in 0..WATCHERS / 2 {
        let mut req = url.as_str().into_client_request().unwrap();
        req.headers_mut().insert("Sec-WebSocket-Protocol", "plexus.msgpack".parse().unwrap());
        let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let call = json!({"id": 1, "method": "feeds.call", "params": {"method": "feed.watch", "params": {}}});
        ws.send(Message::Binary(rmp_serde::to_vec_named(&call).unwrap().into())).await.unwrap();
        // The answer, then `ready`.
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(10), ws.next()).await.expect("a frame in 10 s").unwrap().unwrap();
        }
        packed.push(ws);
    }
    let before = ENCODES.load(Ordering::SeqCst);
    let change = Change { id: "A-1".into(), title: "t".into(), status: "Ready".into(), labels: vec!["x".into()], body: "b".repeat(100) };
    let want = json!({"id": "A-1", "title": "t", "status": "Ready", "labels": ["x"], "body": "b".repeat(100)});
    changes.send(Shared::new(change)).unwrap();
    for sub in &mut json_watchers {
        assert_eq!(next_data(sub).await, want);
    }
    for ws in &mut packed {
        let frame = loop {
            match tokio::time::timeout(Duration::from_secs(10), ws.next()).await.expect("a frame in 10 s").unwrap().unwrap() {
                Message::Binary(b) => break b,
                _ => continue,
            }
        };
        let v: Value = rmp_serde::from_slice(&frame).unwrap();
        assert_eq!(v["params"]["result"]["content"], want, "a msgpack watcher reads the change");
    }
    assert_eq!(ENCODES.load(Ordering::SeqCst) - before, 2, "one encode for each encoding, {WATCHERS} watchers");
}
