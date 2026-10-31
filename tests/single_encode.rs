//! PERF-7: an item encoded once from its typed event is today's frame, as
//! JSON (the owner's `json-bytes`, 2026-10-30: frames are compared as JSON;
//! the content's keys may come in the type's order, where a `Value` sorts
//! them).
//!
//! A property over the shapes serde gives an event — internally tagged and
//! untagged enums, a flattened map, a field skipped when empty, renamed and
//! empty keys, integer map keys, every number edge (NaN and the infinities
//! are `null`, `-0.0`, `u64::MAX`, `i64::MIN`), strings that need escaping,
//! a raw JSON field, a credential (whose item is assembled as today's, the
//! `_credentials` envelope beside it), a plain string, a bare `Value` —
//! generated from a seed, a thousand items a run. Each is read three ways:
//! in process (`route()`, today's path: the event to a `Value`), over
//! plexus-transport's WebSocket (the socket loop's frames) and through the
//! RPC module (jsonrpsee's sink). The two wire paths must read as the
//! in-process item, as JSON.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use futures::stream::{Stream, StreamExt};
use jsonrpsee::core::client::{Subscription, SubscriptionClientT};
use jsonrpsee::core::params::ObjectParams;
use jsonrpsee::ws_client::WsClientBuilder;
use plexus_auth_core::credential::{Credential, CredentialMinter};
use plexus_auth_core::{AttachmentSite, CredentialIssuer, CredentialKind, CredentialMetadata, CredentialScheme, HeaderName, MethodPath, Origin, Scope};
use plexus_core::plexus::PlexusStreamItem;
use plexus_core::DynamicHub;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// A seeded generator (xorshift64*): the same items every run of a seed.
// ---------------------------------------------------------------------------

struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn text(&mut self) -> String {
        const PIECES: &[&str] = &["a", "Z", "0", " ", "\"", "\\", "/", "\n", "\t", "\r", "\u{0}", "\u{1f}", "\u{7f}", "é", "ü", "😀", "𝄞", "</script>", "\u{2028}", "{}", "[]", ":", ","];
        (0..self.below(24)).map(|_| PIECES[self.below(PIECES.len() as u64) as usize]).collect()
    }
    fn float(&mut self) -> f64 {
        const EDGES: &[f64] = &[0.0, -0.0, 0.1, -1.5, 1e300, -1e-300, 5e-324, f64::MAX, f64::MIN_POSITIVE, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 123456789.0, 0.3];
        if self.coin() {
            EDGES[self.below(EDGES.len() as u64) as usize]
        } else {
            (self.next() as i64) as f64 / (self.below(1000) as f64 + 1.0)
        }
    }
    fn int(&mut self) -> i64 {
        const EDGES: &[i64] = &[0, -1, 1, i64::MIN, i64::MAX, 9_007_199_254_740_993];
        if self.coin() {
            EDGES[self.below(EDGES.len() as u64) as usize]
        } else {
            self.next() as i64
        }
    }
    fn value(&mut self, depth: u32) -> Value {
        match self.below(if depth > 3 { 5 } else { 7 }) {
            0 => Value::Null,
            1 => json!(self.coin()),
            2 => json!(self.int()),
            3 => json!(self.float()),
            4 => json!(self.text()),
            5 => Value::Array((0..self.below(4)).map(|_| self.value(depth + 1)).collect()),
            _ => Value::Object((0..self.below(5)).map(|_| (self.text(), self.value(depth + 1))).collect()),
        }
    }
}

// ---------------------------------------------------------------------------
// The shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ShapeEvent {
    Unit,
    Fields {
        zulu: u64,
        alpha: i64,
        mike: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        maybe: Option<String>,
        always: Option<String>,
        floats: Vec<f64>,
        by_number: BTreeMap<u32, String>,
        nested: Value,
        flag: bool,
    },
    Flattened {
        id: String,
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    Raw {
        #[schemars(with = "Value")]
        raw: Box<RawValue>,
    },
    Renamed {
        #[serde(rename = "Weird Key")]
        weird: String,
        #[serde(rename = "")]
        empty: u8,
        #[serde(rename = "type_")]
        not_the_tag: String,
    },
    Login {
        user: String,
        #[schemars(with = "Value")]
        #[serde(skip_deserializing, default = "read_back")]
        session: Credential<String>,
    },
    Inner(Inner),
    #[serde(untagged)]
    Loose { anything: Value },
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct Inner {
    b: Vec<Option<i64>>,
    a: (String, u8),
}

impl plexus_client::FromClientError for ShapeEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        ShapeEvent::Loose { anything: json!(error.to_string()) }
    }
}

/// A credential is never read back from the wire (the client sees its
/// sentinel); deserializing one mints a stand-in.
fn read_back() -> Credential<String> {
    CredentialMinter::new_for_test(issuer()).mint(String::new(), bearer())
}

fn issuer() -> CredentialIssuer {
    CredentialIssuer::new(Origin::new("ws://test"), MethodPath::try_new("auth.login").unwrap())
}

fn bearer() -> CredentialMetadata {
    CredentialMetadata::new(
        CredentialKind::Bearer,
        AttachmentSite::Header { name: HeaderName::try_new("authorization").unwrap() },
        Some(CredentialScheme::new("Bearer ")),
        Vec::<Scope>::new(),
        None,
        None,
        None,
        issuer(),
    )
}

fn shape(g: &mut Gen, minter: &CredentialMinter) -> ShapeEvent {
    match g.below(8) {
        0 => ShapeEvent::Unit,
        1 => ShapeEvent::Fields {
            zulu: g.next(),
            alpha: g.int(),
            mike: g.text(),
            maybe: g.coin().then(|| g.text()),
            always: g.coin().then(|| g.text()),
            floats: (0..g.below(5)).map(|_| g.float()).collect(),
            by_number: (0..g.below(4)).map(|_| (g.next() as u32, g.text())).collect(),
            nested: g.value(0),
            flag: g.coin(),
        },
        2 => ShapeEvent::Flattened { id: g.text(), extra: (0..g.below(4)).map(|_| (format!("k{}", g.below(100)), g.value(1))).collect() },
        3 => ShapeEvent::Raw { raw: RawValue::from_string(format!("{{ \"z\" : [1, 2.5, \"{}\"], \"a\":{{}} }}", g.below(1000))).unwrap() },
        4 => ShapeEvent::Renamed { weird: g.text(), empty: g.below(256) as u8, not_the_tag: g.text() },
        5 => ShapeEvent::Login { user: g.text(), session: minter.mint(format!("jwt-{}", g.next()), bearer()) },
        6 => ShapeEvent::Inner(Inner { b: (0..g.below(4)).map(|_| g.coin().then(|| g.int())).collect(), a: (g.text(), g.below(256) as u8) }),
        _ => ShapeEvent::Loose { anything: g.value(0) },
    }
}

#[derive(Clone)]
struct ShapesActivation;

#[plexus_macros::activation(version = "1.0.0", description = "Every shape serde gives an event")]
impl ShapesActivation {
    /// `n` events from `seed`.
    #[plexus_macros::method(streaming)]
    async fn all(&self, seed: u64, n: u64) -> impl Stream<Item = ShapeEvent> + Send + 'static {
        let minter = CredentialMinter::new_for_test(issuer());
        let mut g = Gen(seed | 1);
        let events: Vec<ShapeEvent> = (0..n).map(|_| shape(&mut g, &minter)).collect();
        stream! {
            for e in events {
                yield e;
            }
        }
    }
}

#[derive(Clone)]
struct TextActivation;

#[plexus_macros::activation(version = "1.0.0", description = "A string an item")]
impl TextActivation {
    /// `n` strings from `seed`.
    #[plexus_macros::method(streaming)]
    async fn all(&self, seed: u64, n: u64) -> impl Stream<Item = String> + Send + 'static {
        let mut g = Gen(seed | 1);
        let texts: Vec<String> = (0..n).map(|_| g.text()).collect();
        stream! {
            for t in texts {
                yield t;
            }
        }
    }
}

/// A bare `Value` an item, as `_info` sends one.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
struct Bare(Value);

impl plexus_client::FromClientError for Bare {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        Bare(json!(error.to_string()))
    }
}

#[derive(Clone)]
struct JsonActivation;

#[plexus_macros::activation(version = "1.0.0", description = "A bare Value an item")]
impl JsonActivation {
    /// `n` values from `seed`.
    #[plexus_macros::method(streaming)]
    async fn all(&self, seed: u64, n: u64) -> impl Stream<Item = Bare> + Send + 'static {
        let mut g = Gen(seed | 1);
        let values: Vec<Bare> = (0..n).map(|_| Bare(g.value(0))).collect();
        stream! {
            for v in values {
                yield v;
            }
        }
    }
}

fn lab() -> Arc<DynamicHub> {
    Arc::new(DynamicHub::new("lab").register(ShapesActivation).register(TextActivation).register(JsonActivation))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// An item as compared: its clock at 0, each credential's id `<id>` (a call
/// mints its own).
fn steady(item: Value) -> Value {
    let text = serde_json::to_string(&item).unwrap();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("cred_") {
        out.push_str(&rest[..at]);
        out.push_str("cred_<id>");
        rest = rest[at + 5..].trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '-');
    }
    out.push_str(rest);
    let mut v: Value = serde_json::from_str(&out).unwrap();
    if let Some(m) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        m.insert("timestamp".into(), json!(0));
    }
    v
}

async fn in_process(hub: &DynamicHub, method: &str, params: &Value) -> Vec<Value> {
    let stream = hub.route(method, params.clone(), None).await.unwrap();
    stream.map(|i: PlexusStreamItem| steady(serde_json::to_value(&i).unwrap())).collect().await
}

async fn over_socket(url: &str, method: &str, params: &Value) -> Vec<Value> {
    let ws = WsClientBuilder::default().max_buffer_capacity_per_subscription(4096).build(url).await.unwrap();
    let mut p = ObjectParams::new();
    p.insert("method", method).unwrap();
    p.insert("params", params.clone()).unwrap();
    let mut sub: Subscription<Value> = ws.subscribe("lab.call", p, "lab.call_unsub").await.unwrap();
    let mut out = Vec::new();
    loop {
        let item = tokio::time::timeout(Duration::from_secs(10), sub.next()).await.expect("an item in 10 s").expect("open").unwrap();
        let done = item["type"] == "done";
        out.push(steady(item));
        if done {
            return out;
        }
    }
}

async fn over_module(hub: &Arc<DynamicHub>, method: &str, params: &Value) -> Vec<Value> {
    let module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "lab.call", "params": {"method": method, "params": params}});
    let (_resp, mut rx) = module.raw_json_request(&req.to_string(), 4096).await.unwrap();
    let mut out = Vec::new();
    while let Ok(Some(m)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        let v: Value = serde_json::from_str(m.get()).unwrap();
        let item = v["params"]["result"].clone();
        let done = item["type"] == "done";
        out.push(steady(item));
        if done {
            break;
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_single_encode_is_todays_frame_as_json_for_every_shape() {
    let hub = lab();
    let module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    let (_server, addr) =
        plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(0), None, Default::default()).await.unwrap();
    let url = format!("ws://{addr}");
    let mut kinds = BTreeMap::<String, usize>::new();
    for seed in [1u64, 7, 42, 2026, 0xdead_beef] {
        for method in ["shapes.all", "text.all", "json.all"] {
            let params = json!({"seed": seed, "n": 200});
            let here = in_process(&hub, method, &params).await;
            assert_eq!(here.len(), 201, "{method}: 200 items and done");
            for item in &here {
                let k = item["content"]["type"].as_str().unwrap_or(item["type"].as_str().unwrap_or("?")).to_string();
                *kinds.entry(format!("{method}:{k}")).or_default() += 1;
            }
            let wire = over_socket(&url, method, &params).await;
            assert_eq!(wire.len(), here.len(), "{method} seed {seed}: as many items on the socket");
            for (n, (w, h)) in wire.iter().zip(&here).enumerate() {
                assert_eq!(w, h, "{method} seed {seed} item {n}: the socket's frame is not today's as JSON");
            }
            let moduled = over_module(&hub, method, &params).await;
            assert_eq!(moduled, here, "{method} seed {seed}: the module's frames are not today's as JSON");
        }
    }
    println!("kinds compared: {kinds:?}");
    for k in ["unit", "fields", "flattened", "raw", "renamed", "login", "inner"] {
        assert!(kinds.contains_key(&format!("shapes.all:{k}")), "the seeds reach {k}: {kinds:?}");
    }
    // A credential's item carries its envelope, as today's does.
    let login = in_process(&hub, "shapes.all", &json!({"seed": 5, "n": 64})).await;
    let with_envelope = login.iter().filter(|i| i["content"]["type"] == "login").find(|i| i["content"].get("_credentials").is_some());
    assert!(with_envelope.is_some(), "a credential's item carries `_credentials`");
}

/// The socket's frames are the events' own encoding: a `fields` item's keys
/// in its type's order (`zulu` before `alpha`), where a `Value` would sort
/// them — the frame was written once from the event, not through a `Value`.
/// Read raw, as the bytes the socket carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sockets_frame_is_the_events_own_encoding() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let module = DynamicHub::arc_into_rpc_module(lab()).unwrap();
    let (_server, addr) =
        plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(0), None, Default::default()).await.unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}")).await.unwrap();
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "lab.call", "params": {"method": "shapes.all", "params": {"seed": 7, "n": 200}}});
    ws.send(Message::Text(call.to_string().into())).await.unwrap();
    let mut fields = 0;
    loop {
        let text = match tokio::time::timeout(Duration::from_secs(10), ws.next()).await.expect("a frame in 10 s").unwrap().unwrap() {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };
        if text.contains(r#""content":{"type":"fields""#) {
            fields += 1;
            let (z, a) = (text.find(r#""zulu":"#).unwrap(), text.find(r#""alpha":"#).unwrap());
            assert!(z < a, "the event's keys in its type's order on the wire: {text}");
        }
        if text.contains(r#""result":{"type":"done""#) {
            break;
        }
    }
    assert!(fields > 0, "the seed reached `fields`");
}
