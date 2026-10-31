//! PERF-9 (spec/13): the hop speaks msgpack to a child that offers it.
//!
//! `RemoteChild` asks for msgpack, then JSON — on stdio as its first line's
//! request (`plexus.encoding {encodings: ["msgpack","json"]}`), over a
//! WebSocket in `Sec-WebSocket-Protocol` — and speaks what the child picks.
//! plexus-wire's reference echo offers both on stdio, and a plexus-transport
//! socket offers both; the kit's stub child predates spec/13 and is spoken to
//! in JSON, on stdio (it
//! answers the request `-32601`) and over a socket (its 101 names no
//! subprotocol: dialed again, asking for nothing). Through the hop, the
//! same calls answer the same items in either encoding.

#[allow(dead_code)]
mod child_support;

#[path = "../../plexus-wire/reference/echo-rs/src/echo.rs"]
#[allow(dead_code)]
mod echo;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use futures::StreamExt;
use plexus_core::plexus::wire::WireEncoding;
use plexus_core::plexus::{ChildOptions, ChildSpec, PlexusStreamItem, RemoteChild};
use plexus_core::DynamicHub;
use serde_json::{json, Value};

/// plexus-wire's reference echo as a program: `PLEXUS_ECHO_RS`, else built
/// (debug, its own workspace) into `CARGO_TARGET_TMPDIR/echo-rs`.
fn echo_rs() -> PathBuf {
    if let Some(p) = std::env::var_os("PLEXUS_ECHO_RS") {
        return PathBuf::from(p);
    }
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("echo-rs");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-wire/reference/echo-rs/Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--bin", "echo-rs", "--manifest-path"])
        .arg(manifest)
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .expect("cargo ran");
    assert!(out.status.success(), "echo-rs did not build:\n{}", String::from_utf8_lossy(&out.stderr));
    target.join("debug/echo-rs")
}

fn stdio(name: &str, argv: Vec<String>) -> ChildSpec {
    ChildSpec::Stdio { name: name.into(), argv }
}

fn asking(encodings: Vec<WireEncoding>) -> ChildOptions {
    ChildOptions { encodings, ..ChildOptions::for_service("svc") }
}

/// `method` through a service that mounts `child` as `echo`, by its own
/// caller (no gate): the items as JSON, timestamps and hashes aside.
async fn through(child: &RemoteChild, method: &str, params: Value) -> Vec<Value> {
    let hub = DynamicHub::new("svc").register(child.clone());
    let s = hub.route(method, params, None).await.expect("routed");
    s.map(|i: PlexusStreamItem| {
        let mut v = serde_json::to_value(&i).unwrap();
        if let Some(m) = v.get_mut("metadata").and_then(Value::as_object_mut) {
            m.insert("timestamp".into(), json!(0));
            m.insert("plexus_hash".into(), json!(""));
        }
        v
    })
    .collect()
    .await
}

const CALLS: &[(&str, &str)] = &[
    ("echo.echo", r#"{"text":"a \"quoted\" ✓ line\nbreak","times":3}"#),
    ("echo.count", r#"{"to":50}"#),
    ("echo.fail", r#"{"kind":"not_found"}"#),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stdio_child_that_offers_msgpack_is_spoken_to_in_msgpack() {
    let program = echo_rs().to_string_lossy().into_owned();
    let packed = RemoteChild::connect(stdio("echo", vec![program.clone(), "--stdio".into()]), asking(WireEncoding::ALL.to_vec())).await.unwrap();
    assert_eq!(packed.encoding(), Some(WireEncoding::Msgpack), "echo-rs offers msgpack: the hop speaks it");
    let plain = RemoteChild::connect(stdio("echo", vec![program.clone(), "--stdio".into()]), asking(vec![WireEncoding::Json])).await.unwrap();
    assert_eq!(plain.encoding(), Some(WireEncoding::Json), "asked for JSON alone");
    let json_only = RemoteChild::connect(stdio("echo", vec![program, "--stdio".into(), "--wire-encodings".into(), "json".into()]), asking(WireEncoding::ALL.to_vec()))
        .await
        .unwrap();
    assert_eq!(json_only.encoding(), Some(WireEncoding::Json), "a child that offers JSON alone picks it");
    for (method, params) in CALLS {
        let params: Value = serde_json::from_str(params).unwrap();
        let a = through(&packed, method, params.clone()).await;
        let b = through(&plain, method, params.clone()).await;
        let c = through(&json_only, method, params).await;
        assert!(matches!(a.last().map(|i| i["type"].as_str()), Some(Some("done" | "error"))), "{method}: a terminal item: {a:?}");
        assert_eq!(a, b, "{method}: the same items through a msgpack link and a JSON one");
        assert_eq!(b, c, "{method}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stdio_child_from_before_spec_13_is_spoken_to_in_json() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("stub.log");
    let argv = vec!["python3".into(), "-I".into(), child_support::stub().to_string_lossy().into_owned(), "--log".into(), log.display().to_string()];
    let t0 = Instant::now();
    let child = RemoteChild::connect(stdio("echo", argv), asking(WireEncoding::ALL.to_vec())).await.unwrap();
    assert!(t0.elapsed() < Duration::from_secs(3), "the request is answered (-32601), not waited out: {:?}", t0.elapsed());
    assert_eq!(child.encoding(), Some(WireEncoding::Json));
    let items = through(&child, "echo.echo", json!({"text": "hi", "times": 2})).await;
    assert_eq!(items.iter().filter(|i| i["type"] == "data").count(), 2, "{items:?}");
}

/// A child on a WebSocket served by plexus-transport (which offers msgpack
/// and JSON): spec/12's surface — `_info`, `echo.call` for `echo.schema` and
/// `echo.echo`, `echo.call_unsub` — written as a raw method table, so the
/// socket's loop crosses its JSON frames to msgpack for a msgpack client.
async fn ws_child() -> u16 {
    use jsonrpsee::{PendingSubscriptionSink, RpcModule};
    use plexus_core::plexus::Activation;
    let mut schema = serde_json::to_value(echo::EchoActivation.plugin_schema()).unwrap();
    schema["namespace"] = json!("echo");
    let meta = || json!({"provenance": ["echo"], "plexus_hash": "h", "timestamp": 1});
    let mut m = RpcModule::new(());
    m.register_subscription("_info", "_info", "_info_unsub", move |_, pending: PendingSubscriptionSink, _, _| async move {
        let sink = pending.accept().await?;
        let content = json!({"backend": "echo"});
        sink.send(serde_json::value::to_raw_value(&json!({"type": "data", "metadata": meta(), "content_type": "_info", "content": content}))?).await?;
        sink.send(serde_json::value::to_raw_value(&json!({"type": "done", "metadata": meta()}))?).await?;
        Ok(())
    })
    .unwrap();
    m.register_subscription("echo.call", "echo.call", "echo.call_unsub", move |params, pending: PendingSubscriptionSink, _, _| {
        let schema = schema.clone();
        async move {
            let p: Value = params.parse()?;
            let sink = pending.accept().await?;
            let data = |ct: &str, content: Value| json!({"type": "data", "metadata": meta(), "content_type": ct, "content": content});
            match p["method"].as_str() {
                Some("echo.schema") => sink.send(serde_json::value::to_raw_value(&data("echo.schema", schema))?).await?,
                Some("echo.echo") => {
                    let text = p["params"]["text"].as_str().unwrap_or("").to_string();
                    for _ in 0..p["params"]["times"].as_u64().unwrap_or(1) {
                        sink.send(serde_json::value::to_raw_value(&data("echo.echo", json!({"type": "said", "text": text})))?).await?;
                    }
                }
                other => panic!("the test child has no {other:?}"),
            }
            sink.send(serde_json::value::to_raw_value(&json!({"type": "done", "metadata": meta()}))?).await?;
            Ok(())
        }
    })
    .unwrap();
    let (handle, addr) = plexus_transport::websocket::serve_websocket_with(m, plexus_transport::WebSocketConfig::new(0), None, Default::default()).await.unwrap();
    std::mem::forget(handle);
    addr.port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_child_that_offers_msgpack_is_spoken_to_in_msgpack() {
    let port = ws_child().await;
    let spec = ChildSpec::Ws { name: "echo".into(), url: format!("ws://127.0.0.1:{port}") };
    let packed = RemoteChild::connect(spec.clone(), asking(WireEncoding::ALL.to_vec())).await.unwrap();
    assert_eq!(packed.encoding(), Some(WireEncoding::Msgpack), "a plexus-transport socket offers msgpack: the hop speaks it");
    let plain = RemoteChild::connect(spec, asking(vec![])).await.unwrap();
    assert_eq!(plain.encoding(), Some(WireEncoding::Json), "asking for nothing: JSON");
    let params = json!({"text": "a \"quoted\" ✓ line\nbreak", "times": 3});
    let a = through(&packed, "echo.echo", params.clone()).await;
    let b = through(&plain, "echo.echo", params).await;
    assert_eq!(a.iter().filter(|i| i["type"] == "data").count(), 3, "{a:?}");
    assert_eq!(a, b, "the same items through a msgpack socket and a JSON one");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_child_from_before_spec_13_is_dialed_again_in_json() {
    let dir = tempfile::tempdir().unwrap();
    let key = child_support::test_key(dir.path(), "svc", [7u8; 32]);
    let stub = child_support::ws_stub(dir.path(), &key.principal, &[]);
    let spec = ChildSpec::Ws { name: "echo".into(), url: format!("ws://127.0.0.1:{}", stub.port) };
    let child = RemoteChild::connect(spec, ChildOptions { key: Some(key.path.clone()), ..asking(WireEncoding::ALL.to_vec()) }).await.unwrap();
    assert_eq!(child.encoding(), Some(WireEncoding::Json), "its 101 names no subprotocol: JSON, on a second dial");
    let items = through(&child, "echo.echo", json!({"text": "hi", "times": 2})).await;
    assert_eq!(items.iter().filter(|i| i["type"] == "data").count(), 2, "{items:?}");
}
