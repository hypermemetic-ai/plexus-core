//! NEST-11's gate: a child calls its service back, under a call it serves.
//!
//! A Rust child served by `serve_child_stdio` — `relay` — mounted by a gated
//! host beside an in-process sibling, `sibling`. While serving `relay.ask`,
//! the child calls `sibling.<method>` through `remote_child::host()` (a
//! `Transport`), and answers what came back. The host routes that call
//! through its own gate **as the caller of `relay.ask`**, within its reach:
//!
//! - a caller holding the sibling's grant gets the sibling's answer, which
//!   names that caller (not the child, not the service);
//! - a caller holding `relay.ask` but not the sibling's grant is refused —
//!   the child sees the gate's `forbidden`;
//! - a call back after the forwarded call ended is refused
//!   `unauthenticated`, naming why;
//! - the forwarded call ending ends what was made under it (a stream the
//!   child follows is dropped at the sibling);
//! - outside any call the child may ask for a schema, and nothing else.
//!
//! No test harness: this binary is the host and, run again by the seam
//! (`PLEXUS_CHILD_NAME` set), the child on stdio.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use futures::StreamExt;
use plexus_client::{MethodRef, StreamItem, Transport};
use plexus_core::plexus::remote_child::{host, HostTransport};
use plexus_core::plexus::{ChildOptions, ChildSpec, PlexusStreamItem, RemoteChild};
use plexus_core::DynamicHub;
use plexus_testkit::{Host, World, EDITOR, VIEWER};
use serde_json::{json, Value};

const RELAY_ONLY: &str = "key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

// ------------------------------------------------------------------ the sibling

/// Streams of `ticks` open now.
static TICKING: AtomicUsize = AtomicUsize::new(0);

struct Ticking;
impl Drop for Ticking {
    fn drop(&mut self) {
        TICKING.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct SiblingActivation;

/// In the host's own process.
#[plexus_macros::activation(namespace = "sibling", crate_path = "plexus_core")]
impl SiblingActivation {
    /// Who is calling, as this service's gate admitted them.
    #[plexus_macros::method]
    pub async fn get(&self) -> Value {
        let caller = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
        json!({ "sibling": "get", "caller": caller })
    }
    /// The editor's.
    #[plexus_macros::method]
    pub async fn secret(&self) -> Value {
        json!({ "sibling": "secret" })
    }
    /// A stream that never ends by itself.
    #[plexus_macros::method]
    pub async fn ticks(&self) -> impl futures::Stream<Item = u64> + Send + 'static {
        TICKING.fetch_add(1, Ordering::SeqCst);
        let guard = Ticking;
        futures::stream::unfold((0u64, guard), |(n, g)| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((n, (n + 1, g)))
        })
    }
}

// ------------------------------------------------------------------ the child

/// A transport kept past the call it was made in.
static KEPT: OnceLock<HostTransport> = OnceLock::new();
/// What the child got asking its service outside any call, at its start.
static AT_START: OnceLock<Value> = OnceLock::new();

fn sibling(m: &'static str) -> MethodRef {
    MethodRef::new("sibling", m)
}

async fn first(t: &impl Transport, m: MethodRef) -> Value {
    let items: Vec<_> = t.call(m, json!({})).collect().await;
    match items.into_iter().next() {
        Some(Ok(StreamItem::Data { content, .. })) => content,
        Some(Ok(StreamItem::Error { error, message, .. })) => json!({ "refused": serde_json::to_value(&error).unwrap(), "message": message }),
        other => json!({ "other": format!("{other:?}") }),
    }
}

#[derive(Clone)]
pub struct RelayActivation;

/// The child: it calls its service back.
#[plexus_macros::activation(namespace = "relay", crate_path = "plexus_core")]
impl RelayActivation {
    /// Ask the sibling `get` or `secret`, through the service.
    #[plexus_macros::method]
    pub async fn ask(&self, to: String) -> Value {
        let t = match host() {
            Ok(t) => t,
            Err(e) => return json!({ "no_host": e.to_string() }),
        };
        let m = if to == "secret" { sibling("secret") } else { sibling("get") };
        first(&t, m).await
    }
    /// Keep this call's transport for later.
    #[plexus_macros::method]
    pub async fn keep(&self) -> Value {
        let _ = KEPT.set(host().unwrap());
        json!("kept")
    }
    /// Use the kept transport, its call long over.
    #[plexus_macros::method]
    pub async fn later(&self) -> Value {
        first(KEPT.get().unwrap(), sibling("get")).await
    }
    /// Follow the sibling's ticks for as long as this call lasts.
    #[plexus_macros::method]
    pub async fn follow(&self) -> impl futures::Stream<Item = Value> + Send + 'static {
        let t = host().unwrap();
        async_stream::stream! {
            let mut s = t.call(sibling("ticks"), json!({}));
            while let Some(i) = s.next().await {
                match i {
                    Ok(StreamItem::Data { content, .. }) => yield content,
                    other => { yield json!({ "end": format!("{other:?}") }); break; }
                }
            }
        }
    }
    /// What the child got outside any call, at its start.
    #[plexus_macros::method]
    pub async fn started(&self) -> Value {
        AT_START.get().cloned().unwrap_or(Value::Null)
    }
}

/// The child's start: before it serves, it asks its service — outside any
/// call — for `sibling.schema` and for `sibling.get`, on the raw pipe; then
/// serves, the lines it read meanwhile first.
async fn child() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let mut out = tokio::io::stdout();
    for (id, m) in [(9001, "sibling.schema"), (9002, "sibling.get")] {
        let f = json!({ "jsonrpc": "2.0", "id": id, "method": "_host.call", "params": { "method": m, "params": {} } });
        out.write_all(format!("{f}\n").as_bytes()).await.unwrap();
    }
    out.flush().await.unwrap();
    let mut input = BufReader::new(tokio::io::stdin());
    let (mut kept, mut got, mut schema_ns, mut line) = (Vec::new(), json!({}), None, String::new());
    while schema_ns.is_none() || got.get("plain").is_none() {
        line.clear();
        if input.read_line(&mut line).await.unwrap() == 0 {
            return;
        }
        let v: Value = serde_json::from_str(&line).unwrap_or_default();
        match (v.get("id").and_then(Value::as_u64), v.get("method").and_then(Value::as_str)) {
            (Some(9001), None) => {}
            (Some(9002), None) => got["plain"] = v["error"].clone(),
            (None, Some("_host.call")) => {
                if let Some(ns) = v["params"]["result"]["content"]["namespace"].as_str() {
                    schema_ns = Some(ns.to_string());
                }
            }
            _ => kept.extend_from_slice(line.as_bytes()),
        }
    }
    got["schema_namespace"] = json!(schema_ns);
    let _ = AT_START.set(got);
    let r = std::io::Cursor::new(kept).chain(input);
    plexus_core::plexus::remote_child::serve_child(RelayActivation, r, tokio::io::stdout()).await.unwrap();
}

// ------------------------------------------------------------------ the host

/// VIEWER: relay.* and sibling.get/ticks; EDITOR: all; RELAY_ONLY: relay.* alone.
async fn host_and_child() -> (Host, RemoteChild) {
    // A child mounted at a service's start asks, at its own start, before
    // that service exists: it is told the service it will be in. (A child
    // connected inside a call — plexus-dyn's `grow` — learns it from the call.)
    let before = std::sync::Arc::new(DynamicHub::new("host").register(SiblingActivation));
    let spec: ChildSpec = format!("relay=stdio:{}", std::env::current_exe().unwrap().display()).parse().unwrap();
    let child = RemoteChild::connect(spec, ChildOptions::for_service("host").with_host(&before).with_legacy_upcalls(true)).await.expect("the child mounts");
    std::mem::forget(before);
    let relay = ["relay.ask", "relay.keep", "relay.later", "relay.follow", "relay.started"];
    let viewer: Vec<&str> = relay.iter().copied().chain(["sibling.get", "sibling.ticks"]).collect();
    let editor: Vec<&str> = viewer.iter().copied().chain(["sibling.secret"]).collect();
    let host = World::new().host().with(SiblingActivation).with(child.clone());
    let host = host.roles([("viewer", viewer), ("editor", editor), ("relayer", relay.to_vec())]).member(RELAY_ONLY, "relayer").await;
    (host, child)
}

// ------------------------------------------------------------------ the rows

/// The call back is routed as the forwarded call's caller: the sibling
/// names the viewer.
async fn the_child_calls_a_sibling_as_the_original_caller() {
    let (host, child) = host_and_child().await;
    let at_start = child.stats().calls_back;
    let got = host.as_(VIEWER).call("relay.ask", json!({ "to": "get" })).await.values();
    assert_eq!(got[0], json!({ "sibling": "get", "caller": VIEWER }), "{got:?}");
    let got = host.as_(EDITOR).call("relay.ask", json!({ "to": "get" })).await.values();
    assert_eq!(got[0]["caller"], EDITOR, "{got:?}");
    assert_eq!(child.stats().calls_back - at_start, 2, "the schema at its start, then one a call");
    assert_eq!(child.calls_open_back(), 0, "each forwarded call ended, and its standing with it");
}

/// The gate applies as the original caller: one without the sibling's
/// grant is refused, though the child is the service's own.
async fn a_caller_without_the_siblings_grant_is_refused() {
    let (host, _child) = host_and_child().await;
    let got = host.as_(RELAY_ONLY).call("relay.ask", json!({ "to": "get" })).await.values();
    assert_eq!(got[0]["refused"]["kind"], "forbidden", "{got:?}");
    assert!(got[0]["message"].as_str().unwrap().contains("sibling.get"), "{got:?}");
    let got = host.as_(VIEWER).call("relay.ask", json!({ "to": "secret" })).await.values();
    assert_eq!(got[0]["refused"]["kind"], "forbidden", "a viewer holds no sibling.secret: {got:?}");
    let got = host.as_(EDITOR).call("relay.ask", json!({ "to": "secret" })).await.values();
    assert_eq!(got[0], json!({ "sibling": "secret" }), "{got:?}");
}

/// Outside a live forwarded call, a call back is refused `unauthenticated`,
/// naming why.
async fn a_call_back_after_its_call_ended_is_refused() {
    let (host, _child) = host_and_child().await;
    let kept = host.as_(VIEWER).call("relay.keep", json!({})).await.values();
    assert_eq!(kept[0], "kept");
    let got = host.as_(VIEWER).call("relay.later", json!({})).await.values();
    assert_eq!(got[0]["refused"]["kind"], "unauthenticated", "{got:?}");
    assert!(got[0]["message"].as_str().unwrap().contains("no call"), "{got:?}");
}

/// The forwarded call ends (its caller lets go): the stream the child was
/// following through the service is dropped at the sibling.
async fn the_forwarded_call_ending_ends_what_was_made_under_it() {
    let (host, child) = host_and_child().await;
    let before = TICKING.load(Ordering::SeqCst);
    {
        let mut s = host.as_(VIEWER).stream("relay.follow", json!({})).await.unwrap();
        let mut seen = vec![];
        while seen.len() < 3 {
            if let Some(PlexusStreamItem::Data { content, .. }) = s.next().await {
                seen.push(content.into_value());
            }
        }
        assert_eq!(seen, [json!(0), json!(1), json!(2)]);
        assert_eq!(TICKING.load(Ordering::SeqCst), before + 1, "the sibling streams while the call lasts");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TICKING.load(Ordering::SeqCst) != before {
        assert!(std::time::Instant::now() < deadline, "the sibling's stream outlived the call it was made under");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(child.calls_open_back(), 0);
}

/// At its start, outside any call: a schema is answered (the service's
/// whole description), anything else refused `unauthenticated`.
async fn outside_a_call_only_a_schema_is_answered() {
    let (host, _child) = host_and_child().await;
    let got = host.as_(VIEWER).call("relay.started", json!({})).await.values();
    assert_eq!(got[0]["schema_namespace"], "sibling", "{got:?}");
    assert_eq!(got[0]["plain"]["code"], -32001, "{got:?}");
    assert!(got[0]["plain"]["message"].as_str().unwrap().contains("only for a schema"), "{got:?}");
}

/// A call with no hop at all (a child that is not served through the seam)
/// has no service to call.
async fn no_host_outside_the_seam() {
    let got = RelayActivation.ask("get".into()).await;
    assert!(got["no_host"].as_str().is_some_and(|w| w.contains("outside a call")), "{got:?}");
}

fn main() {
    if std::env::var_os("PLEXUS_CHILD_NAME").is_some() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(child());
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        macro_rules! run {
            ($($t:ident),*) => {{ let mut n = 0; $( $t().await; println!("test {} ... ok", stringify!($t)); n += 1; )* n }};
        }
        let n = run!(
            the_child_calls_a_sibling_as_the_original_caller,
            a_caller_without_the_siblings_grant_is_refused,
            a_call_back_after_its_call_ended_is_refused,
            the_forwarded_call_ending_ends_what_was_made_under_it,
            outside_a_call_only_a_schema_is_answered,
            no_host_outside_the_seam
        );
        println!("\ntest result: ok. {n} passed; 0 failed");
    });
}
