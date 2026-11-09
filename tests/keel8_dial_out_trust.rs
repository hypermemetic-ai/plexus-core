//! KEEL-8 · a dial-out believes its relay only as the key the relay proves.
//! No trusted key: refused before dialing. At each connect the relay
//! proves the trusted key at `_info {nonce}` (DYNAUTH-5's proof, the one a
//! mount asks of its child); one that proves none, another, or a forged
//! one is refused, and no call of its is run. A hop is believed only when
//! it names the proven key — the socket is never `ChildPeer::Pipe`. The
//! dial takes a mount's TLS (`tls_roots`) and its connect timeout.
//!
//!   cargo test -p plexus-core --test keel8_dial_out_trust
//!   cargo test -p plexus-core --features child-wss --test keel8_dial_out_trust

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_stream::stream;
use futures::{SinkExt, Stream, StreamExt};
use plexus_core::plexus::peer_token::PeerKey;
use plexus_core::plexus::remote_child::{DialOut, DialState, Exposed};
use plexus_core::plexus::{PlexusStreamItem, StreamMetadata};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Counts every call it runs: what a refused relay must leave at 0.
#[derive(Clone, Default)]
pub struct CountedActivation {
    runs: Arc<AtomicUsize>,
}

#[plexus_macros::activation(crate_path = "plexus_core", version = "0.1.0", description = "counts its runs")]
impl CountedActivation {
    /// Run once.
    #[plexus_macros::method]
    async fn hit(&self) -> impl Stream<Item = String> + Send + 'static {
        self.runs.fetch_add(1, Ordering::SeqCst);
        stream! { yield "hit".to_string(); }
    }
}

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MALLORY: &str = "key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// A key file (0600) in `dir`: the dialing service's own.
fn key_file(dir: &std::path::Path) -> std::path::PathBuf {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("svc.key");
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([11u8; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// How the stand-in relay answers `_info {nonce}`.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Proves {
    /// The trusted key, signed by it.
    Trusted,
    /// No key at all (a plain service's `_info`).
    Nothing,
    /// Another key, properly signed by that key.
    Other,
    /// The trusted key named, signed by another.
    Forged,
    /// The trusted key, but the offer's answer names another principal.
    NamesOther,
}

/// A call into the dialed-out service, as a relay sends it: `hop.principal`
/// the service acting.
fn call(id: &str, principal: &str) -> Value {
    let hop = json!({ "principal": principal, "for": [ADA], "limit": { "grant": "counted.hit", "held_on": ["*"] }, "call": id });
    json!({ "jsonrpc": "2.0", "id": id, "method": "counted.call", "params": { "method": "counted.hit", "params": {}, "hop": hop } })
}

/// A stand-in relay on loopback: proves as `proves`, sends a call before
/// `_info` is answered (`early`), one right after (`after-info`, when it
/// proves badly), and — once the offer is answered — one under the trusted
/// key (`good`) and one under another (`bad`). Every frame it is sent comes
/// out of the receiver.
async fn stand_in(trusted: Arc<PeerKey>, proves: Proves) -> (u16, mpsc::UnboundedReceiver<Value>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let other = PeerKey::generate();
        while let Ok((tcp, _)) = listener.accept().await {
            let (trusted, tx) = (Arc::clone(&trusted), tx.clone());
            let other = other.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                let _ = ws.send(Message::text(call("early", trusted.kid()).to_string())).await;
                while let Some(Ok(m)) = ws.next().await {
                    let Message::Text(t) = m else { continue };
                    let v: Value = serde_json::from_str(&t).unwrap_or_default();
                    let _ = tx.send(v.clone());
                    let (id, method) = (v["id"].clone(), v["method"].as_str().unwrap_or_default().to_string());
                    let mut out = Vec::new();
                    if method == "_info" {
                        let nonce = v["params"]["nonce"].as_str().unwrap_or_default();
                        let mut content = json!({ "backend": "relay" });
                        match proves {
                            Proves::Trusted | Proves::NamesOther => {
                                content["key"] = json!(trusted.kid());
                                content["proof"] = json!(trusted.key_proof(nonce, "relay"));
                            }
                            Proves::Nothing => {}
                            Proves::Other => {
                                content["key"] = json!(other.kid());
                                content["proof"] = json!(other.key_proof(nonce, "relay"));
                            }
                            Proves::Forged => {
                                content["key"] = json!(trusted.kid());
                                content["proof"] = json!(other.key_proof(nonce, "relay"));
                            }
                        }
                        let md = StreamMetadata::new(vec!["relay".into()], "0".into());
                        out.push(json!({ "jsonrpc": "2.0", "id": id, "result": "s1" }));
                        out.push(json!({ "jsonrpc": "2.0", "method": "_info", "params": { "subscription": "s1", "result": PlexusStreamItem::data(md.clone(), "_info".into(), content) } }));
                        out.push(json!({ "jsonrpc": "2.0", "method": "_info", "params": { "subscription": "s1", "result": PlexusStreamItem::done(md) } }));
                        if !matches!(proves, Proves::Trusted | Proves::NamesOther) {
                            out.push(call("after-info", trusted.kid()));
                        }
                    } else if method == "relay.offer" {
                        let principal = if proves == Proves::NamesOther { MALLORY.to_string() } else { trusted.kid().to_string() };
                        out.push(json!({ "jsonrpc": "2.0", "id": id, "result": { "offered": true, "mount": "c", "path": "peers.c", "service": { "principal": principal } } }));
                        if proves == Proves::Trusted {
                            out.push(call("good", trusted.kid()));
                            out.push(call("bad", MALLORY));
                        }
                    }
                    for f in out {
                        if ws.send(Message::text(f.to_string())).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (port, rx)
}

/// What the dialed-out side answered to each call of `ids`: its first item
/// that is not `done`, or the JSON-RPC error that refused it.
async fn answers(rx: &mut mpsc::UnboundedReceiver<Value>, ids: &[&str]) -> std::collections::HashMap<String, Value> {
    let mut sids = std::collections::HashMap::new();
    let mut got = std::collections::HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while got.len() < ids.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        let v = tokio::time::timeout(left, rx.recv()).await.unwrap_or_else(|_| panic!("no answer to all of {ids:?}: {got:?}")).expect("the relay ended");
        if let Some(id) = v["id"].as_str().filter(|i| ids.contains(i)) {
            match v.get("error") {
                Some(e) => {
                    got.insert(id.to_string(), json!({ "refused": e }));
                }
                None => {
                    sids.insert(v["result"].to_string(), id.to_string());
                }
            }
            continue;
        }
        if let Some(id) = sids.get(&v["params"]["subscription"].to_string()) {
            let item = &v["params"]["result"];
            if item["type"] != "done" {
                got.entry(id.clone()).or_insert_with(|| item.clone());
            }
        }
    }
    got
}

// ------------------------------------------------------------------ acceptance 1

/// No trusted key — or one that is not a key — and the dial-out is refused
/// before dialing, naming what is missing; nothing reaches the listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_out_with_no_trusted_key_is_refused_before_dialing() {
    let dir = tempfile::tempdir().unwrap();
    let k = key_file(dir.path());
    let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let url = format!("ws://127.0.0.1:{}/ws", trap.local_addr().unwrap().port());
    for (opts, says) in [(DialOut::new(url.clone(), &k).mount("c"), "no trusted key"), (DialOut::new(url.clone(), &k).mount("c").trust("service:relay"), "is not a key")] {
        let exposed = Exposed::new(opts);
        let t = Instant::now();
        exposed.serve(CountedActivation::default());
        let _ = exposed.mounted(Duration::from_secs(10)).await;
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        match exposed.state() {
            DialState::Refused { why } => assert!(why.contains(says), "{why}"),
            other => panic!("{other:?}"),
        }
    }
    match trap.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("dialed: {other:?}"),
    }
}

// ------------------------------------------------------------------ acceptance 2 and 3

/// A relay that proves the trusted key is served — a hop naming that key
/// runs, a hop naming another is refused `forbidden` (the socket is not a
/// pipe), and a call before the proof is refused, never run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_proves_the_trusted_key_is_served_and_only_as_that_key() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(PeerKey::generate());
    let (port, mut rx) = stand_in(Arc::clone(&relay), Proves::Trusted).await;
    let counted = CountedActivation::default();
    let exposed = Exposed::new(DialOut::new(format!("ws://127.0.0.1:{port}/ws"), key_file(dir.path())).trust(relay.kid()).mount("c"));
    exposed.serve(counted.clone());
    assert_eq!(exposed.mounted(Duration::from_secs(10)).await.unwrap(), "peers.c");
    assert!(matches!(exposed.state(), DialState::Mounted { relay: ref r, .. } if r == relay.kid()), "{:?}", exposed.state());

    let got = answers(&mut rx, &["early", "good", "bad"]).await;
    assert!(got["early"]["refused"]["message"].as_str().is_some_and(|m| m.contains("not proved")), "a call before the proof: {got:?}");
    assert_eq!(got["good"]["content"], "hit", "{got:?}");
    assert_eq!(got["bad"]["error_kind"], "forbidden", "a hop naming another than the proven key: {got:?}");
    assert_eq!(counted.runs.load(Ordering::SeqCst), 1, "the good call alone ran");
    exposed.stop();
}

/// A relay that proves no key, another key, or the trusted key with
/// another's signature — or that names another principal at the offer —
/// is refused (and not dialed again), and none of its calls is run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_proves_none_or_another_is_refused_and_nothing_it_sends_runs() {
    let dir = tempfile::tempdir().unwrap();
    let k = key_file(dir.path());
    for (proves, says) in [
        (Proves::Nothing, "proved no key"),
        (Proves::Other, "proved another key"),
        (Proves::Forged, "without proving it"),
        (Proves::NamesOther, "as the service acting"),
    ] {
        let relay = Arc::new(PeerKey::generate());
        let (port, mut rx) = stand_in(Arc::clone(&relay), proves).await;
        let counted = CountedActivation::default();
        let exposed = Exposed::new(DialOut::new(format!("ws://127.0.0.1:{port}/ws"), &k).trust(relay.kid()).mount("c"));
        exposed.serve(counted.clone());
        let e = exposed.mounted(Duration::from_secs(10)).await.unwrap_err();
        match exposed.state() {
            DialState::Refused { why } => assert!(why.contains(says), "{proves:?}: {why}"),
            other => panic!("{proves:?}: {other:?} ({e})"),
        }
        // Whatever else it sent arrives or is dropped with the socket; none of it runs.
        tokio::time::timeout(Duration::from_millis(200), async { while rx.recv().await.is_some() {} }).await.ok();
        assert_eq!(counted.runs.load(Ordering::SeqCst), 0, "{proves:?}: a refused relay's calls never run");
    }
}

/// The dial-out path holds no `ChildPeer::Pipe`: its socket is a proven
/// connection or nothing (the behaviour is the test above's `bad` hop).
#[test]
fn the_dial_out_path_makes_no_pipe() {
    let src = include_str!("../src/plexus/remote_child/dial_out.rs");
    assert!(!src.contains("ChildPeer::Pipe"), "dial_out.rs constructs a pipe peer");
    assert!(src.contains("ChildPeer::connection(trusted"), "the host is served on the proven key");
}

// ------------------------------------------------------------------ acceptance 4

/// A socket accepted and left: the dial-out gives up at its timeout, as a
/// mount's dial does, and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upgrade_is_given_the_connect_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let held = tokio::spawn(async move {
        let mut kept = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            kept.push(s);
        }
    });
    let relay = PeerKey::generate();
    let mut opts = DialOut::new(format!("ws://127.0.0.1:{port}/ws"), key_file(dir.path())).trust(relay.kid()).mount("c");
    opts.timeout = Duration::from_millis(300);
    let exposed = Exposed::new(opts);
    let t = Instant::now();
    exposed.serve(CountedActivation::default());
    let mut states = exposed.watch();
    let down = tokio::time::timeout(Duration::from_secs(5), states.wait_for(|s| matches!(s, DialState::Down { .. }))).await.expect("down at its timeout").unwrap().clone();
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    match down {
        DialState::Down { why } => assert!(why.contains("no answer to the upgrade in 300ms"), "{why}"),
        other => panic!("{other:?}"),
    }
    exposed.stop();
    held.abort();
}

/// `tls_roots` is honoured as a mount's: the same TLS client (the same
/// refusal of roots that do not read), from the option or from
/// `transport.tls_roots` in the configuration.
#[cfg(feature = "child-wss")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_roots_are_honoured_as_a_mounts() {
    use plexus_core::plexus::config::{settings::TRANSPORT_TLS_ROOTS, Config, Source};
    use plexus_core::plexus::{ChildOptions, RemoteChild};
    let dir = tempfile::tempdir().unwrap();
    let k = key_file(dir.path());
    let roots = dir.path().join("no-such-roots.pem");
    let url = "wss://127.0.0.1:9/ws";
    let mount = RemoteChild::connect(format!("far={url}").parse().unwrap(), ChildOptions { tls_roots: Some(roots.clone()), ..ChildOptions::default() }).await.unwrap_err().to_string();
    let shown = format!("the TLS roots {}", roots.display());
    assert!(mount.contains(&shown), "{mount}");
    let c = Config::new();
    c.seed(&TRANSPORT_TLS_ROOTS, Source::Flag, Some(Some(roots.display().to_string())));
    let relay = PeerKey::generate();
    for opts in [DialOut::new(url, &k).trust(relay.kid()).tls_roots(&roots), DialOut::new(url, &k).trust(relay.kid()).configured(&c)] {
        let exposed = Exposed::new(opts);
        exposed.serve(CountedActivation::default());
        let _ = exposed.mounted(Duration::from_secs(5)).await;
        match exposed.state() {
            DialState::Refused { why } => assert!(why.contains(&shown), "{why}"),
            other => panic!("{other:?}"),
        }
    }
}
