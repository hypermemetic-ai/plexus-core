//! KEEL-7 · `ws://` beyond loopback is refused by plexus-core's own dials —
//! a `ws://` child's (`RemoteChild::connect`, `--child`) and a dial-out's
//! (`Exposed`) — before any socket opens, with plexus-dyn's reason
//! (`insecure_transport`), unless `transport.insecure_ws` (the config, or
//! `ChildOptions::insecure_ws` / `DialOut::insecure_ws`) allows it; then
//! the dial goes and its mount says `insecure`. Loopback is one function,
//! `check_ws_url` / `is_loopback_host`, which plexus-dyn's `check_url`
//! calls. `wss://` is untouched.
//!
//!   cargo test -p plexus-core --test keel7_insecure_dial

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_stream::stream;
use futures::{SinkExt, Stream, StreamExt};
use plexus_core::plexus::config::{settings::TRANSPORT_INSECURE_WS, Config, Source};
use plexus_core::plexus::remote_child::{check_ws_url, is_loopback_host, DialOut, DialState, Exposed, INSECURE_TRANSPORT};
use plexus_core::plexus::{ChildOptions, PlexusStreamItem, RemoteChild, StreamMetadata};
use plexus_core::DynamicHub;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone)]
pub struct PingActivation;

#[plexus_macros::activation(crate_path = "plexus_core", version = "0.1.0", description = "answers ping")]
impl PingActivation {
    /// Pong.
    #[plexus_macros::method]
    async fn ping(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "pong".to_string(); }
    }
}

/// A documentation address (RFC 5737): nothing answers there, so a dial
/// that went would hang until its timeout, never return at once.
const NOWHERE: &str = "192.0.2.1";

/// This machine's address beyond loopback, if it has one (the one a route
/// out would leave from; nothing is sent). As plexus-dyn's tests find it.
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("10.255.255.255:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// A key file (0600) in `dir`.
fn key(dir: &std::path::Path, seed: u8) -> std::path::PathBuf {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("k{seed}.key"));
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([seed; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// A listener on `ip` that is never accepted from: after a refusal, nothing
/// queued on it proves no socket was opened to it.
fn trap(ip: std::net::IpAddr) -> (std::net::TcpListener, u16) {
    let l = std::net::TcpListener::bind((ip, 0)).unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

fn untouched(l: &std::net::TcpListener) {
    match l.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("a socket was opened to the trap: {other:?}"),
    }
}

/// The far service, on every address.
async fn far_anywhere() -> (u16, jsonrpsee::server::ServerHandle) {
    let module = DynamicHub::arc_into_rpc_module(Arc::new(DynamicHub::new("far").register(PingActivation))).unwrap();
    let server = jsonrpsee::server::Server::builder().build("0.0.0.0:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    (port, server.start(module))
}

/// A stand-in relay on `ip`: answers `_info` (`backend: relay`, its key
/// proved over the nonce — KEEL-8) and the offer (mounted as
/// `peers.<mount>`), then holds the socket. Its port and its key.
async fn stand_in_relay(ip: std::net::IpAddr) -> (u16, String) {
    let relay = Arc::new(plexus_core::plexus::peer_token::PeerKey::generate());
    let kid = relay.kid().to_string();
    // KEEL-19: the proof is made for the dialing peer (`key(dir, 3)`).
    let dialer = plexus_core::plexus::peer_token::PeerKey::from_seed([3u8; 32]).kid().to_string();
    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (relay, dialer) = (Arc::clone(&relay), dialer.clone());
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                while let Some(Ok(m)) = ws.next().await {
                    let Message::Text(t) = m else { continue };
                    let v: Value = serde_json::from_str(&t).unwrap_or_default();
                    let (id, method) = (v["id"].clone(), v["method"].as_str().unwrap_or_default().to_string());
                    let mut out = Vec::new();
                    if method == "_info" {
                        let md = StreamMetadata::new(vec!["relay".into()], "0".into());
                        out.push(json!({ "jsonrpc": "2.0", "id": id, "result": "s1" }));
                        let nonce = v["params"]["nonce"].as_str().unwrap_or_default();
                        let data = PlexusStreamItem::data(md.clone(), "_info".into(), json!({ "backend": "relay", "key": relay.kid(), "proof": relay.key_proof_for(nonce, "relay", &dialer) }));
                        out.push(json!({ "jsonrpc": "2.0", "method": "_info", "params": { "subscription": "s1", "result": data } }));
                        out.push(json!({ "jsonrpc": "2.0", "method": "_info", "params": { "subscription": "s1", "result": PlexusStreamItem::done(md) } }));
                    } else if method == "relay.offer" {
                        let mount = v["params"]["mount"].as_str().unwrap_or("x").to_string();
                        out.push(json!({ "jsonrpc": "2.0", "id": id, "result": { "offered": true, "mount": mount, "path": format!("peers.{mount}"), "service": { "principal": relay.kid() } } }));
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
    (port, kid)
}

// ------------------------------------------------------------------ acceptance 2

/// The loopback forms plexus-dyn admits are admitted by plexus-core's one
/// function; the rest refused (plexus-dyn's own list, and a mapped 127.x).
#[test]
fn loopback_is_one_function_in_plexus_core() {
    for ok in ["ws://127.0.0.1:1", "ws://127.9.9.9/x", "ws://localhost:80", "ws://LOCALHOST.", "ws://[::1]:4", "ws://[::ffff:127.0.0.1]:4", "ws://u:p@127.0.0.1:1", "wss://example.com", "wss://10.0.0.1:443/ws"] {
        assert_eq!(check_ws_url(ok, false), Ok(()), "{ok}");
    }
    for bad in ["ws://example.com", "ws://10.0.0.1:1", "ws://[::2]:1", "ws://[::ffff:10.0.0.1]:1", "ws://127.0.0.1.example.com", "ws://localhost.example.com:1", "ws://u@example.com", "http://127.0.0.1", "ws://"] {
        assert!(check_ws_url(bad, false).is_err(), "{bad}");
    }
    assert!(check_ws_url("ws://example.com", false).unwrap_err().contains("transport.insecure_ws"), "the refusal names the setting");
    assert_eq!(check_ws_url("ws://example.com", true), Ok(()), "the override");
    assert!(is_loopback_host("127.0.0.1") && is_loopback_host("::1") && is_loopback_host("localhost") && !is_loopback_host("10.0.0.1"));
    assert_eq!(INSECURE_TRANSPORT, "insecure_transport");
}

// ------------------------------------------------------------------ acceptance 1

/// `--child far=ws://<beyond loopback>` is refused at start, before any
/// socket opens (and before the key proof is made), naming the reason and
/// the setting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ws_child_beyond_loopback_is_refused_before_any_socket_opens() {
    let dir = tempfile::tempdir().unwrap();
    let opts = ChildOptions { key: Some(key(dir.path(), 1)), timeout: Duration::from_secs(30), ..ChildOptions::for_service("svc") };
    let t = Instant::now();
    let e = RemoteChild::connect(format!("far=ws://{NOWHERE}:9").parse().unwrap(), opts.clone()).await.unwrap_err().to_string();
    assert!(t.elapsed() < Duration::from_secs(2), "refused at once, not dialed: {:?}", t.elapsed());
    assert!(e.contains("insecure_transport") && e.contains("transport.insecure_ws") && e.contains("plain ws://"), "{e}");

    let Some(ip) = lan_ip() else {
        println!("measure: no address beyond loopback here; the trap test is the documentation address alone");
        return;
    };
    let (l, port) = trap(ip);
    let e = RemoteChild::connect(format!("far=ws://{ip}:{port}").parse().unwrap(), opts).await.unwrap_err().to_string();
    assert!(e.contains("insecure_transport"), "{e}");
    untouched(&l);
}

/// A dial-out to `ws://<beyond loopback>` is refused (not dialed again),
/// before any socket opens, naming the reason and the setting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_out_beyond_loopback_is_refused_before_any_socket_opens() {
    let dir = tempfile::tempdir().unwrap();
    let k = key(dir.path(), 2);
    let mut targets = vec![(format!("ws://{NOWHERE}:9/ws"), None)];
    if let Some(ip) = lan_ip() {
        let (l, port) = trap(ip);
        targets.push((format!("ws://{ip}:{port}/ws"), Some(l)));
    }
    for (url, trap) in targets {
        let exposed = Exposed::new(DialOut::new(url.clone(), &k).mount("p"));
        let t = Instant::now();
        exposed.serve(PingActivation);
        let e = exposed.mounted(Duration::from_secs(30)).await.unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(2), "{url}: refused at once: {:?}", t.elapsed());
        match exposed.state() {
            DialState::Refused { why } => assert!(why.starts_with("insecure_transport: ") && why.contains("transport.insecure_ws"), "{why}"),
            other => panic!("{url}: {other:?} ({e})"),
        }
        if let Some(l) = trap {
            untouched(&l);
        }
    }
}

// ------------------------------------------------------------------ acceptance 3

/// With `transport.insecure_ws` — `ChildOptions::insecure_ws`, or the
/// config read at the mount — a far `ws://` child is dialed and mounted, and
/// its mount says `insecure`; a loopback mount does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_override_dials_a_child_and_says_so() {
    let (port, far) = far_anywhere().await;
    let near = RemoteChild::connect(format!("far=ws://127.0.0.1:{port}").parse().unwrap(), ChildOptions::default()).await.unwrap();
    assert!(!near.insecure(), "loopback is not insecure");
    assert!(format!("{near:?}").contains("insecure: false"));
    let Some(ip) = lan_ip() else {
        println!("measure: no address beyond loopback here; the override is not dialed");
        return;
    };
    let spec = || format!("far=ws://{ip}:{port}").parse().unwrap();
    let e = RemoteChild::connect(spec(), ChildOptions::default()).await.unwrap_err().to_string();
    assert!(e.contains("insecure_transport"), "{e}");

    let by_options = RemoteChild::connect(spec(), ChildOptions { insecure_ws: true, ..ChildOptions::default() }).await.unwrap();
    assert!(by_options.insecure(), "said");
    assert!(format!("{by_options:?}").contains("insecure: true"));

    let c = Config::new();
    assert!(!ChildOptions::default().configured(&c).insecure_ws, "off by default");
    c.seed(&TRANSPORT_INSECURE_WS, Source::Flag, Some(true));
    let by_config = RemoteChild::connect(spec(), ChildOptions::default().configured(&c)).await.unwrap();
    assert!(by_config.insecure(), "said");
    // And the options put into a configuration say it as its flag layer.
    let seeded = Config::new();
    ChildOptions { insecure_ws: true, ..ChildOptions::default() }.seed(&seeded);
    assert!(seeded.get(&TRANSPORT_INSECURE_WS) && seeded.source(&TRANSPORT_INSECURE_WS) == Source::Flag);
    let _ = far.stop();
}

/// With `DialOut::insecure_ws` (or the config through `DialOut::configured`)
/// a dial-out to a far `ws://` relay goes, and `Mounted` says `insecure`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_override_dials_out_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let k = key(dir.path(), 3);
    let (near, near_key) = stand_in_relay("127.0.0.1".parse().unwrap()).await;
    let exposed = Exposed::new(DialOut::new(format!("ws://127.0.0.1:{near}/ws"), &k).trust(near_key).mount("p"));
    exposed.serve(PingActivation);
    assert_eq!(exposed.mounted(Duration::from_secs(10)).await.unwrap(), "peers.p");
    assert!(matches!(exposed.state(), DialState::Mounted { insecure: false, .. }), "{:?}", exposed.state());
    assert!(serde_json::to_value(exposed.state()).unwrap().get("insecure").is_none(), "loopback says nothing");
    exposed.stop();

    let Some(ip) = lan_ip() else {
        println!("measure: no address beyond loopback here; the override is not dialed");
        return;
    };
    let (far, far_key) = stand_in_relay(ip).await;
    let url = format!("ws://{ip}:{far}/ws");
    let c = Config::new();
    c.seed(&TRANSPORT_INSECURE_WS, Source::Flag, Some(true));
    for opts in [DialOut::new(url.clone(), &k).trust(far_key.clone()).mount("p").insecure_ws(true), DialOut::new(url.clone(), &k).trust(far_key.clone()).mount("p").configured(&c)] {
        let exposed = Exposed::new(opts);
        exposed.serve(PingActivation);
        assert_eq!(exposed.mounted(Duration::from_secs(10)).await.unwrap(), "peers.p");
        assert!(matches!(exposed.state(), DialState::Mounted { insecure: true, .. }), "{:?}", exposed.state());
        assert_eq!(serde_json::to_value(exposed.state()).unwrap()["insecure"], true);
        exposed.stop();
    }
}

// ------------------------------------------------------------------ acceptance 5

/// `wss://` is untouched: admitted anywhere, never refused for its transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wss_is_untouched() {
    assert_eq!(check_ws_url(&format!("wss://{NOWHERE}:9/ws"), false), Ok(()));
    let opts = ChildOptions { timeout: Duration::from_millis(300), ..ChildOptions::default() };
    let e = RemoteChild::connect(format!("far=wss://{NOWHERE}:9").parse().unwrap(), opts).await.unwrap_err().to_string();
    assert!(!e.contains("insecure_transport"), "{e}");
}
