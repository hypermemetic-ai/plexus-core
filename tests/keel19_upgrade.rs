//! KEEL-19 third pass · the asker is a proven key, on both sides.
//!
//! The review's repro3: a service with no dial key acts as the fixed name
//! `service:dyn`, which no transport proves; a keyed peer V "trusting" that
//! name signs its `_info` proof for it whoever asks, so a peer M relays the
//! service's nonce to V, is registered under V's key, and relays the
//! service's forwarded hops to V. Now:
//!
//! - V cannot be served on a connection "proven" as a name — only as a key,
//!   which `serve_child_ws` gets from the upgrade's verified key proof;
//! - a service whose principal is not a key mounts no keyed peer
//!   (`keyed_mount_needs_a_key`);
//! - M, dialing V with its own key, is proven as M: V's proof is made for
//!   M, which the service refuses, and M's relayed hop is not taken.

use futures::{SinkExt, Stream, StreamExt};
use plexus_core::plexus::peer_token::{check_key_proof_for, random_nonce, MintRequest, PeerKey, TokenIssuer, Verifier};
use plexus_core::plexus::remote_child::{serve_child_with, serve_child_ws, ChildOptions, ChildPeer, ChildSpec, KeyedUpgrade, RemoteChild, ServeChild, KEYED_MOUNT_NEEDS_A_KEY};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};

#[derive(Clone)]
pub struct WeatherActivation;

/// V's service.
#[plexus_macros::activation]
impl WeatherActivation {
    /// Says who it ran for.
    #[plexus_macros::method]
    pub async fn forecast(&self, city: String) -> impl Stream<Item = Value> + Send + 'static {
        let who = plexus_core::call::caller().ok().and_then(|c| c.auth().and_then(|a| a.principal()).map(|p| p.to_string()));
        futures::stream::iter([json!({ "city": city, "ran_for": who })])
    }
}

const CALLER: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DYN: &str = "service:dyn";

/// A key file (0600) holding `seed`.
fn key_file(dir: &std::path::Path, seed: u8) -> std::path::PathBuf {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("k{seed}.key"));
    std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([seed; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// V served on loopback as a keyed, verifying child: every upgrade's key
/// proof verified (`serve_child_ws`), `trusted` trusted to act for others.
async fn serve_v(v: &PeerKey, issuer: &TokenIssuer, trusted: &str) -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upgrade = Arc::new(KeyedUpgrade::new([format!("ws://127.0.0.1:{port}")]));
    let (v, jwks, trusted) = (v.clone(), issuer.jwks(), trusted.to_string());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (v, upgrade, trusted) = (v.clone(), Arc::clone(&upgrade), trusted.clone());
            let tokens = Some(Arc::new(Verifier::new(v.kid(), &jwks).unwrap()));
            tokio::spawn(async move {
                let _ = serve_child_ws(WeatherActivation, tcp, &upgrade, vec![trusted], Some(v), tokens).await;
            });
        }
    });
    port
}

/// M's own socket to V: dialed with M's key proof.
async fn dial_as(seed: u8, port: u16) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://127.0.0.1:{port}");
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut nonce = [0u8; 32];
    nonce[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    nonce[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let proof = plexus_auth_core::adapters::sign_key_proof(&[seed; 32], &url, "m", &nonce, ts);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("authorization", HeaderValue::from_str(&format!("Bearer {proof}")).unwrap());
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

/// One frame sent, the first `data` or `error` item answered.
async fn ask(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, frame: Value) -> Value {
    ws.send(Message::text(frame.to_string())).await.unwrap();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("V answers").unwrap().unwrap();
        let Message::Text(t) = m else { continue };
        let v: Value = serde_json::from_str(&t).unwrap();
        if let Some(r) = v.pointer("/params/result") {
            if matches!(r.get("type").and_then(Value::as_str), Some("data" | "error")) {
                return r.clone();
            }
        }
    }
}

/// A server that upgrades anyone and answers `_info` proving `v`'s key for
/// `service:dyn` — what V signed on dyn's old rig.
async fn stand_in_for_dyn(v: PeerKey) -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let v = v.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                while let Some(Ok(Message::Text(t))) = ws.next().await {
                    let f: Value = serde_json::from_str(&t).unwrap_or_default();
                    if f["method"] == "_info" {
                        let nonce = f["params"]["nonce"].as_str().unwrap_or_default();
                        let md = json!({ "provenance": ["weather"], "plexus_hash": "", "timestamp": 0 });
                        let item = json!({ "type": "data", "metadata": md, "content_type": "_info", "content": { "backend": "weather", "key": v.kid(), "proof": v.key_proof_for(nonce, "weather", DYN), "asker": DYN } });
                        for out in [json!({ "jsonrpc": "2.0", "id": f["id"], "result": 1 }), json!({ "jsonrpc": "2.0", "method": "weather.call", "params": { "subscription": 1, "result": item } }), json!({ "jsonrpc": "2.0", "method": "weather.call", "params": { "subscription": 1, "result": { "type": "done", "metadata": md } } })] {
                            let _ = ws.send(Message::text(out.to_string())).await;
                        }
                    }
                }
            });
        }
    });
    port
}

/// repro3, step by step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repro3_a_principal_no_transport_proves_is_no_asker() {
    let (host, v) = (PeerKey::from_seed([1; 32]), PeerKey::generate());
    let issuer = TokenIssuer::new(PeerKey::generate());
    // 0. V as dyn's old rig served it — Connection("service:dyn"): refused.
    let (_to, v_in) = tokio::io::duplex(1 << 10);
    let (v_out, _from) = tokio::io::duplex(1 << 10);
    let rig = ServeChild { peer: ChildPeer::connection(DYN, [DYN.to_string()]), key: Some(v.clone()), tokens: Some(Arc::new(Verifier::new(v.kid(), &issuer.jwks()).unwrap())) };
    let served = tokio::time::timeout(Duration::from_secs(2), serve_child_with(WeatherActivation, v_in, v_out, rig)).await.expect("refused at once");
    assert_eq!(served.unwrap_err().kind(), std::io::ErrorKind::InvalidInput, "a keyed child on a name no transport proves");

    let port = serve_v(&v, &issuer, host.kid()).await;
    let url = format!("ws://127.0.0.1:{port}");
    // 1. A service with no dial key (`service:dyn`) is not even upgraded by
    //    V (no key proof)…
    let keyless = RemoteChild::connect(ChildSpec::Ws { name: "v".into(), url: url.clone() }, ChildOptions::for_service("dyn")).await;
    assert!(keyless.err().expect("refused").to_string().contains("401"));
    assert!(tokio_tungstenite::connect_async(url.as_str()).await.is_err(), "upgraded without a key proof");
    //    …and mounts no keyed peer anywhere: a stand-in that upgrades anyone
    //    and proves V's key for `service:dyn` is refused at the mount.
    let stand_in = stand_in_for_dyn(v.clone()).await;
    let keyless = RemoteChild::connect(ChildSpec::Ws { name: "v".into(), url: format!("ws://127.0.0.1:{stand_in}") }, ChildOptions::for_service("dyn")).await;
    let why = keyless.err().expect("refused").to_string();
    assert!(why.contains(KEYED_MOUNT_NEEDS_A_KEY) && why.contains("dial key"), "{why}");

    // 2. M dials V with its own key and relays the service's nonce, naming
    //    `service:dyn` (or the service's key) as the asker: V proves for M.
    let m = PeerKey::from_seed([9; 32]);
    let mut ws = dial_as(9, port).await;
    let nonce = random_nonce();
    let info = ask(&mut ws, json!({ "jsonrpc": "2.0", "id": 1, "method": "_info", "params": { "nonce": nonce, "asker": DYN } })).await;
    let c = &info["content"];
    assert_eq!(c["asker"], m.kid(), "{c}");
    let (key, proof, backend) = (c["key"].as_str().unwrap(), c["proof"].as_str().unwrap(), c["backend"].as_str().unwrap());
    assert!(check_key_proof_for(key, proof, &nonce, backend, DYN).is_err(), "made for `service:dyn`");
    assert!(check_key_proof_for(key, proof, &nonce, backend, host.kid()).is_err(), "made for the service's key");

    // 3. M relays a forwarded hop (token for V's key + the service's proof),
    //    naming `service:dyn` or the service's key as the acting service: not taken.
    for acting in [DYN, host.kid()] {
        let (t, claims) = issuer.mint(MintRequest { sub: CALLER.into(), peer_key: Some(v.kid().into()), name: "m".into(), scope: vec!["weather.forecast@*".into()], call: format!("c-{acting}"), method: "weather.forecast".into(), presented: None }).unwrap();
        let p = issuer.prove_forward(&t, &claims).unwrap();
        let hop = json!({ "principal": acting, "for": [CALLER], "limit": { "grant": "weather.forecast", "held_on": ["*"] }, "call": claims.call, "token": t, "proof": p });
        let got = ask(&mut ws, json!({ "jsonrpc": "2.0", "id": 2, "method": "weather.call", "params": { "method": "weather.forecast", "params": { "city": "m" }, "hop": hop } })).await;
        assert_eq!(got["error_kind"], "forbidden", "M's relay ran as the caller: {got}");
    }

    // 4. The service with a dial key mounts V: its proof is made for that key.
    let dir = tempfile::tempdir().unwrap();
    let mut opts = ChildOptions::for_service("dyn");
    opts.key = Some(key_file(dir.path(), 1));
    let child = RemoteChild::connect(ChildSpec::Ws { name: "v".into(), url }, opts).await.expect("mounted with a dial key");
    assert_eq!(child.peer_key(), Some(v.kid()));
    assert_eq!(child.principal(), host.kid());
}

/// `KeyedUpgrade` takes exactly what plexus-auth-core's key adapter takes:
/// the audience, the window, the signature, each proof once.
#[test]
fn an_upgrade_proof_is_verified() {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let up = KeyedUpgrade::new(["ws://127.0.0.1:4480"]);
    let p = plexus_auth_core::adapters::sign_key_proof(&[5; 32], "ws://127.0.0.1:4480/", "dyn", &[2; 32], ts);
    assert_eq!(up.verify(&p).unwrap(), PeerKey::from_seed([5; 32]).kid());
    assert!(up.verify(&p).unwrap_err().contains("used before"));
    let other = plexus_auth_core::adapters::sign_key_proof(&[5; 32], "ws://127.0.0.1:9999", "dyn", &[3; 32], ts);
    assert!(up.verify(&other).unwrap_err().contains("not for this child"));
    let stale = plexus_auth_core::adapters::sign_key_proof(&[5; 32], "ws://127.0.0.1:4480", "dyn", &[4; 32], ts - 600);
    assert!(up.verify(&stale).unwrap_err().contains("time window"));
    // Another's proof, its `key` swapped for key 5's: the signature is not key 5's.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let theirs = plexus_auth_core::adapters::sign_key_proof(&[8; 32], "ws://127.0.0.1:4480", "dyn", &[6; 32], ts);
    let mut body: Value = serde_json::from_slice(&b64.decode(theirs.strip_prefix("plexus-key.").unwrap()).unwrap()).unwrap();
    body["key"] = json!(PeerKey::from_seed([5; 32]).kid().trim_start_matches("key:"));
    let forged = format!("plexus-key.{}", b64.encode(body.to_string()));
    assert!(up.verify(&forged).unwrap_err().contains("signature"), "a proof signed by another key");
    assert!(up.verify("Bearer nothing").is_err());
}
