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
use plexus_core::plexus::remote_child::{dial_proof, serve_child_with, serve_child_ws, ChildOptions, ChildPeer, ChildSpec, KeyedUpgrade, RemoteChild, ServeChild, CHILD_DIAL_AGENT, KEYED_MOUNT_NEEDS_A_KEY, UPGRADE_LEDGER_MAX};

/// spec/00's key-proof context (the one form for a child dial and a sign-in).
const CONTEXT: &str = "plexus-key-login/v1";
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

/// A `plexus-key.` proof by the key of `seed` in `context`, made by hand
/// (the stale, the forged and the sign-in ones the dial never makes).
fn proof_in(context: &str, seed: u8, aud: &str, nonce: u8, ts: i64) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let n = b64.encode([nonce; 32]);
    let agent = CHILD_DIAL_AGENT;
    let sig = key.sign(format!("{context}\n{aud}\n{agent}\n{n}\n{ts}").as_bytes());
    let hex: String = key.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let body = json!({ "v": 1, "key": hex, "aud": aud, "agent": agent, "nonce": n, "ts": ts, "sig": b64.encode(sig.to_bytes()) });
    format!("plexus-key.{}", b64.encode(body.to_string()))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// M's own socket to V: dialed with M's key proof.
async fn dial_as(seed: u8, port: u16) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://127.0.0.1:{port}");
    let proof = dial_proof(&PeerKey::from_seed([seed; 32]), &url);
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

/// `KeyedUpgrade` takes a child dial's proof — the audience, the window, the
/// signature, each proof once — and nothing else.
#[test]
fn an_upgrade_proof_is_verified() {
    let (ts, aud) = (now(), "ws://127.0.0.1:4480");
    let up = KeyedUpgrade::new([aud]);
    let p = proof_in(CONTEXT, 5, "ws://127.0.0.1:4480/", 2, ts);
    assert_eq!(up.verify(&p).unwrap().principal(), PeerKey::from_seed([5; 32]).kid());
    assert!(up.verify(&p).unwrap_err().contains("used before"));
    assert!(up.verify(&proof_in(CONTEXT, 5, "ws://127.0.0.1:9999", 3, ts)).unwrap_err().contains("not for this child"));
    assert!(up.verify(&proof_in(CONTEXT, 5, aud, 4, ts - 600)).unwrap_err().contains("time window"));
    // Another's proof, its `key` swapped for key 5's: the signature is not key 5's.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let theirs = proof_in(CONTEXT, 8, aud, 6, ts);
    let mut body: Value = serde_json::from_slice(&b64.decode(theirs.strip_prefix("plexus-key.").unwrap()).unwrap()).unwrap();
    body["key"] = json!(PeerKey::from_seed([5; 32]).kid().trim_start_matches("key:"));
    let forged = format!("plexus-key.{}", b64.encode(body.to_string()));
    assert!(up.verify(&forged).unwrap_err().contains("signature"), "a proof signed by another key");
    assert!(up.verify("Bearer nothing").is_err());
    // `dial_proof` is what it takes.
    assert!(up.verify(&dial_proof(&PeerKey::from_seed([5; 32]), aud)).is_ok());
}

/// P2, with no change to the wire: a child dial is signed as the reserved
/// agent `plexus.child-dial` (in the signed bytes). A child takes nothing
/// else — a sign-in proof is refused — and the sign-in adapter refuses a
/// child dial.
#[tokio::test]
async fn a_sign_in_proof_and_a_child_dial_are_told_apart() {
    use plexus_auth_core::identity::{Authenticator, Presentation};
    let aud = "ws://127.0.0.1:4481";
    let login = plexus_auth_core::adapters::sign_key_proof(&[5; 32], aud, "dyn", &[7; 32], now());
    assert!(KeyedUpgrade::new([aud]).verify(&login).unwrap_err().contains("not a child dial"), "a sign-in taken as a child dial");
    let adapter = plexus_auth_core::adapters::KeyProofAdapter::new([aud]).unwrap();
    let dial = dial_proof(&PeerKey::from_seed([5; 32]), aud);
    assert!(adapter.authenticate(&Presentation::Bearer { token: dial }).await.is_err(), "a child dial taken as a sign-in");
    // Each still takes its own.
    assert!(KeyedUpgrade::new([aud]).verify(&dial_proof(&PeerKey::from_seed([5; 32]), aud)).is_ok());
    let login = plexus_auth_core::adapters::sign_key_proof(&[5; 32], aud, "dyn", &[9; 32], now());
    assert!(adapter.authenticate(&Presentation::Bearer { token: login }).await.is_ok());
}

/// P3a (repro4): a full ledger refuses new upgrades; it never forgets a
/// proof early, so a flood of proofs by fresh keys cannot evict a captured
/// one and replay it.
#[test]
fn a_full_ledger_refuses_and_never_forgets_early() {
    let aud = "ws://127.0.0.1:4801";
    let up = KeyedUpgrade::new([aud]);
    // Captured, and as late in its window as the flood (90 s to expire).
    let captured = proof_in(CONTEXT, 255, aud, 255, now() + 30);
    let started = std::time::Instant::now();
    assert!(up.verify(&captured).is_ok());
    assert!(up.verify(&captured).unwrap_err().contains("used before"));
    // The flood: valid proofs by fresh keys, 30 s ahead (expiring last).
    let mut accepted = 1;
    for i in 0..UPGRADE_LEDGER_MAX {
        if up.verify(&proof_in(CONTEXT, (i % 256) as u8, aud, (i / 256) as u8, now() + 30)).is_ok() {
            accepted += 1;
        }
    }
    assert!(started.elapsed() < Duration::from_secs(80), "the flood outlived the window: {:?}", started.elapsed());
    assert_eq!(accepted, UPGRADE_LEDGER_MAX, "the ledger holds exactly its most");
    let full = up.verify(&dial_proof(&PeerKey::generate(), aud)).unwrap_err();
    assert!(full.contains("refused until some expire"), "{full}");
    assert!(up.verify(&captured).is_err(), "the captured proof replayed after the flood");
}

/// P1: a keyed child cannot be served on a string — not on the service's
/// dial key written as `proven` (the updated repro3's step 0), not on any
/// `ChildPeer`; only on a `Proven` a verifier made (`serve_child_proven`).
#[tokio::test]
async fn a_keyed_child_is_never_served_on_a_string() {
    let (v, dial) = (PeerKey::generate(), PeerKey::generate());
    let issuer = TokenIssuer::new(PeerKey::generate());
    for peer in [ChildPeer::connection(dial.kid(), [dial.kid().to_string()]), ChildPeer::connection(DYN, [DYN.to_string()]), ChildPeer::Pipe] {
        for (key, tokens) in [(Some(v.clone()), None), (None, Some(Arc::new(Verifier::new(v.kid(), &issuer.jwks()).unwrap())))] {
            let (_to, v_in) = tokio::io::duplex(1 << 10);
            let (v_out, _from) = tokio::io::duplex(1 << 10);
            let served = tokio::time::timeout(Duration::from_secs(2), serve_child_with(WeatherActivation, v_in, v_out, ServeChild { peer: peer.clone(), key, tokens })).await.expect("refused at once");
            assert_eq!(served.unwrap_err().kind(), std::io::ErrorKind::InvalidInput, "{peer:?}");
        }
    }
}
