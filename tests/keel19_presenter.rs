//! KEEL-19 · the reviewer's attack on the token stack, at the audience.
//!
//! Peer A, handed a caller's token, exchanges it for one addressed to peer B
//! and sends B the hop itself, over a connection proven as A, which B trusts
//! for nothing (B takes hops for others only from the service). In 0.11.0 B
//! ran the method as the caller: a hop whose token verified was believed
//! whoever sent it. Now the exchanged token is bound to its presenter's key
//! (`cnf`), and B runs the hop only on that presenter's proof of possession,
//! over a connection proven as that key; a token the service forwards
//! (bound to B's own key) is taken only from the service's own connection;
//! and a subject token is exchanged once per (`jti`, audience, method).
//!
//! Whether the presenter may have such a token at all — mounted, not
//! revoked, consented to reach B — is the service's decision
//! (`TokenIssuer::exchange_decided`, plexus-dyn's `dyn.exchange`), tested in
//! plexus-dyn; here A is given the token by the issuer's primitive, as the
//! reviewer's program was.
//!
//! The second review (`b1`, `b2`): a peer M asks V's `_info` over its own
//! connection, relays the proof to the service at its mount and is
//! registered under V's key; every token for calls into M is then bound to
//! V's own key, and M sends them to V. Now the `_info` proof is made for the
//! asker the connection proved (M), so the service refuses it; a keyed or
//! key-verifying child cannot be served on a `Pipe`; and a forwarded token
//! is taken only with the service's own proof (`prove_forward`), on a pipe
//! and a connection alike — its `jti` spent only once the sender is proven.

#![allow(deprecated)] // the undecided `exchange` primitive is the attacker's tool here

use futures::Stream;
use plexus_core::plexus::peer_token::{check_key_proof_for, prove, random_nonce, MintRequest, PeerKey, ProofCache, TokenError, TokenIssuer, Verifier, EXCHANGE};
use plexus_core::plexus::remote_child::{dial_proof, serve_child_proven, serve_child_with, ChildPeer, KeyedUpgrade, ServeChild};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Clone)]
pub struct WeatherActivation;

/// B's service.
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

struct World {
    host: PeerKey,
    a: PeerKey,
    b: PeerKey,
    issuer: TokenIssuer,
}

impl World {
    fn new() -> Self {
        let host = PeerKey::generate();
        Self { issuer: TokenIssuer::new(host.clone()), host, a: PeerKey::generate(), b: PeerKey::generate() }
    }

    /// The service forwards the caller's call of A's `weather.forecast` to A
    /// (A named its namespace `weather`, B's): A's token.
    fn a_token(&self) -> (String, plexus_core::plexus::peer_token::PeerClaims) {
        self.issuer
            .mint(MintRequest { sub: CALLER.into(), peer_key: Some(self.a.kid().into()), name: "a".into(), scope: vec!["weather.forecast@*".into()], call: uuid::Uuid::new_v4().to_string(), method: "weather.forecast".into(), presented: None })
            .unwrap()
    }

    /// A exchanges its token for one addressed to B (the issuer's primitive:
    /// no consent asked, as `dyn.exchange` was in 0.11.0).
    fn exchanged_for_b(&self, method: &str) -> Result<(String, plexus_core::plexus::peer_token::PeerClaims), TokenError> {
        let (t_a, c_a) = self.a_token();
        let proof = prove(&self.a, &t_a, EXCHANGE, &c_a.call);
        self.issuer.exchange(&t_a, Some(&proof), "b", Some(self.b.kid().into()), None, &uuid::Uuid::new_v4().to_string(), method, &ProofCache::default())
    }

    /// B, verifying, serving one input whose sender is `peer`.
    fn serve_b(&self, by: &PeerKey, trusted: &PeerKey) -> Input {
        self.serve_b_with(by, trusted, self.verifier())
    }

    fn verifier(&self) -> Arc<Verifier> {
        Arc::new(Verifier::new(self.b.kid(), &self.issuer.jwks()).unwrap())
    }

    /// The service's mint for a call into the peer keyed `aud` (bound to
    /// that key: a forward), and its proof that it sends it.
    fn forwarded(&self, aud: &str, call: &str) -> (String, String) {
        let (t, c) = self
            .issuer
            .mint(MintRequest { sub: CALLER.into(), peer_key: Some(aud.into()), name: "b".into(), scope: vec!["weather.forecast@*".into()], call: call.into(), method: "weather.forecast".into(), presented: None })
            .unwrap();
        let p = self.issuer.prove_forward(&t, &c).unwrap();
        (t, p)
    }

    /// B, serving one input whose sender is `peer`, with the verifier `v`
    /// (shared between inputs: one replay cache).
    fn serve_b_with(&self, by: &PeerKey, trusted: &PeerKey, v: Arc<Verifier>) -> Input {
        // KEEL-19: B's input proven as `by` — by verifying `by`'s dial proof,
        // as `serve_child_ws` does at the upgrade; never a written string.
        let proven = KeyedUpgrade::new(["ws://b.test"]).verify(&dial_proof(by, "ws://b.test")).unwrap();
        let (to_b, b_in) = tokio::io::duplex(1 << 16);
        let (b_out, from_b) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_child_proven(WeatherActivation, b_in, b_out, proven, vec![trusted.kid().to_string()], Some(self.b.clone()), Some(v)));
        Input { to_b, lines: BufReader::new(from_b).lines(), next: 1 }
    }
}

struct Input {
    to_b: tokio::io::DuplexStream,
    lines: tokio::io::Lines<BufReader<tokio::io::DuplexStream>>,
    next: u64,
}

impl Input {
    /// Send `weather.call` with `hop` and answer its first item.
    async fn call(&mut self, hop: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let frame = json!({ "jsonrpc": "2.0", "id": id, "method": "weather.call", "params": { "method": "weather.forecast", "params": { "city": "lisbon" }, "hop": hop } });
        self.to_b.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
        loop {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), self.lines.next_line()).await.expect("B answers").unwrap().unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            if v.get("method").and_then(Value::as_str) == Some("weather.call") {
                return v["params"]["result"].clone();
            }
        }
    }
}

fn hop(principal: &str, call: &str, token: Option<&str>, proof: Option<String>) -> Value {
    let mut h = json!({ "principal": principal, "for": [CALLER], "limit": { "grant": "weather.forecast", "held_on": ["*"] }, "call": call });
    if let Some(t) = token {
        h["token"] = json!(t);
    }
    if let Some(p) = proof {
        h["proof"] = json!(p);
    }
    h
}

fn refused(got: &Value, says: &str) {
    assert_eq!(got["type"], "error", "{got}");
    assert_eq!(got["error_kind"], "forbidden", "{got}");
    assert!(got["message"].as_str().is_some_and(|m| m.contains(says)), "wanted `{says}`: {got}");
}

/// The reviewer's program, as it ran: A sends B the exchanged token, over a
/// connection proven as A, B trusting only the service. Refused now — the
/// token is bound to A's key, and A sent no proof of it. (KEEL-19 (2).)
#[tokio::test]
async fn the_reviewers_attack_is_refused_at_the_audience() {
    let w = World::new();
    let (t_b, c_b) = w.exchanged_for_b("weather.forecast").unwrap();
    assert_eq!(c_b.cnf.as_ref().map(|c| c.jkt.as_str()), Some(w.a.thumbprint().as_str()), "the exchanged token names its presenter's key");
    let mut b = w.serve_b(&w.a, &w.host);
    // Control: without a token, A's hop is refused (A is not trusted).
    refused(&b.call(hop(w.a.kid(), "x", None, None)).await, "no token");
    // The attack: the exchanged token in A's hop, no proof.
    let got = b.call(hop(w.a.kid(), &c_b.call, Some(&t_b), None)).await;
    refused(&got, "no proof of possession");
    assert_ne!(got["content"]["ran_for"], CALLER, "B ran the method as the caller: {got}");
}

/// A token the service forwarded to B (bound to B's own key), stolen and
/// sent by A: taken only from the service's own connection, and only with
/// the service's proof that it sends it. (KEEL-19 (2), second pass (a).)
#[tokio::test]
async fn a_forwarded_token_is_taken_only_from_the_service_with_its_proof() {
    let w = World::new();
    let b = w.b.kid().to_string();
    let mut from_a = w.serve_b(&w.a, &w.host);
    let (t, p) = w.forwarded(&b, "f1");
    refused(&from_a.call(hop(w.a.kid(), "f1", Some(&t), Some(p))).await, "the service's own connection");
    // Even with a proof by A: the token is B's, not A's.
    let (t, _) = w.forwarded(&b, "f2");
    refused(&from_a.call(hop(w.a.kid(), "f2", Some(&t), Some(prove(&w.a, &t, "weather.forecast", "f2")))).await, "the service's own connection");
    // On the service's own connection, but with no proof, or another's.
    let mut from_host = w.serve_b(&w.host, &w.host);
    let (t, _) = w.forwarded(&b, "f3");
    refused(&from_host.call(hop(w.host.kid(), "f3", Some(&t), None)).await, "no proof of possession");
    let (t, _) = w.forwarded(&b, "f4");
    refused(&from_host.call(hop(w.host.kid(), "f4", Some(&t), Some(prove(&w.a, &t, "weather.forecast", "f4")))).await, "another key");
    // The service's own proof, on its own connection: taken, as the caller.
    let (t, p) = w.forwarded(&b, "f5");
    let got = from_host.call(hop(w.host.kid(), "f5", Some(&t), Some(p))).await;
    assert_eq!(got["content"]["ran_for"], CALLER, "{got}");
}

/// The second review's b1: M asks V's `_info` over M's own connection and
/// relays V's proof to the service as its own. The proof was made for M,
/// the asker V's connection proved, so the service — checking it was made
/// for itself — refuses it, and M is never registered under V's key.
/// (Second pass (b).) Any token M holds bound to V's key (minted as if it
/// were) and sent to V is refused as well.
#[tokio::test]
async fn b1_a_relayed_key_proof_is_refused_and_v_takes_nothing_from_m() {
    let w = World::new();
    let m = PeerKey::generate();
    let mut b = w.serve_b(&m, &w.host);
    let nonce = random_nonce();
    // M relays the service's nonce, naming the service as the asker.
    let frame = json!({ "jsonrpc": "2.0", "id": 9, "method": "_info", "params": { "nonce": nonce, "asker": w.host.kid() } });
    b.to_b.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
    let info = loop {
        let line = tokio::time::timeout(std::time::Duration::from_secs(5), b.lines.next_line()).await.unwrap().unwrap().unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        if v.pointer("/params/result/type").and_then(Value::as_str) == Some("data") {
            break v["params"]["result"]["content"].clone();
        }
    };
    let _done = b.lines.next_line().await.unwrap();
    assert_eq!(info["asker"], m.kid(), "made for the asker the connection proved, not the one named: {info}");
    let (key, proof, backend) = (info["key"].as_str().unwrap(), info["proof"].as_str().unwrap(), info["backend"].as_str().unwrap());
    assert!(check_key_proof_for(key, proof, &nonce, backend, w.host.kid()).is_err(), "the service refuses a proof made for M");
    assert!(check_key_proof_for(key, proof, &nonce, backend, m.kid()).is_ok(), "it is V's proof, for M");
    // Were M registered so: the token for a call into M, sent by M to V.
    let (t, p) = w.forwarded(w.b.kid(), "m1");
    refused(&b.call(hop(m.kid(), "m1", Some(&t), Some(p))).await, "the service's own connection");
}

/// The second review's b2: V served as `ServeChild::default()` (a `Pipe`)
/// on a network, as dyn's tests served a WebSocket peer. A keyed child, or
/// one verifying tokens addressed to a key, is refused on a pipe outright;
/// a pipe child verifying pipe tokens takes a forwarded hop only with the
/// service's proof. (Second pass (a).)
#[tokio::test]
async fn b2_a_pipe_proves_nobody() {
    let w = World::new();
    // A keyed child on a pipe: refused before it reads a line.
    let (_to, b_in) = tokio::io::duplex(1 << 10);
    let (b_out, _from) = tokio::io::duplex(1 << 10);
    let at_once = std::time::Duration::from_secs(2);
    let keyed = tokio::time::timeout(at_once, serve_child_with(WeatherActivation, b_in, b_out, ServeChild { peer: ChildPeer::Pipe, key: Some(w.b.clone()), tokens: Some(w.verifier()) })).await.expect("refused at once, not served");
    assert_eq!(keyed.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    let (_to, b_in) = tokio::io::duplex(1 << 10);
    let (b_out, _from) = tokio::io::duplex(1 << 10);
    let key_verifier = tokio::time::timeout(at_once, serve_child_with(WeatherActivation, b_in, b_out, ServeChild { peer: ChildPeer::Pipe, key: None, tokens: Some(w.verifier()) })).await.expect("refused at once, not served");
    assert_eq!(key_verifier.unwrap_err().kind(), std::io::ErrorKind::InvalidInput, "a key-addressed verifier on a pipe");
    // A pipe child verifying its pipe's tokens: the bytes of a forwarded
    // token alone are refused; with the service's proof, taken.
    let pipe = Arc::new(Verifier::new("pipe:v", &w.issuer.jwks()).unwrap());
    let opts = ServeChild { peer: ChildPeer::Pipe, key: None, tokens: Some(pipe) };
    let (mut to_v, v_in) = tokio::io::duplex(1 << 16);
    let (v_out, from_v) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve_child_with(WeatherActivation, v_in, v_out, opts));
    let mut v = Input { to_b: std::mem::replace(&mut to_v, tokio::io::duplex(1).0), lines: BufReader::new(from_v).lines(), next: 1 };
    let mint = |call: &str| {
        let (t, c) = w.issuer.mint(MintRequest { sub: CALLER.into(), peer_key: None, name: "v".into(), scope: vec!["weather.forecast@*".into()], call: call.into(), method: "weather.forecast".into(), presented: None }).unwrap();
        let p = w.issuer.prove_forward(&t, &c).unwrap();
        (t, p)
    };
    let (t, _) = mint("p1");
    refused(&v.call(hop(w.host.kid(), "p1", Some(&t), None)).await, "no proof of possession");
    let (t, p) = mint("p2");
    let got = v.call(hop(w.host.kid(), "p2", Some(&t), Some(p))).await;
    assert_eq!(got["content"]["ran_for"], CALLER, "{got}");
}

/// N3: a replay of a token without its proof, by someone who saw it, does
/// not spend it: the service's own presentation, with its proof, is taken
/// after it.
#[tokio::test]
async fn a_replay_without_its_proof_does_not_burn_the_token() {
    let w = World::new();
    let v = w.verifier();
    let mut observer = w.serve_b_with(&w.a, &w.host, Arc::clone(&v));
    let mut from_host = w.serve_b_with(&w.host, &w.host, v);
    let (t, p) = w.forwarded(w.b.kid(), "r1");
    refused(&observer.call(hop(w.a.kid(), "r1", Some(&t), None)).await, "the service's own connection");
    let got = from_host.call(hop(w.host.kid(), "r1", Some(&t), Some(p))).await;
    assert_eq!(got["content"]["ran_for"], CALLER, "the observer's replay spent the token: {got}");
    // An exchanged token replayed by an observer without its presenter's proof, too.
    let mut from_a = w.serve_b_with(&w.a, &w.host, w.verifier());
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    refused(&from_a.call(hop(w.a.kid(), &c.call, Some(&t), None)).await, "no proof of possession");
    let got = from_a.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&w.a, &t, "weather.forecast", &c.call)))).await;
    assert_eq!(got["content"]["ran_for"], CALLER, "{got}");
}

/// The legitimate direct hop: A presents its exchanged token with its own
/// proof, over a connection proven as A — B runs it, as the caller. A proof
/// by another key, a proof for another method or call, or the right proof
/// over a connection proven as another: refused.
#[tokio::test]
async fn the_presenter_with_its_proof_is_taken() {
    let w = World::new();
    let mallory = PeerKey::generate();
    let mut b = w.serve_b(&w.a, &w.host);
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    refused(&b.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&mallory, &t, "weather.forecast", &c.call)))).await, "another key");
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    refused(&b.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&w.a, &t, "weather.secret", &c.call)))).await, "presented for weather.forecast");
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    let got = b.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&w.a, &t, "weather.forecast", &c.call)))).await;
    assert_eq!(got["content"], json!({ "city": "lisbon", "ran_for": CALLER }), "{got}");
    // A's token and proof, carried by Mallory's connection.
    let mut via_mallory = w.serve_b(&mallory, &w.host);
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    refused(&via_mallory.call(hop(mallory.kid(), &c.call, Some(&t), Some(prove(&w.a, &t, "weather.forecast", &c.call)))).await, "not as the presenter");
}

/// A subject token is exchanged once per (`jti`, audience, method): a second
/// ask, with a fresh proof, is refused. (KEEL-19 (3).)
#[tokio::test]
async fn a_subject_is_exchanged_once() {
    let w = World::new();
    let (t_a, c_a) = w.a_token();
    let seen = ProofCache::default();
    let ask = |method: &str| {
        let proof = prove(&w.a, &t_a, EXCHANGE, &c_a.call);
        w.issuer.exchange(&t_a, Some(&proof), "b", Some(w.b.kid().into()), None, &uuid::Uuid::new_v4().to_string(), method, &seen)
    };
    assert!(ask("weather.forecast").is_ok());
    assert!(matches!(ask("weather.forecast"), Err(TokenError::Refused(w)) if w.contains("once")), "a second exchange of one subject");
    assert!(ask("weather.history").is_ok(), "another method is another exchange");
}
