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

use futures::Stream;
use plexus_core::plexus::peer_token::{prove, MintRequest, PeerKey, ProofCache, TokenError, TokenIssuer, Verifier, EXCHANGE};
use plexus_core::plexus::remote_child::{serve_child_with, ChildPeer, ServeChild};
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
    fn serve_b(&self, peer: ChildPeer) -> Input {
        let v = Verifier::new(self.b.kid(), &self.issuer.jwks()).unwrap();
        let opts = ServeChild { peer, key: Some(self.b.clone()), tokens: Some(Arc::new(v)) };
        let (to_b, b_in) = tokio::io::duplex(1 << 16);
        let (b_out, from_b) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_child_with(WeatherActivation, b_in, b_out, opts));
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
    let mut b = w.serve_b(ChildPeer::connection(w.a.kid(), [w.host.kid().to_string()]));
    // Control: without a token, A's hop is refused (A is not trusted).
    refused(&b.call(hop(w.a.kid(), "x", None, None)).await, "no token");
    // The attack: the exchanged token in A's hop, no proof.
    let got = b.call(hop(w.a.kid(), &c_b.call, Some(&t_b), None)).await;
    refused(&got, "no proof of possession");
    assert_ne!(got["content"]["ran_for"], CALLER, "B ran the method as the caller: {got}");
}

/// A token the service forwarded to B (bound to B's own key), stolen and
/// sent by A: taken only from the service's own connection. (KEEL-19 (2).)
#[tokio::test]
async fn a_forwarded_token_is_taken_only_from_the_service() {
    let w = World::new();
    let forwarded = |call: &str| {
        w.issuer
            .mint(MintRequest { sub: CALLER.into(), peer_key: Some(w.b.kid().into()), name: "b".into(), scope: vec!["weather.forecast@*".into()], call: call.into(), method: "weather.forecast".into(), presented: None })
            .unwrap()
            .0
    };
    let mut from_a = w.serve_b(ChildPeer::connection(w.a.kid(), [w.host.kid().to_string()]));
    refused(&from_a.call(hop(w.a.kid(), "f1", Some(&forwarded("f1")), None)).await, "the service's own connection");
    // Even with a proof by A: the token is B's, not A's.
    let t = forwarded("f2");
    refused(&from_a.call(hop(w.a.kid(), "f2", Some(&t), Some(prove(&w.a, &t, "weather.forecast", "f2")))).await, "the service's own connection");
    // From the service, on its own connection: taken, as the caller.
    let mut from_host = w.serve_b(ChildPeer::connection(w.host.kid(), [w.host.kid().to_string()]));
    let got = from_host.call(hop(w.host.kid(), "f3", Some(&forwarded("f3")), None)).await;
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
    let mut b = w.serve_b(ChildPeer::connection(w.a.kid(), [w.host.kid().to_string()]));
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    refused(&b.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&mallory, &t, "weather.forecast", &c.call)))).await, "another key");
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    refused(&b.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&w.a, &t, "weather.secret", &c.call)))).await, "presented for weather.forecast");
    let (t, c) = w.exchanged_for_b("weather.forecast").unwrap();
    let got = b.call(hop(w.a.kid(), &c.call, Some(&t), Some(prove(&w.a, &t, "weather.forecast", &c.call)))).await;
    assert_eq!(got["content"], json!({ "city": "lisbon", "ran_for": CALLER }), "{got}");
    // A's token and proof, carried by Mallory's connection.
    let mut via_mallory = w.serve_b(ChildPeer::connection(mallory.kid(), [w.host.kid().to_string()]));
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
