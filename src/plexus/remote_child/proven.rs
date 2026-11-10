//! KEEL-19 · a principal a verifier proved, as a type.
//!
//! A keyed child — one that proves a key at `_info`, or verifies tokens
//! addressed to a key — believes a forwarded hop from the service acting for
//! others only over a connection whose sender was *proven*. A principal
//! written as a string proves nothing: anyone can write the service's key.
//! [`Proven`] is that proof as a type: it has no constructor from a string,
//! and is made only where a signature was checked —
//!
//! - [`KeyedUpgrade::verify`]: the key proof a mount dials its child with
//!   (`Authorization: Bearer plexus-key.…`, plexus-wire spec/00), which
//!   `serve_child_ws` asks at the upgrade, or an embedder's own transport
//!   hands it.
//!
//! (A dial-out's relay proof, `relay_proved`, is checked too, but the
//! dial-out serves a keyless host and needs no `Proven`.) A keyed child is
//! served only through `serve_child_proven` (or `serve_child_ws`, which
//! calls it); `serve_child_with` refuses one, whatever `ChildPeer` it is
//! given.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use ed25519_dalek::Signer;

/// A principal (`key:<hex>`) whose key signed a proof a verifier checked.
/// No constructor from a string: [`KeyedUpgrade::verify`] makes it.
///
/// ```compile_fail
/// // A string is not a proof: there is no way to write one.
/// let p = plexus_core::plexus::remote_child::Proven { principal: "key:00".into() };
/// ```
///
/// ```compile_fail
/// let p: plexus_core::plexus::remote_child::Proven = "key:00".to_string().into();
/// ```
///
/// Not `Clone`: it is the proof of one socket's upgrade, consumed by serving
/// that socket ([`super::serve_child_proven`]).
#[derive(Debug, PartialEq, Eq)]
pub struct Proven {
    principal: String,
}

impl Proven {
    /// The principal proven (`key:<hex>`).
    pub fn principal(&self) -> &str {
        &self.principal
    }
}

/// spec/00's key-proof context, the one a child is dialed with. (KEEL-19's
/// P2 — a context of its own for a child dial — is a plexus-wire spec/00
/// change, not made here: a sign-in proof and a child dial are one form.)
pub(super) const KEY_PROOF_CONTEXT: &str = "plexus-key-login/v1";

/// The most (key, nonce) pairs a [`KeyedUpgrade`] holds at once. Full, it
/// refuses new upgrades until entries leave their 60 s window — it never
/// forgets one early (KEEL-19, P3a: an evicted proof could be replayed).
pub const UPGRADE_LEDGER_MAX: usize = 4096;

/// KEEL-19 (P2): the agent id a child dial's key proof is signed as. spec/00
/// has one key-proof form for a dial and a sign-in; `agent` is in the signed
/// bytes, so a child takes only a proof made as this agent: a sign-in proof
/// replayed to a child at the same URL is refused. A server's sign-in
/// (plexus-auth-core's `KeyProofAdapter`) takes a dial proof as the dialing
/// key's sign-in for its own URL, by design: that is how a service mounts a
/// service behind key sign-in.
pub const CHILD_DIAL_AGENT: &str = "plexus.child-dial";

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A spec/00 key proof by `key`, for the child at `aud` (its URL), as the
/// reserved agent [`CHILD_DIAL_AGENT`] — what a mount sends at the upgrade
/// (`ws::dial` does), and what an embedder's client of a keyed child sends.
pub fn dial_proof(key: &crate::plexus::peer_token::PeerKey, aud: &str) -> String {
    let agent = CHILD_DIAL_AGENT;
    let mut n = [0u8; 32];
    n[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    n[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let aud = aud.trim_end_matches('/');
    let nonce = b64(&n);
    let sig = key.signing().sign(format!("{KEY_PROOF_CONTEXT}\n{aud}\n{agent}\n{nonce}\n{ts}").as_bytes());
    let hex: String = key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let body = serde_json::json!({ "v": 1, "key": hex, "aud": aud, "agent": agent, "nonce": nonce, "ts": ts, "sig": b64(&sig.to_bytes()) });
    format!("plexus-key.{}", b64(body.to_string().as_bytes()))
}

/// KEEL-19 · the accepting side of a child's dial: what verifies the key
/// proof a service dials its child with (`Authorization: Bearer
/// plexus-key.…`, spec/00) and so makes the [`Proven`] a keyed child is
/// served on. `aud`
/// must be one of the URLs this child is dialed at, `ts` within 60 s past
/// and 30 s ahead, each (key, nonce) once — remembered for its window, at
/// most [`UPGRADE_LEDGER_MAX`]; a restarted child forgets, so a proof
/// captured in its last 60 s can be replayed once to it after a restart.
pub struct KeyedUpgrade {
    audiences: Vec<String>,
    seen: Mutex<HashMap<(String, String), i64>>,
    /// When the last "ledger full" warning was written, and how many
    /// refusals since were not (at most one line per 10 s).
    full_said: Mutex<(Option<std::time::Instant>, u64)>,
}

impl std::fmt::Debug for KeyedUpgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyedUpgrade").field("audiences", &self.audiences).finish()
    }
}

impl KeyedUpgrade {
    /// Proofs addressed to one of `audiences` (`ws://127.0.0.1:<port>`, …).
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(audiences: I) -> Self {
        Self { audiences: audiences.into_iter().map(|a| a.as_ref().trim().trim_end_matches('/').to_string()).collect(), seen: Default::default(), full_said: Default::default() }
    }

    /// The principal the bearer value `bearer` proves, or why not.
    pub fn verify(&self, bearer: &str) -> Result<Proven, String> {
        use ed25519_dalek::Signature;
        let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let body = bearer.trim().strip_prefix("plexus-key.").ok_or("not a key proof (`plexus-key.…`)")?;
        let p: serde_json::Value = b64.decode(body).ok().and_then(|j| serde_json::from_slice(&j).ok()).ok_or("a key proof that does not read")?;
        let s = |k: &str| p.get(k).and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
        let (key, aud, agent, nonce, sig) = (s("key"), s("aud"), s("agent"), s("nonce"), s("sig"));
        let ts = p.get("ts").and_then(serde_json::Value::as_i64).ok_or("a key proof with no `ts`")?;
        if p.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err("a key proof whose `v` is not 1".into());
        }
        if agent != CHILD_DIAL_AGENT {
            return Err(format!("a key proof as agent `{agent}`, not a child dial (`{CHILD_DIAL_AGENT}`): a sign-in proof is not taken here"));
        }
        if !self.audiences.iter().any(|a| a == aud.trim_end_matches('/')) {
            return Err(format!("a key proof for `{aud}`, not for this child"));
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        if ts + 60 < now || ts > now + 30 {
            return Err("a key proof out of its time window".into());
        }
        let vk = crate::plexus::peer_token::key_of(&format!("key:{key}")).ok_or("a key proof whose `key` is not an Ed25519 key")?;
        let sig: [u8; 64] = b64.decode(&sig).ok().and_then(|b| b.try_into().ok()).ok_or("a key proof whose `sig` does not read")?;
        vk.verify_strict(format!("{KEY_PROOF_CONTEXT}\n{aud}\n{agent}\n{nonce}\n{ts}").as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| "a key proof whose signature does not verify")?;
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, until| *until >= now);
        if seen.contains_key(&(key.clone(), nonce.clone())) {
            return Err("a key proof used before".into());
        }
        // P3a: bounded, and full it refuses — never forgets a proof early.
        if seen.len() >= UPGRADE_LEDGER_MAX {
            let mut said = self.full_said.lock().unwrap();
            said.1 += 1;
            if said.0.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(10)) {
                tracing::warn!(target: "plexus::audit", held = seen.len(), refused = said.1, audiences = ?self.audiences, "child upgrade ledger full: new upgrades refused until proofs leave their 60 s window");
                *said = (Some(std::time::Instant::now()), 0);
            }
            return Err(format!("this child holds {UPGRADE_LEDGER_MAX} key proofs in their 60 s window: a new upgrade is refused until some expire"));
        }
        seen.insert((key.clone(), nonce), ts + 60);
        Ok(Proven { principal: format!("key:{key}") })
    }
}
