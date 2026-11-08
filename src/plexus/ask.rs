//! ASK-2 — a method that proposes (ASK-1, replacing the in-call question).
//!
//! A method that needs its caller's yes, or a value only planning can name,
//! finishes its call with a **proposal** — a `needs_input` item saying what
//! it would do — and is called again with the proposal's token. Two ordinary
//! calls any client can make; no server-to-client question, no open channel.
//!
//! ```text
//! → tickets.archive { filter: "label stale" }
//! ← data  tickets.archive  {"type":"needs_input","summary":"archive 3 tickets","effects":[…],"fields":[],"token":"v1.…","expires":"…"}
//! ← done
//! → tickets.archive { filter: "label stale", confirm: "v1.…" }
//! ← data  tickets.archive  {"type":"archived","id":"MENGER-4"} …
//! ```
//!
//! | piece | what it is |
//! | -- | -- |
//! | `#[plexus_macros::method(asks)]` | the method declares `confirm: Option<ConfirmToken>`; its schema and IR say `asks: true`; its item type carries a `NeedsInput(NeedsInput)` variant |
//! | [`NeedsInput`] | the proposal: `summary`, `effects`, `fields`, `token`, `expires` (RFC 3339), an ordinary `data` item of the call |
//! | [`ConfirmToken`] | `v1.<expiry>.<base64url HMAC-SHA256(key, caller · method path · plan · expiry)>`, opaque to every client |
//! | [`propose`] | seals a plan for the caller and the method, and builds the item |
//! | [`check`] | the token against the plan rebuilt now: `Ok` proceeds; [`Stale`] says why the method proposes again |
//! | [`ConfirmKey`] | the seal's key: random per process ([`ConfirmKey::process`]) unless the service is given one ([`DynamicHub::with_confirm_key`]: replicas share it) |
//!
//! **The plan** is whatever the method would act on, as the method builds it
//! now — the ids it would touch and the store version it read. A token covers
//! that plan exactly, so a second call proceeds only if nothing moved; the
//! first confirmed call moves the store, so the same token sent twice meets a
//! plan that no longer matches and is answered with a fresh proposal. A
//! field's value (a parameter the caller fills on the answer) is not part of
//! the plan: the plan is what the caller was shown.
//!
//! ```ignore
//! #[plexus_macros::method(asks)]
//! async fn archive(&self, filter: Filter, confirm: Option<ConfirmToken>) -> impl Stream<Item = ArchiveEvent> + Send + 'static {
//!     let (ids, version) = self.store.matching(&filter);
//!     let plan = json!({ "ids": ids, "version": version });
//!     stream! {
//!         if ids.is_empty() { return; }                          // nothing to change: answer directly
//!         if let Err(_) = ask::check(confirm.as_ref(), &plan) { // no token, or the plan moved
//!             yield ArchiveEvent::NeedsInput(ask::propose(&plan, Proposal::new(format!("archive {} tickets", ids.len())).effects(&ids)));
//!             return;
//!         }
//!         for id in self.store.archive(&ids) { yield ArchiveEvent::Archived { id }; }
//!     }
//! }
//! ```
//!
//! [`DynamicHub::with_confirm_key`]: crate::plexus::DynamicHub::with_confirm_key

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use futures::Stream;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::content_hash::canonical_json;

/// How long a proposal stands unless [`Proposal::ttl`] says otherwise.
pub const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// The token's version prefix.
const V1: &str = "v1";

// ---------------------------------------------------------------- the types

/// The token a proposal carries and the answer sends back in `confirm`:
/// `v1.<expiry>.<base64url HMAC-SHA256>`, opaque to every client. Its JSON is
/// a string.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfirmToken(String);

impl JsonSchema for ConfirmToken {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ConfirmToken".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "The token of a proposal this method answered (`needs_input`), sent back to do what it proposed. Opaque."
        })
    }
}

impl ConfirmToken {
    /// A token as a client received it.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// When the token stops standing, in Unix seconds — `None` for a token
    /// that is not a v1 token.
    pub fn expiry(&self) -> Option<i64> {
        let mut parts = self.0.splitn(3, '.');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(V1), Some(exp), Some(_)) => exp.parse().ok(),
            _ => None,
        }
    }
}

impl fmt::Debug for ConfirmToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ConfirmToken").field(&self.0).finish()
    }
}

impl fmt::Display for ConfirmToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A proposal: what the method would do, the values it needs, and the token
/// that does it. A method marked `asks` yields it as its item type's
/// `NeedsInput(NeedsInput)` variant, which a `type`-tagged enum writes as
/// `{"type": "needs_input", "summary", "effects", "fields", "token", "expires"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NeedsInput {
    /// What would happen, in a line.
    pub summary: String,
    /// Each thing that would change, in the method's own terms.
    pub effects: Vec<Value>,
    /// The parameters the caller fills on the answer — none for a plain
    /// confirmation.
    pub fields: Vec<Field>,
    /// Sent back as `confirm` to do what was proposed.
    pub token: ConfirmToken,
    /// When the token stops standing (RFC 3339).
    pub expires: String,
}

/// A value the answer supplies: a parameter the method already declares,
/// sent on the answer under its own name. Its type is that parameter's; the
/// field adds only the choices, a default and help.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Field {
    /// The parameter's name.
    pub name: String,
    /// The values to choose from, when there are few.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<Value>>,
    /// The value taken when the caller says only yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    /// What the value decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

impl Field {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), options: None, default: None, help: None }
    }

    pub fn options<T: Serialize>(mut self, options: impl IntoIterator<Item = T>) -> Self {
        self.options = Some(options.into_iter().map(to_value).collect());
        self
    }

    pub fn default(mut self, value: impl Serialize) -> Self {
        self.default = Some(to_value(value));
        self
    }

    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}

/// What [`propose`] says besides the token: the summary, the effects, the
/// fields, and how long the proposal stands.
#[derive(Debug, Clone)]
pub struct Proposal {
    summary: String,
    effects: Vec<Value>,
    fields: Vec<Field>,
    ttl: Duration,
}

impl Proposal {
    pub fn new(summary: impl Into<String>) -> Self {
        Self { summary: summary.into(), effects: Vec::new(), fields: Vec::new(), ttl: DEFAULT_TTL }
    }

    /// One more effect.
    pub fn effect(mut self, effect: impl Serialize) -> Self {
        self.effects.push(to_value(effect));
        self
    }

    /// Effects, one per item.
    pub fn effects<T: Serialize>(mut self, effects: impl IntoIterator<Item = T>) -> Self {
        self.effects.extend(effects.into_iter().map(to_value));
        self
    }

    /// A value the answer supplies.
    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    /// How long the token stands (default [`DEFAULT_TTL`]).
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

fn to_value(v: impl Serialize) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// Why a token does not confirm the plan rebuilt now: the method changes
/// nothing and proposes again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// No token: the first call.
    Missing,
    /// Not a token this service sealed (another version, or unreadable).
    Malformed,
    /// Past its expiry.
    Expired,
    /// Sealed for another plan, caller, method or key: the plan moved (the
    /// store did, or another ticket matched), or the token is not this
    /// caller's for this method.
    Moved,
    /// Checked outside a method marked `asks` (no method path to check it for).
    NotAsking,
}

impl fmt::Display for Stale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Stale::Missing => "no confirm token",
            Stale::Malformed => "the confirm token is not one this service sealed",
            Stale::Expired => "the confirm token has expired",
            Stale::Moved => "the plan moved since it was proposed (or the token is another caller's or method's)",
            Stale::NotAsking => "checked outside a method marked `asks`",
        })
    }
}

impl std::error::Error for Stale {}

// ---------------------------------------------------------------- the seal

/// The seal's key: 32 bytes. Random per process unless the service is given
/// one ([`DynamicHub::with_confirm_key`](crate::plexus::DynamicHub::with_confirm_key)),
/// as replicas must share one for a token to cross them.
#[derive(Clone)]
pub struct ConfirmKey([u8; 32]);

impl fmt::Debug for ConfirmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmKey(..)")
    }
}

impl ConfirmKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A fresh random key.
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("the system's random source");
        Self(b)
    }

    /// This process's key: random, made once.
    pub fn process() -> Arc<ConfirmKey> {
        static KEY: OnceLock<Arc<ConfirmKey>> = OnceLock::new();
        Arc::clone(KEY.get_or_init(|| Arc::new(ConfirmKey::random())))
    }

    /// Seal `plan` for `caller` calling `method`, standing until `expiry`
    /// (Unix seconds).
    pub fn seal(&self, caller: &str, method: &str, plan: &Value, expiry: i64) -> ConfirmToken {
        let mac = self.mac(caller, method, plan, expiry);
        ConfirmToken(format!("{V1}.{expiry}.{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac)))
    }

    /// Whether `token` is this key's seal of `plan` for `caller` calling
    /// `method`, standing at `now` (Unix seconds).
    pub fn check(&self, token: &ConfirmToken, caller: &str, method: &str, plan: &Value, now: i64) -> Result<(), Stale> {
        let mut parts = token.0.splitn(3, '.');
        let (Some(V1), Some(exp), Some(mac)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(Stale::Malformed);
        };
        let Ok(expiry) = exp.parse::<i64>() else { return Err(Stale::Malformed) };
        let Ok(mac) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(mac) else { return Err(Stale::Malformed) };
        if mac.len() != 32 {
            return Err(Stale::Malformed);
        }
        // The seal first: an expiry is believed only once it is the seal's.
        if !constant_time_eq(&mac, &self.mac(caller, method, plan, expiry)) {
            return Err(Stale::Moved);
        }
        if now >= expiry {
            return Err(Stale::Expired);
        }
        Ok(())
    }

    /// HMAC-SHA256 over the four parts, each length-prefixed (u64 BE) so no
    /// two splits of the same bytes seal the same: caller, method path, the
    /// plan's canonical JSON, the expiry in decimal.
    fn mac(&self, caller: &str, method: &str, plan: &Value, expiry: i64) -> [u8; 32] {
        let plan = canonical_json(plan);
        let expiry = expiry.to_string();
        let mut msg = Vec::with_capacity(32 + caller.len() + method.len() + plan.len() + expiry.len());
        for part in [caller.as_bytes(), method.as_bytes(), plan.as_bytes(), expiry.as_bytes()] {
            msg.extend_from_slice(&(part.len() as u64).to_be_bytes());
            msg.extend_from_slice(part);
        }
        hmac_sha256(&self.0, &msg)
    }
}

/// RFC 2104 over SHA-256.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(key);
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------- the call

tokio::task_local! {
    /// The method path (`<ns>.<method>`) of the `asks` method this runs in.
    static ASKING: &'static str;
}

/// Run `fut` as the body of the `asks` method `method` (`<ns>.<method>`):
/// what `#[plexus_macros::method(asks)]`'s dispatch does, and a hand-written
/// activation does for its own. [`asking_stream`] carries it into the stream
/// the method answers.
pub fn asking<F: Future>(method: &'static str, fut: F) -> impl Future<Output = F::Output> {
    ASKING.scope(method, fut)
}

/// The stream an `asks` method answered, each poll run as the method
/// `method` (`<ns>.<method>`), so its body reads the path as the method's
/// first line does.
pub fn asking_stream<S: Stream + Send + 'static>(method: &'static str, stream: S) -> Pin<Box<dyn Stream<Item = S::Item> + Send>> {
    Box::pin(Asking { method, inner: Box::pin(stream) })
}

struct Asking<S> {
    method: &'static str,
    inner: Pin<Box<S>>,
}

impl<S: Stream> Stream for Asking<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        let method = self.method;
        ASKING.sync_scope(method, || self.inner.as_mut().poll_next(cx))
    }
}

/// The method path of the `asks` method this runs in.
pub fn method_path() -> Option<&'static str> {
    ASKING.try_with(|m| *m).ok()
}

/// Who the call's seal is for: the caller the dispatch admitted (in a child,
/// the one the hop names), by principal; `""` for an anonymous caller or
/// outside a call.
fn caller_name() -> String {
    let Ok(ctx) = crate::call::context() else { return String::new() };
    ctx.auth()
        .map(|a| a.principal().map(|p| p.to_string()).unwrap_or_else(|| a.user_id.clone()))
        .unwrap_or_default()
}

/// The key of the service the call runs in, else the process's.
fn key() -> Arc<ConfirmKey> {
    crate::call::context().ok().and_then(|c| c.confirm_key().cloned()).unwrap_or_else(ConfirmKey::process)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The first helper: seal `plan` for this call's caller and method, and
/// build the `needs_input` item — the method yields it (as its item type's
/// `NeedsInput` variant) and ends, having changed nothing.
pub fn propose(plan: &impl Serialize, proposal: Proposal) -> NeedsInput {
    let plan = to_value(plan);
    let ttl = i64::try_from(proposal.ttl.as_secs()).unwrap_or(i64::MAX / 2);
    let expiry = now().saturating_add(ttl.max(1));
    let token = key().seal(&caller_name(), method_path().unwrap_or(""), &plan, expiry);
    let expires = chrono::DateTime::<chrono::Utc>::from_timestamp(expiry, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    NeedsInput { summary: proposal.summary, effects: proposal.effects, fields: proposal.fields, token, expires }
}

/// The second helper: does `confirm` seal the plan the method rebuilt now,
/// for this caller and method, unexpired? `Ok`: proceed. `Err`: change
/// nothing and [`propose`] again — a stale token is never an error.
pub fn check(confirm: Option<&ConfirmToken>, plan: &impl Serialize) -> Result<(), Stale> {
    let token = confirm.ok_or(Stale::Missing)?;
    let method = method_path().ok_or(Stale::NotAsking)?;
    key().check(token, &caller_name(), method, &to_value(plan), now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> ConfirmKey {
        ConfirmKey::from_bytes([7; 32])
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2_shape() {
        // RFC 4231 test case 2 has a 4-byte key; ours is 32 bytes, zero-padded
        // the same way HMAC pads any short key — so the vector holds.
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(b"Jefe");
        let mac = hmac_sha256(&k, b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn a_seal_checks_for_its_own_plan_caller_method_and_time() {
        let plan = json!({"ids": ["A-1"], "version": 3});
        let t = key().seal("key:ada", "tickets.archive", &plan, 1000);
        assert!(t.as_str().starts_with("v1.1000."), "{t}");
        assert_eq!(t.expiry(), Some(1000));
        assert_eq!(key().check(&t, "key:ada", "tickets.archive", &plan, 999), Ok(()));
        // key order does not matter: the plan is canonical JSON
        assert_eq!(key().check(&t, "key:ada", "tickets.archive", &json!({"version": 3, "ids": ["A-1"]}), 999), Ok(()));
        assert_eq!(key().check(&t, "key:ada", "tickets.archive", &json!({"ids": ["A-1"], "version": 4}), 999), Err(Stale::Moved));
        assert_eq!(key().check(&t, "key:bob", "tickets.archive", &plan, 999), Err(Stale::Moved));
        assert_eq!(key().check(&t, "key:ada", "tickets.delete", &plan, 999), Err(Stale::Moved));
        assert_eq!(ConfirmKey::from_bytes([8; 32]).check(&t, "key:ada", "tickets.archive", &plan, 999), Err(Stale::Moved));
        assert_eq!(key().check(&t, "key:ada", "tickets.archive", &plan, 1000), Err(Stale::Expired));
    }

    #[test]
    fn an_expiry_is_believed_only_under_its_seal() {
        let plan = json!(1);
        let t = key().seal("", "m.m", &plan, 10);
        let mac = t.as_str().rsplit('.').next().unwrap();
        let forged = ConfirmToken::new(format!("v1.99999.{mac}"));
        assert_eq!(key().check(&forged, "", "m.m", &plan, 50), Err(Stale::Moved));
    }

    #[test]
    fn what_is_not_a_token_is_malformed() {
        for bad in ["", "v1", "v1.10", "v2.10.AAAA", "v1.x.AAAA", "v1.10.!!", "v1.10.AAAA"] {
            assert_eq!(key().check(&ConfirmToken::new(bad), "", "m.m", &json!(1), 0), Err(Stale::Malformed), "{bad}");
        }
    }

    #[test]
    fn the_item_is_the_wire_tables() {
        let n = NeedsInput {
            summary: "s".into(),
            effects: vec![json!("e")],
            fields: vec![Field::new("children").options(["reparent", "delete"]).default("reparent"), Field::new("n")],
            token: ConfirmToken::new("v1.1.x"),
            expires: "1970-01-01T00:00:01Z".into(),
        };
        assert_eq!(
            serde_json::to_value(&n).unwrap(),
            json!({"summary":"s","effects":["e"],"fields":[{"name":"children","options":["reparent","delete"],"default":"reparent"},{"name":"n"}],"token":"v1.1.x","expires":"1970-01-01T00:00:01Z"})
        );
    }

    #[tokio::test]
    async fn check_outside_an_asks_method_is_refused_and_inside_it_holds() {
        let plan = json!({"v": 1});
        let n = asking("t.m", async { propose(&plan, Proposal::new("do it")) }).await;
        assert_eq!(check(Some(&n.token), &plan), Err(Stale::NotAsking));
        assert_eq!(asking("t.m", async { check(Some(&n.token), &plan) }).await, Ok(()));
        assert_eq!(asking("t.other", async { check(Some(&n.token), &plan) }).await, Err(Stale::Moved));
        assert_eq!(asking("t.m", async { check(None, &plan) }).await, Err(Stale::Missing));
        assert!(n.expires.ends_with('Z'), "{}", n.expires);
    }
}
