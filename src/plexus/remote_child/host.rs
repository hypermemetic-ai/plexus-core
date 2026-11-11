//! RETURNS-47 · the seam's far side, in Rust: an activation served to the
//! service that mounts it, on stdio (spec/11, 12) — the plugin's half of
//! [`RemoteChild`](super::RemoteChild).
//!
//! ```ignore
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     plexus_core::plexus::remote_child::serve_child_stdio(GitHub::new()).await
//! }
//! ```
//!
//! It answers `_info` (`backend`: the activation's namespace), `{ns}.call
//! {method, params, hop}` and `{ns}.call_unsub [sid]`.
//!
//! **A child receives auth** (owner, 2026-11-04). Each call runs in the hop's
//! context ([`crate::call`]): `call::caller()` is the caller the hop names
//! (`for`'s far end; anonymous when `for` is empty), its reach the hop's
//! ceiling (`limit.held_on` for `limit.grant`, as a gate of the hop alone
//! answers it; nowhere when `for` cannot be read),
//! never wider; `current_reach()` and `reach: Reach` answer that ceiling; a
//! method under `auth = "required"` refuses an anonymous hop; a `#[from_auth]`
//! verifier (on a parameter, or on a trait-impl method) is the child's own,
//! run on that caller. `call::hop()` answers the hop itself.
//!
//! A plugin bounds its reads with `call::caller()?.reach()` (or
//! `current_reach()`): within the ceiling for the caller the hop names, and
//! nowhere when it names none it can read. `call::hop()?.allows(…)` answers
//! the same.
//!
//! The far side decides again (spec/12 rule 2), before the method runs: a
//! call with no hop is `unauthenticated`; a hop no gate decided (`limit:
//! null`, or no grant) and a hop admitted for another grant than the method
//! called — or than the dynamic slot it goes through (NEST-6:
//! `{ns}.solar.{planet}.info` for `{ns}.solar.earth.info`, an untyped slot's
//! `{ns}.belt.{rock}` for every method on a rock) — are `forbidden`. A schema call (`{ns}.schema`) answers whatever its
//! hop, in its context when it has one, as every call (a dynamic child's
//! lookup included) runs. Nothing is written to stdout but the protocol.
//!
//! # Who may send a hop — the trust model
//!
//! A hop is unsigned JSON: it is believed only from a sender the child
//! trusts to act for others, and [`ChildPeer`] says who that is.
//!
//! - **A pipe** ([`ChildPeer::Pipe`], [`serve_child`], [`serve_child_stdio`]):
//!   the child's stdin is the pipe of the service that spawned it — nobody
//!   else writes it — so every hop on it is the parent's. Serve a child this
//!   way only on a pipe its parent owns.
//! - **A connection** ([`ChildPeer::connection`], [`serve_child_on`]): the
//!   transport has proven who is on the other end (a WebSocket's key proof,
//!   plexus-wire spec/00 — what `RemoteChild` dials `child-ws` with, its
//!   `--child-key`), and the child takes a hop only when that principal is
//!   one it trusts to act for others (a configured list) and the hop names
//!   it as the acting service (`hop.principal`). Any other hop is refused
//!   `forbidden`, before the method runs. plexus-core has no WebSocket
//!   server of its own for a Rust child: the server that proves the
//!   connection hands this its principal.
//!
//! What a trusted sender says is believed: the caller it names and the
//! ceiling it gives. GRAFT-1's credential scoped to the call is what would
//! let a child check the claim rather than the sender.
//!
//! # Calling the service back (NEST-11)
//!
//! While it serves a call, the activation may call its service back on the
//! same connection: [`host()`] is a [`plexus_client::Transport`] for the
//! call being run — a generated client takes it as any other — whose calls
//! are `_host.call {method, params, under}`, `under` the hop's `call` id.
//! The service routes each through its own gate as the hop's caller, within
//! the hop's reach, and ends them when the call they were made under ends
//! ([`super::RemoteChild`]'s side, `upcall.rs`). Dropping a call's stream
//! sends `_host.call_unsub`.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};
use plexus_client::{ItemStream, MethodRef, StreamItem, Transport, TransportError, TransportErrorKind};
use plexus_client::{DenyReason, RemoteError};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{mpsc, oneshot};

use super::link::{meta, write_lines};
use super::upcall::{HOST_CALL, HOST_CALL_UNSUB};
use crate::call::{CallContext, CallError, Hop, InCall};
use crate::plexus::plexus::{error_item, Activation};
use crate::plexus::slots::Slots;
use crate::plexus::types::PlexusStreamItem;

type Live = Arc<Mutex<HashMap<u64, tokio::task::AbortHandle>>>;

/// Who is on the other end of a child's input, and so whose hops it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildPeer {
    /// A pipe the parent owns (the child's stdin): every hop is the
    /// parent's.
    Pipe,
    /// A connection whose sender is `proven`; a hop is taken only when
    /// `proven` is one of `acts_for_others` and the hop names it as the
    /// acting service. KEEL-19: `proven` is whatever string it is given —
    /// nothing here checks it. For a keyless child whose embedder vouches
    /// for it; a keyed child is served only with a [`super::Proven`]
    /// ([`serve_child_proven`]).
    Connection { proven: String, acts_for_others: Vec<String> },
}

impl ChildPeer {
    /// A connection said to be proven as `proven`, the child trusting
    /// `acts_for_others` (service principals) to act for others. **It
    /// proves nothing itself**: the string is believed as given — for a
    /// keyless child only (`serve_child_with` refuses a keyed one).
    pub fn connection(proven: impl Into<String>, acts_for_others: impl IntoIterator<Item = String>) -> Self {
        ChildPeer::Connection { proven: proven.into(), acts_for_others: acts_for_others.into_iter().collect() }
    }

    /// Whether a hop on this input is believed.
    fn takes(&self, hop: &Hop) -> bool {
        match self {
            ChildPeer::Pipe => true,
            ChildPeer::Connection { proven, acts_for_others } => {
                acts_for_others.iter().any(|t| t == proven) && hop.principal == *proven
            }
        }
    }
}

/// Serve `activation` as a child on this process's stdin and stdout, until
/// the service closes stdin (spec/11: the end of input ends every call).
/// Only for a process the service spawned: its stdin is the service's alone
/// ([`ChildPeer::Pipe`]).
pub async fn serve_child_stdio<A>(activation: A) -> std::io::Result<()>
where
    A: Activation + Clone,
{
    serve_child(activation, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Serve `activation` as a child over `r` (frames from the service, one per
/// line) and `w` (frames to it), until `r` ends — a pipe its parent owns
/// ([`ChildPeer::Pipe`]): every hop on it is believed (see the module docs).
pub async fn serve_child<A, R, W>(activation: A, r: R, w: W) -> std::io::Result<()>
where
    A: Activation + Clone,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_child_on(activation, r, w, ChildPeer::Pipe).await
}

/// [`serve_child`] on an input whose sender is `peer`: a hop is taken only
/// as [`ChildPeer`] says, and refused `forbidden` otherwise.
pub async fn serve_child_on<A, R, W>(activation: A, r: R, w: W, peer: ChildPeer) -> std::io::Result<()>
where
    A: Activation + Clone,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_child_with(activation, r, w, ServeChild { peer, ..ServeChild::default() }).await
}

/// How a child serves (DYNAUTH-5): whose hops it takes, and the key it
/// proves to the service that mounts it.
#[derive(Debug, Clone)]
pub struct ServeChild {
    /// Whose hops it takes.
    pub peer: ChildPeer,
    /// DYNAUTH-5: the child's own Ed25519 key. With one, `_info {nonce}` is
    /// answered `{backend, key, proof, asker}` (the nonce, backend and
    /// asker signed — KEEL-19: the asker the connection proved), so the
    /// service registers and pins it; peer tokens are addressed and bound to
    /// it (DYNAUTH-12). KEEL-19: a keyed child is served on a proven
    /// connection only — on a `Pipe` `serve_child_with` refuses to start.
    pub key: Option<crate::plexus::peer_token::PeerKey>,
    /// DYNAUTH-12: verify each hop's token (`hop.token`) — signed by an
    /// issuer this verifier trusts (the service's `dyn.jwks`), addressed to
    /// this child (its key's id; `pipe:<name>` on a pipe), naming the hop's
    /// call and the method called, fresh and not seen before, its `sub` the
    /// hop's caller and its scope holding the hop's grant where the hop
    /// says it was admitted. One without, or whose token does not, is
    /// refused `forbidden`, saying why. A schema call needs none.
    ///
    /// KEEL-19: a token is believed only from whoever it names, proven by a
    /// proof of possession in the hop (`hop.proof`, for the method called
    /// under `hop.call`). A token bound to this child's own key (or, on a
    /// pipe, to none) is one the service forwards: the proof is the
    /// service's (`TokenIssuer::prove_forward`, by the key that signed it,
    /// checked against this verifier's JWKS), and on a connection its sender
    /// is also one [`ChildPeer`] takes — the token only narrows what that
    /// sender says. A token bound to another key is one its holder exchanged
    /// to present here itself (`dyn.exchange`): the proof is that holder's,
    /// over a connection proven as that key. A token's `jti` is spent only
    /// once its sender is proven. A verifier addressed to a key is refused
    /// on a `Pipe`.
    pub tokens: Option<Arc<crate::plexus::peer_token::Verifier>>,
}

impl Default for ServeChild {
    fn default() -> Self {
        Self { peer: ChildPeer::Pipe, key: None, tokens: None }
    }
}

/// [`serve_child_on`] with every option ([`ServeChild`]) — for a keyless
/// child. KEEL-19: a child with a key, or verifying tokens addressed to a
/// key, is refused (`InvalidInput`) whatever `ChildPeer` it is given: a
/// principal written as a string proves nothing. Serve one with
/// [`serve_child_proven`] (or `serve_child_ws`).
pub async fn serve_child_with<A, R, W>(activation: A, r: R, w: W, opts: ServeChild) -> std::io::Result<()>
where
    A: Activation + Clone,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if opts.key.is_some() || opts.tokens.as_ref().is_some_and(|v| v.audience().starts_with("key:")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a child with a key, or verifying tokens addressed to a key, is served on a connection a verifier proved (serve_child_proven with a Proven, or serve_child_ws): a principal written as a string, or a pipe, proves nobody",
        ));
    }
    serve(activation, r, w, opts).await
}

/// KEEL-19 · serve a keyed child (its `key`, its token verifier `tokens`) on
/// an input whose sender a verifier proved (`proven`, from
/// [`super::KeyedUpgrade::verify`]), trusting `trusted` (service principals,
/// `key:<hex>`) to act for others: a hop is believed only when `proven` is
/// one of them and the hop names it (see [`ServeChild::tokens`] for what a
/// token adds). `serve_child_ws` takes a WebSocket upgrade this way; an
/// embedder with its own transport verifies the upgrade's proof with a
/// [`super::KeyedUpgrade`] and calls this.
pub async fn serve_child_proven<A, R, W>(
    activation: A,
    r: R,
    w: W,
    proven: super::Proven,
    trusted: Vec<String>,
    key: Option<crate::plexus::peer_token::PeerKey>,
    tokens: Option<Arc<crate::plexus::peer_token::Verifier>>,
) -> std::io::Result<()>
where
    A: Activation + Clone,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let peer = ChildPeer::Connection { proven: proven.principal().to_string(), acts_for_others: trusted };
    serve(activation, r, w, ServeChild { peer, key, tokens }).await
}

/// The far side's loop, its options already admitted.
pub(super) async fn serve<A, R, W>(activation: A, r: R, w: W, opts: ServeChild) -> std::io::Result<()>
where
    A: Activation + Clone,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let ns = activation.namespace().to_string();
    let key = opts.key.clone().map(Arc::new);
    let tokens = opts.tokens.clone();
    let peer = Arc::new(opts.peer);
    // KEEL-19: the presenters' proofs seen, each once.
    let proofs = Arc::new(crate::plexus::peer_token::ProofCache::default());
    let slots = Arc::new(slot_index(&activation));
    let (call_m, unsub_m) = (format!("{ns}.call"), format!("{ns}.call_unsub"));
    let (out, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(write_lines(w, out_rx));
    let send = |out: &mpsc::UnboundedSender<Vec<u8>>, v: Value| {
        let _ = out.send(serde_json::to_vec(&v).unwrap_or_default());
    };
    let live: Live = Arc::default();
    let link = Arc::new(HostLink::new(out.clone(), key.clone()));
    let mut next_sid: u64 = 1;
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            send(&out, json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }));
            continue;
        };
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(Value::as_str).unwrap_or_default();
        // NEST-11: an answer to a call back (spec/14 rule 2: no `method`, an
        // id of this side's), or an item of one.
        if msg.get("method").is_none() {
            if let Some(n) = id.as_u64() {
                link.answered(n, msg.get("result").cloned(), msg.get("error").cloned());
            }
            continue;
        }
        if method == HOST_CALL && id.is_null() {
            let p = msg.get("params");
            if let (Some(sid), Some(item)) = (p.and_then(|p| p.get("subscription")).and_then(Value::as_u64), p.and_then(|p| p.get("result"))) {
                link.item(sid, item.clone()).await;
            }
            continue;
        }
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        if method == "_info" || method == call_m {
            let (target, p, hop) = if method == "_info" {
                ("_info".to_string(), params.clone(), None)
            } else {
                let Some(target) = params.get("method").and_then(Value::as_str) else {
                    send(&out, json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": "Invalid params: method" } }));
                    continue;
                };
                // KEEL-19: `_info` is asked as itself, never through `{ns}.call`.
                if target == "_info" {
                    send(&out, json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": "Invalid params: `_info` is not called through `{ns}.call`" } }));
                    continue;
                }
                (target.to_string(), params.get("params").cloned().unwrap_or_else(|| json!({})), params.get("hop").cloned())
            };
            let sid = next_sid;
            next_sid += 1;
            // spec/02: the subscription id before any of its items.
            send(&out, json!({ "jsonrpc": "2.0", "id": id, "result": sid }));
            let task = tokio::spawn(run(activation.clone(), ns.clone(), out.clone(), Arc::clone(&live), sid, target, p, hop, Arc::clone(&peer), Arc::clone(&slots), Arc::clone(&link), key.clone(), tokens.clone(), Arc::clone(&proofs)));
            live.lock().unwrap().insert(sid, task.abort_handle());
        } else if method == unsub_m {
            let held = params.get(0).and_then(Value::as_u64).and_then(|sid| live.lock().unwrap().remove(&sid));
            let stopped = held.map(|h| {
                h.abort();
                true
            });
            send(&out, json!({ "jsonrpc": "2.0", "id": id, "result": stopped.unwrap_or(false) }));
        } else if !id.is_null() {
            send(&out, json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Method not found" } }));
        }
    }
    for (_, h) in live.lock().unwrap().drain() {
        h.abort();
    }
    link.close();
    drop(out);
    let _ = writer.await;
    Ok(())
}

/// NEST-6: the slots of the activation served — its own schema's, its
/// static children's and, to any depth, each typed slot's — so a hop's grant
/// is checked against the slot a path goes through, as the mount's gate
/// decided it ([`Slots::resolve`]).
fn slot_index<A: Activation>(activation: &A) -> Slots {
    let schema = activation.plugin_schema();
    let statics = crate::plexus::children::qualified(&schema.namespace, activation.static_child_schemas());
    let (mut typed, mut untyped) = (Vec::new(), Vec::new());
    for s in std::iter::once(&schema).chain(statics.iter()) {
        crate::plexus::slots::slot_schemas(s, &mut typed, &mut untyped);
    }
    Slots::of(std::iter::once(&schema).chain(statics.iter()).chain(typed.iter()), &untyped)
}

/// One call: its items as `{ns}.call` notifications for `sid`, in order,
/// the last one terminal.
#[allow(clippy::too_many_arguments)]
async fn run<A: Activation>(
    activation: A,
    ns: String,
    out: mpsc::UnboundedSender<Vec<u8>>,
    live: Live,
    sid: u64,
    target: String,
    params: Value,
    hop: Option<Value>,
    peer: Arc<ChildPeer>,
    slots: Arc<Slots>,
    link: Arc<HostLink>,
    key: Option<Arc<crate::plexus::peer_token::PeerKey>>,
    tokens: Option<Arc<crate::plexus::peer_token::Verifier>>,
    proofs: Arc<crate::plexus::peer_token::ProofCache>,
) {
    let item = |v: Value| {
        let frame = json!({ "jsonrpc": "2.0", "method": format!("{ns}.call"), "params": { "subscription": sid, "result": v } });
        let _ = out.send(serde_json::to_vec(&frame).unwrap_or_default());
    };
    let refuse = |error: RemoteError| item(serde_json::to_value(PlexusStreamItem::error(meta(&ns), error, false)).unwrap_or_default());
    let done = || item(serde_json::to_value(PlexusStreamItem::Done { metadata: meta(&ns) }).unwrap_or_default());

    if target == "_info" {
        let mut content = json!({ "backend": ns });
        // DYNAUTH-5: a child with a key proves it over the mount's nonce —
        // KEEL-19: for the asker its connection proved, and no other.
        if let (Some(key), Some(nonce)) = (&key, params.get("nonce").and_then(Value::as_str)) {
            let asker = match peer.as_ref() {
                ChildPeer::Connection { proven, .. } => proven.clone(),
                ChildPeer::Pipe => params.get("asker").and_then(Value::as_str).unwrap_or_default().to_string(),
            };
            content["key"] = json!(key.kid());
            content["proof"] = json!(key.key_proof_for(nonce, &ns, &asker));
            content["asker"] = json!(asker);
        }
        item(json!({ "type": "data", "metadata": meta(&ns), "content_type": "_info", "content": content }));
        done();
    } else if let Some(method) = target.strip_prefix(&format!("{ns}.")) {
        // KEEL-19: the sender's proof of possession rides beside the token.
        let proof = hop.as_ref().and_then(|h| h.get("proof")).and_then(Value::as_str).map(str::to_string);
        // ONE-7: the door the near side admitted the call at (`limit.door`),
        // as it was sent: it names exactly this call or nothing.
        let door_said = hop.as_ref().and_then(|h| h.get("limit")).and_then(|l| l.get("door")).cloned();
        let hop: Option<Hop> = hop.and_then(|h| serde_json::from_value(h).ok());
        let door = match door_of(door_said.as_ref(), hop.as_ref(), &target, &slots) {
            Ok(d) => d,
            Err(why) => {
                let mut e = PlexusStreamItem::error(meta(&ns), RemoteError::Forbidden {
                    reason: DenyReason::MissingGrant { grant: target.clone(), scope: "*".into(), roles: vec![], held_on: vec![] },
                }, false);
                if let PlexusStreamItem::Error { message, .. } = &mut e {
                    *message = format!("the hop's door is refused: {why}");
                }
                item(serde_json::to_value(e).unwrap_or_default());
                live.lock().unwrap().remove(&sid);
                return;
            }
        };
        let introspection = method == "schema" || method.ends_with(".schema");
        // DYNAUTH-12: a verifying child believes a hop by its token —
        // KEEL-19: and only from whoever the token says may present it.
        // N3: the `jti` is recorded only once the sender is proven, so a
        // replay without its proof cannot burn it for the one who may.
        let verdict = match (&tokens, &hop) {
            (Some(v), Some(h)) if !introspection => Some(hop_token_claims(v, h, &target, door.as_ref()).and_then(|claims| {
                presented_by(v, &peer, h, &claims, &target, proof.as_deref(), &proofs)?;
                v.admit(&claims, crate::plexus::peer_token::now()).map_err(|e| e.to_string())
            })),
            _ => None,
        };
        if let Some(Err(why)) = &verdict {
            let mut e = PlexusStreamItem::error(meta(&ns), RemoteError::Forbidden {
                reason: DenyReason::MissingGrant { grant: target.clone(), scope: "*".into(), roles: vec![], held_on: vec![] },
            }, false);
            if let PlexusStreamItem::Error { message, .. } = &mut e {
                *message = format!("the hop's token is refused: {why}");
            }
            item(serde_json::to_value(e).unwrap_or_default());
            live.lock().unwrap().remove(&sid);
            return;
        }
        // Who may send a hop: one this child does not take is refused
        // (a schema call answers without it) — unless its token verified
        // and was presented by the key it is bound to, proven (KEEL-19).
        let untrusted = !matches!(verdict, Some(Ok(()))) && hop.as_ref().is_some_and(|h| !peer.takes(h));
        let hop = if untrusted && introspection { None } else { hop };
        // The far side decides again, before the method runs: no hop is
        // nobody; a hop no gate decided (`limit: null`, or no grant) or one
        // admitted for another grant is forbidden. A schema call answers
        // what the child is, whatever the hop (the mount asks it with none).
        let forbidden = || RemoteError::Forbidden {
            reason: DenyReason::MissingGrant { grant: target.clone(), scope: "*".into(), roles: vec![], held_on: vec![] },
        };
        let refused = match &hop {
            _ if untrusted && !introspection => Some(RemoteError::Forbidden {
                reason: DenyReason::MissingGrant { grant: target.clone(), scope: "*".into(), roles: vec![], held_on: vec![] },
            }),
            _ if introspection => None,
            None => Some(RemoteError::Unauthenticated),
            // NEST-6: or, for a path through a dynamic slot, the slot's
            // grant (`{ns}.a.{item}.m`; an untyped slot's `{ns}.a.{item}`),
            // which is what a mount's gate decided it on.
            Some(h) => match h.grant() {
                Some(g) if g == target => None,
                Some(g) if slots.resolve(&target).as_deref() == Some(g) => None,
                _ => Some(forbidden()),
            },
        };
        match (refused, hop) {
            (Some(error), _) => refuse(error),
            (None, hop) => {
                let routed = match hop {
                    Some(hop) => {
                        // The hop's caller is the call's: `caller()` and a
                        // `#[from_auth]` parameter both name it.
                        let ctx = CallContext::through_hop_with(hop, door.as_ref(), link);
                        let auth = ctx.auth().cloned();
                        crate::call::scope(ctx.clone(), async { activation.call(method, params, auth.as_ref(), None).await })
                            .await
                            .map(|s| -> crate::plexus::PlexusStream { Box::pin(InCall::new(ctx, s)) })
                    }
                    None => activation.call(method, params, None, None).await,
                };
                match routed {
                    Ok(mut stream) => {
                        while let Some(i) = stream.next().await {
                            item(serde_json::to_value(i).unwrap_or_default());
                        }
                    }
                    Err(e) => item(error_item(&ns, &e)),
                }
            }
        }
    } else {
        refuse(RemoteError::ActivationNotFound { activation: target.split('.').next().unwrap_or_default().to_string() });
    }
    live.lock().unwrap().remove(&sid);
}

/// ONE-7 · the door a hop says the near side admitted it at (`limit.door`):
/// `Ok(None)` when it says none; `Ok(Some(call))` when it names exactly the
/// call served — the address scope `/{target}`, for the hop's own grant
/// (the method's, or the slot's it goes through, as the far side checks it)
/// — built as the dispatcher builds every call
/// ([`crate::plexus::grant_gate::dispatched`]); `Err` for a door that is not
/// a string, names another call, or whose call has no address. A door never
/// stands for data: it opens this call and holds nothing else.
fn door_of(said: Option<&Value>, hop: Option<&Hop>, target: &str, slots: &Slots) -> Result<Option<plexus_auth_core::grants::DispatchedCall>, String> {
    let Some(said) = said.filter(|v| !v.is_null()) else { return Ok(None) };
    let door = said.as_str().ok_or("it is not an address")?;
    if door != format!("/{target}") {
        return Err(format!("it names `{door}`, and this call is `{target}`"));
    }
    let grant = hop.and_then(Hop::grant).ok_or("the hop has no verdict to hold it for")?;
    let ok_grant = grant == target || slots.resolve(target).as_deref() == Some(grant);
    if !ok_grant {
        return Err(format!("it is for `{grant}`, which is not this call's"));
    }
    let ambiguous = std::collections::HashSet::new();
    crate::plexus::grant_gate::dispatched(target, &plexus_auth_core::grants::Grant::new(grant), &ambiguous)
        .map(Some)
        .ok_or_else(|| format!("`{target}` has no address"))
}

/// DYNAUTH-12: whether `hop`'s token is the one for this call of `target`:
/// verified (see [`ServeChild::tokens`]), its `sub` the hop's caller, its
/// scope holding the hop's grant on every scope the hop says — and, ONE-7,
/// at the door it says (`grant@/{target}`).
#[cfg(test)]
fn check_hop_token(v: &crate::plexus::peer_token::Verifier, hop: &crate::call::Hop, target: &str) -> Result<(), String> {
    let claims = hop_token_claims(v, hop, target, None)?;
    v.admit(&claims, crate::plexus::peer_token::now()).map_err(|e| e.to_string())
}

/// [`check_hop_token`] but the replay cache, answering the token's claims.
fn hop_token_claims(
    v: &crate::plexus::peer_token::Verifier,
    hop: &crate::call::Hop,
    target: &str,
    door: Option<&plexus_auth_core::grants::DispatchedCall>,
) -> Result<crate::plexus::peer_token::PeerClaims, String> {
    use crate::plexus::peer_token::{is_within, now, Expect};
    let token = hop.token.as_deref().ok_or("the hop carries no token, and this child takes a hop only by its token")?;
    let claims = v.inspect_at(token, &Expect { call: Some(&hop.call), method: Some(target) }, now()).map_err(|e| e.to_string())?;
    if hop.caller() != Some(claims.sub.as_str()) {
        return Err(format!("it is {}'s, and the hop is for {}", claims.sub, hop.caller().unwrap_or("nobody")));
    }
    let limit = hop.limit.as_ref().ok_or("the hop has no verdict")?;
    let mut asked: Vec<String> = limit.held_on.iter().map(|s| format!("{}@{s}", limit.grant)).collect();
    asked.extend(door.map(|d| format!("{}@/{}", limit.grant, d.at().path())));
    if asked.is_empty() || !is_within(&asked, &claims.scope) {
        return Err(format!("its scope does not hold {}", asked.join(" ")));
    }
    Ok(claims)
}

/// KEEL-19: whether this hop's sender is proven to be the one its token
/// may be presented by (see [`ServeChild::tokens`]), by a proof of
/// possession in the hop (`hop.proof`, for `target` under `hop.call`):
///
/// - A token bound to this child's own key — or, addressed to a pipe, to
///   none — is the service's forward: the proof is by the key that signed
///   it (`iss`, one the verifier trusts: `TokenIssuer::prove_forward`), and
///   on a connection its sender is also one `peer` takes.
/// - One bound to another key is its holder's (an exchanged token): the
///   proof is by that key, and on a connection the connection is proven as
///   that key and the hop names it.
///
/// The connection is checked before the proof, so a proof carried by
/// another's connection is not spent.
fn presented_by(
    v: &crate::plexus::peer_token::Verifier,
    peer: &ChildPeer,
    hop: &Hop,
    claims: &crate::plexus::peer_token::PeerClaims,
    target: &str,
    proof: Option<&str>,
    proofs: &crate::plexus::peer_token::ProofCache,
) -> Result<(), String> {
    use crate::plexus::peer_token::{check_proof_by, key_of, now, thumbprint};
    let own = key_of(v.audience()).map(|k| thumbprint(&k));
    let presenter = claims.cnf.as_ref().map(|c| c.jkt.clone()).filter(|j| Some(j) != own.as_ref());
    let (jkt, whose) = match presenter {
        None => {
            if let ChildPeer::Connection { .. } = peer {
                if !peer.takes(hop) {
                    return Err("it is one the service forwards, taken only from the service's own connection, and this hop's sender is not one this child trusts to act for others".into());
                }
            }
            let iss = key_of(&claims.iss).map(|k| thumbprint(&k)).ok_or("its issuer is not a key")?;
            (iss, "the service's")
        }
        Some(jkt) => {
            if let ChildPeer::Connection { proven, .. } = peer {
                let proven_jkt = key_of(proven).map(|k| thumbprint(&k));
                if proven_jkt.as_deref() != Some(jkt.as_str()) || hop.principal != *proven {
                    return Err(format!("it is bound to its presenter's key, and this connection is proven as {proven}, not as the presenter named by the hop"));
                }
            }
            (jkt, "its presenter's")
        }
    };
    let token = hop.token.as_deref().unwrap_or_default();
    let proof = proof.ok_or_else(|| format!("the hop carries no proof of possession (`hop.proof`): {whose} is wanted"))?;
    check_proof_by(proof, token, &jkt, target, &hop.call, now(), proofs).map_err(|e| format!("{whose} {e}"))
}

// ------------------------------------------------------------------ NEST-11

/// The far side's link back to the service on this connection: the calls
/// it opened there, by the request id it minted and then the subscription id
/// the service minted (spec/14 rule 2: ids are per direction).
pub(super) struct HostLink {
    /// Taken at the end of input, so the writer ends with the last call.
    out: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    next: AtomicU64,
    pending: Mutex<HashMap<u64, Opening>>,
    subs: Mutex<HashMap<u64, mpsc::Sender<Value>>>,
    closed: AtomicBool,
    /// DYNAUTH-12: the child's key, to prove possession of the token a call
    /// back is made under.
    key: Option<Arc<crate::plexus::peer_token::PeerKey>>,
}

struct Opening {
    reply: oneshot::Sender<Result<u64, Value>>,
    items: mpsc::Sender<Value>,
}

const BUFFER: usize = 1024;

impl HostLink {
    fn new(out: mpsc::UnboundedSender<Vec<u8>>, key: Option<Arc<crate::plexus::peer_token::PeerKey>>) -> Self {
        Self { out: Mutex::new(Some(out)), next: AtomicU64::new(1), pending: Mutex::default(), subs: Mutex::default(), closed: AtomicBool::new(false), key }
    }

    fn send(&self, v: &Value) {
        if let Some(out) = self.out.lock().unwrap().as_ref() {
            let _ = out.send(serde_json::to_vec(v).unwrap_or_default());
        }
    }

    /// The service answered request `id`: a call opened (its subscription
    /// routed before the next frame is read, so no item beats it) or
    /// refused; an unsubscribe's answer is nobody's.
    fn answered(&self, id: u64, result: Option<Value>, error: Option<Value>) {
        let Some(open) = self.pending.lock().unwrap().remove(&id) else { return };
        match (result.as_ref().and_then(Value::as_u64), error) {
            (Some(sid), _) => {
                self.subs.lock().unwrap().insert(sid, open.items);
                if open.reply.send(Ok(sid)).is_err() {
                    // Its caller let go before it opened.
                    self.unsubscribe(sid);
                }
            }
            (None, e) => {
                let _ = open.reply.send(Err(e.unwrap_or_else(|| json!({ "message": "an answer with neither a subscription nor an error" }))));
            }
        }
    }

    /// One item of a call back; the terminal one ends it.
    async fn item(&self, sid: u64, item: Value) {
        let terminal = matches!(item.get("type").and_then(Value::as_str), Some("done" | "error"));
        let tx = {
            let mut subs = self.subs.lock().unwrap();
            if terminal {
                subs.remove(&sid)
            } else {
                subs.get(&sid).cloned()
            }
        };
        if let Some(tx) = tx {
            let _ = tx.send(item).await;
        }
    }

    fn unsubscribe(&self, sid: u64) {
        self.subs.lock().unwrap().remove(&sid);
        if !self.closed.load(Ordering::Acquire) {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": HOST_CALL_UNSUB, "params": [sid] }));
        }
    }

    /// The connection ended: every call back ends, unanswered.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.out.lock().unwrap().take();
        self.pending.lock().unwrap().clear();
        self.subs.lock().unwrap().clear();
    }

    /// Open `method` with `params` under the forwarded call `under`.
    async fn open(self: Arc<Self>, method: String, params: Value, under: Option<String>, token: Option<String>) -> Result<CallBack, StreamItem> {
        if self.closed.load(Ordering::Acquire) {
            return Err(refused_item(&json!({ "message": "the connection to the service has closed" })));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (items, rx) = mpsc::channel(BUFFER);
        let (reply, answer) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, Opening { reply, items });
        let mut p = json!({ "method": method, "params": params });
        // DYNAUTH-12: the token this call is made under, and a proof of
        // possession by the child's key, for this method and call.
        if let (Some(key), Some(t), Some(u)) = (&self.key, &token, &under) {
            p["token"] = json!(t);
            p["proof"] = json!(crate::plexus::peer_token::prove(key, t, &method, u));
        }
        if let Some(u) = under {
            p["under"] = json!(u);
        }
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": HOST_CALL, "params": p }));
        match answer.await {
            Ok(Ok(sid)) => Ok(CallBack { rx, sid, link: self, over: false }),
            Ok(Err(e)) => Err(refused_item(&e)),
            Err(_) => Err(refused_item(&json!({ "message": "the connection to the service closed before the call opened" }))),
        }
    }
}

/// A JSON-RPC refusal (`{code, message, data?}`) as the one error item a
/// client reads: its `data` when that is a typed [`RemoteError`].
fn refused_item(e: &Value) -> StreamItem {
    let message = e.get("message").and_then(Value::as_str).unwrap_or("the service refused the call").to_string();
    let error = e
        .get("data")
        .and_then(|d| serde_json::from_value::<RemoteError>(d.clone()).ok())
        .unwrap_or_else(|| RemoteError::Execution { message: message.clone() });
    StreamItem::Error {
        metadata: None,
        recoverable: false,
        message: Some(message),
        code: e.get("code").map(|c| c.to_string()),
        error,
        fields: Default::default(),
    }
}

/// One open call back: its items until the terminal one; dropped before
/// it, the service is told (`_host.call_unsub`).
struct CallBack {
    rx: mpsc::Receiver<Value>,
    sid: u64,
    link: Arc<HostLink>,
    over: bool,
}

impl Stream for CallBack {
    type Item = Result<StreamItem, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.over {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(v)) => {
                let item = serde_json::from_value::<StreamItem>(v)
                    .map_err(|e| TransportError::new(TransportErrorKind::Protocol, format!("an item from the service does not read: {e}")));
                if matches!(item, Ok(StreamItem::Done { .. } | StreamItem::Error { .. }) | Err(_)) {
                    self.over = true;
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                self.over = true;
                Poll::Ready(Some(Err(TransportError::new(TransportErrorKind::Closed, "the connection to the service closed"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CallBack {
    fn drop(&mut self) {
        if !self.over {
            self.link.unsubscribe(self.sid);
        }
    }
}

/// NEST-11 · a [`Transport`] back into the service that forwarded the call
/// being run: [`host()`]. Every call it makes names that call (`under`), so
/// the service routes it as that call's caller, within its reach, through
/// its own gate; it ends when that call ends.
#[derive(Clone)]
pub struct HostTransport {
    link: Arc<HostLink>,
    under: Option<String>,
    /// DYNAUTH-12: the token of the call it is made under.
    token: Option<String>,
}

impl std::fmt::Debug for HostTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostTransport").field("under", &self.under).finish()
    }
}

impl HostTransport {
    /// The forwarded call every call made through this names.
    pub fn under(&self) -> Option<&str> {
        self.under.as_deref()
    }
}

impl Transport for HostTransport {
    fn call(&self, method: MethodRef, params: Value) -> ItemStream<'_> {
        let opened = Arc::clone(&self.link).open(method.qualified(), params, self.under.clone(), self.token.clone());
        Box::pin(
            futures::stream::once(async move {
                match opened.await {
                    Ok(call) => call.left_stream(),
                    Err(item) => futures::stream::once(async move { Ok(item) }).right_stream(),
                }
            })
            .flatten(),
        )
    }
}

/// NEST-11 · the service that forwarded the call being run, as a
/// [`Transport`] a generated client takes: `FooClient::new(host()?)`. An
/// error outside a call, and in a call that did not come through the seam.
pub fn host() -> Result<HostTransport, CallError> {
    let ctx = crate::call::context()?;
    let link = ctx.host_link().cloned().ok_or(CallError::NoHop)?;
    let link = link.downcast::<HostLink>().map_err(|_| CallError::NoHop)?;
    let under = ctx.hop().map(|h| h.call.clone()).filter(|c| !c.is_empty());
    let token = ctx.hop().and_then(|h| h.token.clone());
    Ok(HostTransport { link, under, token })
}

#[cfg(test)]
mod token_tests {
    use super::*;
    use crate::plexus::peer_token::{MintRequest, PeerKey, TokenIssuer, Verifier};

    fn hop(for_: &str, grant: &str, held: &[&str], call: &str, token: Option<String>) -> crate::call::Hop {
        serde_json::from_value(json!({ "principal": "service:host", "for": [for_], "limit": { "grant": grant, "held_on": held }, "call": call, "token": token })).unwrap()
    }

    /// DYNAUTH-12: a verifying child takes a hop by its token alone, and
    /// only for its caller, call, method and grant.
    #[test]
    fn a_hop_is_taken_by_its_token() {
        let (host, me, other) = (PeerKey::generate(), PeerKey::generate(), PeerKey::generate());
        let issuer = TokenIssuer::new(host);
        let caller = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mint = |aud: &PeerKey, scope: &[&str], call: &str| {
            issuer
                .mint(MintRequest { sub: caller.into(), peer_key: Some(aud.kid().into()), name: "w".into(), scope: scope.iter().map(|s| s.to_string()).collect(), call: call.into(), method: "weather.forecast".into(), presented: None })
                .unwrap()
                .0
        };
        let v = Verifier::new(me.kid(), &issuer.jwks()).unwrap();
        let ok = hop(caller, "weather.forecast", &["*"], "c1", Some(mint(&me, &["weather.forecast@*"], "c1")));
        assert_eq!(check_hop_token(&v, &ok, "weather.forecast"), Ok(()));
        // The same token again: replayed.
        assert!(check_hop_token(&v, &ok, "weather.forecast").unwrap_err().contains("replayed"));
        // No token.
        assert!(check_hop_token(&v, &hop(caller, "weather.forecast", &["*"], "c2", None), "weather.forecast").unwrap_err().contains("no token"));
        // Another's audience.
        let theirs = hop(caller, "weather.forecast", &["*"], "c3", Some(mint(&other, &["weather.forecast@*"], "c3")));
        assert!(check_hop_token(&v, &theirs, "weather.forecast").unwrap_err().contains("addressed to"));
        // Another call's.
        let moved = hop(caller, "weather.forecast", &["*"], "c4", Some(mint(&me, &["weather.forecast@*"], "c5")));
        assert!(check_hop_token(&v, &moved, "weather.forecast").unwrap_err().contains("another call"));
        // Another caller named in the hop than the token's `sub`.
        let lied = hop("key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "weather.forecast", &["*"], "c6", Some(mint(&me, &["weather.forecast@*"], "c6")));
        assert!(check_hop_token(&v, &lied, "weather.forecast").unwrap_err().contains("the hop is for"));
        // A hop claiming more than its token holds.
        let wide = hop(caller, "weather.forecast", &["*"], "c7", Some(mint(&me, &["weather.forecast@MENGER"], "c7")));
        assert!(check_hop_token(&v, &wide, "weather.forecast").unwrap_err().contains("does not hold"));
    }
}
