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
//! The far side decides again (spec/12 rule 2), before the method runs: a
//! call with no hop is `unauthenticated`; a hop no gate decided (`limit:
//! null`, or no grant) and a hop admitted for another grant than the method
//! called are `forbidden`. A schema call (`{ns}.schema`) answers whatever its
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use plexus_client::{DenyReason, RemoteError};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::mpsc;

use super::link::{meta, write_lines};
use crate::call::{CallContext, Hop, InCall};
use crate::plexus::plexus::{error_item, Activation};
use crate::plexus::types::PlexusStreamItem;

type Live = Arc<Mutex<HashMap<u64, tokio::task::AbortHandle>>>;

/// Who is on the other end of a child's input, and so whose hops it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildPeer {
    /// A pipe the parent owns (the child's stdin): every hop is the
    /// parent's.
    Pipe,
    /// A connection the transport proved: `proven` is the principal it
    /// proved (`key:<hex>`); a hop is taken only when `proven` is one of
    /// `acts_for_others` and the hop names it as the acting service.
    Connection { proven: String, acts_for_others: Vec<String> },
}

impl ChildPeer {
    /// A connection proven as `proven`, the child trusting `acts_for_others`
    /// (service principals) to act for others.
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
    let ns = activation.namespace().to_string();
    let peer = Arc::new(peer);
    let (call_m, unsub_m) = (format!("{ns}.call"), format!("{ns}.call_unsub"));
    let (out, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(write_lines(w, out_rx));
    let send = |out: &mpsc::UnboundedSender<Vec<u8>>, v: Value| {
        let _ = out.send(serde_json::to_vec(&v).unwrap_or_default());
    };
    let live: Live = Arc::default();
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
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        if method == "_info" || method == call_m {
            let (target, p, hop) = if method == "_info" {
                ("_info".to_string(), Value::Null, None)
            } else {
                let Some(target) = params.get("method").and_then(Value::as_str) else {
                    send(&out, json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": "Invalid params: method" } }));
                    continue;
                };
                (target.to_string(), params.get("params").cloned().unwrap_or_else(|| json!({})), params.get("hop").cloned())
            };
            let sid = next_sid;
            next_sid += 1;
            // spec/02: the subscription id before any of its items.
            send(&out, json!({ "jsonrpc": "2.0", "id": id, "result": sid }));
            let task = tokio::spawn(run(activation.clone(), ns.clone(), out.clone(), Arc::clone(&live), sid, target, p, hop, Arc::clone(&peer)));
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
    drop(out);
    let _ = writer.await;
    Ok(())
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
) {
    let item = |v: Value| {
        let frame = json!({ "jsonrpc": "2.0", "method": format!("{ns}.call"), "params": { "subscription": sid, "result": v } });
        let _ = out.send(serde_json::to_vec(&frame).unwrap_or_default());
    };
    let refuse = |error: RemoteError| item(serde_json::to_value(PlexusStreamItem::error(meta(&ns), error, false)).unwrap_or_default());
    let done = || item(serde_json::to_value(PlexusStreamItem::Done { metadata: meta(&ns) }).unwrap_or_default());

    if target == "_info" {
        item(json!({ "type": "data", "metadata": meta(&ns), "content_type": "_info", "content": { "backend": ns } }));
        done();
    } else if let Some(method) = target.strip_prefix(&format!("{ns}.")) {
        let hop: Option<Hop> = hop.and_then(|h| serde_json::from_value(h).ok());
        let introspection = method == "schema" || method.ends_with(".schema");
        // Who may send a hop: one this child does not take is refused
        // (a schema call answers without it).
        let untrusted = hop.as_ref().is_some_and(|h| !peer.takes(h));
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
            Some(h) => match h.grant() {
                Some(g) if g == target => None,
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
                        let ctx = CallContext::through_hop(hop);
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
