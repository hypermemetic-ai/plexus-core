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
//! {method, params, hop}` and `{ns}.call_unsub [sid]`. Each call runs in the
//! hop's context ([`crate::call`]): the method reads it with
//! `plexus_core::call::hop()` — the acting service, the caller it acts for,
//! the near side's verdict as a ceiling ([`Hop::allows`]) and the call id —
//! and `call::caller()` there is an error: no gate of this process admitted
//! anyone, and the hop is no credential.
//!
//! The far side decides again (spec/12 rule 2): a call with no hop is
//! `unauthenticated`, and a hop admitted for another grant than the method
//! called is `forbidden`. A schema call (`{ns}.schema`) answers whatever its
//! hop. Nothing is written to stdout but the protocol.

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

/// Serve `activation` as a child on this process's stdin and stdout, until
/// the service closes stdin (spec/11: the end of input ends every call).
pub async fn serve_child_stdio<A>(activation: A) -> std::io::Result<()>
where
    A: Activation + Clone,
{
    serve_child(activation, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Serve `activation` as a child over `r` (frames from the service, one per
/// line) and `w` (frames to it), until `r` ends.
pub async fn serve_child<A, R, W>(activation: A, r: R, w: W) -> std::io::Result<()>
where
    A: Activation + Clone,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let ns = activation.namespace().to_string();
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
            let task = tokio::spawn(run(activation.clone(), ns.clone(), out.clone(), Arc::clone(&live), sid, target, p, hop));
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
        let refused = match &hop {
            _ if introspection => None,
            None => Some(RemoteError::Unauthenticated),
            Some(h) => h.grant().filter(|g| *g != target).map(|_| RemoteError::Forbidden {
                reason: DenyReason::MissingGrant { grant: target.clone(), scope: "*".into(), roles: vec![], held_on: vec![] },
            }),
        };
        match (refused, hop) {
            (Some(error), _) => refuse(error),
            (None, hop) => {
                let routed = match hop {
                    Some(hop) => {
                        let ctx = CallContext::through_hop(hop);
                        crate::call::scope(ctx.clone(), activation.call(method, params, None, None))
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
