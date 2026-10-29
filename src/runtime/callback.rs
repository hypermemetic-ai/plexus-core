//! Turn-scoped callback delivery and correlation (PLX-80 / M1·C).
//!
//! PLX-77 shipped [`Client<C>`](crate::capability::Client)'s *typing* and left
//! [`CallbackTransport`] deliberately unwired, because choosing the async shape
//! of delivery belonged to this build. This module is that choice.
//!
//! # What a callback costs, in one hop
//!
//! 1. A handler calls a gated accessor —
//!    `client.request_permission_async(req).await`.
//! 2. [`TurnTransport`] mints a [`CallbackId`] (which embeds the [`TurnId`]),
//!    parks a `oneshot` sender under its sequence number, and emits a
//!    [`TurnEvent::Callback`] onto the turn's event stream.
//! 3. The peer answers with
//!    [`TurnControl::respond`](super::TurnControl::respond), quoting the id.
//!    The router matches the **turn first**, then the sequence number.
//! 4. The parked `oneshot` fires and the handler's `await` resolves.
//!
//! # Cross-talk is a type error, not a hope
//!
//! Two turns running concurrently have two routers, two pending maps, and two
//! id namespaces. A response naming turn A offered to turn B is
//! [`RespondError::WrongTurn`] — refused, not re-routed. Sequence numbers are
//! per-turn and start at 0 in both, which is exactly the collision a
//! flat global correlation table would silently mis-deliver.
//!
//! # Cancellation resolves callbacks; it does not strand them
//!
//! On cancel the runtime calls [`CallbackRouter::resolve_all_cancelled`], which
//! drains every parked sender with an error. An awaiting handler's callback
//! future therefore *completes* (with `Err`) instead of hanging forever. That
//! is the framework's half of the cooperative contract; what the handler then
//! does with its subprocess is the handler's half.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use futures::future::BoxFuture;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::capability::CallbackTransport;
use crate::ir::{CallbackIr, MethodIr};

use super::error::RespondError;
use super::event::TurnEvent;
use super::ids::{CallbackId, TurnId};

// ===========================================================================
// PeerCapabilities
// ===========================================================================

/// What server-to-client callbacks the peer has said it can serve.
///
/// The union of [`MethodIr::callbacks`] across an IR is what a service
/// *advertises*; this is the mirror image — what the peer on the other end of
/// a given connection advertises back. [`super::entry`] compares the two
/// **before** dispatching, so a turn that would have discovered mid-flight that
/// its peer cannot answer `fs/write_text_file` never starts.
///
/// # The permissive default is deliberate, and documented
///
/// [`PeerCapabilities::default`] is [`PeerCapabilities::all`] — "assume the
/// peer can serve anything". PLX-80 wires delivery and correlation; it does
/// **not** implement capability *negotiation*, which needs a handshake this
/// build has no transport for. A default of `none()` would make every
/// callback-declaring method unreachable through the legacy
/// [`Activation`](crate::Activation) bridge, i.e. it would fail closed on a
/// check that has no way to be satisfied yet. Callers that do know their peer
/// state pass [`PeerCapabilities::from_names`] and get the pre-flight check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// `None` means "unrestricted"; `Some(set)` is the advertised set.
    advertised: Option<std::collections::BTreeSet<String>>,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self::all()
    }
}

impl PeerCapabilities {
    /// Assume the peer can serve every callback. See the type docs for why
    /// this is the default.
    pub fn all() -> Self {
        Self { advertised: None }
    }

    /// The peer advertises nothing: any method declaring a callback is refused
    /// pre-flight.
    pub fn none() -> Self {
        Self {
            advertised: Some(Default::default()),
        }
    }

    /// The peer advertises exactly these callback wire names.
    pub fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            advertised: Some(names.into_iter().map(Into::into).collect()),
        }
    }

    /// Whether the peer can serve `name`.
    pub fn advertises(&self, name: &str) -> bool {
        match &self.advertised {
            None => true,
            Some(set) => set.contains(name),
        }
    }

    /// Whether this is the unrestricted set.
    pub fn is_unrestricted(&self) -> bool {
        self.advertised.is_none()
    }

    /// The advertised names, in sorted order. Empty for the unrestricted set —
    /// use [`Self::is_unrestricted`] to tell the two apart.
    pub fn names(&self) -> Vec<String> {
        self.advertised
            .as_ref()
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Callbacks `method` declares that this peer cannot serve.
    pub fn missing_for(&self, method: &MethodIr) -> Vec<String> {
        method
            .callbacks
            .iter()
            .filter(|c| !self.advertises(&c.name))
            .map(|c| c.name.clone())
            .collect()
    }
}

// ===========================================================================
// CallbackRouter
// ===========================================================================

/// The per-turn correlation table.
#[derive(Debug)]
pub(crate) struct CallbackRouter {
    turn: TurnId,
    seq: AtomicU64,
    closed: AtomicBool,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>,
    events: mpsc::Sender<TurnEvent>,
}

impl CallbackRouter {
    pub(crate) fn new(turn: TurnId, events: mpsc::Sender<TurnEvent>) -> Self {
        Self {
            turn,
            seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            events,
        }
    }

    pub(crate) fn turn(&self) -> TurnId {
        self.turn
    }

    /// Issue one callback and await its correlated response.
    pub(crate) async fn issue(
        &self,
        callback: &CallbackIr,
        request: Value,
    ) -> Result<Value, String> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(format!("turn {} has resolved; no further callbacks", self.turn));
        }

        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let id = CallbackId::new(self.turn, seq);
        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending.lock().expect("callback router poisoned");
            if self.closed.load(Ordering::SeqCst) {
                return Err(format!("turn {} has resolved; no further callbacks", self.turn));
            }
            pending.insert(seq, tx);
        }

        let event = TurnEvent::callback(id, callback.name.clone(), request);
        if self.events.send(event).await.is_err() {
            self.pending
                .lock()
                .expect("callback router poisoned")
                .remove(&seq);
            return Err(format!(
                "turn {} event stream closed before callback `{}` could be delivered",
                self.turn, callback.name
            ));
        }

        match rx.await {
            Ok(result) => result,
            // The sender was dropped without answering. In practice this only
            // happens if the router itself was dropped, which the turn does not
            // do before resolving; treat it as a resolution rather than a hang.
            Err(_) => Err(format!(
                "callback `{}` on turn {} was dropped without a response",
                callback.name, self.turn
            )),
        }
    }

    /// Deliver a peer's response. See [`RespondError`] for the refusal cases.
    pub(crate) fn respond(&self, id: CallbackId, response: Value) -> Result<(), RespondError> {
        self.deliver(id, Ok(response))
    }

    /// Deliver a peer's *failure* to serve a callback.
    pub(crate) fn fail(&self, id: CallbackId, message: impl Into<String>) -> Result<(), RespondError> {
        self.deliver(id, Err(message.into()))
    }

    fn deliver(&self, id: CallbackId, result: Result<Value, String>) -> Result<(), RespondError> {
        // Turn identity first: this is the cross-talk guard, and checking it
        // before the sequence number is what makes "turn B, seq 0" impossible
        // to mistake for "turn A, seq 0".
        if id.turn != self.turn {
            return Err(RespondError::WrongTurn {
                expected: self.turn,
                actual: id.turn,
            });
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(RespondError::TurnEnded(self.turn));
        }
        let sender = self
            .pending
            .lock()
            .expect("callback router poisoned")
            .remove(&id.seq)
            .ok_or(RespondError::UnknownCallback(id))?;
        // A dropped receiver means the awaiting handler is gone; the response
        // is simply discarded, which is not an error the peer can act on.
        let _ = sender.send(result);
        Ok(())
    }

    /// Resolve every in-flight callback with a cancellation error and stop
    /// accepting new ones.
    ///
    /// This is the "in-flight callbacks resolve uniformly" half of the turn
    /// contract: awaiting handlers get an `Err` promptly instead of hanging.
    pub(crate) fn resolve_all_cancelled(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let drained: Vec<_> = {
            let mut pending = self.pending.lock().expect("callback router poisoned");
            pending.drain().map(|(_, tx)| tx).collect()
        };
        for tx in drained {
            let _ = tx.send(Err(format!(
                "turn {} was cancelled while this callback was in flight",
                self.turn
            )));
        }
    }

    /// Close the router without a cancellation: the turn completed normally.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let drained: Vec<_> = {
            let mut pending = self.pending.lock().expect("callback router poisoned");
            pending.drain().map(|(_, tx)| tx).collect()
        };
        for tx in drained {
            let _ = tx.send(Err(format!(
                "turn {} resolved while this callback was in flight",
                self.turn
            )));
        }
    }

    /// How many callbacks are currently in flight. Test/observability only.
    pub(crate) fn in_flight(&self) -> usize {
        self.pending.lock().expect("callback router poisoned").len()
    }
}

// ===========================================================================
// TurnTransport
// ===========================================================================

/// The [`CallbackTransport`] a turn installs into every
/// [`Client<C>`](crate::capability::Client) it hands its handler.
///
/// # Why the synchronous half refuses
///
/// [`CallbackTransport::call`] is PLX-77's synchronous seam, and PLX-80 keeps
/// it exactly as it was — the whole `Client<C>` compile-time surface, its
/// trybuild fixtures, and the IR derivation all depend on it. Real delivery
/// needs to *await* a correlated response, and the only ways to serve that from
/// a `fn -> Result<..>` are to block a runtime worker or to lie. So this
/// transport implements the async half ([`CallbackTransport::call_async`]) and
/// makes the sync half return an explicit, self-describing error rather than
/// either.
pub struct TurnTransport {
    router: std::sync::Arc<CallbackRouter>,
}

impl TurnTransport {
    pub(crate) fn new(router: std::sync::Arc<CallbackRouter>) -> Self {
        Self { router }
    }
}

impl std::fmt::Debug for TurnTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnTransport")
            .field("turn", &self.router.turn())
            .field("in_flight", &self.router.in_flight())
            .finish()
    }
}

impl CallbackTransport for TurnTransport {
    fn call(&self, callback: &CallbackIr, _request: Value) -> Result<Value, String> {
        Err(format!(
            "callback `{}` was issued through the synchronous accessor; turn-scoped delivery awaits a correlated response, so use the `*_async` accessor (e.g. `client.{}_async(..).await`)",
            callback.name,
            callback.name.replace(['/', '.'], "_")
        ))
    }

    fn call_async<'a>(
        &'a self,
        callback: &'a CallbackIr,
        request: Value,
    ) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move { self.router.issue(callback, request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{MethodIr, SchemaRef};
    use serde_json::json;
    use std::sync::Arc;

    fn schema_ref(name: &str) -> SchemaRef {
        SchemaRef::new(
            name,
            schemars::Schema::try_from(json!({"type": "object"})).unwrap(),
        )
        .unwrap()
    }

    fn cb(name: &str) -> CallbackIr {
        CallbackIr::new(name, schema_ref("Req"), schema_ref("Resp"))
    }

    #[test]
    fn unrestricted_peer_advertises_everything() {
        let p = PeerCapabilities::all();
        assert!(p.advertises("anything/at/all"));
        assert!(p.is_unrestricted());
        let m = MethodIr::new("m", "a.m").with_callback(cb("fs/read_text_file"));
        assert!(p.missing_for(&m).is_empty());
    }

    #[test]
    fn empty_peer_misses_every_declared_callback() {
        let p = PeerCapabilities::none();
        let m = MethodIr::new("m", "a.m")
            .with_callback(cb("fs/read_text_file"))
            .with_callback(cb("fs/write_text_file"));
        assert_eq!(
            p.missing_for(&m),
            vec!["fs/read_text_file", "fs/write_text_file"]
        );
        // A method declaring no callbacks is unaffected.
        assert!(p.missing_for(&MethodIr::new("n", "a.n")).is_empty());
    }

    #[test]
    fn partial_peer_reports_only_what_is_missing() {
        let p = PeerCapabilities::from_names(["fs/read_text_file"]);
        let m = MethodIr::new("m", "a.m")
            .with_callback(cb("fs/read_text_file"))
            .with_callback(cb("fs/write_text_file"));
        assert_eq!(p.missing_for(&m), vec!["fs/write_text_file"]);
        assert_eq!(p.names(), vec!["fs/read_text_file"]);
    }

    #[tokio::test]
    async fn responses_correlate_by_sequence_number() {
        let (tx, mut rx) = mpsc::channel(8);
        let router = Arc::new(CallbackRouter::new(TurnId::new(), tx));

        let r = router.clone();
        let task = tokio::spawn(async move {
            let (cb_a, cb_b) = (cb("a"), cb("b"));
            let a = r.issue(&cb_a, json!({"n": 1}));
            let b = r.issue(&cb_b, json!({"n": 2}));
            futures::future::join(a, b).await
        });

        let mut ids = Vec::new();
        for _ in 0..2 {
            match rx.recv().await.unwrap() {
                TurnEvent::Callback { id, name, .. } => ids.push((id, name)),
                other => panic!("expected a callback event, got {other:?}"),
            }
        }
        // Answer out of order; correlation is by id, not arrival order.
        let by_name = |n: &str| ids.iter().find(|(_, name)| name == n).unwrap().0;
        router.respond(by_name("b"), json!("B")).unwrap();
        router.respond(by_name("a"), json!("A")).unwrap();

        let (a, b) = task.await.unwrap();
        assert_eq!(a.unwrap(), json!("A"));
        assert_eq!(b.unwrap(), json!("B"));
    }

    #[tokio::test]
    async fn a_response_naming_another_turn_is_refused() {
        let (tx, _rx) = mpsc::channel(8);
        let mine = TurnId::new();
        let theirs = TurnId::new();
        let router = CallbackRouter::new(mine, tx);

        let err = router
            .respond(CallbackId::new(theirs, 0), json!("stolen"))
            .unwrap_err();
        assert_eq!(
            err,
            RespondError::WrongTurn {
                expected: mine,
                actual: theirs
            }
        );
    }

    #[tokio::test]
    async fn an_unknown_sequence_number_is_refused() {
        let (tx, _rx) = mpsc::channel(8);
        let turn = TurnId::new();
        let router = CallbackRouter::new(turn, tx);
        let id = CallbackId::new(turn, 41);
        assert_eq!(
            router.respond(id, json!(null)).unwrap_err(),
            RespondError::UnknownCallback(id)
        );
    }

    #[tokio::test]
    async fn cancellation_resolves_in_flight_callbacks_rather_than_stranding_them() {
        let (tx, mut rx) = mpsc::channel(8);
        let router = Arc::new(CallbackRouter::new(TurnId::new(), tx));

        let r = router.clone();
        let task = tokio::spawn(async move { r.issue(&cb("slow"), json!({})).await });
        // Wait for the request to reach the stream, so it is genuinely in flight.
        let _ = rx.recv().await.unwrap();
        assert_eq!(router.in_flight(), 1);

        router.resolve_all_cancelled();

        let out = task.await.unwrap();
        assert!(out.is_err(), "the callback resolved rather than hanging");
        assert!(out.unwrap_err().contains("cancelled"));
        assert_eq!(router.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_closed_router_accepts_no_new_callbacks() {
        let (tx, _rx) = mpsc::channel(8);
        let router = CallbackRouter::new(TurnId::new(), tx);
        router.close();
        assert!(router.issue(&cb("x"), json!({})).await.is_err());
    }

    #[tokio::test]
    async fn the_sync_accessor_reports_that_it_needs_the_async_one() {
        let (tx, _rx) = mpsc::channel(8);
        let router = Arc::new(CallbackRouter::new(TurnId::new(), tx));
        let transport = TurnTransport::new(router);
        let err = transport.call(&cb("fs/read_text_file"), json!({})).unwrap_err();
        assert!(err.contains("_async"), "{err}");
    }
}
