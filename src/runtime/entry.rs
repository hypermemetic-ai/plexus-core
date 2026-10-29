//! The sealed core entry (PLX-80 / M1·C) — one seam, ordinary Rust.
//!
//! [`entry`] is the single function that turns *(an [`ActivationIr`], a
//! [`HandlerTable`], a [`TurnRequest`])* into a running turn. Everything the
//! macro used to re-emit per method arm happens here, once:
//!
//! | Concern | Used to live in | Lives here as |
//! |---|---|---|
//! | method lookup | a generated `match` on `&str` with a `_ =>` arm | one hash probe against the table |
//! | auth injection | a per-arm `if auth.is_none()` template | [`AuthRequirementIr`] read off the method IR |
//! | request extraction | per-arm `quote!` | [`TurnRequest`], one struct |
//! | param decode | per-arm `quote!` | still per-handler, because it genuinely needs the type |
//! | wrap / bidir plumbing | `wrap_stream` / `wrap_stream_with_bidir` call templates | the turn loop below |
//! | terminal | nothing — the stream just ended | [`TurnEvent::Terminal`], guaranteed exactly once |
//!
//! # The turn loop, and what it guarantees
//!
//! The handler runs as its own task. A generator selects over three things —
//! the handler's completion, the turn's event channel, and the cancellation
//! token — and yields events downstream. From that shape, three properties
//! follow structurally rather than by discipline:
//!
//! 1. **Exactly one terminal.** The loop `break`s the instant it yields one,
//!    and it is the only code path that can construct one.
//! 2. **The terminal is last.** Queued updates are drained *before* it.
//! 3. **A cancelled turn resolves promptly.** Cancellation does not wait for
//!    the handler. See the honesty note below.
//!
//! # The honesty note (PLX-73 turn contract)
//!
//! On cancel the runtime resolves every in-flight callback, yields
//! `Terminal{Cancelled}`, and stops consuming the handler task. The task is
//! **detached, not aborted** — it keeps running until it decides to stop. That
//! is deliberate: a handler that spawned a subprocess needs to be able to reap
//! it, and a runtime that dropped the future mid-`await` would take away the
//! chance. `Cancelled` therefore means *the turn stopped waiting*, and this
//! module will not pretend otherwise.
//!
//! # Runtime requirement
//!
//! [`entry`] spawns the handler with [`tokio::spawn`] and must therefore be
//! called from within a Tokio runtime. Every caller in plexus already is —
//! `Activation::call` is `async` — and the detachment above is exactly why a
//! spawned task rather than an inline future is the right shape.

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::ir::{ActivationIr, AuthRequirementIr, StopReason};
use crate::request::RawRequestContext;

use super::callback::{CallbackRouter, PeerCapabilities};
use super::cancel::CancellationToken;
use super::error::{codes, EntryError, RespondError, TurnError};
use super::event::{TurnEvent, TurnStream};
use super::handler::{unit_state, HandlerInput, HandlerTable, TurnContext};
use super::ids::{CallbackId, TurnId};

/// Buffer depth of a turn's event channel.
///
/// Deep enough that a handler emitting a burst of updates does not stall on a
/// consumer that is a few items behind; shallow enough that a consumer which
/// has stopped reading applies backpressure rather than accumulating an
/// unbounded queue.
const TURN_EVENT_BUFFER: usize = 32;

// ===========================================================================
// TurnRequest
// ===========================================================================

/// Everything the entry point needs to open a turn.
///
/// This struct is "request extraction" — the concern the macro used to
/// re-generate per arm — reduced to one type.
#[derive(Debug, Default)]
pub struct TurnRequest {
    /// Local method name (not the dotted id).
    pub method: String,
    /// Raw params; the handler decodes them.
    pub params: Value,
    /// The caller's auth context, if authenticated.
    pub auth: Option<plexus_auth_core::AuthContext>,
    /// The raw HTTP context, if the transport supplied one.
    pub raw_ctx: Option<RawRequestContext>,
    /// What the peer can serve. See [`PeerCapabilities`] — the default is
    /// permissive, on purpose and with reasons.
    pub peer: PeerCapabilities,
}

impl TurnRequest {
    /// A request for `method` with no params, no auth and an unrestricted peer.
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            params: Value::Null,
            auth: None,
            raw_ctx: None,
            peer: PeerCapabilities::all(),
        }
    }

    /// Set the params.
    pub fn with_params(mut self, params: Value) -> Self {
        self.params = params;
        self
    }

    /// Set typed params.
    pub fn with_typed_params<T: serde::Serialize + ?Sized>(
        mut self,
        params: &T,
    ) -> Result<Self, serde_json::Error> {
        self.params = serde_json::to_value(params)?;
        Ok(self)
    }

    /// Attach the caller's auth context.
    pub fn with_auth(mut self, auth: plexus_auth_core::AuthContext) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Attach the raw HTTP context.
    pub fn with_raw_context(mut self, ctx: RawRequestContext) -> Self {
        self.raw_ctx = Some(ctx);
        self
    }

    /// Declare what the peer can serve.
    pub fn with_peer(mut self, peer: PeerCapabilities) -> Self {
        self.peer = peer;
        self
    }
}

// ===========================================================================
// TurnControl / TurnHandle
// ===========================================================================

/// The out-of-band half of a turn: cancel it, and answer its callbacks.
///
/// Clonable and `Send`, so a transport can hold one while something else reads
/// the event stream. Every method is safe to call after the turn has resolved —
/// they report rather than panic.
#[derive(Debug, Clone)]
pub struct TurnControl {
    turn: TurnId,
    cancel: CancellationToken,
    router: Arc<CallbackRouter>,
}

impl TurnControl {
    /// The turn this controls.
    pub fn turn_id(&self) -> TurnId {
        self.turn
    }

    /// Deliver the cancel signal.
    ///
    /// The turn will resolve with
    /// [`StopKind::Cancelled`](crate::ir::StopKind::Cancelled) and its in-flight
    /// callbacks will resolve with an error. The handler's work is the
    /// handler's business — see the module docs.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Whether cancellation has been signalled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// This turn's cancellation token, for a caller that wants to observe it.
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Answer one server-to-client callback.
    ///
    /// `id` must be the exact [`CallbackId`] from the
    /// [`TurnEvent::Callback`] being answered. An id naming another turn is
    /// [`RespondError::WrongTurn`] — never re-routed.
    pub fn respond(&self, id: CallbackId, response: Value) -> Result<(), RespondError> {
        self.router.respond(id, response)
    }

    /// Report that the peer could not serve a callback.
    ///
    /// The handler's `await` resolves with
    /// [`CallbackError::Transport`](crate::capability::CallbackError::Transport),
    /// which it can handle — as opposed to waiting forever for an answer that
    /// is not coming.
    pub fn fail_callback(
        &self,
        id: CallbackId,
        message: impl Into<String>,
    ) -> Result<(), RespondError> {
        self.router.fail(id, message)
    }

    /// How many callbacks are awaiting a response.
    pub fn callbacks_in_flight(&self) -> usize {
        self.router.in_flight()
    }
}

/// A running turn: its event stream plus its control surface.
///
/// `TurnHandle` *is* the stream — `while let Some(ev) = handle.next().await` —
/// and [`TurnHandle::control`] hands out a clonable controller so cancelling
/// and responding do not require giving up the stream.
pub struct TurnHandle {
    control: TurnControl,
    events: TurnStream,
}

impl std::fmt::Debug for TurnHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnHandle")
            .field("turn", &self.control.turn)
            .finish_non_exhaustive()
    }
}

impl TurnHandle {
    /// The turn's id.
    pub fn turn_id(&self) -> TurnId {
        self.control.turn
    }

    /// A clonable controller for cancelling and responding.
    pub fn control(&self) -> TurnControl {
        self.control.clone()
    }

    /// Deliver the cancel signal. Shorthand for `self.control().cancel()`.
    pub fn cancel(&self) {
        self.control.cancel();
    }

    /// Answer a callback. Shorthand for `self.control().respond(..)`.
    pub fn respond(&self, id: CallbackId, response: Value) -> Result<(), RespondError> {
        self.control.respond(id, response)
    }

    /// Drop the control surface and keep only the event stream.
    pub fn into_events(self) -> TurnStream {
        self.events
    }

    /// Split into the two halves.
    pub fn split(self) -> (TurnControl, TurnStream) {
        (self.control, self.events)
    }

    /// Drain the whole turn, returning every event in order.
    ///
    /// Convenience for unary turns and for tests. A turn with callbacks will
    /// stall here unless something else is answering them through a
    /// [`TurnControl`].
    pub async fn collect(self) -> Vec<TurnEvent> {
        use futures::StreamExt;
        self.events.collect().await
    }
}

impl futures::Stream for TurnHandle {
    type Item = TurnEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.events.as_mut().poll_next(cx)
    }
}

// ===========================================================================
// entry
// ===========================================================================

/// **The** sealed core entry: dispatch one method on one activation as a turn.
///
/// Returns `Err` only for the pre-flight failures in [`EntryError`] — cases
/// where no turn exists at all. Everything a running turn can do, including
/// failing, arrives on the returned stream as a terminal.
///
/// ```
/// use plexus_core::ir::{ActivationIr, MethodIr, AuthRequirementIr, StopKind};
/// use plexus_core::runtime::{entry, ErasedHandler, HandlerTable, TurnRequest, TurnOutcome};
///
/// # tokio_test::block_on(async {
/// let ir = ActivationIr::new("demo", "1.0.0").with_method(
///     MethodIr::new("double", "demo.double").with_auth(AuthRequirementIr::Public),
/// );
/// let handlers = HandlerTable::new([(
///     "double",
///     ErasedHandler::new(|input| async move {
///         let n: u32 = plexus_core::runtime::decode_params(input.params)?;
///         TurnOutcome::serialize(&(n * 2))
///     }),
/// )]);
///
/// let turn = entry(&ir, &handlers, TurnRequest::new("double").with_params(21.into())).unwrap();
/// let events = turn.collect().await;
/// assert_eq!(events.len(), 1);
/// assert_eq!(events[0].stop_reason().unwrap().kind(), StopKind::Complete);
/// # });
/// ```
///
/// # Panics
///
/// Panics if called outside a Tokio runtime — see the module docs on why the
/// handler is a spawned task.
pub fn entry(
    ir: &ActivationIr,
    handlers: &HandlerTable,
    request: TurnRequest,
) -> Result<TurnHandle, EntryError> {
    entry_with_state(ir, handlers, unit_state(), request)
}

/// [`entry`], with the activation's state passed to the handler.
///
/// # Why state is a parameter (PLX-97)
///
/// This is PLX-73's specified dispatch shape,
/// `Fn(Arc<S>, …) -> BoxFuture<…>`, restored. The handler table can then be
/// built by closures that capture **nothing** — which is the only way a table
/// can be constructed inside `Activation::call(&self, …)` and still hand the
/// turn a `'static` future. See [`super::handler::ErasedHandler`] for the full
/// argument, including why relocating the `tokio::spawn` does not substitute
/// for it.
///
/// The `Arc<S>` is cloned once per turn and moved into the handler's future, so
/// nothing here requires `S: Clone` — 45 of the 116 activation impls in the
/// macro suite are not `Clone`, and this seam must not care.
///
/// ```
/// use std::sync::Arc;
/// use plexus_core::ir::{ActivationIr, MethodIr, AuthRequirementIr, StopKind};
/// use plexus_core::runtime::{
///     entry_with_state, decode_params, ErasedHandler, HandlerTable, TurnRequest, TurnOutcome,
/// };
///
/// // No `Clone`, no `Arc` inside: an ordinary activation struct.
/// struct Counter { step: u32 }
/// impl Counter {
///     async fn bump(&self, n: u32) -> u32 { n + self.step }
/// }
///
/// # tokio_test::block_on(async {
/// let ir = ActivationIr::new("counter", "1.0.0").with_method(
///     MethodIr::new("bump", "counter.bump").with_auth(AuthRequirementIr::Public),
/// );
/// let handlers = HandlerTable::new([(
///     "bump",
///     ErasedHandler::<Counter>::stateful(|me, input| async move {
///         let n: u32 = decode_params(input.params)?;
///         TurnOutcome::serialize(&me.bump(n).await)
///     }),
/// )]);
///
/// let state = Arc::new(Counter { step: 5 });
/// let turn = entry_with_state(&ir, &handlers, state, TurnRequest::new("bump").with_params(37.into())).unwrap();
/// let events = turn.collect().await;
/// assert_eq!(events[0].stop_reason().unwrap().kind(), StopKind::Complete);
/// # });
/// ```
///
/// # Panics
///
/// Panics if called outside a Tokio runtime — see the module docs on why the
/// handler is a spawned task.
pub fn entry_with_state<S: Send + Sync + 'static>(
    ir: &ActivationIr,
    handlers: &HandlerTable<S>,
    state: Arc<S>,
    request: TurnRequest,
) -> Result<TurnHandle, EntryError> {
    // --- 1. Dispatch: name -> IR method. No enum, no generated match. -------
    let method = ir
        .method(&request.method)
        .ok_or_else(|| EntryError::MethodNotFound {
            activation: ir.namespace.clone(),
            method: request.method.clone(),
        })?;

    // --- 2. Dispatch: name -> handler closure. -----------------------------
    let handler = handlers
        .get(method.name.as_str())
        .ok_or_else(|| EntryError::HandlerMissing {
            activation: ir.namespace.clone(),
            method: method.name.clone(),
        })?
        .clone();

    // --- 3. Auth injection, formerly a per-arm template. --------------------
    if matches!(method.auth, AuthRequirementIr::Required) && request.auth.is_none() {
        return Err(EntryError::Unauthenticated {
            method: method.name.clone(),
        });
    }

    // --- 4. Capability pre-flight, before anything runs. --------------------
    let missing = request.peer.missing_for(method);
    if !missing.is_empty() {
        return Err(EntryError::CapabilityMismatch {
            method: method.name.clone(),
            missing,
            advertised: request.peer.names(),
        });
    }

    // --- 5. Build the turn. ------------------------------------------------
    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));

    let ctx = TurnContext::new(
        turn_id,
        ir.namespace.clone(),
        method.clone(),
        cancel.clone(),
        tx,
        router.clone(),
        request.auth,
        request.raw_ctx,
    );

    let handler_task = tokio::spawn(handler.call_with(
        state,
        HandlerInput {
            params: request.params,
            turn: ctx,
        },
    ));

    // --- 6. The turn loop. -------------------------------------------------
    let loop_cancel = cancel.clone();
    let loop_router = router.clone();
    let events = async_stream::stream! {
        let mut task = handler_task;
        loop {
            // Each iteration produces the events to yield and whether the turn
            // has resolved. Computing them *outside* the `yield` keeps the
            // generator's control flow readable and keeps `select!` free of
            // yield points.
            let (batch, resolved): (Vec<TurnEvent>, bool) = tokio::select! {
                biased;

                // Cancellation wins over everything, including a handler that
                // is about to finish: once the signal is delivered the turn's
                // answer is `Cancelled`, and racing the handler for a different
                // terminal would make the outcome nondeterministic.
                _ = loop_cancel.cancelled() => {
                    loop_router.resolve_all_cancelled();
                    let mut batch = drain(&mut rx);
                    batch.push(TurnEvent::terminal(turn_id, StopReason::cancelled(), None));
                    (batch, true)
                }

                outcome = &mut task => {
                    loop_router.close();
                    let mut batch = drain(&mut rx);
                    let (stop, value) = match outcome {
                        Ok(Ok(o)) => o.into_terminal(),
                        Ok(Err(e)) => (e.into_stop_reason(), None),
                        Err(join_err) => {
                            let e = TurnError::new(
                                codes::HANDLER_PANICKED,
                                format!("the handler task did not complete: {join_err}"),
                            );
                            (e.into_stop_reason(), None)
                        }
                    };
                    batch.push(TurnEvent::terminal(turn_id, stop, value));
                    (batch, true)
                }

                Some(ev) = rx.recv() => (vec![ev], false),
            };

            for ev in batch {
                yield ev;
            }
            if resolved {
                break;
            }
        }
        // Dropping `task` here detaches it; it is never aborted. See the
        // module docs on the cooperative boundary.
    };

    Ok(TurnHandle {
        control: TurnControl {
            turn: turn_id,
            cancel,
            router,
        },
        events: Box::pin(events),
    })
}

/// Pull every already-queued event without awaiting, so the terminal is
/// yielded strictly after the updates that preceded it.
fn drain(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}
