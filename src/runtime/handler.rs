//! Erased-closure dispatch and the handler's view of its turn (PLX-80 / M1·C).
//!
//! # Why closures and not an enum
//!
//! PLX-73's `q-dispatch-representation` settled this with evidence rather than
//! taste. The generated method enum was never in the dispatch business: the
//! macro's `Activation::call` matched on the raw `&str` with a `_ =>` wildcard
//! already present, and the enum's only consumer was `schemars::schema_for!`.
//! Above the macro, `DynamicHub` already stores
//! `HashMap<String, Arc<dyn ActivationObject>>` and boxes every future — so a
//! closure table adds one hash lookup and one indirect call to a path that is
//! already double-erased, against method bodies that spawn subprocesses and
//! model sessions.
//!
//! What it buys is that the five per-arm concerns the macro used to
//! re-monomorphize — auth injection, `from_auth` resolvers, request extraction,
//! param decode, wrap/bidir plumbing — collapse to **one**. Only the typed
//! param decode and the call to the user's function need to be generic, and
//! those stay inside each closure. Everything else moved into
//! [`super::entry`] as ordinary Rust: breakpointable, unit-tested, versioned
//! once instead of re-expanded per activation.
//!
//! `benches/dispatch.rs` is the formality gate for that argument.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::capability::{CapabilitySet, Client};
use crate::ir::{MethodIr, StopDetail, StopReason};
use crate::request::RawRequestContext;

use super::callback::{CallbackRouter, TurnTransport};
use super::cancel::CancellationToken;
use super::error::TurnError;
use super::event::TurnEvent;
use super::ids::TurnId;

// ===========================================================================
// TurnOutcome
// ===========================================================================

/// How a handler says its turn ended.
///
/// `Ok(TurnOutcome)` covers every non-error terminal; `Err(TurnError)` is the
/// [`StopKind::Failed`](crate::ir::StopKind::Failed) case. The split matters
/// because [`Refused`](Self::Refused) is *not* an error — PLX-73 recorded
/// "a considered NO gets flattened into an error today" as a defect, and a
/// handler that returns `Refused` here produces a terminal that generic tooling
/// classifies correctly without inspecting any message text.
#[derive(Debug, Clone, PartialEq)]
pub enum TurnOutcome {
    /// The turn did what was asked.
    Complete {
        /// The terminal value, when the method declares one.
        value: Option<Value>,
        /// Optional domain elaboration (e.g. `acp:end_turn`).
        detail: Option<StopDetail>,
    },
    /// A considered NO: policy, permission denied, guardrail.
    Refused(StopDetail),
    /// A bound was hit: tokens, turns, time, size, rate.
    Limited(StopDetail),
    /// Any other stop reason, spelled out. The escape hatch that keeps this
    /// enum from needing a variant per future vocabulary.
    Stopped {
        /// The reason.
        stop: StopReason,
        /// The terminal value, if any.
        value: Option<Value>,
    },
}

impl TurnOutcome {
    /// Complete with no terminal value.
    pub fn complete() -> Self {
        Self::Complete {
            value: None,
            detail: None,
        }
    }

    /// Complete with an already-serialized terminal value.
    pub fn value(value: Value) -> Self {
        Self::Complete {
            value: Some(value),
            detail: None,
        }
    }

    /// Complete with a typed terminal value.
    ///
    /// Serialization failure becomes a [`TurnError`] rather than a panic or a
    /// silently dropped value.
    pub fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Self, TurnError> {
        serde_json::to_value(value)
            .map(Self::value)
            .map_err(|e| {
                TurnError::new(
                    "plexus.terminal_unserializable",
                    format!("the turn's terminal value could not be serialized: {e}"),
                )
            })
    }

    /// Attach domain detail to a [`Complete`](Self::Complete) outcome.
    pub fn with_detail(mut self, d: StopDetail) -> Self {
        if let Self::Complete { detail, .. } = &mut self {
            *detail = Some(d);
        }
        self
    }

    /// Split into the terminal's two halves.
    pub fn into_terminal(self) -> (StopReason, Option<Value>) {
        match self {
            Self::Complete { value, detail } => {
                let stop = match detail {
                    Some(d) => StopReason::complete().with_detail(d),
                    None => StopReason::complete(),
                };
                (stop, value)
            }
            Self::Refused(d) => (StopReason::refused(d), None),
            Self::Limited(d) => (StopReason::limited(d), None),
            Self::Stopped { stop, value } => (stop, value),
        }
    }
}

// ===========================================================================
// TurnContext
// ===========================================================================

#[derive(Debug)]
struct TurnContextInner {
    turn_id: TurnId,
    method: MethodIr,
    activation: String,
    cancel: CancellationToken,
    events: mpsc::Sender<TurnEvent>,
    update_seq: AtomicU64,
    transport: Arc<TurnTransport>,
    auth: Option<plexus_auth_core::AuthContext>,
    raw_ctx: Option<RawRequestContext>,
}

/// Everything a handler is given about the turn it is serving.
///
/// Cheap to clone; every clone addresses the same turn.
#[derive(Debug, Clone)]
pub struct TurnContext {
    inner: Arc<TurnContextInner>,
}

/// Emitting an update failed because the turn's consumer is gone.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("turn {0} is no longer accepting updates: its consumer dropped the event stream")]
pub struct TurnClosed(pub TurnId);

impl TurnContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        turn_id: TurnId,
        activation: String,
        method: MethodIr,
        cancel: CancellationToken,
        events: mpsc::Sender<TurnEvent>,
        router: Arc<CallbackRouter>,
        auth: Option<plexus_auth_core::AuthContext>,
        raw_ctx: Option<RawRequestContext>,
    ) -> Self {
        Self {
            inner: Arc::new(TurnContextInner {
                turn_id,
                method,
                activation,
                cancel,
                events,
                update_seq: AtomicU64::new(0),
                transport: Arc::new(TurnTransport::new(router)),
                auth,
                raw_ctx,
            }),
        }
    }

    /// This turn's id.
    pub fn turn_id(&self) -> TurnId {
        self.inner.turn_id
    }

    /// The namespace of the activation serving the turn.
    pub fn activation(&self) -> &str {
        &self.inner.activation
    }

    /// The IR of the method being served — params, declared updates, declared
    /// terminal, declared callbacks, auth requirement, extensions.
    pub fn method(&self) -> &MethodIr {
        &self.inner.method
    }

    /// The caller's auth context, when there is one.
    ///
    /// Auth *injection* — deciding whether a method may run unauthenticated —
    /// happens in [`super::entry`] before the handler is ever called. By the
    /// time a handler sees this, a `Required` method is guaranteed `Some`.
    pub fn auth(&self) -> Option<&plexus_auth_core::AuthContext> {
        self.inner.auth.as_ref()
    }

    /// The raw HTTP request context, when the transport supplied one.
    pub fn raw_context(&self) -> Option<&RawRequestContext> {
        self.inner.raw_ctx.as_ref()
    }

    /// This turn's cancellation token.
    ///
    /// **Read [`super`] before relying on it.** The framework delivers the
    /// signal and resolves the turn; observing the token and actually stopping
    /// work is the handler's job, and nothing here can do it for you.
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.inner.cancel
    }

    /// Shorthand for `self.cancellation_token().is_cancelled()`.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel.is_cancelled()
    }

    /// Shorthand for `self.cancellation_token().cancelled().await`.
    pub async fn cancelled(&self) {
        self.inner.cancel.cancelled().await
    }

    /// Emit one update. The runtime assigns the sequence number.
    pub async fn emit(&self, content: Value) -> Result<(), TurnClosed> {
        let seq = self.inner.update_seq.fetch_add(1, Ordering::SeqCst);
        self.inner
            .events
            .send(TurnEvent::update(self.inner.turn_id, seq, content))
            .await
            .map_err(|_| TurnClosed(self.inner.turn_id))
    }

    /// Emit one typed update.
    ///
    /// A value that cannot be serialized is reported as a [`TurnError`]
    /// rather than dropped — an update that vanishes is worse than a turn that
    /// fails loudly.
    pub async fn emit_typed<T: Serialize + ?Sized>(&self, value: &T) -> Result<(), TurnError> {
        let content = serde_json::to_value(value).map_err(|e| {
            TurnError::new(
                "plexus.update_unserializable",
                format!("an update could not be serialized: {e}"),
            )
        })?;
        self.emit(content).await.map_err(|e| {
            TurnError::new("plexus.turn_closed", e.to_string())
        })
    }

    /// How many updates this turn has emitted so far.
    pub fn updates_emitted(&self) -> u64 {
        self.inner.update_seq.load(Ordering::SeqCst)
    }

    /// A capability handle wired to this turn's callback transport.
    ///
    /// `C` is chosen **at the call site**, which is what preserves PLX-77's
    /// guarantee end to end: the handler asks for exactly the capability set
    /// its method signature declares, `Client<C>`'s gated accessors are the
    /// only way to use them, and `Client::<C>::callbacks()` derives the very
    /// same [`MethodIr::callbacks`] the runtime pre-flight-checked against the
    /// peer. Nothing here erases or widens `C`.
    ///
    /// Use the `*_async` accessors — see
    /// [`CallbackTransport`](crate::capability::CallbackTransport) for why the
    /// synchronous ones cannot serve a correlated response.
    pub fn client<C: CapabilitySet>(&self) -> Client<C> {
        Client::new(self.inner.transport.clone())
    }
}

// ===========================================================================
// ErasedHandler
// ===========================================================================

/// What a handler closure is handed.
#[derive(Debug)]
pub struct HandlerInput {
    /// The raw params, still undecoded. The closure owns the typed decode —
    /// that is the one thing that genuinely needs monomorphization.
    pub params: Value,
    /// The turn: cancellation, updates, callbacks, auth, method IR.
    pub turn: TurnContext,
}

/// The future an [`ErasedHandler`] returns.
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<TurnOutcome, TurnError>> + Send>>;

/// One method's implementation, type-erased.
///
/// The state a handler needs (`Arc<S>`, config, pools) is **captured** by the
/// closure at table-construction time rather than threaded through this
/// signature. That keeps the seam narrow — one parameter, one return type —
/// and it is what makes the table buildable by a macro that knows nothing about
/// the runtime beyond these two types.
#[derive(Clone)]
pub struct ErasedHandler(Arc<dyn Fn(HandlerInput) -> HandlerFuture + Send + Sync + 'static>);

impl std::fmt::Debug for ErasedHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ErasedHandler(..)")
    }
}

impl ErasedHandler {
    /// Erase an async closure into a handler.
    ///
    /// ```
    /// use plexus_core::runtime::{ErasedHandler, TurnOutcome};
    /// use plexus_core::runtime::decode_params;
    ///
    /// let handler = ErasedHandler::new(|input| async move {
    ///     let n: u32 = decode_params(input.params)?;
    ///     TurnOutcome::serialize(&(n * 2))
    /// });
    /// # let _ = handler;
    /// ```
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(HandlerInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<TurnOutcome, TurnError>> + Send + 'static,
    {
        Self(Arc::new(move |input| Box::pin(f(input))))
    }

    /// Invoke the handler.
    pub fn call(&self, input: HandlerInput) -> HandlerFuture {
        (self.0)(input)
    }
}

// ===========================================================================
// HandlerTable
// ===========================================================================

/// Name → handler. The whole of dispatch.
///
/// Built from `Vec<(&'static str, ErasedHandler)>` — the exact shape PLX-73's
/// sketch named — and indexed once at construction so lookup is a hash probe
/// rather than a linear scan over method names.
#[derive(Clone, Debug, Default)]
pub struct HandlerTable {
    by_name: HashMap<&'static str, ErasedHandler>,
    order: Vec<&'static str>,
}

impl HandlerTable {
    /// Build a table.
    ///
    /// A duplicate name keeps the **last** entry, matching how a `match` arm
    /// list would behave if it could contain duplicates at all; [`Self::order`]
    /// records each name once, in first-seen order.
    pub fn new(entries: impl IntoIterator<Item = (&'static str, ErasedHandler)>) -> Self {
        let mut by_name = HashMap::new();
        let mut order = Vec::new();
        for (name, handler) in entries {
            if by_name.insert(name, handler).is_none() {
                order.push(name);
            }
        }
        Self { by_name, order }
    }

    /// Look up a handler by method name.
    pub fn get(&self, name: &str) -> Option<&ErasedHandler> {
        self.by_name.get(name)
    }

    /// Whether a handler is registered under `name`.
    pub fn contains(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Registered names, in insertion order.
    pub fn order(&self) -> &[&'static str] {
        &self.order
    }

    /// How many handlers are registered.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

impl FromIterator<(&'static str, ErasedHandler)> for HandlerTable {
    fn from_iter<T: IntoIterator<Item = (&'static str, ErasedHandler)>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl From<Vec<(&'static str, ErasedHandler)>> for HandlerTable {
    fn from(v: Vec<(&'static str, ErasedHandler)>) -> Self {
        Self::new(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn noop() -> ErasedHandler {
        ErasedHandler::new(|_| async { Ok(TurnOutcome::complete()) })
    }

    #[test]
    fn table_indexes_by_name_and_keeps_order() {
        let t = HandlerTable::new([("a", noop()), ("b", noop()), ("c", noop())]);
        assert_eq!(t.len(), 3);
        assert_eq!(t.order(), &["a", "b", "c"]);
        assert!(t.contains("b"));
        assert!(t.get("zz").is_none());
    }

    #[test]
    fn duplicate_names_collapse_without_duplicating_the_order() {
        let t = HandlerTable::new([("a", noop()), ("a", noop())]);
        assert_eq!(t.len(), 1);
        assert_eq!(t.order(), &["a"]);
    }

    #[tokio::test]
    async fn a_handler_is_an_ordinary_async_closure() {
        let h = ErasedHandler::new(|input: HandlerInput| async move {
            let n: u32 = super::super::error::decode_params(input.params)?;
            TurnOutcome::serialize(&(n + 1))
        });
        // Build a throwaway context just to satisfy the signature.
        let (tx, _rx) = mpsc::channel(4);
        let turn_id = TurnId::new();
        let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));
        let ctx = TurnContext::new(
            turn_id,
            "test".into(),
            MethodIr::new("m", "test.m"),
            CancellationToken::new(),
            tx,
            router,
            None,
            None,
        );
        let out = h
            .call(HandlerInput {
                params: json!(41),
                turn: ctx,
            })
            .await
            .unwrap();
        assert_eq!(out.into_terminal().1, Some(json!(42)));
    }

    #[test]
    fn outcomes_map_onto_the_closed_stop_kinds() {
        use crate::ir::StopKind;
        let cases = [
            (TurnOutcome::complete(), StopKind::Complete),
            (
                TurnOutcome::Refused(StopDetail::new("policy:denied")),
                StopKind::Refused,
            ),
            (
                TurnOutcome::Limited(StopDetail::new("acp:max_tokens")),
                StopKind::Limited,
            ),
            (
                TurnOutcome::Stopped {
                    stop: StopReason::cancelled(),
                    value: None,
                },
                StopKind::Cancelled,
            ),
        ];
        for (outcome, expected) in cases {
            assert_eq!(outcome.into_terminal().0.kind(), expected);
        }
    }

    #[test]
    fn a_refusal_is_not_rendered_as_an_error() {
        let (stop, value) = TurnOutcome::Refused(StopDetail::new("policy:denied")).into_terminal();
        assert!(stop.error().is_none(), "a refusal carries no error payload");
        assert!(!stop.is_success());
        assert!(value.is_none());
    }

    #[test]
    fn complete_can_carry_domain_detail() {
        let (stop, _) = TurnOutcome::value(json!("x"))
            .with_detail(StopDetail::new("acp:end_turn"))
            .into_terminal();
        assert!(stop.is_success());
        assert_eq!(stop.detail().unwrap().code, "acp:end_turn");
    }
}
