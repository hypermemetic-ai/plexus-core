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

use crate::ir::{MethodIr, StopDetail, StopReason};
use crate::request::RawRequestContext;

use super::callback::{CallbackRouter, TurnTransport};
use super::cancel::CancellationToken;
use super::error::TurnError;
use super::event::TurnEvent;
use super::ids::TurnId;

// ===========================================================================
// TurnStop — how an `Err` chooses its stop kind (PLX-112)
// ===========================================================================

/// What a handler's `Err` value means in [`StopKind`](crate::ir::StopKind)
/// terms.
///
/// # Why this type exists
///
/// PLX-110 made `#[method] -> Result<T, E>` compile and bound `E` with
/// `E: Into<TurnError>`, which *defines* `Err` as
/// [`Failed`](crate::ir::StopKind::Failed). RFC 002 §6.6 says a considered
/// "no" is [`Refused`](crate::ir::StopKind::Refused) and MUST NOT be conflated
/// with `Failed` — and until this type existed no generated handler could emit
/// one, because the only channel out of the error position was a `TurnError`
/// and `TurnError::into_stop_reason` is `Failed` by construction. A refusal had
/// no spelling at all.
///
/// `TurnStop` is that spelling. It is deliberately **not** a field on
/// `TurnError`: RFC 002 §6.7.1 says a terminal whose kind is not `Failed` MUST
/// NOT carry a structured error, so a "refused error" is a contradiction the
/// checker is required to reject. A refusal carries [`StopDetail`] — §6.5's
/// open domain vocabulary — and nothing else.
///
/// # What is NOT here, and why
///
/// - **`Cancelled` is not a variant.** RFC 002 §6.8 makes cancellation
///   *cooperative*: a cancel signal MUST be delivered to the turn and the turn
///   resolves `Cancelled`. Letting a handler's `Err` claim `Cancelled` would
///   let a turn assert a signal that was never delivered, making the kind
///   unfalsifiable. `Cancelled` stays the runtime's to emit — which is the same
///   call [`TurnOutcome`] already made, and why it has no `Cancelled` variant
///   either. A handler that genuinely must spell one has
///   [`TurnOutcome::Stopped`] on the success side.
/// - **No `Complete` variant.** An `Err` that means success is a bug in the
///   signature, not a stop kind.
///
/// # The default is unchanged
///
/// The blanket [`IntoTurnStop`] impl maps every `E: Into<TurnError>` to
/// [`TurnStop::Failed`], so PLX-110's bound and behaviour survive untouched. An
/// error type that says nothing about kind terminates exactly as it did.
#[derive(Debug, Clone, PartialEq)]
pub enum TurnStop {
    /// The default: a structured error, [`StopKind::Failed`](crate::ir::StopKind::Failed).
    Failed(TurnError),
    /// A considered NO: policy, denied permission, guardrail. Not an error.
    Refused(StopDetail),
    /// A bound was hit: tokens, turns, time, size, rate. Not an error.
    Limited(StopDetail),
}

impl TurnStop {
    /// A refusal carrying only its domain code.
    pub fn refused(code: impl Into<String>) -> Self {
        Self::Refused(StopDetail::new(code))
    }

    /// A limit stop carrying only its domain code.
    pub fn limited(code: impl Into<String>) -> Self {
        Self::Limited(StopDetail::new(code))
    }

    /// Project onto what a handler closure returns.
    ///
    /// `Failed` is the `Err` half; the non-error kinds ride the `Ok` half as a
    /// [`TurnOutcome`], because they are not errors and the runtime must not
    /// render them through [`TurnError::into_stop_reason`].
    pub fn into_handler_result(self) -> Result<TurnOutcome, TurnError> {
        match self {
            Self::Failed(e) => Err(e),
            Self::Refused(d) => Ok(TurnOutcome::Refused(d)),
            Self::Limited(d) => Ok(TurnOutcome::Limited(d)),
        }
    }
}

/// How an error type says which [`StopKind`](crate::ir::StopKind) it means.
///
/// This is the bound a generated handler's `Err` arm goes through. **The macro
/// guesses nothing**: it names no kind, inspects no type, and reads no
/// attribute — it calls one trait method and the author's own impl decides.
/// That is the same posture as PLX-110's `E: Into<TurnError>`, one level up.
///
/// # Which impl an author writes
///
/// | the author wants | the impl to write |
/// |---|---|
/// | `Failed` (the default) | `impl From<MyError> for TurnError` — nothing else |
/// | `Refused` / `Limited` | `impl IntoTurnStop for MyError` |
///
/// The blanket impl below covers the first row, so **no existing code changes**
/// and `E = TurnError` still needs no impl at all. Writing *both* for one type
/// is a coherence conflict (E0119) rather than a silent precedence rule — the
/// error names both impls, which is the loud failure this design wants.
///
/// `String` is still refused, exactly as under PLX-110: it implements neither
/// side, so the flattened-error back door stays shut.
pub trait IntoTurnStop {
    /// Which stop kind this error means.
    fn into_turn_stop(self) -> TurnStop;
}

impl<E: Into<TurnError>> IntoTurnStop for E {
    fn into_turn_stop(self) -> TurnStop {
        TurnStop::Failed(self.into())
    }
}

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

    /// This turn's callback transport.
    ///
    /// Deliberately `pub(crate)` and deliberately *not* a `Client<C>` factory.
    /// This accessor used to be `pub fn client<C: CapabilitySet>(&self) ->
    /// Client<C>` with `C` free, and a doc comment claiming the guarantee
    /// survived because "the handler asks for exactly the capability set its
    /// method signature declares" — usage, not a constraint. A handler serving
    /// a method that declared `(FsRead,)` could mint `Client<(FsWrite,)>` and
    /// only find out at the transport.
    ///
    /// Minting is now [`Turn<C>::client`](super::Turn::client), where `C` is
    /// the set the method declared and no other set typechecks. See
    /// [`super::declared`] (PLX-102).
    pub(crate) fn transport(&self) -> Arc<dyn crate::capability::CallbackTransport> {
        self.inner.transport.clone()
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

/// One method's implementation, type-erased over the activation state `S`.
///
/// # State is a parameter, not a capture (PLX-97)
///
/// PLX-73's `q-dispatch-representation` specified
/// `Fn(Arc<S>, Value, AuthCtxOpt, RawCtxOpt) -> …` — **state passed in**.
/// PLX-80 narrowed that to captured state, which is a strictly narrower seam
/// and works whenever the table is built from owned state. It does *not* work
/// for the construction the macro switchover needs: a handler built inside
/// `Activation::call(&self, …)` that calls `self.method(…)`. A closure
/// capturing `&'a self` cannot produce the `'static` future the turn's stream
/// outlives, so that construction fails with `E0521: borrowed data escapes
/// outside of method` — and no amount of restructuring the turn loop changes
/// it, because [`super::entry`] returns a stream that lives past the borrow.
///
/// Threading the state through the call restores PLX-73's shape and closes the
/// seam: the closure captures **nothing**, so it is `'static` no matter where
/// it is constructed, and the only owned thing anyone needs is one `Arc<S>` —
/// obtained without requiring `S: Clone`.
///
/// `S` defaults to `()`, so a handler that needs no activation state is written
/// exactly as before with [`ErasedHandler::new`].
pub struct ErasedHandler<S = ()>(
    Arc<dyn Fn(Arc<S>, HandlerInput) -> HandlerFuture + Send + Sync + 'static>,
);

impl<S> Clone for ErasedHandler<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> std::fmt::Debug for ErasedHandler<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ErasedHandler(..)")
    }
}

impl ErasedHandler<()> {
    /// Erase a stateless async closure into a handler.
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
        Self(Arc::new(move |_state, input| Box::pin(f(input))))
    }

    /// Invoke a stateless handler.
    pub fn call(&self, input: HandlerInput) -> HandlerFuture {
        (self.0)(unit_state(), input)
    }
}

impl<S: Send + Sync + 'static> ErasedHandler<S> {
    /// Erase an async closure that is handed the activation's state.
    ///
    /// The closure receives `Arc<S>` as its first argument, so it may be — and
    /// for the macro switchover *is* — a closure that captures nothing at all.
    /// That is what makes it constructible from inside `&self` methods.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use plexus_core::runtime::{ErasedHandler, TurnOutcome, decode_params};
    ///
    /// // Deliberately not `Clone`.
    /// struct Service { factor: u32 }
    /// impl Service {
    ///     async fn scale(&self, n: u32) -> u32 { n * self.factor }
    /// }
    ///
    /// let handler = ErasedHandler::<Service>::stateful(|me, input| async move {
    ///     let n: u32 = decode_params(input.params)?;
    ///     TurnOutcome::serialize(&me.scale(n).await)
    /// });
    /// # let _ = handler;
    /// ```
    pub fn stateful<F, Fut>(f: F) -> Self
    where
        F: Fn(Arc<S>, HandlerInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<TurnOutcome, TurnError>> + Send + 'static,
    {
        Self(Arc::new(move |state, input| Box::pin(f(state, input))))
    }

    /// Invoke the handler against a state handle.
    pub fn call_with(&self, state: Arc<S>, input: HandlerInput) -> HandlerFuture {
        (self.0)(state, input)
    }
}

/// The shared `Arc<()>` every stateless turn passes.
///
/// `Arc::new(())` still allocates an `ArcInner`; a turn should not pay for a
/// state it does not have, so the unit state is created once and cloned.
pub(crate) fn unit_state() -> Arc<()> {
    static UNIT: std::sync::OnceLock<Arc<()>> = std::sync::OnceLock::new();
    UNIT.get_or_init(|| Arc::new(())).clone()
}

// ===========================================================================
// HandlerTable
// ===========================================================================

/// Name → handler. The whole of dispatch.
///
/// Built from `Vec<(&'static str, ErasedHandler<S>)>` — the exact shape PLX-73's
/// sketch named — and indexed once at construction so lookup is a hash probe
/// rather than a linear scan over method names.
///
/// `S` is the activation state the handlers are called with; it defaults to
/// `()` for tables whose handlers need none.
pub struct HandlerTable<S = ()> {
    by_name: HashMap<&'static str, ErasedHandler<S>>,
    order: Vec<&'static str>,
}

// Hand-written rather than derived: a derive would demand `S: Clone`/`S: Debug`
// /`S: Default`, none of which a table actually needs — it only ever holds
// `Arc`-shaped closures over `S`.
impl<S> Clone for HandlerTable<S> {
    fn clone(&self) -> Self {
        Self {
            by_name: self.by_name.clone(),
            order: self.order.clone(),
        }
    }
}

impl<S> std::fmt::Debug for HandlerTable<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerTable")
            .field("order", &self.order)
            .finish()
    }
}

impl<S> Default for HandlerTable<S> {
    fn default() -> Self {
        Self {
            by_name: HashMap::new(),
            order: Vec::new(),
        }
    }
}

impl<S> HandlerTable<S> {
    /// Build a table.
    ///
    /// A duplicate name keeps the **last** entry, matching how a `match` arm
    /// list would behave if it could contain duplicates at all; [`Self::order`]
    /// records each name once, in first-seen order.
    pub fn new(entries: impl IntoIterator<Item = (&'static str, ErasedHandler<S>)>) -> Self {
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
    pub fn get(&self, name: &str) -> Option<&ErasedHandler<S>> {
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

impl<S> FromIterator<(&'static str, ErasedHandler<S>)> for HandlerTable<S> {
    fn from_iter<T: IntoIterator<Item = (&'static str, ErasedHandler<S>)>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl<S> From<Vec<(&'static str, ErasedHandler<S>)>> for HandlerTable<S> {
    fn from(v: Vec<(&'static str, ErasedHandler<S>)>) -> Self {
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

    // -----------------------------------------------------------------------
    // PLX-112 — TurnStop / IntoTurnStop
    // -----------------------------------------------------------------------

    /// The ordinary error type: a `From` impl and nothing else.
    #[derive(Debug)]
    struct Boom;

    impl From<Boom> for TurnError {
        fn from(_: Boom) -> Self {
            TurnError::new("app.boom", "boom")
        }
    }

    /// The considered "no": implements `IntoTurnStop` directly and deliberately
    /// has **no** `Into<TurnError>` impl, so the two can never both apply.
    #[derive(Debug)]
    struct Denied {
        who: &'static str,
    }

    impl IntoTurnStop for Denied {
        fn into_turn_stop(self) -> TurnStop {
            TurnStop::Refused(
                StopDetail::new("app.denied")
                    .with_message("the user said no")
                    .with_data("who", json!(self.who)),
            )
        }
    }

    #[test]
    fn plx112_failed_stays_the_default_for_an_error_that_says_nothing_about_kind() {
        // The blanket impl. This is PLX-110's behaviour, unchanged.
        let stop = Boom.into_turn_stop();
        assert_eq!(stop, TurnStop::Failed(TurnError::new("app.boom", "boom")));

        let e = stop.into_handler_result().unwrap_err();
        let reason = e.into_stop_reason();
        assert_eq!(reason.kind(), crate::ir::StopKind::Failed);
        assert!(reason.error().is_some(), "Failed carries its structured error");
    }

    #[test]
    fn plx112_turn_error_itself_needs_no_impl() {
        let stop = TurnError::new("app.x", "x").into_turn_stop();
        assert!(matches!(stop, TurnStop::Failed(_)));
    }

    #[test]
    fn plx112_a_refusal_lands_as_refused_and_carries_no_error() {
        let outcome = Denied { who: "operator" }
            .into_turn_stop()
            .into_handler_result()
            .expect("a refusal is not an error, so it rides the Ok half");

        let (stop, value) = outcome.into_terminal();
        assert_eq!(stop.kind(), crate::ir::StopKind::Refused);
        // RFC 002 §6.7.1: a non-Failed terminal MUST NOT carry a structured error.
        assert!(stop.error().is_none());
        assert!(value.is_none());

        let d = stop.detail().expect("§6.5: the domain vocabulary rides in detail");
        assert_eq!(d.code, "app.denied");
        assert_eq!(d.message.as_deref(), Some("the user said no"));
        assert_eq!(d.data.get("who"), Some(&json!("operator")));
    }

    #[test]
    fn plx112_a_limit_lands_as_limited_and_carries_no_error() {
        let (stop, value) = TurnStop::limited("acp:max_tokens")
            .into_handler_result()
            .expect("a bound is not an error")
            .into_terminal();
        assert_eq!(stop.kind(), crate::ir::StopKind::Limited);
        assert!(stop.error().is_none());
        assert!(value.is_none());
        assert_eq!(stop.detail().unwrap().code, "acp:max_tokens");
    }

    #[test]
    fn plx112_refused_is_neither_success_nor_error() {
        let (stop, _) = TurnStop::refused("policy:denied")
            .into_handler_result()
            .unwrap()
            .into_terminal();
        assert!(!stop.is_success());
        assert!(stop.error().is_none());
    }
}
