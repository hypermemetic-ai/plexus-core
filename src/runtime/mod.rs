//! The turn runtime (PLX-80 / M1·C+D) — one sealed entry, erased-closure
//! dispatch, native turn lifecycle.
//!
//! # What this is
//!
//! [`entry`] is the whole of dispatch. Give it an
//! [`ActivationIr`](crate::ir::ActivationIr), a [`HandlerTable`] of erased
//! closures, and a [`TurnRequest`], and it returns a [`TurnHandle`]: a stream
//! of [`TurnEvent`]s plus a [`TurnControl`] for cancelling the turn and
//! answering its callbacks.
//!
//! ```
//! use plexus_core::ir::{ActivationIr, AuthRequirementIr, MethodIr, StopKind};
//! use plexus_core::runtime::{entry, decode_params, ErasedHandler, HandlerTable, TurnOutcome, TurnRequest};
//!
//! # tokio_test::block_on(async {
//! let ir = ActivationIr::new("counter", "1.0.0").with_method(
//!     MethodIr::new("count", "counter.count").with_auth(AuthRequirementIr::Public),
//! );
//!
//! let handlers = HandlerTable::new([(
//!     "count",
//!     ErasedHandler::new(|input| async move {
//!         let n: u64 = decode_params(input.params)?;
//!         for i in 0..n {
//!             input.turn.emit(serde_json::json!({ "at": i })).await.ok();
//!         }
//!         TurnOutcome::serialize(&n)
//!     }),
//! )]);
//!
//! let events = entry(&ir, &handlers, TurnRequest::new("count").with_params(3.into()))
//!     .unwrap()
//!     .collect()
//!     .await;
//!
//! // Three updates, then exactly one terminal — always in that order.
//! assert_eq!(events.iter().filter(|e| e.is_update()).count(), 3);
//! assert_eq!(events.iter().filter(|e| e.is_terminal()).count(), 1);
//! assert!(events.last().unwrap().is_terminal());
//! assert_eq!(events.last().unwrap().stop_reason().unwrap().kind(), StopKind::Complete);
//! # });
//! ```
//!
//! # Where a handler's state comes from (PLX-97)
//!
//! A handler that needs the activation itself takes it as a **parameter**:
//! build the table with [`ErasedHandler::stateful`] and open the turn with
//! [`entry_with_state`], which hands each handler an `Arc<S>`. The closures
//! then capture nothing, so a table can be built inside `&self` methods — the
//! construction the macro switchover needs and the reason this is a parameter
//! rather than a capture. [`ErasedHandler`]'s docs carry the full argument,
//! including why moving the `tokio::spawn` is not a substitute.
//!
//! # The turn contract
//!
//! Every call is a **turn**, not a stream that ends (PLX-73
//! `q-acp-as-communication-model`, ADOPTed):
//!
//! - **zero or more updates**, then **exactly one terminal** carrying a
//!   [`StopReason`](crate::ir::StopReason). The runtime, not the handler, is
//!   what makes "exactly one, always last" true — see [`entry`]'s module docs
//!   for the loop that guarantees it structurally.
//! - **failure is that same terminal**, with
//!   [`StopKind::Failed`](crate::ir::StopKind::Failed) and a structured
//!   [`TurnError`] payload. Not a side channel, and not a `message: String`.
//!   See [`error`] for why the structure survives the wire.
//! - **refusal is not failure.** A handler returning
//!   [`TurnOutcome::Refused`] produces `StopKind::Refused`, which generic
//!   tooling classifies without parsing prose. PLX-73 recorded the flattening
//!   of considered NOs into errors as a defect; this is the fix.
//! - **callbacks are capability-gated**, and checked against the peer
//!   *pre-flight* rather than discovered mid-turn. See [`PeerCapabilities`].
//!
//! # A handler may call only what its method declares (PLX-102)
//!
//! A turn's capability handle comes from [`DeclaredHandler`], which derives the
//! method's declared [`CallbackIr`](crate::ir::CallbackIr)s *and* the handler's
//! `Client<C>` from a single `C`. Inside such a handler `input.turn` is a
//! [`Turn<C>`], and `turn.client()` infers exactly that set — asking for any
//! other set does not compile. [`TurnContext`] itself cannot mint a client at
//! all, which is what keeps the guarantee from depending on which constructor
//! an author picked. See [`declared`] for the seam this closed and for the one
//! piece that is still convention.
//!
//! # Cancellation is cooperative — read this before relying on it
//!
//! This is the single most over-claimable thing in the runtime, so it is
//! stated flatly. PLX-73's turn contract, in the operator's words: *"There is
//! never a way to cancel guaranteed. Cancellation must be handled by the
//! service implementor."*
//!
//! **What the framework guarantees**, when [`TurnControl::cancel`] is called:
//!
//! 1. the [`CancellationToken`] the handler holds flips, and every
//!    [`CancellationToken::cancelled`] waiter wakes;
//! 2. the turn **resolves** — a `Terminal` with
//!    [`StopKind::Cancelled`](crate::ir::StopKind::Cancelled) is emitted
//!    promptly, without waiting on the handler;
//! 3. every **in-flight callback resolves** with an error rather than hanging,
//!    so a handler blocked on `client.request_permission_async(..).await`
//!    proceeds instead of stalling forever.
//!
//! **What the framework does not guarantee**: that the handler's work stopped.
//! The handler task is *detached, not aborted*. A spawned subprocess, an
//! in-flight model call, a half-written row — those are the implementor's
//! responsibility, and the runtime deliberately leaves the task alive so the
//! implementor can clean them up rather than being killed mid-`await`.
//!
//! So `StopKind::Cancelled` means **"the turn stopped waiting"**. It does not
//! mean "the work stopped". A handler that wants the second meaning writes it:
//!
//! ```
//! # use plexus_core::runtime::{ErasedHandler, TurnOutcome};
//! # use plexus_core::ir::StopReason;
//! let handler = ErasedHandler::new(|input| async move {
//!     for chunk in 0..1000 {
//!         if input.turn.is_cancelled() {
//!             // The implementor's half: stop, clean up, report.
//!             return Ok(TurnOutcome::Stopped { stop: StopReason::cancelled(), value: None });
//!         }
//!         let _ = chunk;
//!     }
//!     Ok(TurnOutcome::complete())
//! });
//! # let _ = handler;
//! ```
//!
//! A future build may add a per-method declaration of whether a method is
//! cancellation-aware, so tooling can *warn* rather than silently imply the
//! stronger guarantee (PLX-73 raised it; PLX-80 does not decide it).
//!
//! # Dispatch is a closure table, and that was measured
//!
//! No enum, no generated `match`. PLX-73's `q-dispatch-representation` found
//! that the method enum was never used for dispatch and that `DynamicHub`
//! already type-erases everything above the macro, so a closure table costs one
//! hash probe and one indirect call on a path that already boxes every future.
//! `benches/dispatch.rs` is the formality gate for that claim. See [`handler`]
//! for what the collapse buys.
//!
//! # This is additive
//!
//! Nothing here modifies [`Activation`](crate::Activation), `DynamicHub`,
//! `route_with_ctx`, `wrap_stream`, or `plexus.rs`'s dispatch path. The new
//! runtime lives beside them, and [`IrActivation`] is the bridge that lets a
//! turn-native service be registered on today's hub before the macro
//! switchover. See [`bridge`].

pub mod bridge;
pub mod callback;
pub mod declared;
pub mod cancel;
pub mod entry;
pub mod error;
pub mod event;
pub mod handler;
pub mod ids;

/// PLX-88 measurement scaffolding. Not part of the runtime; compiled only under
/// the `profiling` feature, which only `benches/turn_profile.rs` and
/// `examples/turn_alloc.rs` enable.
#[cfg(feature = "profiling")]
#[doc(hidden)]
pub mod profile;

#[cfg(test)]
mod tests;

pub use bridge::{turn_stream_to_plexus_stream, IrActivation, IrMethods, LiveTurns};
pub use callback::{PeerCapabilities, TurnTransport};
pub use cancel::CancellationToken;
pub use declared::{CapabilityInput, DeclaredHandler, Turn};
pub use entry::{entry, entry_with_state, TurnControl, TurnHandle, TurnRequest};
pub use error::{
    codes, decode_param, decode_params, EntryError, RespondError, TurnError,
};
pub use event::{TurnEvent, TurnStream};
pub use handler::{
    ErasedHandler, HandlerFuture, HandlerInput, HandlerTable, IntoTurnStop, TurnClosed, TurnContext,
    TurnOutcome, TurnStop,
};
pub use ids::{CallbackId, TurnId};
