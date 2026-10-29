//! Staged ablation ladder for PLX-88 — **measurement scaffolding, not runtime**.
//!
//! Compiled only under the `profiling` cargo feature, which nothing but
//! `benches/turn_profile.rs` and `examples/turn_alloc.rs` enable. It exists
//! because the components of a turn — [`CallbackRouter`], [`TurnContext::new`],
//! the event channel — are `pub(crate)`, so an out-of-crate bench cannot build
//! the prefixes of [`super::entry`] needed to attribute its cost.
//!
//! # Method
//!
//! Each `s*` function performs a strict **prefix** of [`super::entry`]'s body,
//! in the same order, with the same types, and then drops what it built. The
//! cost of a component is the delta between consecutive rungs:
//!
//! | delta | attributes |
//! |---|---|
//! | `s1 - s0` | `TurnId::new()` (uuid v4) |
//! | `s2 - s1` | `CancellationToken::new()` |
//! | `s3 - s2` | `mpsc::channel(32)` |
//! | `s4 - s3` | `Arc<CallbackRouter>` |
//! | `s5 - s4` | `TurnContext::new` (method clone, namespace clone, 2 Arcs) |
//! | `s6 - s5` | `HandlerInput` + `ErasedHandler::call` (the `Box::pin`) |
//! | `s6b - s6` | polling the handler body inline |
//! | `s7 - s6b` | `tokio::spawn` + `JoinHandle` await |
//! | `s8 - s7` | `into_terminal()` + `TurnEvent::terminal` + `drain` |
//! | `s9 - s8` | the `async_stream` generator, `select!` loop, `Box::pin`, collect |
//!
//! `s9` is the *real* [`super::entry`] driven to completion, so the ladder is
//! self-checking: if the rungs do not sum to `s9` the decomposition is wrong and
//! the residual is reported rather than hidden.
//!
//! Every rung is `async` and is driven by the same criterion harness, so the
//! harness's own per-iteration cost is common to all of them and cancels in the
//! deltas. `s0` is the zero point: it is the part of `entry` that cannot be
//! removed without removing dispatch itself.

use std::hint::black_box;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::ir::{ActivationIr, AuthRequirementIr, StopReason};

use super::callback::CallbackRouter;
use super::cancel::CancellationToken;
use super::entry::TurnRequest;
use super::event::TurnEvent;
use super::handler::{HandlerInput, HandlerTable, TurnContext};
use super::ids::TurnId;

/// Mirrors `entry`'s private constant. Kept in sync by
/// [`self::tests::buffer_matches_entry`].
const TURN_EVENT_BUFFER: usize = 32;

/// A rung's result, reduced to one integer so criterion can `black_box` it
/// without the return type changing what is measured.
pub type Rung = u64;

/// The four pre-flight checks, resolved. `s0` is the zero point of the ladder.
///
/// Steps 1-4 of `entry`: IR method lookup, handler lookup + `Arc` clone, the
/// auth requirement, and the peer-capability pre-flight.
pub async fn s0_preflight(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);
    black_box(&handler);
    (missing.len() + method.name.len()) as Rung
}

/// `s0` + `TurnId::new()`.
pub async fn s1_turn_id(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);
    black_box(&handler);

    let turn_id = TurnId::new();
    black_box(&turn_id);
    (missing.len() + method.name.len()) as Rung
}

/// `s1` + `CancellationToken::new()`.
pub async fn s2_cancel(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);
    black_box(&handler);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    black_box((&turn_id, &cancel));
    (missing.len() + method.name.len()) as Rung
}

/// `s2` + the turn's event channel.
pub async fn s3_channel(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);
    black_box(&handler);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    black_box((&turn_id, &cancel, &tx, &rx));
    (missing.len() + method.name.len()) as Rung
}

/// `s3` + `Arc<CallbackRouter>`.
pub async fn s4_router(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);
    black_box(&handler);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));
    black_box((&turn_id, &cancel, &tx, &rx, &router));
    (missing.len() + method.name.len()) as Rung
}

/// `s4` + `TurnContext::new` — the rung that carries `MethodIr::clone`.
pub async fn s5_context(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);
    black_box(&handler);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));
    let ctx = TurnContext::new(
        turn_id,
        ir.namespace.clone(),
        method.clone(),
        cancel.clone(),
        tx,
        router.clone(),
        None,
        None,
    );
    black_box((&cancel, &rx, &router, &ctx));
    (missing.len() + method.name.len()) as Rung
}

/// `s5` + `HandlerInput` construction and `ErasedHandler::call` — the boxed
/// future, built but never polled.
pub async fn s6_handler_future(
    ir: &ActivationIr,
    handlers: &HandlerTable,
    req: &TurnRequest,
) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));
    let ctx = TurnContext::new(
        turn_id,
        ir.namespace.clone(),
        method.clone(),
        cancel.clone(),
        tx,
        router.clone(),
        None,
        None,
    );
    let fut = handler.call(HandlerInput {
        params: req.params.clone(),
        turn: ctx,
    });
    black_box((&cancel, &rx, &router, &fut));
    (missing.len() + method.name.len()) as Rung
}

/// `s6` + polling the handler future **inline** (no task). Isolates the body's
/// own cost from `tokio::spawn`'s.
pub async fn s6b_inline_await(
    ir: &ActivationIr,
    handlers: &HandlerTable,
    req: &TurnRequest,
) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));
    let ctx = TurnContext::new(
        turn_id,
        ir.namespace.clone(),
        method.clone(),
        cancel.clone(),
        tx,
        router.clone(),
        None,
        None,
    );
    let outcome = handler
        .call(HandlerInput {
            params: req.params.clone(),
            turn: ctx,
        })
        .await;
    black_box((&cancel, &rx, &router, &outcome));
    (missing.len() + method.name.len()) as Rung
}

/// `s6b` but through `tokio::spawn` + `JoinHandle`, exactly as `entry` does.
pub async fn s7_spawn_await(
    ir: &ActivationIr,
    handlers: &HandlerTable,
    req: &TurnRequest,
) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);

    let turn_id = TurnId::new();
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel::<TurnEvent>(TURN_EVENT_BUFFER);
    let router = Arc::new(CallbackRouter::new(turn_id, tx.clone()));
    let ctx = TurnContext::new(
        turn_id,
        ir.namespace.clone(),
        method.clone(),
        cancel.clone(),
        tx,
        router.clone(),
        None,
        None,
    );
    let task = tokio::spawn(handler.call(HandlerInput {
        params: req.params.clone(),
        turn: ctx,
    }));
    let outcome = task.await;
    black_box((&cancel, &rx, &router, &outcome));
    (missing.len() + method.name.len()) as Rung
}

/// `s7` + the terminal projection: `into_terminal`, `TurnEvent::terminal`, and
/// the `drain` that guarantees the terminal is last.
pub async fn s8_terminal(ir: &ActivationIr, handlers: &HandlerTable, req: &TurnRequest) -> Rung {
    let method = ir.method(&req.method).expect("method exists");
    let handler = handlers.get(method.name.as_str()).expect("handler exists").clone();
    if matches!(method.auth, AuthRequirementIr::Required) && req.auth.is_none() {
        return 0;
    }
    let missing = req.peer.missing_for(method);

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
        None,
        None,
    );
    let task = tokio::spawn(handler.call(HandlerInput {
        params: req.params.clone(),
        turn: ctx,
    }));
    let outcome = task.await;

    router.close();
    let mut batch = drain(&mut rx);
    let (stop, value) = match outcome {
        Ok(Ok(o)) => o.into_terminal(),
        Ok(Err(e)) => (e.into_stop_reason(), None),
        Err(_) => (StopReason::cancelled(), None),
    };
    batch.push(TurnEvent::terminal(turn_id, stop, value));

    black_box((&cancel, &router, &batch));
    (missing.len() + method.name.len() + batch.len()) as Rung
}

/// Copy of `entry`'s private `drain`.
fn drain(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::MethodIr;
    use crate::runtime::{ErasedHandler, TurnOutcome};

    fn fixture() -> (ActivationIr, HandlerTable) {
        let ir = ActivationIr::new("prof", "1.0.0").with_method(
            MethodIr::new("m", "prof.m").with_auth(AuthRequirementIr::Public),
        );
        let handlers = HandlerTable::new([(
            "m",
            ErasedHandler::new(|_| async { Ok(TurnOutcome::complete()) }),
        )]);
        (ir, handlers)
    }

    /// The ladder is only meaningful if every rung runs the same pre-flight.
    #[tokio::test]
    async fn every_rung_resolves_the_same_method() {
        let (ir, handlers) = fixture();
        let req = TurnRequest::new("m");
        let expected = s0_preflight(&ir, &handlers, &req).await;
        assert_eq!(s1_turn_id(&ir, &handlers, &req).await, expected);
        assert_eq!(s2_cancel(&ir, &handlers, &req).await, expected);
        assert_eq!(s3_channel(&ir, &handlers, &req).await, expected);
        assert_eq!(s4_router(&ir, &handlers, &req).await, expected);
        assert_eq!(s5_context(&ir, &handlers, &req).await, expected);
        assert_eq!(s6_handler_future(&ir, &handlers, &req).await, expected);
        assert_eq!(s6b_inline_await(&ir, &handlers, &req).await, expected);
        assert_eq!(s7_spawn_await(&ir, &handlers, &req).await, expected);
        // s8 additionally counts the one terminal it built.
        assert_eq!(s8_terminal(&ir, &handlers, &req).await, expected + 1);
    }

    /// The ladder replicates `entry`'s channel depth; a drift here would make
    /// the `s3 - s2` attribution measure a different channel than the one the
    /// runtime allocates.
    #[test]
    fn buffer_matches_entry() {
        // `entry`'s constant is private; this asserts the documented value so
        // a change there fails a test rather than silently skewing a profile.
        assert_eq!(TURN_EVENT_BUFFER, 32);
    }
}
