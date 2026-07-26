//! Decision gate 2 (PLX-74 / PLX-80): does erased-closure dispatch cost enough
//! to matter?
//!
//! # The question, stated so it can be answered
//!
//! PLX-73's `q-dispatch-representation` chose an erased-closure registry over
//! the generated string `match`, and set a *formality gate* rather than
//! asserting the result: build the bench, run it, and
//!
//! > **adopt the closure registry unless the dispatch delta exceeds 5% of the
//! > cheapest real method's p50.**
//!
//! Three groups answer that:
//!
//! 1. `dispatch/string_match/*` — a hand-written 19-arm `match name { .. }`
//!    with a `_ =>` wildcard, shaped exactly like the code
//!    `plexus-macros` emits into `Activation::call` (activation.rs:654-691),
//!    including the boxed future the `async_trait` return forces.
//! 2. `dispatch/closure_registry/*` — the same 19 methods in a
//!    [`HandlerTable`], dispatched by name.
//! 3. `reference_bar/echo.once` — `DynamicHub::route_with_ctx("echo.once", ..)`
//!    driven to completion. `echo.once` is the *cheapest real method* in the
//!    tree: it yields one event and does no I/O. Its p50 is the bar the delta
//!    is measured against.
//!
//! Each dispatch group is measured at the **first**, **median** and **last**
//! method-name position, because a linear `match` and a hash probe degrade
//! differently across the arm list and an average would hide it.
//!
//! `turn_overhead/*` is reported alongside but is **not** part of the gate: it
//! measures the whole turn lifecycle (spawn, channel, terminal) against the
//! whole legacy path, which is a different question from the representation of
//! dispatch.

//!
//! # The resolution this bench ran under (PLX-101)
//!
//! Every number below is a function of the resolved dependency set as much as
//! of the source. `main` prints the resolution banner before criterion starts —
//! see [`benches/common/resolution.rs`]. Two numbers with different
//! lock-fingerprints are not comparable, and the gate this bench decides is not
//! re-decidable from a number quoted without one.

use std::hint::black_box;

use criterion::{criterion_group, Criterion};
use futures::future::BoxFuture;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::runtime::Runtime;

use plexus_core::activations::echo::Echo;
use plexus_core::ir::{ActivationIr, AuthRequirementIr, MethodIr};
use plexus_core::plexus::DynamicHub;
use plexus_core::runtime::{
    entry, ErasedHandler, HandlerInput, HandlerTable, TurnOutcome, TurnRequest,
};

/// A claudecode-shaped activation: 19 methods.
const METHOD_COUNT: usize = 19;

const NAMES: [&str; METHOD_COUNT] = [
    "list", "create", "resume", "chat", "prompt", "cancel", "status", "history", "fork", "diff",
    "apply", "revert", "search", "index", "watch", "tail", "config", "health", "close",
];

/// The three positions we probe: first, median, last.
fn probe_positions() -> [(&'static str, &'static str); 3] {
    [
        ("first", NAMES[0]),
        ("median", NAMES[METHOD_COUNT / 2]),
        ("last", NAMES[METHOD_COUNT - 1]),
    ]
}

// ===========================================================================
// A — the generated string match
// ===========================================================================

/// The shape `plexus-macros` emits: match the raw `&str`, with a wildcard arm
/// for child routing / MethodNotFound, and box the resulting future because
/// `async_trait` does.
///
/// Each arm calls the *same* trivial body, so the only thing that differs
/// between this and the registry is how the body was reached.
fn string_match_dispatch(name: &str, params: Value) -> Option<BoxFuture<'static, Value>> {
    macro_rules! arm {
        ($p:expr) => {
            Some(Box::pin(async move { body($p).await }) as BoxFuture<'static, Value>)
        };
    }
    match name {
        "list" => arm!(params),
        "create" => arm!(params),
        "resume" => arm!(params),
        "chat" => arm!(params),
        "prompt" => arm!(params),
        "cancel" => arm!(params),
        "status" => arm!(params),
        "history" => arm!(params),
        "fork" => arm!(params),
        "diff" => arm!(params),
        "apply" => arm!(params),
        "revert" => arm!(params),
        "search" => arm!(params),
        "index" => arm!(params),
        "watch" => arm!(params),
        "tail" => arm!(params),
        "config" => arm!(params),
        "health" => arm!(params),
        "close" => arm!(params),
        // The wildcard the generated code already has — exhaustiveness over
        // network strings was always illusory.
        _ => None,
    }
}

/// The shared "method body": a typed decode and a trivial computation, which
/// is the part that legitimately needs monomorphization in either design.
async fn body(params: Value) -> Value {
    let n: u64 = serde_json::from_value(params).unwrap_or(0);
    json!(n + 1)
}

// ===========================================================================
// B — the erased-closure registry
// ===========================================================================

fn closure_table() -> HandlerTable {
    HandlerTable::new(NAMES.iter().map(|name| {
        (
            *name,
            ErasedHandler::new(|input: HandlerInput| async move {
                Ok(TurnOutcome::value(body(input.params).await))
            }),
        )
    }))
}

/// Dispatch through the table without building a turn — the apples-to-apples
/// comparison against `string_match_dispatch`, which likewise only resolves a
/// name to a future.
fn closure_dispatch(
    table: &HandlerTable,
    ctx: &plexus_core::runtime::TurnContext,
    name: &str,
    params: Value,
) -> Option<BoxFuture<'static, Value>> {
    let handler = table.get(name)?.clone();
    let turn = ctx.clone();
    Some(Box::pin(async move {
        // The registry hands back a `TurnOutcome`; project it onto the same
        // `Value` the match arm produces so the two futures do equal work.
        match handler
            .call(HandlerInput { params, turn })
            .await
        {
            Ok(o) => o.into_terminal().1.unwrap_or(Value::Null),
            Err(_) => Value::Null,
        }
    }))
}

/// A `TurnContext` for the isolated-dispatch benchmark.
///
/// Built **once, eagerly, outside criterion's runtime** and then cloned, so the
/// cost of constructing a turn does not contaminate the measurement of
/// dispatching into one. Turn construction is measured separately, in
/// `turn_overhead`.
fn build_ctx() -> plexus_core::runtime::TurnContext {
    // Open a real turn and steal its context by running a handler that hands
    // it back — the only way to get one without widening the runtime's API for
    // a benchmark's convenience.
    let rt = Runtime::new().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let ir = ActivationIr::new("bench", "1.0.0").with_method(
        MethodIr::new("ctx", "bench.ctx").with_auth(AuthRequirementIr::Public),
    );
    let handlers = HandlerTable::new([(
        "ctx",
        ErasedHandler::new(move |input: HandlerInput| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(input.turn.clone());
                Ok(TurnOutcome::complete())
            }
        }),
    )]);
    rt.block_on(async {
        let turn = entry(&ir, &handlers, TurnRequest::new("ctx")).unwrap();
        let _ = turn.collect().await;
    });
    rx.recv().expect("the handler handed back its context")
}

// ===========================================================================
// The benchmarks
// ===========================================================================

fn bench_dispatch(c: &mut Criterion) {
    let ctx = build_ctx();
    let rt = Runtime::new().unwrap();
    let table = closure_table();

    let mut group = c.benchmark_group("dispatch");

    for (position, name) in probe_positions() {
        group.bench_function(format!("string_match/{position}"), |b| {
            b.to_async(&rt).iter(|| async {
                let fut = string_match_dispatch(black_box(name), black_box(json!(41)))
                    .expect("the arm exists");
                black_box(fut.await)
            });
        });

        group.bench_function(format!("closure_registry/{position}"), |b| {
            b.to_async(&rt).iter(|| async {
                let fut = closure_dispatch(&table, &ctx, black_box(name), black_box(json!(41)))
                    .expect("the row exists");
                black_box(fut.await)
            });
        });
    }

    // The miss path, which is where a `match`'s wildcard and a hash probe's
    // failed lookup could plausibly differ most.
    group.bench_function("string_match/miss", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(string_match_dispatch(black_box("nope"), black_box(json!(1))).is_none())
        });
    });
    group.bench_function("closure_registry/miss", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                closure_dispatch(&table, &ctx, black_box("nope"), black_box(json!(1))).is_none(),
            )
        });
    });

    group.finish();
}

/// The bar: the cheapest *real* method, end to end through today's hub.
fn bench_reference_bar(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let hub = DynamicHub::new("bench_hub").register(Echo::new());

    let mut group = c.benchmark_group("reference_bar");
    group.bench_function("echo.once", |b| {
        b.to_async(&rt).iter(|| async {
            let stream = hub
                .route("echo.once", json!({"message": "x"}), None)
                .await
                .expect("echo.once routes");
            let items: Vec<_> = stream.collect().await;
            black_box(items.len())
        });
    });
    group.finish();
}

/// Reported for context, deliberately **outside** the gate: the whole turn
/// lifecycle against the whole legacy path.
fn bench_turn_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let ir = {
        let mut ir = ActivationIr::new("bench", "1.0.0");
        for name in NAMES {
            ir = ir.with_method(
                MethodIr::new(name, format!("bench.{name}")).with_auth(AuthRequirementIr::Public),
            );
        }
        ir
    };
    let table = closure_table();
    let hub = DynamicHub::new("bench_hub").register(Echo::new());

    let mut group = c.benchmark_group("turn_overhead");
    group.bench_function("entry/full_turn", |b| {
        b.to_async(&rt).iter(|| async {
            let turn = entry(
                &ir,
                &table,
                TurnRequest::new(black_box("chat")).with_params(json!(41)),
            )
            .expect("the turn opens");
            black_box(turn.collect().await.len())
        });
    });
    group.bench_function("route_with_ctx/echo.once", |b| {
        b.to_async(&rt).iter(|| async {
            let stream = hub
                .route("echo.once", json!({"message": "x"}), None)
                .await
                .unwrap();
            black_box(stream.collect::<Vec<_>>().await.len())
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_dispatch,
    bench_reference_bar,
    bench_turn_overhead
);

/// Hand-written rather than `criterion_main!` for exactly one reason: the
/// resolution banner must be emitted **before** the first measurement, so that
/// a copy-pasted run always carries the lock it was measured against. The rest
/// of the body is what `criterion_main!` expands to.
fn main() {
    resolution::emit("dispatch");
    benches();
    Criterion::default().configure_from_args().final_summary();
}

#[path = "common/resolution.rs"]
mod resolution;
