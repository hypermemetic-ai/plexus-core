//! PLX-88 — where does a turn's ~7.5 µs go?
//!
//! `benches/dispatch.rs` (PLX-80, decision gate 2) settled the *representation*
//! of dispatch: +10.4 ns, 1.28% of the cheapest real method. It also reported,
//! outside the gate, that a full turn costs ~7.5 µs against ~847 ns for
//! `route_with_ctx/echo.once`. This bench answers the question that left open.
//!
//! # Five groups, five questions
//!
//! 1. **`ladder_{multi,current}/*`** — attribution. Each rung is a strict prefix of
//!    [`plexus_core::runtime::entry`]'s body (see
//!    `plexus_core::runtime::profile`), so the cost of a component is the delta
//!    between consecutive rungs. `ladder/full_turn` is the *real* `entry`
//!    driven to completion, which makes the ladder self-checking: the rungs
//!    must sum to it, and the residual is reported rather than hidden.
//! 2. **`concurrent_multi/*`** — the same call with 64 turns in flight, which
//!    is what decides whether the idle-runtime number means anything. See
//!    [`bench_concurrent`].
//! 3. **`updates_{multi,current}/*`** — fixed versus per-update cost. A large fixed cost and a
//!    large per-update cost have different fixes, so the slope across 0, 1, 4,
//!    16 and 64 updates is measured rather than assumed.
//! 4. **`in_process_{multi,current}/*`** — the case that could actually bite. A hub calling its
//!    own child activation without crossing a transport, new runtime versus
//!    legacy, through the same `DynamicHub::route`.
//! 5. **`micro/*`** — two individually-accused components isolated, because the
//!    ladder lumps them into one rung.
//!
//! # Keeping the harness out of the measured region
//!
//! - The Tokio runtime, the `ActivationIr`, the `HandlerTable` and the hub are
//!   all built **once, before** `bench_function`, never inside `iter`.
//! - Every rung is an `async fn` driven by the same `b.to_async(rt).iter(..)`
//!   shape, so criterion's per-iteration cost is a constant common term and
//!   **cancels in the deltas** — which is why the attribution is stated as
//!   deltas and the zero point (`ladder/s0_preflight`) is reported alongside.
//! - Inputs are `black_box`ed on the way in and results on the way out, so the
//!   optimiser cannot hoist a rung out of the loop.
//! - Everything is measured on **both** Tokio flavors. The first run of this
//!   bench showed one rung — `tokio::spawn` — swamping the rest on a
//!   multi-threaded runtime, and the single-threaded column is what separates
//!   "the turn does this work" from "the harness woke a sleeping thread".
//!
//! # One reading is known bad
//!
//! `ladder_current/s9_entry_construct` is **invalid** and reported only so it
//! is not mistaken for a result: it opens a turn and drops the handle without
//! driving it, so on a single-threaded runtime the spawned handler tasks are
//! never polled inside the iteration and pile up. The multi-thread column of
//! that row is the usable one.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::StreamExt;
use serde_json::json;
use tokio::runtime::Runtime;

use plexus_core::activations::echo::Echo;
use plexus_core::ir::{ActivationIr, AuthRequirementIr, MethodIr};
use plexus_core::plexus::DynamicHub;
use plexus_core::runtime::profile;
use plexus_core::runtime::{
    entry, ErasedHandler, HandlerInput, HandlerTable, IrActivation, TurnOutcome, TurnRequest,
};

/// The same 19-method fixture `benches/dispatch.rs` uses, so the two benches
/// are talking about the same activation.
const NAMES: [&str; 19] = [
    "list", "create", "resume", "chat", "prompt", "cancel", "status", "history", "fork", "diff",
    "apply", "revert", "search", "index", "watch", "tail", "config", "health", "close",
];

/// The method the ladder profiles — the median position, matching the
/// `turn_overhead/entry/full_turn` case that produced the 7.5 µs.
const PROBE: &str = "chat";

fn bench_ir() -> ActivationIr {
    let mut ir = ActivationIr::new("bench", "1.0.0");
    for name in NAMES {
        ir = ir.with_method(
            MethodIr::new(name, format!("bench.{name}")).with_auth(AuthRequirementIr::Public),
        );
    }
    ir
}

/// Handlers that do the same trivial body `benches/dispatch.rs` uses: one typed
/// decode, one addition. Nothing here is the subject of the measurement.
fn bench_table() -> HandlerTable {
    HandlerTable::new(NAMES.iter().map(|name| {
        (
            *name,
            ErasedHandler::new(|input: HandlerInput| async move {
                let n: u64 = serde_json::from_value(input.params).unwrap_or(0);
                Ok(TurnOutcome::value(json!(n + 1)))
            }),
        )
    }))
}

/// A table whose handler emits `k` updates before terminating, for the
/// fixed-versus-per-update slope.
fn emitting_table(k: u64) -> HandlerTable {
    HandlerTable::new(NAMES.iter().map(move |name| {
        (
            *name,
            ErasedHandler::new(move |input: HandlerInput| async move {
                for i in 0..k {
                    input.turn.emit(json!(i)).await.ok();
                }
                Ok(TurnOutcome::value(json!(k)))
            }),
        )
    }))
}

// ===========================================================================
// 1 — the attribution ladder
// ===========================================================================

/// The two Tokio flavors, because the first run of this bench showed the
/// `s7 - s6b` rung (`tokio::spawn` + `JoinHandle`) dominating everything else,
/// and a spawn's cost is not a property of the runtime code — it is a property
/// of whether the task lands on *another* worker thread and has to wake it.
///
/// `multi` is `Runtime::new()`, which is what `benches/dispatch.rs` used to
/// produce the 7.5 µs. `current` is a single-threaded runtime, where a spawn is
/// a local enqueue. Reporting only one of them would have made the attribution
/// a statement about the bench's harness rather than about the turn.
fn flavors() -> [(&'static str, Runtime); 2] {
    [
        ("multi", Runtime::new().unwrap()),
        (
            "current",
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        ),
    ]
}

fn bench_ladder(c: &mut Criterion) {
    for (flavor, rt) in flavors() {
        bench_ladder_on(c, flavor, &rt);
    }
}

fn bench_ladder_on(c: &mut Criterion, flavor: &str, rt: &Runtime) {
    let ir = bench_ir();
    let table = bench_table();

    let mut group = c.benchmark_group(format!("ladder_{flavor}"));

    macro_rules! rung {
        ($label:literal, $f:path) => {
            group.bench_function($label, |b| {
                b.to_async(rt).iter(|| async {
                    let req = TurnRequest::new(black_box(PROBE)).with_params(json!(41));
                    black_box($f(&ir, &table, &req).await)
                });
            });
        };
    }

    rung!("s0_preflight", profile::s0_preflight);
    rung!("s1_turn_id", profile::s1_turn_id);
    rung!("s2_cancel", profile::s2_cancel);
    rung!("s3_channel", profile::s3_channel);
    rung!("s4_router", profile::s4_router);
    rung!("s5_context", profile::s5_context);
    rung!("s6_handler_future", profile::s6_handler_future);
    rung!("s6b_inline_await", profile::s6b_inline_await);
    rung!("s7_spawn_await", profile::s7_spawn_await);
    rung!("s8_terminal", profile::s8_terminal);

    // The real `entry`, constructed and dropped without being driven: turn
    // construction including the generator and its `Box::pin`.
    group.bench_function("s9_entry_construct", |b| {
        b.to_async(rt).iter(|| async {
            let turn = entry(
                &ir,
                &table,
                TurnRequest::new(black_box(PROBE)).with_params(json!(41)),
            )
            .expect("the turn opens");
            black_box(turn.turn_id())
        });
    });

    // `tokio::spawn` of an empty task, isolated: the floor the `s7 - s6b` rung
    // cannot go below on this flavor. If this and `s7 - s6b` agree, the rung is
    // measuring the spawn and not the handler.
    group.bench_function("spawn_noop_join", |b| {
        b.to_async(rt)
            .iter(|| async { black_box(tokio::spawn(async {}).await.is_ok()) });
    });

    // The real `entry`, driven to completion. This is the 7.5 µs number, and
    // the sum the ladder has to reproduce.
    group.bench_function("full_turn", |b| {
        b.to_async(rt).iter(|| async {
            let turn = entry(
                &ir,
                &table,
                TurnRequest::new(black_box(PROBE)).with_params(json!(41)),
            )
            .expect("the turn opens");
            black_box(turn.collect().await.len())
        });
    });

    // The bar, re-measured in this bench so the two numbers come from the same
    // machine, the same build and the same session.
    let hub = DynamicHub::new("bench_hub").register(Echo::new());
    group.bench_function("legacy_echo_once", |b| {
        b.to_async(rt).iter(|| async {
            let stream = hub
                .route("echo.once", json!({"message": "x"}), None)
                .await
                .expect("echo.once routes");
            black_box(stream.collect::<Vec<_>>().await.len())
        });
    });

    group.finish();
}

// ===========================================================================
// 2 — fixed versus per-update
// ===========================================================================

fn bench_updates(c: &mut Criterion) {
    for (flavor, rt) in flavors() {
        bench_updates_on(c, flavor, &rt);
    }
}

fn bench_updates_on(c: &mut Criterion, flavor: &str, rt: &Runtime) {
    let ir = bench_ir();

    let mut group = c.benchmark_group(format!("updates_{flavor}"));
    for k in [0u64, 1, 4, 16, 64] {
        let table = emitting_table(k);
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
            b.to_async(rt).iter(|| async {
                let turn = entry(
                    &ir,
                    &table,
                    TurnRequest::new(black_box(PROBE)).with_params(json!(0)),
                )
                .expect("the turn opens");
                black_box(turn.collect().await.len())
            });
        });
    }
    group.finish();
}

// ===========================================================================
// 3 — the in-process hub-to-child call
// ===========================================================================

/// A hub calling its own child activation with no transport in between — what
/// substrate and hyperforge do today and what M2 is about to do at volume.
///
/// Both arms go through the *same* `DynamicHub::route`, so the delta is the
/// activation implementation and nothing else:
///
/// - `legacy/echo.once` — `Echo`, the cheapest real method in the tree.
/// - `turn/ir_child.work` — an [`IrActivation`] on the new runtime, whose
///   handler does the same trivial amount of work.
///
/// `turn/open_turn_direct` is the same activation without the hub and without
/// the legacy `PlexusStream` projection, which separates the runtime's cost
/// from the bridge's.
fn bench_in_process(c: &mut Criterion) {
    for (flavor, rt) in flavors() {
        bench_in_process_on(c, flavor, &rt);
    }
}

fn bench_in_process_on(c: &mut Criterion, flavor: &str, rt: &Runtime) {
    let child_ir = ActivationIr::new("ir_child", "1.0.0").with_method(
        MethodIr::new("work", "ir_child.work").with_auth(AuthRequirementIr::Public),
    );
    let child_handlers = HandlerTable::new([(
        "work",
        ErasedHandler::new(|input: HandlerInput| async move {
            let n: u64 = serde_json::from_value(input.params).unwrap_or(0);
            Ok(TurnOutcome::value(json!(n + 1)))
        }),
    )]);
    let child = IrActivation::new(child_ir, child_handlers);

    let legacy_hub = DynamicHub::new("hub").register(Echo::new());
    let turn_hub = DynamicHub::new("hub").register(child.clone());

    let mut group = c.benchmark_group(format!("in_process_{flavor}"));

    group.bench_function("legacy/hub_to_echo.once", |b| {
        b.to_async(rt).iter(|| async {
            let stream = legacy_hub
                .route("echo.once", json!({"message": "x"}), None)
                .await
                .expect("echo.once routes");
            black_box(stream.collect::<Vec<_>>().await.len())
        });
    });

    group.bench_function("turn/hub_to_ir_child.work", |b| {
        b.to_async(rt).iter(|| async {
            let stream = turn_hub
                .route("ir_child.work", json!(41), None)
                .await
                .expect("ir_child.work routes");
            black_box(stream.collect::<Vec<_>>().await.len())
        });
    });

    group.bench_function("turn/open_turn_direct", |b| {
        b.to_async(rt).iter(|| async {
            let turn = child
                .open_turn(TurnRequest::new(black_box("work")).with_params(json!(41)))
                .expect("the turn opens");
            black_box(turn.collect().await.len())
        });
    });

    group.finish();
}

// ===========================================================================
// 4 — the components the ladder lumps together
// ===========================================================================

fn bench_micro(c: &mut Criterion) {
    let ir = bench_ir();
    let method = ir.method(PROBE).expect("the probe method exists");

    let mut group = c.benchmark_group("micro");

    // `s5 - s4` carries this plus a namespace clone and two `Arc`s; a
    // `MethodIr` is four `String`s and four `Vec`s, so it is worth isolating.
    group.bench_function("method_ir_clone", |b| {
        b.iter(|| black_box(black_box(method).clone()));
    });

    // `s1 - s0`: uuid v4 draws from the OS CSPRNG.
    group.bench_function("turn_id_new", |b| {
        b.iter(|| black_box(plexus_core::runtime::TurnId::new()));
    });

    group.finish();
}

// ===========================================================================
// 5 — the same call under concurrency
// ===========================================================================

/// The measurement that decides whether the multi-thread number means anything.
///
/// `ladder_multi/spawn_noop_join` costs ~8 µs while `ladder_current` costs
/// ~0.9 µs for the same spawn. That gap is not work — it is a **park/unpark
/// round trip**: on an idle multi-threaded runtime the caller blocks on a
/// `JoinHandle` while the task is handed to a sleeping worker that must be
/// woken, and the bench measures thread-wake latency rather than the turn.
///
/// A server does not run one turn at a time on an idle runtime. This group
/// keeps `BATCH` turns in flight so the workers stay hot, and reports the cost
/// of the whole batch; per-turn is that divided by `BATCH`. If the per-turn
/// figure collapses toward the single-threaded ladder, the 7.5 µs was an
/// artifact of an idle harness and the in-process verdict changes accordingly.
fn bench_concurrent(c: &mut Criterion) {
    const BATCH: usize = 64;
    let rt = Runtime::new().unwrap();
    let ir = bench_ir();
    let table = bench_table();
    let hub = DynamicHub::new("hub").register(Echo::new());

    let mut group = c.benchmark_group("concurrent_multi");
    group.throughput(criterion::Throughput::Elements(BATCH as u64));

    group.bench_function("turn/batch64", |b| {
        b.to_async(&rt).iter(|| async {
            let futs = (0..BATCH).map(|_| {
                let turn = entry(
                    &ir,
                    &table,
                    TurnRequest::new(black_box(PROBE)).with_params(json!(41)),
                )
                .expect("the turn opens");
                turn.collect()
            });
            black_box(futures::future::join_all(futs).await.len())
        });
    });

    group.bench_function("legacy/batch64", |b| {
        b.to_async(&rt).iter(|| async {
            let mut futs = Vec::with_capacity(BATCH);
            for _ in 0..BATCH {
                let stream = hub
                    .route("echo.once", json!({"message": "x"}), None)
                    .await
                    .expect("echo.once routes");
                futs.push(stream.collect::<Vec<_>>());
            }
            black_box(futures::future::join_all(futs).await.len())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ladder,
    bench_concurrent,
    bench_updates,
    bench_in_process,
    bench_micro
);
criterion_main!(benches);
