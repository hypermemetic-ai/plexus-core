//! PLX-88 — allocations per turn, counted rather than guessed.
//!
//! Wall time says *how long*; allocation count says *why*, and it is the more
//! actionable of the two. This binary installs `dhat`'s allocator as the global
//! allocator and reports, for each phase, the delta in dhat's cumulative
//! `total_blocks` / `total_bytes` counters divided by the iteration count.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --features profiling --example turn_alloc
//! ```
//!
//! # Keeping the harness out of the measured region
//!
//! - The Tokio runtime, the IR, the handler tables and the hubs are built
//!   **before** the first snapshot and live for the whole run.
//! - Every phase is preceded by a warm-up of the same closure, so one-time
//!   allocations (worker-thread stacks, lazy statics, the first `Notify`) are
//!   already paid when the snapshot is taken.
//! - Each phase is reported at two different iteration counts. If the
//!   per-iteration figures agree, per-phase constant overhead is negligible;
//!   if they diverge, the profile says so instead of averaging it away.
//! - The ladder phases are the same `runtime::profile` rungs the criterion
//!   bench uses, so the allocation attribution and the time attribution are
//!   decompositions of the *same* prefixes.

use serde_json::json;
use tokio::runtime::Runtime;

use plexus_core::activations::echo::Echo;
use plexus_core::ir::{ActivationIr, AuthRequirementIr, MethodIr};
use plexus_core::plexus::DynamicHub;
use plexus_core::runtime::profile;
use plexus_core::runtime::{
    entry, ErasedHandler, HandlerInput, HandlerTable, IrActivation, TurnOutcome, TurnRequest,
};

use futures::StreamExt;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const NAMES: [&str; 19] = [
    "list", "create", "resume", "chat", "prompt", "cancel", "status", "history", "fork", "diff",
    "apply", "revert", "search", "index", "watch", "tail", "config", "health", "close",
];
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

/// Run `f` `iters` times inside `rt` and report the allocation delta per
/// iteration. Warms up first so one-time costs land outside the snapshot.
fn measure<F, Fut>(rt: &Runtime, label: &str, iters: [u64; 2], mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // Warm-up: same code path, outside every snapshot.
    rt.block_on(async {
        for _ in 0..64 {
            f().await;
        }
    });

    let mut results = [(0.0f64, 0.0f64); 2];
    for (slot, n) in iters.iter().enumerate() {
        let before = dhat::HeapStats::get();
        rt.block_on(async {
            for _ in 0..*n {
                f().await;
            }
        });
        let after = dhat::HeapStats::get();
        let blocks = (after.total_blocks - before.total_blocks) as f64 / *n as f64;
        let bytes = (after.total_bytes - before.total_bytes) as f64 / *n as f64;
        results[slot] = (blocks, bytes);
    }

    let agreement = if (results[0].0 - results[1].0).abs() < 0.5 {
        "stable"
    } else {
        "DIVERGENT"
    };
    println!(
        "{label:<34} {:>8.2} blocks {:>10.1} bytes   (n={}: {:.2}/{:.1}; n={}: {:.2}/{:.1}) {agreement}",
        results[1].0, results[1].1, iters[0], results[0].0, results[0].1, iters[1], results[1].0, results[1].1,
    );
}

fn main() {
    let _profiler = dhat::Profiler::builder().testing().build();
    let rt = Runtime::new().unwrap();

    let ir = bench_ir();
    let tables: Vec<(u64, HandlerTable)> =
        [0u64, 1, 4, 16, 64].iter().map(|k| (*k, emitting_table(*k))).collect();
    let table0 = &tables[0].1;

    let child_ir = ActivationIr::new("ir_child", "1.0.0").with_method(
        MethodIr::new("work", "ir_child.work").with_auth(AuthRequirementIr::Public),
    );
    let child = IrActivation::new(
        child_ir,
        HandlerTable::new([(
            "work",
            ErasedHandler::new(|input: HandlerInput| async move {
                let n: u64 = serde_json::from_value(input.params).unwrap_or(0);
                Ok(TurnOutcome::value(json!(n + 1)))
            }),
        )]),
    );
    let legacy_hub = DynamicHub::new("hub").register(Echo::new());
    let turn_hub = DynamicHub::new("hub").register(child.clone());

    const N: [u64; 2] = [200, 2000];

    println!("\n== PLX-88 allocations per turn (dhat, release) ==\n");

    // The channel's 5.4 KB is `TURN_EVENT_BUFFER` slots of this, so the type's
    // size is part of the finding rather than trivia.
    println!(
        "-- sizes: TurnEvent={}B  StopReason={}B  serde_json::Value={}B  MethodIr={}B  channel(32)={}B --",
        std::mem::size_of::<plexus_core::runtime::TurnEvent>(),
        std::mem::size_of::<plexus_core::ir::StopReason>(),
        std::mem::size_of::<serde_json::Value>(),
        std::mem::size_of::<MethodIr>(),
        32 * std::mem::size_of::<plexus_core::runtime::TurnEvent>(),
    );

    println!("-- the ladder: allocation attribution by prefix of `entry` --");
    macro_rules! rung {
        ($label:literal, $f:path) => {
            measure(&rt, $label, N, || async {
                let req = TurnRequest::new(PROBE).with_params(json!(41));
                std::hint::black_box($f(&ir, table0, &req).await);
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

    measure(&rt, "s9_entry_construct", N, || async {
        let turn = entry(&ir, table0, TurnRequest::new(PROBE).with_params(json!(41))).unwrap();
        std::hint::black_box(turn.turn_id());
    });

    println!("\n-- fixed vs per-update: a full turn with k updates --");
    for (k, table) in &tables {
        measure(&rt, &format!("full_turn/{k}_updates"), N, || async {
            let turn = entry(&ir, table, TurnRequest::new(PROBE).with_params(json!(0))).unwrap();
            std::hint::black_box(turn.collect().await.len());
        });
    }

    println!("\n-- in-process: a hub calling its own child --");
    measure(&rt, "legacy/hub_to_echo.once", N, || async {
        let stream = legacy_hub
            .route("echo.once", json!({"message": "x"}), None)
            .await
            .unwrap();
        std::hint::black_box(stream.collect::<Vec<_>>().await.len());
    });
    measure(&rt, "turn/hub_to_ir_child.work", N, || async {
        let stream = turn_hub.route("ir_child.work", json!(41), None).await.unwrap();
        std::hint::black_box(stream.collect::<Vec<_>>().await.len());
    });
    measure(&rt, "turn/open_turn_direct", N, || async {
        let turn = child
            .open_turn(TurnRequest::new("work").with_params(json!(41)))
            .unwrap();
        std::hint::black_box(turn.collect().await.len());
    });

    println!();
}
