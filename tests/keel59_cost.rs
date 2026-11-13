//! KEEL-59 · what holding a call to its admission costs.
//!
//! - **A call:** a one-item call routed and drained in process, held (a
//!   signed-in caller on a grant) against not held (the same method,
//!   `public`): allocations and time a call.
//! - **A move:** with N calls open and held, the grants generation moves;
//!   how long until every one has been decided again (each still holds), and
//!   — a revoke — until every one has ended.
//!
//! Measurements, not assertions of speed: `cargo test --release --test
//! keel59_cost -- --ignored --nocapture --test-threads=1`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use plexus_auth_core::grants::{Gate, GrantsMove, Membership, Memberships, RoleTable};
use plexus_auth_core::identity::Principal;
use plexus_core::DynamicHub;
use plexus_testkit::parts::{who, Everywhere, Members};
use plexus_testkit::Caller;
use serde_json::{json, Value};

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
}

#[global_allocator]
static A: Counting = Counting;

const ALICE: &str = "key:a11ce00000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
pub struct CostActivation;

#[plexus_macros::activation(namespace = "cost", crate_path = "plexus_core")]
impl CostActivation {
    /// One item.
    #[plexus_macros::method]
    pub async fn once(&self) -> impl futures::Stream<Item = Value> + Send + 'static {
        futures::stream::iter([json!(1)])
    }

    /// The same, open to anyone.
    #[plexus_macros::method(public)]
    pub async fn open_once(&self) -> impl futures::Stream<Item = Value> + Send + 'static {
        futures::stream::iter([json!(1)])
    }

    /// Open until let go, saying nothing after its first item.
    #[plexus_macros::method]
    pub async fn hold(&self) -> impl futures::Stream<Item = Value> + Send + 'static {
        futures::stream::iter([json!("open")]).chain(futures::stream::pending())
    }
}

/// The memberships, counting each time the gate asks.
struct Counted(Arc<Members>, Arc<AtomicU64>);

impl Memberships for Counted {
    fn held(&self, who: &Principal) -> Vec<Membership> {
        self.1.fetch_add(1, Ordering::Relaxed);
        self.0.held(who)
    }
}

/// A gated service: ALICE holds `reader` everywhere; every membership
/// lookup the gate makes is counted.
struct Rig {
    service: Arc<DynamicHub>,
    gate: Arc<Gate>,
    members: Arc<Members>,
    lookups: Arc<AtomicU64>,
}

fn rig() -> Rig {
    let members = Arc::new(Members::default());
    members.hold(ALICE, "reader");
    let lookups = Arc::new(AtomicU64::new(0));
    let roles = RoleTable::new().define("reader", ["cost.once", "cost.hold"]).unwrap();
    let gate = Arc::new(Gate::new(Arc::new(Counted(members.clone(), lookups.clone())), Arc::new(roles), Arc::new(Everywhere)));
    let service = Arc::new(DynamicHub::new("svc").register(CostActivation).with_gate(gate.clone()));
    Rig { service, gate, members, lookups }
}

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn a_call_held_costs() {
    let r = rig();
    let alice = Caller::new(r.service.clone(), Some(who(ALICE)));
    let n: u64 = std::env::var("KEEL59_N").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000);
    for (label, method) in [("held (cost.once, signed in)", "cost.once"), ("not held (cost.open_once, public)", "cost.open_once")] {
        for _ in 0..1000 {
            let s = alice.stream(method, json!({})).await.unwrap();
            let _: Vec<_> = s.collect().await;
        }
        let a0 = ALLOCS.load(Ordering::Relaxed);
        let t0 = Instant::now();
        for _ in 0..n {
            let s = alice.stream(method, json!({})).await.unwrap();
            let _: Vec<_> = s.collect().await;
        }
        let ns = t0.elapsed().as_nanos() as f64 / n as f64;
        let allocs = (ALLOCS.load(Ordering::Relaxed) - a0) as f64 / n as f64;
        println!("RESULT call {label}: {ns:.0} ns, {allocs:.2} allocations a call");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_move_costs() {
    for n in [1usize, 100, 10_000] {
        let r = rig();
        let alice = Caller::new(r.service.clone(), Some(who(ALICE)));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Instant>();
        let mut readers = Vec::with_capacity(n);
        for _ in 0..n {
            let mut s = alice.stream("cost.hold", json!({})).await.unwrap();
            assert!(s.next().await.is_some());
            let tx = tx.clone();
            readers.push(tokio::spawn(async move {
                while let Some(item) = s.next().await {
                    if matches!(item, plexus_core::plexus::PlexusStreamItem::Error { .. }) {
                        let _ = tx.send(Instant::now());
                    }
                }
            }));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A move that changes nothing for them: each is decided again, holds.
        let before = r.lookups.load(Ordering::Relaxed);
        let t0 = Instant::now();
        r.gate.moved(GrantsMove::RoleEdit);
        while r.lookups.load(Ordering::Relaxed) < before + n as u64 && t0.elapsed() < Duration::from_secs(30) {
            tokio::task::yield_now().await;
        }
        let asked = t0.elapsed();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let decided = r.lookups.load(Ordering::Relaxed) - before;
        // A revoke: every one ends.
        r.members.forget(ALICE);
        let t1 = Instant::now();
        r.gate.moved(GrantsMove::Revoke);
        let mut last = t1;
        for _ in 0..n {
            last = tokio::time::timeout(Duration::from_secs(30), rx.recv()).await.expect("ended").unwrap();
        }
        println!(
            "RESULT move with {n} open: every one decided again in {:.2} ms ({decided} membership lookups); every one ended by a revoke in {:.2} ms",
            asked.as_secs_f64() * 1e3,
            last.duration_since(t1).as_secs_f64() * 1e3
        );
        for h in readers {
            let _ = h.await;
        }
    }
}
