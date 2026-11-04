//! RETURNS-40's re-review: what `IrCache` keeps while answers are built —
//! the reviewer's `cache.rs`, each stated as what must hold.
//!
//! - an ask cancelled while it builds hands the build to the next waiter;
//! - 30,000 asks cancelled while building leave a bounded number of slots
//!   (none, once each is gone), and the next build is not held up by them;
//! - a slot being built is never evicted (so never built twice for want of
//!   room): an ask with no room builds without keeping;
//! - an answer bigger than the byte bound is not kept.

use std::sync::Arc;
use std::time::{Duration, Instant};

use plexus_core::plexus::ir::{IrCache, IrError, IrKey, ServiceIr};
use serde_json::value::RawValue;

fn key(n: usize) -> IrKey {
    IrKey { view: format!("h{n}"), roots: vec![vec![]], permitted: None }
}

fn ir(bytes: usize) -> ServiceIr {
    ServiceIr(Arc::from(RawValue::from_string(format!("\"{}\"", "x".repeat(bytes - 2))).unwrap()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_builder_hands_the_build_to_the_next_waiter() {
    let cache = Arc::new(IrCache::with_limits(128, 1 << 20));
    let c = cache.clone();
    let a = tokio::spawn(async move {
        c.get_or_build(key(0), || async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(ir(10))
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let c = cache.clone();
    let b = tokio::spawn(async move { c.get_or_build(key(0), || async { Ok::<_, IrError>(ir(20)) }).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    a.abort();
    let got = tokio::time::timeout(Duration::from_secs(5), b).await.expect("B is answered").unwrap().expect("an IR");
    assert_eq!(got.0.get().len(), 20, "B's own build");
    assert_eq!(cache.builds(), 2);
    assert_eq!((cache.len(), cache.bytes()), (1, 20), "B's answer kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_thousand_cancelled_asks_leave_nothing_behind() {
    let limit = 128;
    let cache = Arc::new(IrCache::with_limits(limit, 1 << 30));
    let n = 30_000;
    let mut asks = Vec::new();
    for i in 0..n {
        let c = cache.clone();
        asks.push(tokio::spawn(async move {
            c.get_or_build(key(i), || async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(ir(10))
            })
            .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(cache.len() <= limit, "{} slots while building, the bound {limit}", cache.len());
    for a in &asks {
        a.abort();
    }
    for a in asks {
        let _ = a.await;
    }
    assert_eq!(cache.len(), 0, "a slot whose every asker is gone is gone");
    let t = Instant::now();
    cache.get_or_build(key(n + 1), || async { Ok(ir(10)) }).await.unwrap();
    let took = t.elapsed();
    assert!(took < Duration::from_millis(10), "the next build took {took:?}");
    assert_eq!(cache.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slot_being_built_is_never_evicted() {
    let cache = Arc::new(IrCache::with_limits(1, 1 << 20));
    let slow = || async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(ir(10))
    };
    let c = cache.clone();
    let a = tokio::spawn(async move { c.get_or_build(key(1), slow).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    // no room beside key 1, which is building: key 2 is built, not kept
    cache.get_or_build(key(2), || async { Ok(ir(10)) }).await.unwrap();
    let c = cache.clone();
    let b = tokio::spawn(async move { c.get_or_build(key(1), slow).await });
    a.await.unwrap().unwrap();
    b.await.unwrap().unwrap();
    assert_eq!(cache.builds(), 2, "key 1 once, key 2 once");
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn an_answer_past_the_byte_bound_is_not_kept() {
    let cache = IrCache::with_limits(128, 100);
    cache.get_or_build(key(0), || async { Ok(ir(50)) }).await.unwrap();
    cache.get_or_build(key(1), || async { Ok(ir(500)) }).await.unwrap();
    assert_eq!((cache.len(), cache.bytes()), (1, 50), "the 500-byte answer is not kept, and costs the 50-byte one nothing");
    cache.get_or_build(key(1), || async { Ok(ir(500)) }).await.unwrap();
    assert_eq!(cache.builds(), 3);
}
