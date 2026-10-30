//! PERF-5 (3) and (5): in process, no socket — dispatch through the
//! service (plain and gated), the gate check alone, an item's wrapping and
//! its frame built step by step, `Box<dyn Stream>` and a boxed future per
//! item / per call, and tokio's spawn + join on each runtime. JSON lines.

use std::hint::black_box;
use std::sync::Arc;

use futures::{Stream, StreamExt};
use perf5::echo;
use perf5::micro::{bench, emit, Micro};
use plexus_core::plexus::{Grant, PlexusStreamItem, StreamMetadata};
use serde::Serialize;
use serde_json::{json, value::RawValue};

fn e(m: Micro, group: &str) {
    emit(&m, json!({"group": group}));
}

#[derive(Serialize)]
struct Notif<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: Params<'a>,
}
#[derive(Serialize)]
struct Params<'a> {
    subscription: u64,
    result: &'a RawValue,
}

fn main() {
    let only = std::env::args().nth(1).filter(|a| !a.starts_with('-')).unwrap_or_default();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let plain = Arc::new(echo::plain_service());
    let gated = Arc::new(echo::gated_service());
    plexus_core::plexus::PlexusContext::init(plain.compute_hash());
    let auth = echo::bench_auth();
    let empty = json!({});

    if only.is_empty() || only == "dispatch" {
        let base = bench("block_on(empty)", || rt.block_on(async {}));
        e(base.clone(), "dispatch");
        let drain = |hub: &Arc<plexus_core::DynamicHub>, m: &str, p: &serde_json::Value, a: Option<&plexus_core::plexus::AuthContext>| {
            rt.block_on(async {
                let mut s = hub.route(m, p.clone(), a).await.unwrap();
                let mut n = 0;
                while let Some(i) = s.next().await {
                    black_box(&i);
                    n += 1;
                }
                n
            })
        };
        e(bench("dispatch.echo_once (plain service, route → drain)", || { black_box(drain(&plain, "bench.once", &empty, None)); }), "dispatch");
        e(bench("dispatch.echo_once (gated service, signed in)", || { black_box(drain(&gated, "bench.once", &empty, Some(&auth))); }), "dispatch");
        let p1000 = json!({"to": 1000, "size": 64});
        let m = bench("stream.1000 in process (plain), per call", || { black_box(drain(&plain, "bench.count", &p1000, None)); });
        e(m, "dispatch");
        let gate = gated.gate().unwrap().clone();
        let grant = Grant::of("bench", "once");
        e(bench("gate.check (Gate::check, repeated)", || { black_box(gate.check(Some(black_box(&auth)), &grant, None).is_ok()); }), "gate");
    }

    if only.is_empty() || only == "frame" {
        // one item of bench.count (64 B), step by step as plexus-core and jsonrpsee build its frame
        let ev = echo::BenchEvent::Item { n: 4242, pad: serde_json::from_value(json!("x".repeat(64))).unwrap() };
        let meta = StreamMetadata { provenance: vec!["bench".into()], plexus_hash: "190a802f261e2c6f".into(), timestamp: 1_793_259_270 };
        e(bench("1 · metadata.clone() + content_type.to_string()", || { black_box((meta.clone(), "bench.count".to_string())); }), "frame");
        e(bench("2 · event → Value (serialize_with_credential_capture's to_value)", || { black_box(serde_json::to_value(black_box(&ev)).unwrap()); }), "frame");
        let item = PlexusStreamItem::Data { metadata: meta.clone(), content_type: "bench.count".into(), content: serde_json::to_value(&ev).unwrap() };
        e(bench("3 · item → RawValue (to_raw_value, the second encode)", || { black_box(serde_json::value::to_raw_value(black_box(&item)).unwrap()); }), "frame");
        let raw = serde_json::value::to_raw_value(&item).unwrap();
        e(bench("4 · envelope: notification → String (jsonrpsee, copies the RawValue)", || {
            black_box(serde_json::to_string(&Notif { jsonrpc: "2.0", method: "perf5.call", params: Params { subscription: 2_174_681_772_066_080, result: black_box(&raw) } }).unwrap());
        }), "frame");
        let text = serde_json::to_string(&Notif { jsonrpc: "2.0", method: "perf5.call", params: Params { subscription: 2_174_681_772_066_080, result: &raw } }).unwrap();
        e(bench("5 · ws frame: header + copy into the write buffer", || {
            let mut b = Vec::with_capacity(text.len() + 10);
            b.extend_from_slice(&perf5::rawws::server_text_frame(&[])[..0]);
            b.push(0x81);
            b.push(126);
            b.extend_from_slice(&(text.len() as u16).to_be_bytes());
            b.extend_from_slice(black_box(text.as_bytes()));
            black_box(b);
        }), "frame");
        e(bench("all five, as today", || {
            let m = meta.clone();
            let ct = "bench.count".to_string();
            let c = serde_json::to_value(black_box(&ev)).unwrap();
            let it = PlexusStreamItem::Data { metadata: m, content_type: ct, content: c };
            let r = serde_json::value::to_raw_value(&it).unwrap();
            let t = serde_json::to_string(&Notif { jsonrpc: "2.0", method: "perf5.call", params: Params { subscription: 2_174_681_772_066_080, result: &r } }).unwrap();
            let mut b = Vec::with_capacity(t.len() + 4);
            b.extend_from_slice(&[0x81, 126]);
            b.extend_from_slice(&(t.len() as u16).to_be_bytes());
            b.extend_from_slice(t.as_bytes());
            black_box(b);
        }), "frame");
        // the floor: the typed item written once, straight into the frame buffer (PERF-7's shape)
        #[derive(Serialize)]
        struct Typed<'a, T> { #[serde(rename = "type")] t: &'a str, metadata: &'a StreamMetadata, content_type: &'a str, content: &'a T }
        #[derive(Serialize)]
        struct Notif2<'a, T> { jsonrpc: &'a str, method: &'a str, params: Params2<'a, T> }
        #[derive(Serialize)]
        struct Params2<'a, T> { subscription: u64, result: Typed<'a, T> }
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        e(bench("one encode into a reused frame buffer (the floor PERF-7 aims at)", || {
            buf.clear();
            buf.extend_from_slice(&[0x81, 126, 0, 0]);
            serde_json::to_writer(&mut buf, &Notif2 { jsonrpc: "2.0", method: "perf5.call", params: Params2 { subscription: 2_174_681_772_066_080, result: Typed { t: "data", metadata: &meta, content_type: "bench.count", content: black_box(&ev) } } }).unwrap();
            let n = (buf.len() - 4) as u16;
            buf[2..4].copy_from_slice(&n.to_be_bytes());
            black_box(&buf);
        }), "frame");
    }

    if only.is_empty() || only == "boxing" {
        fn generic<S: Stream<Item = u64> + Unpin>(s: S) -> S { s }
        e(bench("1000 items, generic stream", || {
            let s = generic(futures::stream::iter(0..1000u64).map(|x| x + 1));
            black_box(futures::executor::block_on(s.fold(0u64, |a, b| async move { a + b })));
        }), "boxing");
        e(bench("1000 items, Pin<Box<dyn Stream>> (×2: the method's and wrap_stream's)", || {
            let s: std::pin::Pin<Box<dyn Stream<Item = u64> + Send>> = Box::pin(futures::stream::iter(0..1000u64).map(|x| x + 1));
            let s: std::pin::Pin<Box<dyn Stream<Item = u64> + Send>> = Box::pin(s.map(|x| x));
            black_box(futures::executor::block_on(s.fold(0u64, |a, b| async move { a + b })));
        }), "boxing");
        e(bench("a boxed future per call (async_trait)", || {
            let f: std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send>> = Box::pin(async { black_box(1u64) });
            black_box(futures::executor::block_on(f));
        }), "boxing");
        e(bench("an unboxed future per call", || {
            black_box(futures::executor::block_on(async { black_box(1u64) }));
        }), "boxing");
    }

    if only.is_empty() || only == "tokio" {
        for (name, rt) in [
            ("current-thread", tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()),
            ("multi-thread ×4", tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap()),
        ] {
            let rt = Arc::new(rt);
            let r2 = rt.clone();
            e(bench(&format!("tokio::spawn + join ({name}), 1,000 in a row ÷ — per op ×1000"), move || {
                r2.block_on(async {
                    for _ in 0..1000 {
                        tokio::spawn(async { black_box(1) }).await.unwrap();
                    }
                })
            }), "tokio");
            let r3 = rt.clone();
            e(bench(&format!("mpsc hand-off task → task, 1,000 items ({name})"), move || {
                r3.block_on(async {
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(64);
                    let h = tokio::spawn(async move { let mut s = 0; while let Some(x) = rx.recv().await { s += x; } s });
                    for i in 0..1000 { tx.send(i).await.unwrap(); }
                    drop(tx);
                    black_box(h.await.unwrap());
                })
            }), "tokio");
        }
    }
}
