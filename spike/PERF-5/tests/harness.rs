//! PERF-5: the harness's own tests, written before the harness. A number the
//! harness reports is only as good as these: the open-loop client must not
//! coordinate with the server (a stall shows on every request queued behind
//! it), the histogram's percentiles must be right, the allocation counter
//! must count exactly, and the frame boundary must count every byte.

use std::time::{Duration, Instant};

use perf5::{alloc, hist::Lat, openloop::Schedule, rawws};

#[test]
fn the_allocation_counter_counts_this_threads_allocations_exactly() {
    alloc::enable(true);
    let before = alloc::thread_snapshot();
    let v: Vec<u8> = std::hint::black_box(Vec::with_capacity(100));
    let b = std::hint::black_box(Box::new([0u64; 4]));
    let after = alloc::thread_snapshot();
    drop((v, b));
    let freed = alloc::thread_snapshot();
    assert_eq!(after.allocs - before.allocs, 2, "two allocations");
    assert_eq!(after.bytes - before.bytes, 132, "100 + 32 bytes");
    assert_eq!(freed.frees - after.frees, 2, "two frees");
}

#[test]
fn a_realloc_is_counted_as_an_allocation_and_its_growth_as_bytes() {
    alloc::enable(true);
    let mut v: Vec<u8> = std::hint::black_box(Vec::with_capacity(16));
    let before = alloc::thread_snapshot();
    v.reserve_exact(64); // len 0, cap 16 → 64
    std::hint::black_box(&v);
    let after = alloc::thread_snapshot();
    assert_eq!(after.reallocs - before.reallocs, 1);
    assert_eq!(after.allocs - before.allocs, 1, "a realloc is an allocation event");
    assert_eq!(after.bytes - before.bytes, 48, "the growth, 16 → 64");
}

#[test]
fn the_histograms_percentiles_are_right() {
    let mut h = Lat::new();
    for us in 1..=1000u64 {
        h.record(Duration::from_micros(us));
    }
    let s = h.summary();
    assert_eq!(s.n, 1000);
    assert!((s.p50_us - 500.0).abs() <= 1.0, "{s:?}");
    assert!((s.p99_us - 990.0).abs() <= 1.0, "{s:?}");
    assert!((s.p999_us - 999.0).abs() <= 1.0, "{s:?}");
    assert!((s.max_us - 1000.0).abs() <= 1.0, "{s:?}");
}

#[test]
fn the_schedule_says_when_each_request_was_meant_to_go() {
    let t0 = Instant::now();
    let s = Schedule::new(t0, 2_000.0);
    assert_eq!(s.intended(0), t0);
    assert_eq!(s.intended(2_000), t0 + Duration::from_secs(1));
    assert_eq!(s.intended(1), t0 + Duration::from_micros(500));
}

#[test]
fn a_client_frame_is_counted_byte_for_byte_at_the_boundary() {
    let payload = br#"{"jsonrpc":"2.0","id":1,"method":"bench.call","params":{"method":"bench.once"}}"#;
    let f = rawws::client_text_frame(payload);
    // FIN|text, MASK|len (< 126), a 4-byte mask, the payload.
    assert_eq!(f.len(), 2 + 4 + payload.len());
    assert_eq!(f[0], 0x81);
    assert_eq!(f[1] & 0x80, 0x80);
    let big = vec![b'x'; 4096];
    let f = rawws::client_text_frame(&big);
    assert_eq!(f.len(), 2 + 2 + 4 + 4096, "126 → a 16-bit length");
    let mut r = rawws::FrameReader::default();
    let server = rawws::server_text_frame(&big);
    r.feed(&server[..100]);
    assert!(r.next_frame().is_none(), "a partial frame is not a frame");
    r.feed(&server[100..]);
    let (op, p) = r.next_frame().expect("a whole frame");
    assert_eq!((op, p.len()), (1, 4096));
    assert_eq!(r.bytes_in(), server.len() as u64);
}

#[test]
fn the_reader_classifies_a_plexus_item_by_its_own_type_not_its_contents() {
    let data = br#"{"jsonrpc":"2.0","method":"bench.call","params":{"subscription":7,"result":{"type":"data","metadata":{},"content_type":"x","content":{"type":"done"}}}}"#;
    let done = br#"{"jsonrpc":"2.0","method":"bench.call","params":{"subscription":"ab","result":{"type":"done","metadata":{}}}}"#;
    let answer = br#"{"jsonrpc":"2.0","id":10000000000000000042,"result":7}"#;
    assert_eq!(rawws::classify(data), rawws::Msg::Item { sub: b"7".to_vec(), kind: rawws::Kind::Data });
    assert_eq!(rawws::classify(done), rawws::Msg::Item { sub: b"\"ab\"".to_vec(), kind: rawws::Kind::Done });
    assert_eq!(rawws::classify(answer), rawws::Msg::Answer { id: 42, sub: b"7".to_vec() });
}

/// No coordinated omission: a server that stalls once for 50 ms, answering
/// in order, behind an open-loop client sending 2,000 calls a second. Every
/// call meant to go during the stall waits for it, so ~100 calls must show
/// ≥ 10 ms. A closed-loop client measuring from its actual send would show
/// one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stall_shows_on_every_call_queued_behind_it() {
    let addr = rawws::testing::stalling_server(Duration::from_millis(50), 200).await;
    let url = format!("ws://{addr}/");
    let run = rawws::open_loop_calls(&url, &[], "bench.call", r#"{"method":"bench.once"}"#, 1_000, 2_000.0, 0)
        .await
        .unwrap();
    let slow = run.latencies_us.iter().filter(|&&us| us >= 10_000.0).count();
    assert!(slow >= 80, "only {slow} calls ≥ 10 ms: the client coordinated with the server");
    assert_eq!(run.latencies_us.len(), 1_000);
}

#[test]
fn a_patched_call_frame_is_valid_json_with_its_id() {
    let mut f = rawws::CallFrame::new("perf5.call", r#"{"method":"bench.once","params":{}}"#);
    for id in [0u64, 7, 123_456_789] {
        let frame = f.with_id(id).to_vec();
        let mut r = rawws::FrameReader::default();
        r.feed(&frame);
        let (_, p) = r.next_frame().unwrap();
        let v: serde_json::Value = serde_json::from_slice(p).expect("valid JSON");
        assert_eq!(rawws::CallFrame::id_of(v["id"].as_u64().unwrap()), id);
    }
}
