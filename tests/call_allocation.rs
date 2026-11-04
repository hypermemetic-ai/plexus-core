//! BIDIR-6/17: a call to a method with no `Input` costs what it did before
//! the input half. A `{ns}.call`'s future is boxed once, its largest
//! allocation; the seam a method with an `Input` needs (the unaccepted
//! subscription, the params, room for an opened duplex) is in its own future
//! only, never in a plain call's. call.one_item read +1,192 bytes a call when
//! one future held both.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use futures::{Stream, StreamExt};
use plexus_core::plexus::{DynamicHub, Input};

struct Largest;

thread_local! {
    static RECORDING: Cell<bool> = const { Cell::new(false) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let _ = RECORDING.try_with(|r| {
            if r.get() {
                let _ = LARGEST.try_with(|m| m.set(m.get().max(l.size())));
            }
        });
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
}

#[global_allocator]
static A: Largest = Largest;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TallyEvent {
    Count { n: u64 },
}

impl plexus_client::FromClientError for TallyEvent {
    fn from_client_error(_: plexus_client::ClientError) -> Self {
        TallyEvent::Count { n: 0 }
    }
}

#[derive(Clone)]
pub struct TallyActivation;

#[plexus_macros::activation(namespace = "tally", crate_path = "plexus_core")]
impl TallyActivation {
    /// One item, no input
    #[plexus_macros::method]
    pub async fn once(&self, n: u64) -> impl Stream<Item = TallyEvent> + Send + 'static {
        futures::stream::once(async move { TallyEvent::Count { n } })
    }

    /// Count what comes in
    #[plexus_macros::method]
    pub async fn count(&self, items: Input<u64>) -> impl Stream<Item = TallyEvent> + Send + 'static {
        futures::stream::once(async move { TallyEvent::Count { n: items.into_stream().count().await as u64 } })
    }
}

/// The largest allocation one call made, on this thread.
async fn largest(m: &jsonrpsee::RpcModule<()>, method: &str) -> usize {
    let req = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"svc.call","params":{{"method":"{method}","params":{{"n":1}}}}}}"#);
    RECORDING.with(|r| r.set(true));
    LARGEST.with(|m| m.set(0));
    let (_, mut rx) = m.raw_json_request(&req, 1024).await.unwrap();
    // `count` is refused here (no socket, no input half): one error item.
    while let Some(item) = rx.recv().await {
        let t = item.get();
        if t.contains(r#""type":"done""#) || t.contains(r#""type":"error""#) {
            break;
        }
    }
    RECORDING.with(|r| r.set(false));
    LARGEST.with(Cell::get)
}

#[tokio::test(flavor = "current_thread")]
async fn a_call_with_no_input_carries_no_seam() {
    let m = DynamicHub::new("svc").register(TallyActivation).into_rpc_module().unwrap();
    // Warm: the service's indexes are built on the first call.
    let _ = (largest(&m, "tally.once").await, largest(&m, "tally.count").await);
    let (plain, seamed) = (largest(&m, "tally.once").await, largest(&m, "tally.count").await);
    // The seam alone is hundreds of bytes (384 today).
    assert!(plain + 256 <= seamed, "a plain call's largest allocation {plain} B, a seamed one's {seamed} B");
}
