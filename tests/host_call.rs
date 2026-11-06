//! V2-57: a host that answers `{ns}.call` itself — its own checks first, as
//! menger's call layer holds limits — hands the call to
//! [`DynamicHub::serve_call`], and a method with an `Input` streams its input
//! half exactly as under the service's own `{ns}.call`. Before it, a host's
//! handler could reach only `route`, which runs outside the call's seam, and
//! every `Input` method answered "this transport carries none".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::{Stream, StreamExt};
use plexus_core::plexus::{DynamicHub, Input};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SumEvent {
    Sum { total: u64, items: u64 },
    Error { message: String },
}

impl plexus_client::FromClientError for SumEvent {
    fn from_client_error(e: plexus_client::ClientError) -> Self {
        SumEvent::Error { message: e.to_string() }
    }
}

#[derive(Clone)]
pub struct SumActivation;

#[plexus_macros::activation(namespace = "sum", crate_path = "plexus_core")]
impl SumActivation {
    /// Add up what comes in
    #[plexus_macros::method]
    pub async fn add(&self, items: Input<u64>) -> impl Stream<Item = SumEvent> + Send + 'static {
        async_stream::stream! {
            let mut items = items;
            let (mut total, mut n) = (0, 0);
            while let Some(item) = items.next().await {
                total += item;
                n += 1;
            }
            yield SumEvent::Sum { total, items: n };
        }
    }

    /// One item, no input
    #[plexus_macros::method]
    pub async fn echo(&self, n: u64) -> impl Stream<Item = SumEvent> + Send + 'static {
        futures::stream::once(async move { SumEvent::Sum { total: n, items: 0 } })
    }
}

/// The service's module with `host.call` replaced by the host's own: it
/// counts each call (its check), then hands it to `serve_call`.
async fn served(seen: Arc<AtomicUsize>) -> String {
    let service = Arc::new(DynamicHub::new("host").register(SumActivation));
    let mut module = DynamicHub::arc_into_rpc_module(service.clone()).unwrap();
    module.remove_method("host.call");
    module.remove_method("host.call_unsub");
    module
        .register_subscription("host.call", "host.call", "host.call_unsub", move |params, pending, _ctx, ext| {
            let (service, seen) = (service.clone(), seen.clone());
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                service.serve_call(params, pending, ext, "host").await
            }
        })
        .unwrap();
    let (_handle, addr) = plexus_transport::websocket::serve_websocket_with(module, plexus_transport::WebSocketConfig::new(0), None, Default::default())
        .await
        .unwrap();
    std::mem::forget(_handle);
    format!("ws://{addr}")
}

#[tokio::test]
async fn a_hosts_own_call_carries_the_input_half() {
    let seen = Arc::new(AtomicUsize::new(0));
    let url = served(seen.clone()).await;
    let ws = plexus_client::WsTransport::connect(&url, "host").await.unwrap();
    let client = SumClient::new(&ws);
    let items: Vec<u64> = (1..=100).collect();
    let out: Vec<SumEvent> = client.add(futures::stream::iter(items)).map(|r| r.unwrap()).collect().await;
    assert!(matches!(out.as_slice(), [SumEvent::Sum { total: 5050, items: 100 }]), "{out:?}");
    assert_eq!(seen.load(Ordering::SeqCst), 1, "the host's own handler ran");
}

#[tokio::test]
async fn a_hosts_own_call_serves_a_plain_method_as_before() {
    let seen = Arc::new(AtomicUsize::new(0));
    let url = served(seen.clone()).await;
    let ws = plexus_client::WsTransport::connect(&url, "host").await.unwrap();
    let out: Vec<SumEvent> = SumClient::new(&ws).echo(7).map(|r| r.unwrap()).collect().await;
    assert!(matches!(out.as_slice(), [SumEvent::Sum { total: 7, items: 0 }]), "{out:?}");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}
