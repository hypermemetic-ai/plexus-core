//! README.md's example: an activation registered on a service and called in
//! process, through the client `#[activation]` writes for it.

use futures::stream::{self, Stream, StreamExt, TryStreamExt};
use plexus_core::plexus::HubTransport;
use plexus_core::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CountEvent {
    Tick { n: u32 },
}

#[derive(Clone)]
pub struct EchoActivation;

/// Say things back.
#[plexus_macros::activation(version = "1.0.0")]
impl EchoActivation {
    /// Ticks from 1 up to `to`.
    #[plexus_macros::method]
    pub async fn count(&self, to: u32) -> impl Stream<Item = CountEvent> + Send + 'static {
        stream::iter(1..=to).map(|n| CountEvent::Tick { n })
    }
}

#[tokio::test]
async fn count_is_called_in_process() {
    let service = Arc::new(DynamicHub::new("myservice").register(EchoActivation));
    let client = EchoClient::new(HubTransport::anonymous(service));

    let ticks: Vec<CountEvent> = client.count(3).try_collect().await.unwrap();

    assert_eq!(ticks, [1, 2, 3].map(|n| CountEvent::Tick { n }));
}
