# plexus-core

The core of a Plexus RPC service: the service that activations register
with, the `Activation` trait, dispatch, schemas, the gate that decides each
call, the in-process transport, and children mounted from another process.

## Most people want plexus-rpc

[plexus-rpc](https://github.com/hypermemetic-ai/plexus-rpc) is the one
dependency a service takes. It brings this crate as `plexus_rpc::core`,
with the macros, the server and a prelude.

## Install

```toml
[dependencies]
plexus-core = "0.11"
plexus-macros = "0.11"
plexus-client = "0.11"
async-trait = "0.1"
futures = "0.3"
jsonrpsee = { version = "0.26", features = ["server", "macros"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt"] }
uuid = "1"
```

`#[activation]` writes code that names these crates, so each is in the
manifest.

## An activation, called in process

<!-- tests/readme_example.rs -->
```rust
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
```

`#[activation]` writes `EchoClient`. `HubTransport::anonymous` calls as
nobody, and `HubTransport::as_` calls as an `AuthContext`. A service with a
gate (`DynamicHub::with_gate`) decides each call by its caller's roles.

`cargo test` runs this file and holds this page to it.

## More

- [docs.rs](https://docs.rs/plexus-core): the API.
- [Changelog](CHANGELOG.md).
- [Activations](docs/activations.md): hosting one, nesting, the two this crate ships.
- [The service root](docs/service-root.md): a top level that changes while the service serves.
- [The gate](docs/gate.md): how each call is decided, and a role held on an address.
- [Keyed peers](docs/keyed-peers.md): the rules a child with a key and its service apply.

AGPL-3.0-only.
