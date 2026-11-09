//! NEST-15 — the `plexus_hash` every item carries is the process's: set once
//! by the first service built into a module, and moved when that service's
//! root changes while it serves. Alone in its binary, so no other service
//! sets it first.

use std::sync::Arc;

use async_stream::stream;
use futures::stream::Stream;
use plexus_core::plexus::PlexusContext;
use plexus_core::DynamicHub;

#[derive(Clone)]
struct EchoActivation;

#[plexus_macros::activation(namespace = "echo", version = "1.0.0", description = "NEST-15 fixture")]
impl EchoActivation {
    /// Say it back.
    #[plexus_macros::method]
    async fn say(&self, text: String) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield text; }
    }
}

#[test]
fn the_items_hash_moves_with_the_service_that_set_it() {
    let hub = Arc::new(DynamicHub::new("ctx"));
    let _module = DynamicHub::arc_into_rpc_module(hub.clone()).unwrap();
    let set = PlexusContext::hash();
    assert_eq!(set, hub.compute_hash());
    // Another service's change leaves it alone…
    let other = DynamicHub::new("other").register(EchoActivation);
    other.root().remove("echo");
    assert_eq!(PlexusContext::hash(), set);
    // …this one's moves it, and back.
    hub.root().insert(EchoActivation).unwrap();
    assert_eq!(PlexusContext::hash(), hub.compute_hash());
    assert_ne!(PlexusContext::hash(), set);
    hub.root().remove("echo");
    assert_eq!(PlexusContext::hash(), set);
}
