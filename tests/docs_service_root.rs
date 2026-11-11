//! docs/service-root.md's example: a top level that changes while the
//! service serves.

use futures::stream::{self, Stream};
use plexus_core::plexus::Peer;
use plexus_core::DynamicHub;
use std::sync::Arc;

#[derive(Clone)]
pub struct WeatherActivation;

/// The weather.
#[plexus_macros::activation(version = "1.0.0")]
impl WeatherActivation {
    /// Tomorrow's weather somewhere.
    #[plexus_macros::method]
    pub async fn forecast(&self, place: String) -> impl Stream<Item = String> + Send + 'static {
        stream::iter([format!("rain in {place}")])
    }
}

#[tokio::test]
async fn the_top_level_changes_while_the_service_serves() {
    let service = Arc::new(DynamicHub::new("myservice"));
    let root = service.root();
    let mut changes = root.watch();

    root.insert(WeatherActivation).unwrap();
    assert_eq!(root.names(), ["weather"]);
    assert!(root.peer("weather").await.is_ok());

    let sky = Arc::new(WeatherActivation) as Arc<dyn Peer>;
    assert_eq!(root.insert_peer("sky", sky, false), Ok(false));
    assert_eq!(root.names(), ["sky", "weather"]);

    assert!(root.remove("weather"));
    assert!(!root.contains("weather"));

    assert!(changes.has_changed().unwrap());
    assert_eq!(*changes.borrow_and_update(), root.hash());
}
