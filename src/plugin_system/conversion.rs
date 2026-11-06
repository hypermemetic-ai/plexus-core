use super::types::ActivationStreamItem;
use crate::plexus::{PlexusContext, Provenance, PlexusStreamItem};
use futures::{Stream, StreamExt};
use jsonrpsee::{PendingSubscriptionSink, core::SubscriptionError};
use tracing::{debug, trace, warn};

pub type SubscriptionResult = Result<(), SubscriptionError>;

/// Trait that enforces Stream<T> can be converted to SubscriptionResult
pub trait IntoSubscription: Send + 'static {
    type Item: ActivationStreamItem;

    /// Convert this stream into a jsonrpsee subscription
    ///
    /// The plexus hash is automatically retrieved from the global PlexusContext.
    async fn into_subscription(
        self,
        pending: PendingSubscriptionSink,
        provenance: Provenance,
    ) -> SubscriptionResult;
}

/// Blanket implementation for any Stream<Item = T> where T: ActivationStreamItem
impl<S, T> IntoSubscription for S
where
    S: Stream<Item = T> + Send + Unpin + 'static,
    T: ActivationStreamItem,
{
    type Item = T;

    async fn into_subscription(
        self,
        pending: PendingSubscriptionSink,
        provenance: Provenance,
    ) -> SubscriptionResult {
        debug!(
            provenance = ?provenance,
            content_type = T::content_type(),
            "SUBSCRIPTION: Accepting"
        );
        let sink = pending.accept().await?;
        let plexus_hash = PlexusContext::hash();

        crate::rt::spawn(async move {
            let mut stream = Box::pin(self);
            let mut item_count = 0u64;
            debug!(provenance = ?provenance, "SUBSCRIPTION: Stream processing started");

            while let Some(item) = stream.next().await {
                item_count += 1;
                let is_terminal = item.is_terminal();
                debug!(
                    provenance = ?provenance,
                    item_count,
                    is_terminal,
                    "SUBSCRIPTION: Stream item received"
                );

                let body_item = item.into_plexus_item(provenance.clone(), &plexus_hash);

                // Send as raw JSON value
                if let Ok(raw_value) = serde_json::value::to_raw_value(&body_item) {
                    if sink.send(raw_value).await.is_err() {
                        warn!(provenance = ?provenance, item_count, "Client disconnected");
                        break; // Client disconnected
                    }
                } else {
                    warn!(provenance = ?provenance, item_count, "Serialization error");
                    break; // Serialization error
                }
            }

            debug!(provenance = ?provenance, item_count, "SUBSCRIPTION: Stream ended, sending Done");
            // Send Done event when stream completes
            let done = PlexusStreamItem::done(plexus_hash, provenance);
            if let Ok(raw_value) = serde_json::value::to_raw_value(&done) {
                let _ = sink.send(raw_value).await;
            }
        });

        Ok(())
    }
}
