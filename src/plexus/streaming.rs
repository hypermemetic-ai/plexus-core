//! Streaming helpers for the caller-wraps architecture
//!
//! These functions are used by the DynamicHub routing layer to wrap activation
//! responses with metadata. Activations return typed domain events, and
//! the caller uses these helpers to create PlexusStreamItems.

use futures::stream::{self, Stream, StreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::bidirectional::BidirChannel;
use super::context::PlexusContext;
use super::types::{PlexusStreamItem, StreamMetadata};

/// Type alias for boxed stream of PlexusStreamItem
pub type PlexusStream = Pin<Box<dyn Stream<Item = PlexusStreamItem> + Send>>;

/// Wrap a typed stream into PlexusStream with automatic Done event
///
/// This is the core helper for the caller-wraps architecture.
/// Activations return typed domain events (e.g., HealthEvent),
/// and the caller wraps them with metadata. A Done event is
/// automatically appended when the stream completes.
///
/// # Example
///
/// ```ignore
/// let stream = health.check();  // Returns Stream<Item = HealthEvent>
/// let wrapped = wrap_stream(stream, "health.status", vec!["health".into()]);
/// // Stream will emit: Data, Data, ..., Done
/// ```
pub fn wrap_stream<T: Serialize + Send + 'static>(
    stream: impl Stream<Item = T> + Send + 'static,
    content_type: &'static str,
    provenance: Vec<String>,
) -> PlexusStream {
    let plexus_hash = PlexusContext::hash();
    let metadata = StreamMetadata::new(provenance.clone(), plexus_hash.clone());
    let done_metadata = StreamMetadata::new(provenance, plexus_hash);

    let data_stream = stream.map(move |item| PlexusStreamItem::Data {
        metadata: metadata.clone(),
        content_type: content_type.to_string(),
        content: serde_json::to_value(item).expect("serialization failed"),
    });

    let done_stream = stream::once(async move { PlexusStreamItem::Done {
        metadata: done_metadata,
    }});

    Box::pin(data_stream.chain(done_stream))
}


/// Create a bidirectional channel and wrap a stream, merging Request items
///
/// This function:
/// 1. Creates a BidirChannel connected to an internal mpsc channel
/// 2. Wraps the user's typed stream into PlexusStreamItems
/// 3. Merges in any Request items emitted by the BidirChannel
/// 4. Returns both the channel (for the activation to use) and the merged stream
///
/// # Arguments
///
/// * `content_type` - Content type string for data items (e.g., "interactive.wizard")
/// * `provenance` - Provenance path for metadata
///
/// # Returns
///
/// Returns a tuple of:
/// * `Arc<BidirChannel<Req, Resp>>` - The bidirectional channel for the activation
/// * A closure that takes the user's stream and returns the merged PlexusStream
///
/// # Example
///
/// ```ignore
/// let (ctx, wrap_fn) = create_bidir_stream::<StandardRequest, StandardResponse>(
///     "interactive.wizard",
///     vec!["interactive".into()],
/// );
/// let user_stream = activation.wizard(&ctx).await;
/// let merged_stream = wrap_fn(user_stream);
/// ```
pub fn create_bidir_stream<Req, Resp>(
    _content_type: &'static str,
    provenance: Vec<String>,
) -> (
    Arc<BidirChannel<Req, Resp>>,
    impl FnOnce(Pin<Box<dyn Stream<Item = PlexusStreamItem> + Send>>) -> PlexusStream,
)
where
    Req: Serialize + DeserializeOwned + Send + Sync + 'static,
    Resp: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let plexus_hash = PlexusContext::hash();

    // Create channel for BidirChannel to send Request items
    let (bidir_tx, bidir_rx) = mpsc::channel::<PlexusStreamItem>(32);

    // Create the BidirChannel with:
    // - bidirectional_supported = true (we support it)
    // - use_global_registry = true (responses come via substrate.respond)
    let bidir_channel = Arc::new(BidirChannel::<Req, Resp>::new(
        bidir_tx,
        true,  // bidirectional_supported
        provenance.clone(),
        plexus_hash.clone(),
    ));

    // Create the wrapper closure
    let wrap_fn = move |user_stream: Pin<Box<dyn Stream<Item = PlexusStreamItem> + Send>>| -> PlexusStream {
        let bidir_stream = ReceiverStream::new(bidir_rx);

        // Use stream::select to interleave items from both streams
        // This allows Request items to appear in the stream alongside Data items
        let merged = stream::select(user_stream, bidir_stream);

        Box::pin(merged)
    };

    (bidir_channel, wrap_fn)
}

/// Wrap a typed stream with bidirectional support
///
/// Convenience wrapper that creates a BidirChannel and wraps the stream in one call.
/// The channel is returned for use by the activation.
///
/// # Type Parameters
///
/// * `T` - The type of items in the user's stream
/// * `Req` - Request type for bidirectional channel
/// * `Resp` - Response type for bidirectional channel
///
/// # Example
///
/// ```ignore
/// use plexus_core::plexus::{StandardRequest, StandardResponse, wrap_stream_with_bidir};
///
/// let (ctx, stream) = wrap_stream_with_bidir::<_, StandardRequest, StandardResponse>(
///     user_stream,
///     "interactive.wizard",
///     vec!["interactive".into()],
/// );
/// // ctx can now be used for bidirectional requests
/// // stream includes both data items and any Request items
/// ```
pub fn wrap_stream_with_bidir<T, Req, Resp>(
    stream: impl Stream<Item = T> + Send + 'static,
    content_type: &'static str,
    provenance: Vec<String>,
) -> (Arc<BidirChannel<Req, Resp>>, PlexusStream)
where
    T: Serialize + Send + 'static,
    Req: Serialize + DeserializeOwned + Send + Sync + 'static,
    Resp: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let (ctx, wrap_fn) = create_bidir_stream::<Req, Resp>(content_type, provenance.clone());

    // Wrap the user's typed stream into PlexusStreamItems
    let wrapped_user_stream = wrap_stream(stream, content_type, provenance);

    // Merge with bidir stream
    let merged = wrap_fn(wrapped_user_stream);

    (ctx, merged)
}

/// Create an error stream
///
/// Returns a single-item stream containing an error event.
pub fn error_stream(
    message: String,
    provenance: Vec<String>,
    recoverable: bool,
) -> PlexusStream {
    let metadata = StreamMetadata::new(provenance, PlexusContext::hash());

    Box::pin(stream::once(async move {
        PlexusStreamItem::Error {
            metadata,
            message,
            code: None,
            recoverable,
        }
    }))
}

/// Create an error stream with error code
///
/// Returns a single-item stream containing an error event with a code.
pub fn error_stream_with_code(
    message: String,
    code: String,
    provenance: Vec<String>,
    recoverable: bool,
) -> PlexusStream {
    let metadata = StreamMetadata::new(provenance, PlexusContext::hash());

    Box::pin(stream::once(async move {
        PlexusStreamItem::Error {
            metadata,
            message,
            code: Some(code),
            recoverable,
        }
    }))
}

/// Create a done stream
///
/// Returns a single-item stream containing a done event.
pub fn done_stream(provenance: Vec<String>) -> PlexusStream {
    let metadata = StreamMetadata::new(provenance, PlexusContext::hash());

    Box::pin(stream::once(async move {
        PlexusStreamItem::Done { metadata }
    }))
}

/// Create a progress stream
///
/// Returns a single-item stream containing a progress event.
pub fn progress_stream(
    message: String,
    percentage: Option<f32>,
    provenance: Vec<String>,
) -> PlexusStream {
    let metadata = StreamMetadata::new(provenance, PlexusContext::hash());

    Box::pin(stream::once(async move {
        PlexusStreamItem::Progress {
            metadata,
            message,
            percentage,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestEvent {
        value: i32,
    }

    #[tokio::test]
    async fn test_wrap_stream() {
        let events = vec![TestEvent { value: 1 }, TestEvent { value: 2 }];
        let input_stream = stream::iter(events);

        let wrapped = wrap_stream(input_stream, "test.event", vec!["test".into()]);
        let items: Vec<_> = wrapped.collect().await;

        // 2 data items + 1 done
        assert_eq!(items.len(), 3);

        // Check first item
        match &items[0] {
            PlexusStreamItem::Data {
                content_type,
                content,
                metadata,
            } => {
                assert_eq!(content_type, "test.event");
                assert_eq!(content["value"], 1);
                assert_eq!(metadata.provenance, vec!["test"]);
            }
            _ => panic!("Expected Data item"),
        }

        // Check done at end
        assert!(matches!(items[2], PlexusStreamItem::Done { .. }));
    }


    #[tokio::test]
    async fn test_error_stream() {
        let stream = error_stream("Something failed".into(), vec!["test".into()], false);
        let items: Vec<_> = stream.collect().await;

        assert_eq!(items.len(), 1);
        match &items[0] {
            PlexusStreamItem::Error {
                message,
                recoverable,
                code,
                ..
            } => {
                assert_eq!(message, "Something failed");
                assert!(!recoverable);
                assert!(code.is_none());
            }
            _ => panic!("Expected Error item"),
        }
    }

    #[tokio::test]
    async fn test_error_stream_with_code() {
        let stream = error_stream_with_code(
            "Not found".into(),
            "NOT_FOUND".into(),
            vec!["test".into()],
            true,
        );
        let items: Vec<_> = stream.collect().await;

        assert_eq!(items.len(), 1);
        match &items[0] {
            PlexusStreamItem::Error {
                message,
                code,
                recoverable,
                ..
            } => {
                assert_eq!(message, "Not found");
                assert_eq!(code.as_deref(), Some("NOT_FOUND"));
                assert!(recoverable);
            }
            _ => panic!("Expected Error item"),
        }
    }
}
