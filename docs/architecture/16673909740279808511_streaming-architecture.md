# Streaming Architecture

> The caller-wraps streaming pattern, PlexusStreamItem types, and streaming helpers.

## The Caller-Wraps Pattern

Activations return plain domain events. The framework wraps them:

```
Your method yields:  EchoEvent::Echo { message: "hi", count: 1 }
                            ↓
Framework wraps to:  PlexusStreamItem::Data {
                       metadata: StreamMetadata { provenance, plexus_hash, timestamp },
                       content_type: "echo.echo",
                       content: { "type": "echo", "message": "hi", "count": 1 }
                     }
                            ↓
Stream ends with:    PlexusStreamItem::Done { metadata }
```

## PlexusStreamItem Variants

```rust
pub enum PlexusStreamItem {
    Data { metadata, content_type, content: Value },
    Progress { metadata, content_type, content: Value },   // the method's progress `P` (default `Note`)
    Error { metadata, recoverable: bool, error: RemoteError },
    Done { metadata },
    Request { ... },  // For bidirectional communication
}
```

0.7 (RETURNS-6): the error frame carries a typed `plexus_client::RemoteError`
(`kind`-tagged) in place of `message` / `code` — build it as
`PlexusStreamItem::error(metadata, RemoteError::from(&e), recoverable)`; the
progress frame carries the call's `content_type` and a typed progress value.

## PlexusStream Type

```rust
pub type PlexusStream = Pin<Box<dyn Stream<Item = PlexusStreamItem> + Send>>;
```

## Streaming Helpers

Defined in `plexus-core/src/plexus/streaming.rs`. The macro handles wrapping automatically for `#[hub_method]` returns. Use these directly only for manual `Activation` implementations:

```rust
// Wrap a typed stream with metadata and auto-appended Done event
wrap_stream(stream, content_type, provenance) -> PlexusStream

// Single-item error frame
error_stream(error: RemoteError, provenance, recoverable) -> PlexusStream

// Single-item progress frame for the call `content_type`
progress_stream(content_type, content: Value, provenance) -> PlexusStream

// Single-item done event
done_stream(provenance) -> PlexusStream
```

### `wrap_stream` Details

```rust
pub fn wrap_stream<T: Serialize + Send + 'static>(
    stream: impl Stream<Item = T> + Send + 'static,
    content_type: &'static str,
    provenance: Vec<String>,
) -> PlexusStream
```

- Maps each item to `PlexusStreamItem::Data` with serialized content
- Chains a `PlexusStreamItem::Done` at the end
- Includes `StreamMetadata` with provenance path and plexus hash

## Method Return Requirements

Every `#[hub_method]` must return:
- `impl Stream<Item = T> + Send + 'static`
- Where `T: Serialize + Send`
- Use `async_stream::stream!` macro for the cleanest syntax

### Simple Stream

```rust
async fn my_method(&self) -> impl Stream<Item = MyEvent> + Send + 'static {
    stream! {
        yield MyEvent::First { value: 1 };
        yield MyEvent::Second { value: 2 };
    }
}
```

### Stream with Loop

```rust
async fn echo(&self, message: String, count: u32)
    -> impl Stream<Item = EchoEvent> + Send + 'static {
    stream! {
        for i in 0..count {
            tokio::time::sleep(Duration::from_millis(500)).await;
            yield EchoEvent::Echo { message: message.clone(), count: i + 1 };
        }
    }
}
```

## Bidirectional Streaming

For methods that need to prompt the client mid-execution:

```rust
pub fn wrap_stream_with_bidir<T, Req, Resp>(
    stream: impl Stream<Item = T> + Send + 'static,
    content_type: &'static str,
    provenance: Vec<String>,
) -> (Arc<BidirChannel<Req, Resp>>, PlexusStream)
```

Creates a `BidirChannel` and merges the user's data stream with `Request` items from the channel. The channel lets the activation send requests to the client and await responses.

### Usage

```rust
use plexus_core::plexus::{wrap_stream_with_bidir, StandardRequest, StandardResponse};

let (ctx, stream) = wrap_stream_with_bidir::<_, StandardRequest, StandardResponse>(
    user_stream,
    "interactive.wizard",
    vec!["interactive".into()],
);
// ctx.request(...) sends a request to the client and awaits response
```

### Two-Step API

For more control, use `create_bidir_stream` to separate channel creation from stream wrapping:

```rust
let (ctx, wrap_fn) = create_bidir_stream::<StandardRequest, StandardResponse>(
    "interactive.wizard",
    vec!["interactive".into()],
);
let user_stream = activation.wizard(&ctx).await;
let merged_stream = wrap_fn(user_stream);
```

## Source Paths

| Component | Path |
|-----------|------|
| Streaming helpers | `plexus-core/src/plexus/streaming.rs` |
| PlexusStreamItem types | `plexus-core/src/plexus/types.rs` |
| Bidirectional channels | `plexus-core/src/plexus/bidirectional.rs` |
