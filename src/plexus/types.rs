//! Plexus RPC streaming types
//!
//! These types define the wire format for all Plexus RPC streaming responses.
//! The key architectural principle is "caller wraps" - activations return
//! typed domain events, and the caller (DynamicHub routing layer) wraps them with metadata.

use plexus_client::RemoteError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Metadata applied by the caller when wrapping activation responses
///
/// This metadata is added at each layer of the call stack, enabling
/// provenance tracking and cache invalidation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamMetadata {
    /// Call path through the system (e.g., ["substrate", "health"])
    pub provenance: Vec<String>,

    /// Hash of Plexus RPC server configuration for cache invalidation
    /// Changes when activations are added/removed/updated
    pub plexus_hash: String,

    /// Unix timestamp (seconds) when the event was wrapped
    pub timestamp: i64,
}

impl StreamMetadata {
    /// Create new metadata with current timestamp
    pub fn new(provenance: Vec<String>, plexus_hash: String) -> Self {
        Self {
            provenance,
            plexus_hash,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

/// Universal stream item - all activations emit this type
///
/// The caller (DynamicHub routing layer) wraps activation responses with
/// metadata. This is the only type that crosses the wire.
///
/// # 0.7 wire shape (RETURNS-6)
///
/// ```text
/// {"type":"data",    "metadata":…, "content_type":"ns.method", "content":<T>}
/// {"type":"progress","metadata":…, "content_type":"ns.method", "content":<P>}
/// {"type":"error",   "metadata":…, "recoverable":<bool>, "error":<RemoteError>}
/// {"type":"request", "requestId":…, "requestData":…, "timeoutMs":…}
/// {"type":"done",    "metadata":…}
/// ```
///
/// The progress frame carries the method's declared progress type `P`
/// (`plexus_client::Note` by default) and the same `content_type` a data
/// frame does, so a receiver attributes it to its call the same way. The
/// error frame carries a typed [`RemoteError`] — the call failed — in place
/// of 0.6's stringly `message` / `code`; `RemoteError`'s `Display` is the
/// human line. `plexus_client::StreamItem` mirrors this type; the
/// cross-serialization test is `tests/client_envelope_compat.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlexusStreamItem {
    /// Data payload with caller-applied metadata
    Data {
        /// Metadata from calling layer
        metadata: StreamMetadata,
        /// Type identifier for deserialization (e.g., "health.status")
        content_type: String,
        /// The actual payload (serialized activation event)
        content: Value,
    },

    /// An intermediate report of a method that declares progress — one
    /// `Progress::Update(p)` of its return type. Never terminates the stream.
    Progress {
        /// Metadata from calling layer
        metadata: StreamMetadata,
        /// The call's method, as on its data frames (e.g. "tickets.import")
        content_type: String,
        /// The method's progress value `P`, serialized
        /// (`{"message", "percentage"}` for the default `Note`)
        content: Value,
    },

    /// The call failed — bad params, unknown method, auth, or the method
    /// itself blew up. (An activation saying no is a data item, not this.)
    Error {
        /// Metadata from calling layer
        metadata: StreamMetadata,
        /// Whether the operation can be retried
        recoverable: bool,
        /// Why the call failed, typed. Its `Display` is the human line.
        error: RemoteError,
    },

    /// Bidirectional request from server to client
    ///
    /// Server can ask client for input during stream execution.
    /// Client must respond via transport-specific mechanism
    /// (MCP: _plexus_respond tool, WebSocket: plexus.respond RPC).
    #[serde(rename_all = "camelCase")]
    Request {
        /// Unique identifier for correlating response
        request_id: String,
        /// Serialized request data (generic Req type)
        request_data: Value,
        /// Maximum time to wait for response (milliseconds)
        timeout_ms: u64,
    },

    /// Stream completed successfully
    Done {
        /// Metadata from calling layer
        metadata: StreamMetadata,
    },
}

impl PlexusStreamItem {
    /// Create a Data item
    pub fn data(metadata: StreamMetadata, content_type: String, content: Value) -> Self {
        Self::Data {
            metadata,
            content_type,
            content,
        }
    }

    /// Create a Progress item carrying the method's progress value `content`
    pub fn progress(metadata: StreamMetadata, content_type: String, content: Value) -> Self {
        Self::Progress {
            metadata,
            content_type,
            content,
        }
    }

    /// Create an Error item.
    ///
    /// Dispatch never builds one by hand from a `PlexusError`:
    /// `PlexusStreamItem::error(metadata, RemoteError::from(&e), recoverable)`.
    pub fn error(metadata: StreamMetadata, error: RemoteError, recoverable: bool) -> Self {
        Self::Error {
            metadata,
            recoverable,
            error,
        }
    }

    /// Create a Request item
    pub fn request(request_id: String, request_data: Value, timeout_ms: u64) -> Self {
        Self::Request {
            request_id,
            request_data,
            timeout_ms,
        }
    }

    /// Create a Done item
    pub fn done(metadata: StreamMetadata) -> Self {
        Self::Done { metadata }
    }

    /// Get the metadata from any stream item variant (if available)
    ///
    /// Note: Request items don't have metadata as they're server-initiated
    pub fn metadata(&self) -> Option<&StreamMetadata> {
        match self {
            Self::Data { metadata, .. } => Some(metadata),
            Self::Progress { metadata, .. } => Some(metadata),
            Self::Error { metadata, .. } => Some(metadata),
            Self::Done { metadata } => Some(metadata),
            Self::Request { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_item_data_serialization() {
        let metadata = StreamMetadata {
            provenance: vec!["substrate".into(), "health".into()],
            plexus_hash: "abc123".into(),
            timestamp: 1735052400,
        };

        let item = PlexusStreamItem::data(
            metadata,
            "health.status".into(),
            serde_json::json!({ "status": "healthy", "uptime": 123 }),
        );

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"data\""));
        assert!(json.contains("\"content_type\":\"health.status\""));
        assert!(json.contains("\"plexus_hash\":\"abc123\""));
        assert!(json.contains("\"provenance\":[\"substrate\",\"health\"]"));
    }

    fn fixed_metadata() -> StreamMetadata {
        StreamMetadata {
            provenance: vec!["tickets".into()],
            plexus_hash: "h".into(),
            timestamp: 1,
        }
    }

    /// RETURNS-6: the 0.7 error frame — `recoverable` and a typed
    /// `RemoteError`; no `message`, no `code`.
    #[test]
    fn test_stream_item_error_serialization() {
        let item = PlexusStreamItem::error(
            fixed_metadata(),
            RemoteError::MethodNotFound {
                activation: "tickets".into(),
                method: "frob".into(),
            },
            false,
        );

        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(
            json,
            r#"{"type":"error","metadata":{"provenance":["tickets"],"plexus_hash":"h","timestamp":1},"recoverable":false,"error":{"kind":"method_not_found","activation":"tickets","method":"frob"}}"#
        );
        let back: PlexusStreamItem = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    /// RETURNS-6: the 0.7 progress frame — `content_type` plus the typed
    /// progress value as `content`.
    #[test]
    fn test_stream_item_progress_serialization() {
        let item = PlexusStreamItem::progress(
            fixed_metadata(),
            "tickets.import".into(),
            // keys in sorted order, so the literal holds with or without
            // serde_json's `preserve_order`
            serde_json::json!({"done": 0, "of": 10, "type": "chunk"}),
        );

        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(
            json,
            r#"{"type":"progress","metadata":{"provenance":["tickets"],"plexus_hash":"h","timestamp":1},"content_type":"tickets.import","content":{"done":0,"of":10,"type":"chunk"}}"#
        );
        let back: PlexusStreamItem = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    /// A 0.6-shaped frame does not parse as 0.7 (no back-compat, RETURNS-1
    /// decision 12): `message`/`code` are gone and `error` is required.
    #[test]
    fn test_stream_item_06_error_frame_is_rejected() {
        let old = serde_json::json!({
            "type": "error",
            "metadata": {"provenance": [], "plexus_hash": "h", "timestamp": 1},
            "message": "boom",
            "code": "-32601",
            "recoverable": false
        });
        assert!(serde_json::from_value::<PlexusStreamItem>(old).is_err());
    }

    #[test]
    fn test_stream_item_done_serialization() {
        let metadata = StreamMetadata::new(vec!["substrate".into()], "hash".into());

        let item = PlexusStreamItem::done(metadata);

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"done\""));
    }
}
