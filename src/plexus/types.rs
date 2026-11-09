//! Plexus RPC streaming types
//!
//! These types define the wire format for all Plexus RPC streaming responses.
//! The key architectural principle is "caller wraps" - activations return
//! typed domain events, and the caller (DynamicHub routing layer) wraps them with metadata.

use std::borrow::Cow;
use std::sync::Arc;

use plexus_client::RemoteError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::wire::Content;

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
    // PERF-7: nothing in a `data` item is made per item. The metadata is
    // the stream's, shared by its items; the content type is the method's;
    // the content is the event encoded once — JSON bytes under the
    // WebSocket pipe, a `Value` anywhere else — and reads as a `Value`
    // either way (`Content`). A transformer that rewrites the content
    // replaces it whole, encoded or not. (The doc comments below are the
    // schema's descriptions, every `<ns>.call`'s `returns`: unchanged.)
    /// Data payload with caller-applied metadata
    Data {
        /// Metadata from calling layer
        metadata: Arc<StreamMetadata>,
        /// Type identifier for deserialization (e.g., "health.status")
        content_type: Cow<'static, str>,
        /// The actual payload (serialized activation event)
        content: Content,
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
        /// spec/05: the human line — never parsed for meaning. For a failed
        /// dispatch, the server's `PlexusError` as it reads; else the
        /// [`RemoteError`]'s `Display`. Optional on reading (RETURNS-6's
        /// frame has none, as plexus-client reads it): a frame without one
        /// reads as empty, and is written back without one — a relay makes
        /// up no `""` for a reader to show over the typed error (RETURNS-36,
        /// re-review #4). Every frame this crate builds has one.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        message: String,
        /// spec/05: the JSON-RPC code in decimal (`"-32601"`), or — for a
        /// refusal with none — its `error_kind` (`"too_many_calls"`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        /// RETURNS-6: why the call failed, typed — what a typed client
        /// decodes. Its `Display` is the human line.
        error: RemoteError,
        /// POLYGLOT-5: the typed error's own fields, flattened beside the
        /// others on the wire (spec/05) — `error_kind` and what that kind
        /// carries: `forbidden`'s `grant`, `scope`, `roles`, `held_on`;
        /// `too_many_calls`' `max`; `child_unavailable`'s `child`, `reason`.
        /// [`PlexusStreamItem::error`] fills them from the `RemoteError`
        /// ([`spec_fields`]); any key an error item carries beyond the named
        /// ones lands here, so an item relayed from a child (or read back by
        /// a client) keeps every field it came with.
        #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
        #[schemars(skip)]
        fields: serde_json::Map<String, Value>,
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
            metadata: Arc::new(metadata),
            content_type: Cow::Owned(content_type),
            content: Content::from(content),
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
            message: error.to_string(),
            code: Some(spec_code(&error)),
            fields: spec_fields(&error),
            error,
        }
    }

    /// An error item for a failed dispatch: the `PlexusError`'s own line as
    /// `message` (spec/05's), its semantic code, and the typed
    /// `RemoteError::from(e)` with its spec/05 fields beside it.
    pub fn from_plexus_error(metadata: StreamMetadata, e: &super::plexus::PlexusError, recoverable: bool) -> Self {
        let error = RemoteError::from(e);
        Self::Error {
            metadata,
            message: e.to_string(),
            recoverable,
            code: Some(spec_code(&error)),
            fields: spec_fields(&error),
            error,
        }
    }

    /// RETURNS-6: an error item's typed [`RemoteError`].
    pub fn remote_error(&self) -> Option<&RemoteError> {
        match self {
            Self::Error { error, .. } => Some(error),
            _ => None,
        }
    }

    /// POLYGLOT-5: an error item's `error_kind`, when it carries one.
    pub fn error_kind(&self) -> Option<&str> {
        match self {
            Self::Error { fields, .. } => fields.get("error_kind").and_then(Value::as_str),
            _ => None,
        }
    }

    /// Create a Done item
    pub fn done(metadata: StreamMetadata) -> Self {
        Self::Done { metadata }
    }

    /// Get the metadata from any stream item variant (if available)
    pub fn metadata(&self) -> Option<&StreamMetadata> {
        match self {
            Self::Data { metadata, .. } => Some(metadata.as_ref()),
            Self::Progress { metadata, .. } => Some(metadata),
            Self::Error { metadata, .. } => Some(metadata),
            Self::Done { metadata } => Some(metadata),
        }
    }
}

/// spec/05's `code` for a call failure: the JSON-RPC code in decimal, or —
/// for a refusal with none — its kind (`"too_many_calls"`).
pub fn spec_code(error: &RemoteError) -> String {
    match error {
        RemoteError::ActivationNotFound { .. } | RemoteError::MethodNotFound { .. } => "-32601".into(),
        RemoteError::InvalidParams { .. } => "-32602".into(),
        RemoteError::Unauthenticated => "-32001".into(),
        RemoteError::Forbidden { .. } => "-32003".into(),
        RemoteError::HandleNotSupported { .. } | RemoteError::Execution { .. } => "-32000".into(),
        RemoteError::TooManyCalls { .. }
        | RemoteError::ChildUnavailable { .. }
        | RemoteError::ChildTimeout { .. }
        | RemoteError::Other(_) => error.kind().into(),
    }
}

/// spec/05's flattened fields for a call failure — `error_kind` and what that
/// kind carries (AUTH-2's `grant`, `scope`, `roles`, `held_on`; `max`;
/// `child`, `reason`, `timeout_ms`); empty for a kind spec/05 gives no
/// `error_kind` (not found, execution).
pub fn spec_fields(error: &RemoteError) -> serde_json::Map<String, Value> {
    use plexus_client::DenyReason;
    let mut m = serde_json::Map::new();
    match error {
        RemoteError::ActivationNotFound { .. }
        | RemoteError::MethodNotFound { .. }
        | RemoteError::HandleNotSupported { .. }
        | RemoteError::Execution { .. } => return m,
        RemoteError::InvalidParams { .. } | RemoteError::Unauthenticated => {}
        RemoteError::Forbidden { reason } => match reason {
            DenyReason::MissingGrant { grant, scope, roles, held_on } => {
                m.insert("grant".into(), grant.as_str().into());
                m.insert("scope".into(), scope.as_str().into());
                m.insert("roles".into(), roles.iter().map(|r| Value::from(r.as_str())).collect());
                m.insert("held_on".into(), held_on.iter().map(|s| Value::from(s.as_str())).collect());
            }
            DenyReason::MissingScope { scope } => {
                m.insert("reason".into(), "missing_scope".into());
                m.insert("scope".into(), scope.as_str().into());
            }
            DenyReason::TenantBoundary => {
                m.insert("reason".into(), "tenant_boundary".into());
            }
            DenyReason::NotAccepted => {
                m.insert("reason".into(), "not_accepted".into());
            }
            DenyReason::NotNeeded { method } => {
                m.insert("reason".into(), "not_needed".into());
                m.insert("method".into(), method.as_str().into());
            }
        },
        RemoteError::TooManyCalls { max, child } => {
            m.insert("max".into(), (*max).into());
            if let Some(child) = child {
                m.insert("child".into(), child.as_str().into());
            }
        }
        RemoteError::ChildUnavailable { child, reason } => {
            m.insert("child".into(), child.as_str().into());
            m.insert("reason".into(), reason.as_str().into());
        }
        RemoteError::ChildTimeout { child, timeout_ms } => {
            m.insert("child".into(), child.as_str().into());
            m.insert("timeout_ms".into(), (*timeout_ms).into());
        }
        // RETURNS-36: a kind this build does not know keeps its own fields
        // beside the frame's (not the frame's own keys).
        RemoteError::Other(other) => {
            for (k, v) in &other.fields {
                if !["type", "metadata", "message", "code", "recoverable", "error", "error_kind"].contains(&k.as_str()) {
                    m.insert(k.clone(), v.clone());
                }
            }
        }
    }
    m.insert("error_kind".into(), error.kind().into());
    m
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

    /// RETURNS-6: the error frame — `recoverable` and a typed
    /// `RemoteError`; RETURNS-36: beside spec/05's `message` and `code`
    /// (and `error_kind` for a kind that has one).
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
            r#"{"type":"error","metadata":{"provenance":["tickets"],"plexus_hash":"h","timestamp":1},"recoverable":false,"message":"method not found: tickets.frob","code":"-32601","error":{"kind":"method_not_found","activation":"tickets","method":"frob"}}"#
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

    /// RETURNS-36 (review #4): `message` is always written, and optional on
    /// reading — RETURNS-6's error frame, `{type, metadata, recoverable,
    /// error}`, is valid, as plexus-client reads it.
    #[test]
    fn an_error_frame_without_message_reads() {
        let frame = serde_json::json!({
            "type": "error",
            "metadata": {"provenance": ["tickets"], "plexus_hash": "h", "timestamp": 1},
            "recoverable": false,
            "error": {"kind": "unauthenticated"}
        });
        let item: PlexusStreamItem = serde_json::from_value(frame).expect("a frame without message reads");
        assert_eq!(item.remote_error(), Some(&RemoteError::Unauthenticated));
        let written = serde_json::to_value(&item).unwrap();
        // RETURNS-36 (re-review #4): read without one, written without one —
        // a relay makes up no `""` for a reader to show over the typed error.
        assert!(written.get("message").is_none(), "no message made up: {written}");
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
