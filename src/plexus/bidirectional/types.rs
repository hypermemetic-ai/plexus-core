//! Bidirectional streaming types
//!
//! This module defines the core types for bidirectional communication in Plexus RPC.
//! These types enable server-to-client requests during streaming execution, supporting
//! interactive workflows like confirmations, prompts, and selection menus.
//!
//! # Type System
//!
//! The bidirectional system uses a **generic type design** that separates:
//!
//! 1. **Standard types** ([`StandardRequest`]/[`StandardResponse`]) for common UI patterns
//! 2. **Custom types** that activations can define for domain-specific interactions
//!
//! # Wire Format
//!
//! All types use `serde` for serialization. The standard types use internally-tagged
//! enums for JSON-friendly wire format:
//!
//! ```json
//! // StandardRequest::Confirm
//! { "type": "confirm", "message": "Delete file?", "default": false }
//!
//! // StandardResponse::Confirmed
//! { "type": "confirmed", "value": true }
//! ```
//!
//! # Error Handling
//!
//! [`BidirError`] covers all failure modes:
//! - Transport doesn't support bidirectional ([`BidirError::NotSupported`])
//! - User cancelled ([`BidirError::Cancelled`])
//! - Request timed out ([`BidirError::Timeout`])
//! - Type/serialization errors

use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Error types for bidirectional communication
///
/// This enum covers all failure modes that can occur during bidirectional
/// request/response cycles. Activations should handle these errors gracefully,
/// especially [`BidirError::NotSupported`] which indicates the transport
/// cannot support interactive features.
///
/// # Common Patterns
///
/// ```rust,ignore
/// use plexus_core::plexus::bidirectional::{BidirError, StandardBidirChannel};
///
/// async fn my_method(ctx: &StandardBidirChannel) {
///     match ctx.confirm("Proceed?").await {
///         Ok(true) => { /* user confirmed */ }
///         Ok(false) => { /* user declined */ }
///         Err(BidirError::NotSupported) => {
///             // Non-interactive transport - use safe defaults
///         }
///         Err(BidirError::Cancelled) => {
///             // User explicitly cancelled
///         }
///         Err(BidirError::Timeout(_)) => {
///             // User didn't respond in time
///         }
///         Err(e) => {
///             // Other errors - log and handle
///             eprintln!("Bidirectional error: {}", e);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, thiserror::Error)]
pub enum BidirError {
    /// Transport does not support bidirectional communication.
    ///
    /// This is a normal condition - many transports (HTTP, some MCP configs)
    /// cannot support server-to-client requests. Activations should have
    /// fallback behavior when this error occurs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match ctx.confirm("Delete?").await {
    ///     Err(BidirError::NotSupported) => {
    ///         // Don't delete without confirmation
    ///         return Err("Interactive confirmation required");
    ///     }
    ///     // ...
    /// }
    /// ```
    #[error("Bidirectional communication not supported by this transport")]
    NotSupported,

    /// Request timed out waiting for client response.
    ///
    /// The timeout value (in milliseconds) is included. Default timeout
    /// is 30 seconds, configurable via `request_with_timeout()` method.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match ctx.confirm("Confirm?").await {
    ///     Err(BidirError::Timeout(ms)) => {
    ///         println!("No response after {}ms", ms);
    ///     }
    ///     // ...
    /// }
    /// ```
    #[error("Request timed out after {0}ms")]
    Timeout(u64),

    /// Client explicitly cancelled the request.
    ///
    /// This indicates the user chose to cancel rather than respond.
    /// Different from declining - cancel means "abort the workflow".
    #[error("Request was cancelled by client")]
    Cancelled,

    /// Response type doesn't match expected type.
    ///
    /// This usually indicates a bug in client code or a protocol mismatch.
    /// For example, responding with `Text` to a `Confirm` request.
    #[error("Type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// Expected type name
        expected: String,
        /// Actual type received
        got: String,
    },

    /// Failed to serialize or deserialize request/response.
    ///
    /// Contains the underlying serialization error message.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Transport-level error during communication.
    ///
    /// This covers network errors, connection drops, etc.
    #[error("Transport error: {0}")]
    Transport(String),

    /// Unknown request ID (response for non-existent request).
    ///
    /// This can happen if:
    /// - The request already timed out
    /// - The request was cancelled
    /// - The request ID was corrupted
    #[error("Unknown request ID")]
    UnknownRequest,

    /// Response channel was closed before response received.
    ///
    /// This typically means the waiting task was cancelled or dropped.
    #[error("Response channel closed")]
    ChannelClosed,

    /// BIDIR-13: an answer from a connection other than the one that was
    /// asked. The question stays pending; the asker may still answer. On
    /// the wire, `{ns}.respond` says `error_kind: "not_this_call"` (BIDIR-7's
    /// name).
    #[error("not_this_call: this request was asked on another connection")]
    NotThisCall,
}

/// Standard request types for common interactive UI patterns.
///
/// These request types cover the most common server-to-client interactions:
///
/// - **Confirm**: Yes/no questions before important actions
/// - **Prompt**: Free-form text input from the user
/// - **Select**: Choose one or more options from a list
/// - **Custom**: Domain-specific request payload
///
/// The type parameter `T` defaults to [`serde_json::Value`] for backwards compatibility.
/// Use a custom type for domain-specific interactions.
///
/// For domain-specific interactions (e.g., image quality selection, custom
/// dialogs), define your own request/response enums and use
/// [`BidirChannel<YourRequest, YourResponse>`](super::BidirChannel).
///
/// # Wire Format
///
/// Uses internally-tagged JSON (`#[serde(tag = "type")]`):
///
/// ```json
/// // Confirm request
/// {
///   "type": "confirm",
///   "message": "Delete 3 files?",
///   "default": false
/// }
///
/// // Prompt request
/// {
///   "type": "prompt",
///   "message": "Enter project name:",
///   "default": "my-project",
///   "placeholder": "project-name"
/// }
///
/// // Select request
/// {
///   "type": "select",
///   "message": "Choose template:",
///   "options": [
///     { "value": "minimal", "label": "Minimal", "description": "Bare-bones starter" },
///     { "value": "full", "label": "Full Featured" }
///   ],
///   "multiSelect": false
/// }
/// ```
///
/// # Client Implementation
///
/// Clients should display appropriate UI for each request type:
///
/// | Type | UI Suggestion |
/// |------|---------------|
/// | `confirm` | Yes/No buttons or checkbox |
/// | `prompt` | Text input field |
/// | `select` | Dropdown, radio buttons, or checkbox list |
/// | `custom` | Application-defined |
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    bound(
        serialize = "T: Serialize",
        deserialize = "T: serde::de::DeserializeOwned"
    )
)]
pub enum StandardRequest<T = serde_json::Value>
where
    T: Serialize + DeserializeOwned + JsonSchema,
{
    /// Binary yes/no confirmation request.
    ///
    /// Use this for important decisions like:
    /// - Confirming destructive operations ("Delete 3 files?")
    /// - Proceeding with potentially expensive operations
    /// - Accepting terms or conditions
    ///
    /// The `default` field suggests the default choice if the user
    /// doesn't explicitly respond (e.g., just presses Enter).
    Confirm {
        /// Question to ask the user.
        /// Should be a clear yes/no question.
        message: String,

        /// Default answer if user accepts without explicit choice.
        /// - `Some(true)` = default to "yes"
        /// - `Some(false)` = default to "no"
        /// - `None` = require explicit choice
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<bool>,
    },

    /// Free-form text input request.
    ///
    /// Use this for collecting:
    /// - Names, titles, identifiers
    /// - Paths, URLs
    /// - Custom values not in a predefined list
    ///
    /// For password/sensitive input, clients should use appropriate
    /// input masking.
    Prompt {
        /// Prompt message shown to the user.
        message: String,

        /// Default value to pre-fill in the input.
        /// User can accept or modify.
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<T>,

        /// Placeholder text shown when input is empty.
        /// Provides a hint about expected format.
        #[serde(skip_serializing_if = "Option::is_none")]
        placeholder: Option<String>,
    },

    /// Selection request for choosing from options.
    ///
    /// Use this when the valid choices are known ahead of time.
    /// Supports both single and multiple selection.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let options = vec![
    ///     SelectOption::new("dev", "Development")
    ///         .with_description("Local dev environment"),
    ///     SelectOption::new("prod", "Production")
    ///         .with_description("Live servers"),
    /// ];
    /// let selected = ctx.select("Choose environment:", options).await?;
    /// ```
    Select {
        /// Selection prompt shown to the user.
        message: String,

        /// Available options to choose from.
        /// Each option has a value (returned) and label (displayed).
        options: Vec<SelectOption<T>>,

        /// Whether to allow selecting multiple options.
        /// - `false` (default): single selection, returns one value
        /// - `true`: multiple selection, returns zero or more values
        #[serde(default)]
        multi_select: bool,
    },

    /// Custom domain-specific request payload.
    ///
    /// Use this for application-specific interactions that don't fit
    /// the standard confirm/prompt/select patterns.
    Custom {
        /// The custom request data.
        data: T,
    },
}

/// Standard response types matching [`StandardRequest`].
///
/// Each variant corresponds to a request type:
///
/// | Request | Response |
/// |---------|----------|
/// | `Confirm` | `Confirmed { value: bool }` |
/// | `Prompt` | `Text { value: T }` |
/// | `Select` | `Selected { values: Vec<T> }` |
/// | Any | `Cancelled` (user cancelled) |
///
/// The type parameter `T` defaults to [`serde_json::Value`] for backwards compatibility.
///
/// # Wire Format
///
/// Uses internally-tagged JSON for consistency with TypeScript clients:
/// ```json
/// { "type": "confirmed", "value": true }
/// { "type": "text", "value": "user-input" }
/// { "type": "selected", "values": ["dev"] }
/// { "type": "cancelled" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    bound(
        serialize = "T: Serialize",
        deserialize = "T: serde::de::DeserializeOwned"
    )
)]
pub enum StandardResponse<T = serde_json::Value>
where
    T: Serialize + DeserializeOwned + JsonSchema,
{
    /// User confirmed (true) or declined (false).
    ///
    /// Response to `StandardRequest::Confirm`.
    /// - `value: true` = user said yes
    /// - `value: false` = user said no
    Confirmed {
        /// Whether the user confirmed (true) or declined (false)
        value: bool,
    },

    /// User entered text or provided a value.
    ///
    /// Response to `StandardRequest::Prompt`.
    /// May be empty if user submitted without entering text.
    Text {
        /// The value entered or provided by the user
        value: T,
    },

    /// User selected one or more options (by value).
    ///
    /// Response to `StandardRequest::Select`.
    /// Contains the `value` field(s) from selected [`SelectOption`]s.
    ///
    /// - For single-select: vector with exactly one element
    /// - For multi-select: vector with zero or more elements
    Selected {
        /// The values of selected options
        values: Vec<T>,
    },

    /// Custom domain-specific response payload.
    ///
    /// Corresponds to `StandardRequest::Custom` or any request type
    /// where the application needs to return a custom response.
    Custom {
        /// The custom response data.
        data: T,
    },

    /// User cancelled the request.
    ///
    /// Can be sent in response to any request type.
    /// Indicates the user chose to abort rather than respond.
    /// This is different from declining (Confirmed { value: false }) - cancel
    /// means "don't proceed with the workflow at all".
    Cancelled,
}

/// An option in a [`StandardRequest::Select`] request.
///
/// Each option has:
/// - **value**: Machine-readable identifier returned in the response (generic over `T`)
/// - **label**: Human-readable text displayed to the user
/// - **description**: Optional additional context about the option
///
/// The type parameter `T` defaults to [`serde_json::Value`] for backwards compatibility.
///
/// # Wire Format
///
/// ```json
/// {
///   "value": "prod",
///   "label": "Production",
///   "description": "Live environment - requires approval"
/// }
/// ```
///
/// # Example
///
/// ```rust
/// use plexus_core::plexus::bidirectional::SelectOption;
///
/// let options = vec![
///     SelectOption::new("minimal", "Minimal Starter")
///         .with_description("Basic project structure"),
///     SelectOption::new("full", "Full Featured")
///         .with_description("All features included"),
///     SelectOption::new("api", "API Only"),  // No description
/// ];
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(bound(
    serialize = "T: Serialize",
    deserialize = "T: serde::de::DeserializeOwned"
))]
pub struct SelectOption<T = serde_json::Value>
where
    T: Serialize + DeserializeOwned + JsonSchema,
{
    /// Machine-readable value returned when this option is selected.
    ///
    /// This is what appears in `StandardResponse::Selected`.
    /// Should be a stable identifier (e.g., "dev", "prod", "option_1").
    pub value: T,

    /// Human-readable label displayed to the user.
    ///
    /// Should be concise but descriptive (e.g., "Development", "Production").
    pub label: String,

    /// Optional description providing additional context.
    ///
    /// Use for longer explanations that don't fit in the label.
    /// Clients may display this as a tooltip or secondary text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SelectOption {
    /// Create a new select option with value and label.
    ///
    /// This constructor is for the default `T = serde_json::Value` type.
    /// The `value` parameter is converted to `serde_json::Value` via `.into()`.
    ///
    /// # Arguments
    ///
    /// * `value` - Machine-readable identifier (returned in response), convertible to `serde_json::Value`
    /// * `label` - Human-readable display text
    ///
    /// # Example
    ///
    /// ```rust
    /// use plexus_core::plexus::bidirectional::SelectOption;
    ///
    /// let opt = SelectOption::new("dev", "Development Environment");
    /// assert_eq!(opt.label, "Development Environment");
    /// ```
    pub fn new(value: impl Into<serde_json::Value>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            description: None,
        }
    }

    /// Add a description to this option.
    ///
    /// # Example
    ///
    /// ```rust
    /// use plexus_core::plexus::bidirectional::SelectOption;
    ///
    /// let opt = SelectOption::new("prod", "Production")
    ///     .with_description("Live environment - changes affect real users");
    ///
    /// assert_eq!(opt.description, Some("Live environment - changes affect real users".into()));
    /// ```
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

impl<T> SelectOption<T>
where
    T: Serialize + DeserializeOwned + JsonSchema,
{
    /// Create a new select option with a typed value and label.
    ///
    /// Use this constructor when working with a custom type `T`.
    ///
    /// # Arguments
    ///
    /// * `value` - The typed value for this option
    /// * `label` - Human-readable display text
    pub fn new_typed(value: T, label: impl Into<String>) -> Self {
        Self {
            value,
            label: label.into(),
            description: None,
        }
    }

    /// Add a description to this option.
    pub fn with_description_typed(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_request_serialization() {
        let req: StandardRequest = StandardRequest::Confirm {
            message: "Continue?".into(),
            default: Some(false),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], "confirm");
        assert_eq!(json["message"], "Continue?");
        assert_eq!(json["default"], false);
    }

    #[test]
    fn test_standard_response_serialization() {
        let resp: StandardResponse = StandardResponse::Confirmed { value: true };

        let json = serde_json::to_value(&resp).unwrap();
        // Internally tagged: { "type": "confirmed", "value": true }
        assert_eq!(json["type"], "confirmed");
        assert_eq!(json["value"], true);

        // Test round-trip
        let roundtrip: StandardResponse = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip, StandardResponse::Confirmed { value: true });
    }

    #[test]
    fn test_select_option_builder() {
        let opt = SelectOption::new("prod", "Production")
            .with_description("Requires approval");

        assert_eq!(opt.value, serde_json::Value::String("prod".into()));
        assert_eq!(opt.label, "Production");
        assert_eq!(opt.description, Some("Requires approval".into()));
    }

    #[test]
    fn test_bidir_error_display() {
        let err = BidirError::Timeout(30000);
        assert_eq!(err.to_string(), "Request timed out after 30000ms");

        let err = BidirError::TypeMismatch {
            expected: "Confirmed".into(),
            got: "Text".into(),
        };
        assert_eq!(
            err.to_string(),
            "Type mismatch: expected Confirmed, got Text"
        );
    }

    #[test]
    fn test_standard_request_prompt_generic() {
        let req: StandardRequest = StandardRequest::Prompt {
            message: "Enter value:".into(),
            default: Some(serde_json::Value::String("default".into())),
            placeholder: None,
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], "prompt");
        assert_eq!(json["default"], "default");
    }

    #[test]
    fn test_standard_response_text_generic() {
        let resp: StandardResponse = StandardResponse::Text {
            value: serde_json::Value::String("hello".into()),
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["value"], "hello");

        let roundtrip: StandardResponse = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip, resp);
    }

    #[test]
    fn test_standard_response_selected_generic() {
        let resp: StandardResponse = StandardResponse::Selected {
            values: vec![
                serde_json::Value::String("a".into()),
                serde_json::Value::String("b".into()),
            ],
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["type"], "selected");
        assert!(json["values"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn test_custom_variant_request() {
        let req: StandardRequest = StandardRequest::Custom {
            data: serde_json::json!({"action": "special", "param": 42}),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], "custom");
        assert_eq!(json["data"]["action"], "special");
    }

    #[test]
    fn test_custom_variant_response() {
        let resp: StandardResponse = StandardResponse::Custom {
            data: serde_json::json!({"result": "ok"}),
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["type"], "custom");
        assert_eq!(json["data"]["result"], "ok");
    }
}
