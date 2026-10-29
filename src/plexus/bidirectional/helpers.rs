//! Helper functions and utilities for bidirectional communication

use super::channel::BidirChannel;
use super::types::{BidirError, StandardRequest, StandardResponse};
use crate::plexus::types::PlexusStreamItem;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Timeout configuration presets for bidirectional requests
///
/// # Examples
///
/// ```rust,ignore
/// use plexus_core::bidirectional::TimeoutConfig;
///
/// let config = TimeoutConfig::normal();
/// let result = ctx.request_with_timeout(req, config.confirm).await?;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    /// Timeout for confirmation requests (yes/no)
    pub confirm: Duration,
    /// Timeout for text prompts (user input)
    pub prompt: Duration,
    /// Timeout for selection menus
    pub select: Duration,
    /// Timeout for custom request types
    pub custom: Duration,
}

impl TimeoutConfig {
    /// Quick timeouts (10 seconds) - for automated/scripted scenarios
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = TimeoutConfig::quick();
    /// assert_eq!(config.confirm, Duration::from_secs(10));
    /// ```
    pub fn quick() -> Self {
        Self {
            confirm: Duration::from_secs(10),
            prompt: Duration::from_secs(10),
            select: Duration::from_secs(10),
            custom: Duration::from_secs(10),
        }
    }

    /// Normal timeouts (30 seconds) - default for interactive use
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = TimeoutConfig::normal();
    /// assert_eq!(config.confirm, Duration::from_secs(30));
    /// ```
    pub fn normal() -> Self {
        Self {
            confirm: Duration::from_secs(30),
            prompt: Duration::from_secs(30),
            select: Duration::from_secs(30),
            custom: Duration::from_secs(30),
        }
    }

    /// Patient timeouts (60 seconds) - for complex decisions
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = TimeoutConfig::patient();
    /// assert_eq!(config.confirm, Duration::from_secs(60));
    /// ```
    pub fn patient() -> Self {
        Self {
            confirm: Duration::from_secs(60),
            prompt: Duration::from_secs(60),
            select: Duration::from_secs(60),
            custom: Duration::from_secs(60),
        }
    }

    /// Extended timeouts (5 minutes) - for long-running workflows
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = TimeoutConfig::extended();
    /// assert_eq!(config.confirm, Duration::from_secs(300));
    /// ```
    pub fn extended() -> Self {
        Self {
            confirm: Duration::from_secs(300),
            prompt: Duration::from_secs(300),
            select: Duration::from_secs(300),
            custom: Duration::from_secs(300),
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self::normal()
    }
}

/// Create a test bidirectional channel for unit tests
///
/// Returns a BidirChannel and the receiver end for capturing stream items.
/// The channel is marked as bidirectional_supported=true for testing.
///
/// # Examples
///
/// ```rust,ignore
/// use plexus_core::bidirectional::{create_test_bidir_channel, StandardRequest, StandardResponse};
///
/// #[tokio::test]
/// async fn test_my_activation() {
///     let (ctx, mut rx) = create_test_bidir_channel::<StandardRequest, StandardResponse>();
///
///     // Use ctx in your test...
///     tokio::spawn(async move {
///         if let Some(item) = rx.recv().await {
///             // Assert on stream items
///         }
///     });
/// }
/// ```
pub fn create_test_bidir_channel<Req, Resp>() -> (
    Arc<BidirChannel<Req, Resp>>,
    mpsc::Receiver<PlexusStreamItem>,
)
where
    Req: Serialize + DeserializeOwned + Send + 'static,
    Resp: Serialize + DeserializeOwned + Send + 'static,
{
    let (tx, rx) = mpsc::channel(32);
    let channel = Arc::new(BidirChannel::new_direct(
        tx,
        true, // bidirectional_supported
        vec!["test".into()],
        "test-hash".into(),
    ));
    (channel, rx)
}

/// Create a standard bidirectional channel for testing
///
/// Convenience wrapper around `create_test_bidir_channel` for standard request/response types.
///
/// # Examples
///
/// ```rust,ignore
/// use plexus_core::bidirectional::create_test_standard_channel;
///
/// #[tokio::test]
/// async fn test_with_standard_channel() {
///     let (ctx, mut rx) = create_test_standard_channel();
///     // Use ctx...
/// }
/// ```
pub fn create_test_standard_channel() -> (
    Arc<BidirChannel<StandardRequest, StandardResponse>>,
    mpsc::Receiver<PlexusStreamItem>,
) {
    create_test_bidir_channel()
}

/// Create a bidirectional channel that automatically responds based on a function
///
/// Useful for testing scenarios where you want deterministic responses without
/// manual response handling.
///
/// # Examples
///
/// ```rust,ignore
/// use plexus_core::bidirectional::{auto_respond_channel, StandardRequest, StandardResponse};
///
/// #[tokio::test]
/// async fn test_with_auto_response() {
///     let ctx = auto_respond_channel(|req: &StandardRequest| {
///         match req {
///             StandardRequest::Confirm { .. } => StandardResponse::Confirmed { value: true },
///             StandardRequest::Prompt { .. } => StandardResponse::Text { value: "test".into() },
///             StandardRequest::Select { .. } => StandardResponse::Selected { values: vec!["opt1".into()] },
///         }
///     });
///
///     let result = ctx.confirm("Test?").await;
///     assert_eq!(result.unwrap(), true);
/// }
/// ```
pub fn auto_respond_channel<Req, Resp>(
    response_fn: impl Fn(&Req) -> Resp + Send + Sync + 'static,
) -> Arc<BidirChannel<Req, Resp>>
where
    Req: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
    Resp: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let (tx, mut rx) = mpsc::channel::<PlexusStreamItem>(32);
    let channel = Arc::new(BidirChannel::new_direct(
        tx,
        true, // bidirectional_supported
        vec!["test".into()],
        "test-hash".into(),
    ));

    // Spawn background task to auto-respond
    let channel_clone = channel.clone();
    tokio::spawn(async move {
        while let Some(item) = rx.recv().await {
            if let PlexusStreamItem::Request {
                request_id,
                request_data,
                ..
            } = item
            {
                // Deserialize request
                if let Ok(req) = serde_json::from_value::<Req>(request_data) {
                    // Generate response
                    let resp = response_fn(&req);

                    // Send response
                    if let Ok(resp_json) = serde_json::to_value(&resp) {
                        let _ = channel_clone.handle_response(request_id, resp_json);
                    }
                }
            }
        }
    });

    channel
}

/// Create a channel that auto-confirms all requests with the given value
///
/// Convenience wrapper for testing confirmations.
///
/// # Examples
///
/// ```rust,ignore
/// use plexus_core::bidirectional::auto_confirm_channel;
///
/// #[tokio::test]
/// async fn test_auto_confirm() {
///     let ctx = auto_confirm_channel(true);
///     let result = ctx.confirm("Delete file?").await;
///     assert_eq!(result.unwrap(), true);
/// }
/// ```
pub fn auto_confirm_channel(confirm_value: bool) -> Arc<BidirChannel<StandardRequest, StandardResponse>> {
    auto_respond_channel(move |req: &StandardRequest| match req {
        StandardRequest::Confirm { default, .. } => StandardResponse::Confirmed {
            value: default.unwrap_or(confirm_value),
        },
        StandardRequest::Prompt { default, .. } => StandardResponse::Text {
            value: default
                .clone()
                .unwrap_or(serde_json::Value::String(String::new())),
        },
        StandardRequest::Select { options, .. } => StandardResponse::Selected {
            values: vec![options
                .first()
                .map(|o| o.value.clone())
                .unwrap_or(serde_json::Value::String(String::new()))],
        },
        StandardRequest::Custom { data } => StandardResponse::Custom { data: data.clone() },
    })
}

/// Get a user-friendly error message from a BidirError
///
/// Useful for displaying errors to end users in activations.
///
/// # Examples
///
/// ```rust,ignore
/// use plexus_core::bidirectional::{BidirError, bidir_error_message};
///
/// let err = BidirError::Timeout(30000);
/// assert_eq!(bidir_error_message(&err), "Request timed out waiting for response (after 30000ms)");
/// ```
pub fn bidir_error_message(err: &BidirError) -> String {
    match err {
        BidirError::NotSupported => {
            "Bidirectional communication not supported by this transport".to_string()
        }
        BidirError::Timeout(ms) => {
            format!("Request timed out waiting for response (after {}ms)", ms)
        }
        BidirError::Cancelled => "Request was cancelled by user".to_string(),
        BidirError::TypeMismatch { expected, got } => {
            format!("Type mismatch: expected {}, got {}", expected, got)
        }
        BidirError::Serialization(e) => format!("Serialization error: {}", e),
        BidirError::Transport(e) => format!("Transport error: {}", e),
        BidirError::UnknownRequest => "Unknown request ID (may have already been handled)".to_string(),
        BidirError::ChannelClosed => "Response channel closed before response received".to_string(),
        BidirError::NotThisCall => "This request was asked on another connection".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_config_quick() {
        let config = TimeoutConfig::quick();
        assert_eq!(config.confirm, Duration::from_secs(10));
        assert_eq!(config.prompt, Duration::from_secs(10));
    }

    #[test]
    fn test_timeout_config_normal() {
        let config = TimeoutConfig::normal();
        assert_eq!(config.confirm, Duration::from_secs(30));
    }

    #[test]
    fn test_timeout_config_patient() {
        let config = TimeoutConfig::patient();
        assert_eq!(config.confirm, Duration::from_secs(60));
    }

    #[test]
    fn test_timeout_config_extended() {
        let config = TimeoutConfig::extended();
        assert_eq!(config.confirm, Duration::from_secs(300));
    }

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.confirm, Duration::from_secs(30)); // Same as normal
    }

    #[tokio::test]
    async fn test_create_test_bidir_channel() {
        let (channel, _rx) = create_test_bidir_channel::<StandardRequest, StandardResponse>();
        assert!(channel.is_bidirectional());
    }

    #[tokio::test]
    async fn test_create_test_standard_channel() {
        let (channel, _rx) = create_test_standard_channel();
        assert!(channel.is_bidirectional());
    }

    #[tokio::test]
    async fn test_auto_respond_channel() {
        let ctx = auto_respond_channel(|req: &StandardRequest| match req {
            StandardRequest::Confirm { .. } => StandardResponse::Confirmed { value: true },
            StandardRequest::Prompt { .. } => StandardResponse::Text {
                value: serde_json::Value::String("hello".into()),
            },
            StandardRequest::Select { options, .. } => StandardResponse::Selected {
                values: vec![options[0].value.clone()],
            },
            StandardRequest::Custom { data } => StandardResponse::Custom { data: data.clone() },
        });

        // Test confirm
        let result = ctx.confirm("Test?").await;
        assert_eq!(result.unwrap(), true);

        // Test prompt
        let result = ctx.prompt("Name?").await;
        assert_eq!(result.unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_auto_confirm_channel() {
        let ctx = auto_confirm_channel(true);
        let result = ctx.confirm("Test?").await;
        assert_eq!(result.unwrap(), true);

        let ctx = auto_confirm_channel(false);
        let result = ctx.confirm("Test?").await;
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_bidir_error_message() {
        assert_eq!(
            bidir_error_message(&BidirError::NotSupported),
            "Bidirectional communication not supported by this transport"
        );

        assert_eq!(
            bidir_error_message(&BidirError::Timeout(30000)),
            "Request timed out waiting for response (after 30000ms)"
        );

        assert_eq!(
            bidir_error_message(&BidirError::Cancelled),
            "Request was cancelled by user"
        );

        assert_eq!(
            bidir_error_message(&BidirError::TypeMismatch {
                expected: "String".into(),
                got: "Integer".into()
            }),
            "Type mismatch: expected String, got Integer"
        );
    }
}
