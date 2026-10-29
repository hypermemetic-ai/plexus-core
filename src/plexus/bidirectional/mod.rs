//! Bidirectional streaming support for Plexus RPC
//!
//! This module enables **server-to-client requests** during streaming RPC execution,
//! allowing for interactive workflows like confirmations, prompts, and multi-step wizards.
//!
//! # Overview
//!
//! Traditional RPC is unidirectional: clients send requests, servers respond. Bidirectional
//! communication extends this by allowing the **server to request input from the client**
//! during stream execution. This is essential for:
//!
//! - **User confirmations** before destructive operations
//! - **Interactive prompts** for missing information
//! - **Multi-step wizards** that guide users through complex workflows
//! - **Dynamic selection menus** based on server-side state
//!
//! # Architecture
//!
//! The bidirectional system is built on generic types that can work with any
//! serializable request/response types:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        BidirChannel<Req, Resp>                      │
//! │  Generic channel for type-safe server→client requests              │
//! └─────────────────────────────────────────────────────────────────────┘
//!                                    │
//!                    ┌───────────────┴───────────────┐
//!                    ▼                               ▼
//! ┌──────────────────────────────┐   ┌──────────────────────────────┐
//! │     StandardBidirChannel     │   │   Custom Request/Response    │
//! │  (confirm/prompt/select)     │   │   (domain-specific types)    │
//! └──────────────────────────────┘   └──────────────────────────────┘
//! ```
//!
//! ## Wire Format
//!
//! Bidirectional requests are sent as `PlexusStreamItem::Request`:
//!
//! ```json
//! {
//!   "type": "request",
//!   "requestId": "550e8400-e29b-41d4-a716-446655440000",
//!   "requestData": { "type": "confirm", "message": "Delete file?" },
//!   "timeoutMs": 30000
//! }
//! ```
//!
//! Clients respond via the `_plexus_respond` method or transport-specific mechanism.
//!
//! # Core Types
//!
//! - [`BidirChannel`] - Generic channel for any request/response types
//! - [`StandardBidirChannel`] - Type alias for [`BidirChannel<StandardRequest, StandardResponse>`]
//! - [`StandardRequest`] - Common UI patterns: `Confirm`, `Prompt`, `Select`
//! - [`StandardResponse`] - Matching responses: `Confirmed`, `Text`, `Selected`, `Cancelled`
//! - [`SelectOption`] - Option for selection menus
//! - [`BidirError`] - Error types for bidirectional operations
//!
//! # Helper Functions
//!
//! - [`TimeoutConfig`] - Timeout presets (quick, normal, patient, extended)
//! - [`auto_respond_channel`] - Create test channel with automatic responses
//! - [`auto_confirm_channel`] - Create test channel that auto-confirms
//! - [`bidir_error_message`] - Get user-friendly error messages
//!
//! # Examples
//!
//! ## Using StandardBidirChannel (Most Common)
//!
//! The `StandardBidirChannel` provides convenience methods for common UI patterns:
//!
//! ```rust,ignore
//! use plexus_core::plexus::bidirectional::{StandardBidirChannel, BidirError, SelectOption};
//!
//! async fn my_method(ctx: &StandardBidirChannel) -> Result<(), BidirError> {
//!     // Simple yes/no confirmation
//!     if ctx.confirm("Delete this file?").await? {
//!         // User confirmed - proceed with deletion
//!     }
//!
//!     // Text input prompt
//!     let name = ctx.prompt("Enter your name:").await?;
//!     println!("Hello, {}!", name);
//!
//!     // Selection from options
//!     let choices = vec![
//!         SelectOption::new("dev", "Development")
//!             .with_description("Local development environment"),
//!         SelectOption::new("staging", "Staging")
//!             .with_description("Pre-production testing"),
//!         SelectOption::new("prod", "Production")
//!             .with_description("Live environment (requires approval)"),
//!     ];
//!     let selected = ctx.select("Choose environment:", choices).await?;
//!     println!("Selected: {:?}", selected);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Handling Errors Gracefully
//!
//! Always handle bidirectional errors to support non-interactive transports:
//!
//! ```rust,ignore
//! use plexus_core::plexus::bidirectional::{StandardBidirChannel, BidirError, bidir_error_message};
//!
//! async fn safe_delete(ctx: &StandardBidirChannel, path: &str) -> Result<bool, String> {
//!     match ctx.confirm(&format!("Delete '{}'?", path)).await {
//!         Ok(true) => {
//!             // User confirmed
//!             Ok(true)
//!         }
//!         Ok(false) => {
//!             // User declined
//!             Ok(false)
//!         }
//!         Err(BidirError::NotSupported) => {
//!             // Transport doesn't support bidirectional - skip deletion for safety
//!             Err("Cannot delete without user confirmation".into())
//!         }
//!         Err(BidirError::Cancelled) => {
//!             // User explicitly cancelled
//!             Ok(false)
//!         }
//!         Err(e) => {
//!             // Other error - log and return user-friendly message
//!             Err(bidir_error_message(&e))
//!         }
//!     }
//! }
//! ```
//!
//! ## Using Custom Request/Response Types
//!
//! For domain-specific interactions, define custom types:
//!
//! ```rust,ignore
//! use serde::{Deserialize, Serialize};
//! use schemars::JsonSchema;
//! use plexus_core::plexus::bidirectional::{BidirChannel, BidirError};
//!
//! #[derive(Serialize, Deserialize, JsonSchema)]
//! #[serde(tag = "type", rename_all = "snake_case")]
//! enum ImageRequest {
//!     ConfirmOverwrite { path: String, size: u64 },
//!     ChooseQuality { min: u8, max: u8, default: u8 },
//!     SelectFormat { formats: Vec<String> },
//! }
//!
//! #[derive(Serialize, Deserialize, JsonSchema)]
//! #[serde(tag = "type", rename_all = "snake_case")]
//! enum ImageResponse {
//!     Confirmed { value: bool },
//!     Quality { value: u8 },
//!     Format { value: String },
//!     Cancelled,
//! }
//!
//! type ImageBidirChannel = BidirChannel<ImageRequest, ImageResponse>;
//!
//! async fn process_image(
//!     ctx: &ImageBidirChannel,
//!     path: &str,
//! ) -> Result<(), BidirError> {
//!     // Ask for quality
//!     let quality = ctx.request(ImageRequest::ChooseQuality {
//!         min: 50, max: 100, default: 85,
//!     }).await?;
//!
//!     if let ImageResponse::Quality { value } = quality {
//!         println!("Processing with quality: {}", value);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Testing with Auto-Response Channels
//!
//! Use test helpers for deterministic unit tests:
//!
//! ```rust,ignore
//! use plexus_core::plexus::bidirectional::{
//!     auto_respond_channel, StandardRequest, StandardResponse
//! };
//!
//! #[tokio::test]
//! async fn test_wizard_flow() {
//!     let ctx = auto_respond_channel(|req: &StandardRequest| {
//!         match req {
//!             StandardRequest::Confirm { .. } => StandardResponse::Confirmed { value: true },
//!             StandardRequest::Prompt { .. } => StandardResponse::Text { value: "test-value".into() },
//!             StandardRequest::Select { options, .. } => {
//!                 StandardResponse::Selected { values: vec![options[0].value.clone()] }
//!             }
//!         }
//!     });
//!
//!     // Test your activation with deterministic responses
//!     let result = ctx.confirm("Test?").await;
//!     assert_eq!(result.unwrap(), true);
//! }
//! ```
//!
//! # Transport Support
//!
//! Bidirectional communication works differently across transports:
//!
//! | Transport  | Mechanism                                           |
//! |------------|-----------------------------------------------------|
//! | WebSocket  | Request sent as stream item, response via dedicated call |
//! | MCP        | Request as logging notification, response via `_plexus_respond` tool |
//! | HTTP       | Not supported (stateless)                           |
//!
//! The `BidirChannel` automatically detects transport capabilities and returns
//! `BidirError::NotSupported` for transports that cannot handle bidirectional requests.

pub mod channel;
pub mod helpers;
pub mod registry;
pub mod types;

pub use channel::{BidirChannel, BidirWithFallback, StandardBidirChannel};
pub use helpers::{
    TimeoutConfig, auto_confirm_channel, auto_respond_channel, bidir_error_message,
    create_test_bidir_channel, create_test_standard_channel,
};
pub use registry::{
    answer_pending, bind_asker, handle_pending_response, is_request_pending, pending_count,
    register_pending_request, unregister_pending_request,
};
pub use types::{BidirError, SelectOption, StandardRequest, StandardResponse};
