//! Echo activation - demonstrates plexus-macros usage with caller-wraps streaming
//!
//! This is a minimal example showing how to create an activation using the
//! `#[plexus_macros::activation]` macro. The macro generates:
//!
//! - RPC trait and server implementation
//! - Activation trait implementation
//! - Method enum with JSON schemas
//!
//! Event types are plain domain types (no special traits needed).
//! The macro handles wrapping with `wrap_stream()` at the call site.

use super::types::{EchoEvent, Message};
use async_stream::stream;
use futures::Stream;
use std::time::Duration;

/// Echo activation - echoes messages back
#[derive(Clone)]
pub struct EchoActivation;

impl EchoActivation {
    pub fn new() -> Self {
        EchoActivation
    }
}

impl Default for EchoActivation {
    fn default() -> Self {
        Self::new()
    }
}

/// `#[plexus_macros::activation]` generates all the boilerplate for this impl block:
/// - EchoRpc trait with JSON-RPC subscription methods
/// - EchoRpcServer implementation
/// - Activation trait implementation
/// - EchoMethod enum with JSON schemas
#[plexus_macros::activation(
    version = "1.0.0",
    description = "Echo messages back - demonstrates plexus-macros usage",
    // MACRO-12: the example — `message` is a `Message`, not a `String`.
    typed_params
)]
impl EchoActivation {
    /// Echo a message back
    #[plexus_macros::method(
        description = "Echo a message back the specified number of times",
        params(
            message = "The message to echo",
            count = "Number of times to repeat (default: 1)"
        )
    )]
    async fn echo(
        &self,
        message: Message,
        count: u32,
    ) -> impl Stream<Item = EchoEvent> + Send + 'static {
        let count = if count == 0 { 1 } else { count };
        let message = message.into_string();
        stream! {
            for i in 0..count {
                if i > 0 {
                    crate::rt::sleep(Duration::from_millis(500)).await;
                }
                yield EchoEvent::Echo {
                    message: message.clone(),
                    count: i + 1,
                };
            }
        }
    }

    /// Echo a simple message once
    #[plexus_macros::method(
        description = "Echo a message once",
        params(message = "The message to echo")
    )]
    async fn once(&self, message: Message) -> impl Stream<Item = EchoEvent> + Send + 'static {
        stream! {
            yield EchoEvent::Echo {
                message: message.into_string(),
                count: 1,
            };
        }
    }
}
