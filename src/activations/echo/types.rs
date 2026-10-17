//! Echo activation event types
//!
//! This demonstrates plain domain types for the caller-wraps streaming pattern.
//! No trait implementations needed - just standard derives.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Events from echo operations
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EchoEvent {
    /// Echo response
    Echo {
        /// The echoed message
        message: String,
        /// Number of times repeated
        count: u32,
    },
}

/// MACRO-13: `EchoClient` implements the `Echo` trait, and a client failure
/// ends its stream as one event. `EchoEvent` has no error variant (adding one
/// would change the wire), so the failure is an echo of its message with
/// `count: 0` — a count no real echo has (they start at 1).
impl plexus_client::FromClientError for EchoEvent {
    fn from_client_error(error: plexus_client::ClientError) -> Self {
        EchoEvent::Echo { message: error.to_string(), count: 0 }
    }
}

/// A message to echo (MACRO-12: the example of a typed parameter). Any
/// text is a message — prose stays prose, but it has a name, so it cannot
/// be passed where another kind of string is meant. On the wire it is the
/// plain string it always was.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Message(String);

impl Message {
    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for Message {
    fn from(text: String) -> Self {
        Self(text)
    }
}

impl From<&str> for Message {
    fn from(text: &str) -> Self {
        Self(text.to_string())
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
