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
