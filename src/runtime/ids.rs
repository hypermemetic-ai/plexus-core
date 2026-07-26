//! Turn and callback identifiers (PLX-80 / M1·C).
//!
//! Both are newtypes rather than `String`/`u64`, and a [`CallbackId`] *embeds*
//! its [`TurnId`]. That embedding is what makes cross-turn callback
//! cross-talk a typed, checkable condition instead of a convention: a response
//! addressed to turn A can never be routed into turn B, because the router
//! compares the id's turn field before it ever looks at the sequence number.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Identity of one turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TurnId(uuid::Uuid);

impl TurnId {
    /// Mint a fresh turn id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// The underlying uuid.
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

impl Default for TurnId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TurnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identity of one in-flight server-to-client callback.
///
/// The `turn` field is load-bearing, not decorative: see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallbackId {
    /// The turn that issued the callback.
    pub turn: TurnId,
    /// Monotonic per-turn sequence number, starting at 0.
    pub seq: u64,
}

impl CallbackId {
    /// Build a callback id.
    pub fn new(turn: TurnId, seq: u64) -> Self {
        Self { turn, seq }
    }
}

impl fmt::Display for CallbackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.turn, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_ids_are_distinct_and_round_trip() {
        let a = TurnId::new();
        let b = TurnId::new();
        assert_ne!(a, b);
        let back: TurnId = serde_json::from_value(serde_json::to_value(a).unwrap()).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn callback_id_carries_its_turn() {
        let t = TurnId::new();
        let id = CallbackId::new(t, 3);
        assert_eq!(id.turn, t);
        assert_eq!(id.to_string(), format!("{t}:3"));
        let back: CallbackId = serde_json::from_value(serde_json::to_value(id).unwrap()).unwrap();
        assert_eq!(back, id);
    }
}
