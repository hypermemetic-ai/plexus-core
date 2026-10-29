//! What a turn emits (PLX-80 / M1·C).
//!
//! # The update/terminal split is a type, not a convention
//!
//! Today a plexus call is "a stream that ends", and a client infers why it
//! ended from whether the last item happened to be an error. PLX-73's turn
//! contract replaces that with a shape the wire can state:
//!
//! - **zero or more** [`TurnEvent::Update`]s,
//! - **at most** one interleaved [`TurnEvent::Callback`] per outstanding
//!   server-to-client request,
//! - and **exactly one** [`TurnEvent::Terminal`], always last, always carrying
//!   a [`StopReason`].
//!
//! The enum is internally tagged on `event`, so an update and a terminal are
//! distinguishable on the wire by a consumer that knows nothing else:
//! `{"event":"update",...}` versus `{"event":"terminal","stop":{...}}`.
//!
//! The runtime — not the handler — is what guarantees the "exactly one
//! terminal, always last" half. See [`super::entry`].

use std::pin::Pin;

use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ir::StopReason;

use super::ids::{CallbackId, TurnId};

/// One item on a turn's event stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TurnEvent {
    /// An intermediate value the turn produced. Notification-shaped: an update
    /// is *not* a result, and a client that ignores updates entirely still gets
    /// a well-formed turn.
    Update {
        /// The turn this update belongs to.
        turn: TurnId,
        /// Monotonic per-turn update counter, starting at 0. Assigned by the
        /// runtime, never by the handler, so it cannot skip or repeat.
        seq: u64,
        /// The payload.
        content: Value,
    },

    /// A server-to-client request awaiting a correlated response.
    ///
    /// The peer answers with [`TurnControl::respond`](super::TurnControl::respond)
    /// (or the transport-specific equivalent) quoting `id` exactly.
    Callback {
        /// Correlation id. Embeds the turn — see [`CallbackId`].
        id: CallbackId,
        /// Wire name of the callback, e.g. `"fs/read_text_file"`.
        name: String,
        /// The request payload.
        request: Value,
    },

    /// The turn's single terminal value. Always the last event.
    Terminal {
        /// The turn that resolved.
        turn: TurnId,
        /// Why it stopped.
        stop: StopReason,
        /// The terminal value, when the method declares one
        /// ([`MethodIr::terminal`](crate::ir::MethodIr::terminal)).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
    },
}

impl TurnEvent {
    /// Build an update.
    pub fn update(turn: TurnId, seq: u64, content: Value) -> Self {
        Self::Update { turn, seq, content }
    }

    /// Build a callback request.
    pub fn callback(id: CallbackId, name: impl Into<String>, request: Value) -> Self {
        Self::Callback {
            id,
            name: name.into(),
            request,
        }
    }

    /// Build a terminal.
    pub fn terminal(turn: TurnId, stop: StopReason, value: Option<Value>) -> Self {
        Self::Terminal { turn, stop, value }
    }

    /// The turn this event belongs to.
    pub fn turn(&self) -> TurnId {
        match self {
            Self::Update { turn, .. } | Self::Terminal { turn, .. } => *turn,
            Self::Callback { id, .. } => id.turn,
        }
    }

    /// Whether this is the terminal event.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }

    /// Whether this is an update.
    pub fn is_update(&self) -> bool {
        matches!(self, Self::Update { .. })
    }

    /// Whether this is a server-to-client callback request.
    pub fn is_callback(&self) -> bool {
        matches!(self, Self::Callback { .. })
    }

    /// The stop reason, present only on the terminal.
    pub fn stop_reason(&self) -> Option<&StopReason> {
        match self {
            Self::Terminal { stop, .. } => Some(stop),
            _ => None,
        }
    }

    /// The stable wire tag: `"update"`, `"callback"` or `"terminal"`.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Update { .. } => "update",
            Self::Callback { .. } => "callback",
            Self::Terminal { .. } => "terminal",
        }
    }
}

/// A boxed stream of [`TurnEvent`]s — the shape a turn hands its consumer.
pub type TurnStream = Pin<Box<dyn Stream<Item = TurnEvent> + Send>>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn update_and_terminal_are_distinguishable_on_the_wire() {
        let t = TurnId::new();
        let u = serde_json::to_value(TurnEvent::update(t, 0, json!({"chunk": "hi"}))).unwrap();
        let term =
            serde_json::to_value(TurnEvent::terminal(t, StopReason::complete(), None)).unwrap();

        assert_eq!(u["event"], json!("update"));
        assert_eq!(term["event"], json!("terminal"));
        assert_eq!(term["stop"], json!({"kind": "complete"}));
        assert!(u.get("stop").is_none(), "an update carries no stop reason");
        assert!(term.get("value").is_none(), "absent value is omitted");
    }

    #[test]
    fn callback_event_carries_its_correlation_id() {
        let t = TurnId::new();
        let ev = TurnEvent::callback(CallbackId::new(t, 2), "fs/read_text_file", json!({}));
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["event"], json!("callback"));
        assert_eq!(v["id"]["seq"], json!(2));
        assert_eq!(ev.turn(), t);
        let back: TurnEvent = serde_json::from_value(v).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn classifiers_agree_with_the_tags() {
        let t = TurnId::new();
        let events = [
            TurnEvent::update(t, 0, json!(1)),
            TurnEvent::callback(CallbackId::new(t, 0), "x", json!(1)),
            TurnEvent::terminal(t, StopReason::complete(), Some(json!(1))),
        ];
        let tags: Vec<_> = events.iter().map(|e| e.tag()).collect();
        assert_eq!(tags, ["update", "callback", "terminal"]);
        assert!(events[0].is_update());
        assert!(events[1].is_callback());
        assert!(events[2].is_terminal());
        assert!(events[2].stop_reason().is_some());
        assert!(events[0].stop_reason().is_none());
    }
}
