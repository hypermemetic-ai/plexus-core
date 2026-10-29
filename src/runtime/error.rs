//! The error envelope (PLX-80 / M1·D) and the pre-flight entry errors.
//!
//! # The envelope IS the terminal
//!
//! PLX-73's turn contract says a turn emits zero or more updates and exactly
//! one terminal carrying a [`StopReason`]. A failure is not a second channel
//! and not a stream that stops early: it is that same terminal, with
//! [`StopKind::Failed`](crate::ir::StopKind::Failed) and a **structured**
//! payload.
//!
//! That is why [`TurnError`] carries [`TurnError::details`] as an arbitrary
//! `serde_json::Value` produced from the handler's own error type. The
//! counterfactual being deleted is the convention this codebase has today —
//! `PlexusError::ExecutionError(String)` — where a typed domain error is
//! `format!`ed at the boundary and every field a caller might have branched on
//! is gone by the time it reaches the wire.
//!
//! ```
//! use plexus_core::ir::StopKind;
//! use plexus_core::runtime::TurnError;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct QuotaExceeded { limit: u32, observed: u32, window: String }
//!
//! let domain = QuotaExceeded { limit: 100, observed: 137, window: "1h".into() };
//! let err = TurnError::structured("app.quota_exceeded", "quota exceeded", &domain)
//!     .retryable(true);
//!
//! let stop = err.into_stop_reason();
//! assert_eq!(stop.kind(), StopKind::Failed);
//!
//! // The payload is structure, not prose: it deserializes straight back.
//! let envelope: TurnError = serde_json::from_value(stop.error().unwrap().clone()).unwrap();
//! let back: QuotaExceeded = serde_json::from_value(envelope.details.unwrap()).unwrap();
//! assert_eq!(back, domain);
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ir::{StopDetail, StopReason};

use super::ids::CallbackId;

// ===========================================================================
// Reserved codes
// ===========================================================================

/// Error codes the runtime itself emits.
///
/// All are namespaced under `plexus.`; domain code should namespace its own
/// (`"app.quota_exceeded"`). Nothing enforces the convention — the runtime does
/// not own other vocabularies, exactly as [`StopDetail`] does not.
pub mod codes {
    /// No such method on the activation.
    pub const METHOD_NOT_FOUND: &str = "plexus.method_not_found";
    /// The IR declares the method but the handler table has no entry for it.
    pub const HANDLER_MISSING: &str = "plexus.handler_missing";
    /// Params could not be decoded into the handler's request type.
    pub const INVALID_PARAMS: &str = "plexus.invalid_params";
    /// The method requires authentication and none was supplied.
    pub const UNAUTHENTICATED: &str = "plexus.unauthenticated";
    /// The peer has not advertised a callback the method declares.
    pub const CAPABILITY_MISMATCH: &str = "plexus.capability_mismatch";
    /// The handler panicked, or its task was aborted.
    pub const HANDLER_PANICKED: &str = "plexus.handler_panicked";
    /// A server-to-client callback could not be completed.
    pub const CALLBACK_FAILED: &str = "plexus.callback_failed";

    // -----------------------------------------------------------------------
    // PLX-133 item 8 — codes the runtime already emitted but never declared.
    //
    // `plexus.` is reserved for the runtime (PLX-114), and these four were being
    // emitted as bare string literals: three from `runtime::handler` and one
    // from the code plexus-macros generates. Undeclared, they were reserved-
    // namespace codes that no consumer could discover from this module, which is
    // the module's entire job. Declaring them is additive — no code string
    // changes, so no client branching on a code is affected.
    // -----------------------------------------------------------------------

    /// A handler returned an error the macro-generated arm could not attribute
    /// to a domain type. Emitted from plexus-macros' generated handler.
    pub const EXECUTION_ERROR: &str = "plexus.execution_error";
    /// The turn's terminal value could not be serialized.
    pub const TERMINAL_UNSERIALIZABLE: &str = "plexus.terminal_unserializable";
    /// An update could not be serialized, so the turn fails rather than
    /// silently dropping it.
    pub const UPDATE_UNSERIALIZABLE: &str = "plexus.update_unserializable";
    /// An update was emitted after the turn's channel had closed.
    pub const TURN_CLOSED: &str = "plexus.turn_closed";
    /// The error envelope itself could not be serialized when rendering the
    /// terminal's [`super::StopReason`]. Not named by PLX-133, but found by its
    /// own criterion-6 grep and in exactly the same class as the four above.
    pub const ERROR_ENVELOPE_UNSERIALIZABLE: &str = "plexus.error_envelope_unserializable";
}

// ===========================================================================
// TurnError
// ===========================================================================

/// The structured error a failed turn's terminal carries.
///
/// Serializable both ways so an error can cross a process boundary and be
/// re-examined — the property a `String` message does not have.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TurnError {
    /// Stable machine token, e.g. `"app.quota_exceeded"`. Branch on this.
    pub code: String,

    /// Human-readable summary. For humans; never the only copy of a fact.
    pub message: String,

    /// Whether retrying could plausibly succeed, when the producer knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,

    /// The handler's own error value, serialized. This is the field that makes
    /// the envelope structured rather than flattened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,

    /// Additional structured context the runtime or the handler attaches.
    /// A `BTreeMap` (never a `HashMap`) so its serialization is
    /// insertion-order independent, matching [`StopDetail`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, Value>,
}

impl TurnError {
    /// An error with a code and a message and nothing else.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: None,
            details: None,
            context: BTreeMap::new(),
        }
    }

    /// An error carrying the handler's own typed error value.
    ///
    /// This is the constructor the error envelope exists for: `E` is serialized
    /// into [`details`](Self::details) and survives the round-trip to the wire
    /// with every field intact.
    ///
    /// If `E` fails to serialize the error is still produced — with the
    /// serialization failure recorded under `context["details_error"]` rather
    /// than swallowed, because losing an error while reporting an error is the
    /// worst available outcome.
    pub fn structured<E: Serialize + ?Sized>(
        code: impl Into<String>,
        message: impl Into<String>,
        details: &E,
    ) -> Self {
        let mut err = Self::new(code, message);
        match serde_json::to_value(details) {
            Ok(v) => err.details = Some(v),
            Err(e) => {
                err.context
                    .insert("details_error".into(), Value::String(e.to_string()));
            }
        }
        err
    }

    /// Mark the error retryable (or not).
    pub fn retryable(mut self, r: bool) -> Self {
        self.retryable = Some(r);
        self
    }

    /// Attach a structured detail payload.
    pub fn with_details(mut self, v: Value) -> Self {
        self.details = Some(v);
        self
    }

    /// Attach one context entry.
    pub fn with_context(mut self, k: impl Into<String>, v: Value) -> Self {
        self.context.insert(k.into(), v);
        self
    }

    /// Recover the handler's typed error from [`details`](Self::details).
    ///
    /// Returns `None` when there is no payload or it is not an `E`.
    pub fn details_as<E: DeserializeOwned>(&self) -> Option<E> {
        self.details
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
    }

    /// Params that did not decode into the handler's request type.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, message)
    }

    /// A callback that could not be completed.
    pub fn callback_failed(message: impl Into<String>) -> Self {
        Self::new(codes::CALLBACK_FAILED, message)
    }

    /// Render as the terminal's [`StopReason`].
    ///
    /// The whole envelope — code, message, retryability, details, context —
    /// becomes [`StopReason::Failed::error`], and a `StopDetail` echoing the
    /// code rides alongside so generic tooling that only reads
    /// [`StopReason::detail`] still gets the machine token.
    pub fn into_stop_reason(self) -> StopReason {
        let detail = StopDetail::new(self.code.clone()).with_message(self.message.clone());
        let error = serde_json::to_value(&self).unwrap_or_else(|e| {
            serde_json::json!({
                "code": codes::ERROR_ENVELOPE_UNSERIALIZABLE,
                "message": e.to_string(),
            })
        });
        StopReason::failed(error).with_detail(detail)
    }
}

impl fmt::Display for TurnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TurnError {}

/// Decode `params` into a handler's request type, producing the envelope's
/// `invalid_params` error on failure.
///
/// This is one of the concerns that used to be re-emitted per method arm by
/// `quote!` templates. It is ordinary, breakpointable, unit-tested Rust here;
/// the *call* to it stays inside each handler closure, which is where the
/// monomorphization genuinely belongs.
pub fn decode_params<T: DeserializeOwned>(params: Value) -> Result<T, TurnError> {
    serde_json::from_value(params).map_err(|e| {
        TurnError::invalid_params(format!(
            "could not decode params into `{}`: {e}",
            std::any::type_name::<T>()
        ))
    })
}

/// Decode one named field out of a params object.
///
/// The shape the legacy dispatch path uses for multi-parameter methods:
/// params arrive as a JSON object keyed by parameter name.
pub fn decode_param<T: DeserializeOwned>(params: &Value, name: &str) -> Result<T, TurnError> {
    let field = params.get(name).cloned().unwrap_or(Value::Null);
    serde_json::from_value(field).map_err(|e| {
        TurnError::invalid_params(format!(
            "could not decode param `{name}` into `{}`: {e}",
            std::any::type_name::<T>()
        ))
    })
}

// ===========================================================================
// EntryError — the pre-flight failures
// ===========================================================================

/// Why [`entry`](super::entry) refused to open a turn at all.
///
/// These are distinct from [`TurnError`] on purpose. A `TurnError` is a turn
/// that ran and failed, and it arrives as a terminal on the event stream. An
/// `EntryError` means **no turn exists**: nothing was dispatched, no handler
/// ran, no cancellation token was minted, and there is no stream to carry a
/// terminal on. Collapsing the two would force every caller to open a stream
/// just to learn that a method name was wrong.
///
/// Each variant converts to a `TurnError` ([`EntryError::to_turn_error`]) for
/// callers that want one uniform envelope, and to [`crate::PlexusError`] for
/// the bridge into the legacy dispatch surface.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    /// The activation IR declares no method by that name.
    #[error("method not found: {activation}.{method}")]
    MethodNotFound {
        /// Namespace of the activation that was addressed.
        activation: String,
        /// The method name that was not found.
        method: String,
    },

    /// The IR declares the method but the handler table has no closure for it.
    ///
    /// This is a *wiring* bug — an IR and a handler table that disagree — and
    /// is deliberately not reported as `MethodNotFound`, which would hide it
    /// behind an ordinary client mistake.
    #[error("handler missing for declared method {activation}.{method}: the IR and the handler table disagree")]
    HandlerMissing {
        /// Namespace of the activation.
        activation: String,
        /// The declared method with no handler.
        method: String,
    },

    /// The method requires authentication and the request carried none.
    #[error("authentication required for method `{method}`")]
    Unauthenticated {
        /// The method that was refused.
        method: String,
    },

    /// The peer cannot serve a callback the method declares.
    ///
    /// Raised **before** the handler runs, which is the entire point: a turn
    /// that would have discovered mid-flight that its peer cannot answer
    /// `fs/write_text_file` never starts.
    #[error("capability mismatch on `{method}`: peer does not advertise {missing:?} (advertised: {advertised:?})")]
    CapabilityMismatch {
        /// The method that was refused.
        method: String,
        /// Callbacks the method declares that the peer did not advertise.
        missing: Vec<String>,
        /// What the peer did advertise.
        advertised: Vec<String>,
    },
}

impl EntryError {
    /// The machine token for this failure — the same vocabulary
    /// [`TurnError::code`] uses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MethodNotFound { .. } => codes::METHOD_NOT_FOUND,
            Self::HandlerMissing { .. } => codes::HANDLER_MISSING,
            Self::Unauthenticated { .. } => codes::UNAUTHENTICATED,
            Self::CapabilityMismatch { .. } => codes::CAPABILITY_MISMATCH,
        }
    }

    /// Render as the structured envelope, for callers that want one shape.
    pub fn to_turn_error(&self) -> TurnError {
        let mut e = TurnError::new(self.code(), self.to_string());
        match self {
            Self::MethodNotFound { activation, method }
            | Self::HandlerMissing { activation, method } => {
                e = e
                    .with_context("activation", Value::String(activation.clone()))
                    .with_context("method", Value::String(method.clone()));
            }
            Self::Unauthenticated { method } => {
                e = e.with_context("method", Value::String(method.clone()));
            }
            Self::CapabilityMismatch {
                method,
                missing,
                advertised,
            } => {
                e = e
                    .with_context("method", Value::String(method.clone()))
                    .with_context(
                        "missing",
                        Value::Array(missing.iter().cloned().map(Value::String).collect()),
                    )
                    .with_context(
                        "advertised",
                        Value::Array(advertised.iter().cloned().map(Value::String).collect()),
                    );
            }
        }
        e
    }
}

impl From<EntryError> for crate::PlexusError {
    fn from(e: EntryError) -> Self {
        match &e {
            EntryError::MethodNotFound { activation, method } => {
                crate::PlexusError::MethodNotFound {
                    activation: activation.clone(),
                    method: method.clone(),
                }
            }
            EntryError::HandlerMissing { .. } => crate::PlexusError::ExecutionError(e.to_string()),
            EntryError::Unauthenticated { .. } => {
                crate::PlexusError::Unauthenticated(e.to_string())
            }
            // There is no `PlexusError` variant for a capability mismatch and
            // PLX-80 does not add one: `plexus.rs` is not this build's surface.
            // `InvalidParams` is the closest honest legacy rendering — the call
            // as issued cannot be served — and the structured form is available
            // via `EntryError::to_turn_error`.
            EntryError::CapabilityMismatch { .. } => {
                crate::PlexusError::InvalidParams(e.to_string())
            }
        }
    }
}

// ===========================================================================
// RespondError
// ===========================================================================

/// Why a callback response could not be delivered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RespondError {
    /// The response was addressed to a different turn.
    ///
    /// This is the cross-talk guard. It is an error, not a best-effort
    /// re-route: a response that names the wrong turn is a bug in the peer,
    /// and silently applying it to the right-looking sequence number in the
    /// current turn would be the worst possible recovery.
    #[error("callback response addressed to turn {actual} was offered to turn {expected}")]
    WrongTurn {
        /// The turn that was asked to accept it.
        expected: super::ids::TurnId,
        /// The turn the response named.
        actual: super::ids::TurnId,
    },

    /// No callback with that id is in flight: it was never issued, it was
    /// already answered, or the turn resolved it on cancellation.
    #[error("no in-flight callback {0}")]
    UnknownCallback(CallbackId),

    /// The turn has resolved; its callback router accepts nothing further.
    #[error("turn {0} has already resolved")]
    TurnEnded(super::ids::TurnId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::StopKind;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Domain {
        limit: u32,
        observed: u32,
        nested: Vec<String>,
    }

    #[test]
    fn structured_details_round_trip_through_the_terminal() {
        let d = Domain {
            limit: 3,
            observed: 9,
            nested: vec!["a".into(), "b".into()],
        };
        let stop = TurnError::structured("app.x", "boom", &d).into_stop_reason();
        assert_eq!(stop.kind(), StopKind::Failed);

        let env: TurnError = serde_json::from_value(stop.error().unwrap().clone()).unwrap();
        assert_eq!(env.code, "app.x");
        assert_eq!(env.details_as::<Domain>().unwrap(), d);
        // The detail echoes the code for tooling that reads only that.
        assert_eq!(stop.detail().unwrap().code, "app.x");
    }

    #[test]
    fn decode_params_reports_the_target_type() {
        let e = decode_params::<u32>(Value::String("nope".into())).unwrap_err();
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert!(e.message.contains("u32"), "{}", e.message);
    }

    #[test]
    fn decode_param_names_the_field() {
        let params = serde_json::json!({"n": "not a number"});
        let e = decode_param::<u32>(&params, "n").unwrap_err();
        assert!(e.message.contains("`n`"), "{}", e.message);
    }

    #[test]
    fn entry_errors_carry_structured_context() {
        let e = EntryError::CapabilityMismatch {
            method: "prompt".into(),
            missing: vec!["fs/write_text_file".into()],
            advertised: vec!["fs/read_text_file".into()],
        };
        let t = e.to_turn_error();
        assert_eq!(t.code, codes::CAPABILITY_MISMATCH);
        assert_eq!(
            t.context.get("missing").unwrap(),
            &serde_json::json!(["fs/write_text_file"])
        );
    }

    #[test]
    fn entry_error_maps_onto_the_legacy_error_type() {
        let e = EntryError::MethodNotFound {
            activation: "echo".into(),
            method: "nope".into(),
        };
        assert!(matches!(
            crate::PlexusError::from(e),
            crate::PlexusError::MethodNotFound { .. }
        ));
    }

    #[test]
    fn context_serialization_is_insertion_order_independent() {
        let a = TurnError::new("c", "m")
            .with_context("z", Value::Bool(true))
            .with_context("a", Value::Bool(false));
        let b = TurnError::new("c", "m")
            .with_context("a", Value::Bool(false))
            .with_context("z", Value::Bool(true));
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
