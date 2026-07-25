//! Why a turn stopped — the terminal value's reason (PLX-77 / M1·A2).
//!
//! # The contract
//!
//! Adopting ACP turn semantics (PLX-73 `q-acp-as-communication-model`) makes
//! every plexus call a **turn**: zero or more updates, then exactly one
//! terminal value carrying a [`StopReason`].
//!
//! PLX-73's "Turn contract" section fixes the design as a **small closed core
//! plus open detail**, on the HTTP precedent (a closed 2xx/4xx/5xx class plus
//! specific codes):
//!
//! - [`StopKind::Complete`] — the turn did what was asked.
//! - [`StopKind::Cancelled`] — cancel was delivered and the turn resolved.
//!   **Cancellation is cooperative**: the framework guarantees the signal was
//!   delivered, the turn stopped waiting, and in-flight callbacks resolved
//!   uniformly. It does *not* guarantee the underlying work stopped — a spawned
//!   subprocess or an in-flight model call is the implementor's responsibility.
//!   `Cancelled` means "the turn stopped waiting", and this module says so
//!   rather than letting the name imply more.
//! - [`StopKind::Refused`] — a considered NO (policy, permission denied,
//!   guardrail). **Not an error**; today this gets flattened into one.
//! - [`StopKind::Limited`] — a bound was hit (tokens, turns, time, size, rate).
//! - [`StopKind::Failed`] — a structured typed error.
//!
//! Generic consumers (synapse's renderer, REST status mapping, metrics, logs)
//! match on the five core kinds and are never surprised. Domain vocabulary —
//! ACP's `end_turn | cancelled | refusal | max_tokens | max_turn_requests`, or
//! anything a future agent protocol invents — rides in [`StopDetail`], so a new
//! reason is additive and adds **no core variant**.
//!
//! # Scope
//!
//! This is a type, not a mechanism. PLX-77 does not wire `StopReason` into
//! dispatch, cancellation, or the error envelope — those are builds C and D.
//! It is defined here so those builds share one vocabulary rather than each
//! inventing their own.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The closed core kind set, without any payload.
///
/// Exists so generic tooling can `match` (or key a metric, or map to an HTTP
/// status) on the classification alone. [`StopReason::kind`] projects onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopKind {
    /// The turn did what was asked.
    Complete,
    /// Cancel was delivered and the turn resolved. Cooperative — see the
    /// [module docs](self).
    Cancelled,
    /// A considered NO. Not an error.
    Refused,
    /// A bound was hit.
    Limited,
    /// A structured typed error.
    Failed,
}

impl StopKind {
    /// The stable snake_case wire token.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
            Self::Limited => "limited",
            Self::Failed => "failed",
        }
    }

    /// Every core kind, in declaration order. Handy for exhaustiveness tests
    /// and for tooling that enumerates the closed set.
    pub const ALL: [StopKind; 5] = [
        Self::Complete,
        Self::Cancelled,
        Self::Refused,
        Self::Limited,
        Self::Failed,
    ];
}

impl fmt::Display for StopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Open, domain-specific elaboration of a [`StopReason`].
///
/// This is the pressure-release valve that keeps [`StopKind`] closed. A
/// protocol that needs to say "I stopped because `max_turn_requests`" says it
/// here, under [`StopKind::Limited`], and every generic consumer still
/// understands the turn as "hit a bound".
///
/// `code` is the domain token; namespacing it (`"acp:max_turn_requests"`) is
/// the recommended convention, and deliberately *not* enforced — the IR does
/// not own other protocols' vocabularies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopDetail {
    /// Domain vocabulary token, e.g. `"acp:max_turn_requests"`.
    pub code: String,

    /// Human-readable elaboration, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Arbitrary structured data. A `BTreeMap` (never a `HashMap`) so its
    /// iteration order is insertion-independent, matching the rest of the IR.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, serde_json::Value>,
}

impl StopDetail {
    /// A detail carrying only its domain code.
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: None,
            data: BTreeMap::new(),
        }
    }

    /// Attach a human-readable message.
    pub fn with_message(mut self, m: impl Into<String>) -> Self {
        self.message = Some(m.into());
        self
    }

    /// Attach one structured datum.
    pub fn with_data(mut self, k: impl Into<String>, v: serde_json::Value) -> Self {
        self.data.insert(k.into(), v);
        self
    }
}

/// Why a turn stopped: one of five closed core kinds, plus open detail.
///
/// Serialized internally tagged on `kind`, so the wire form of a plain
/// completion is `{"kind":"complete"}` and a limited turn is
/// `{"kind":"limited","detail":{"code":"acp:max_tokens"}}`. A consumer that
/// only knows the core kinds reads the tag and ignores the rest.
///
/// Every variant may carry [`StopDetail`] — including `Complete` and
/// `Cancelled`, which PLX-73's vocabulary mapping needs (ACP distinguishes
/// `end_turn` from other successful completions). Uniform detail is what makes
/// "new reasons are additive" true for *all* kinds rather than only the two
/// that happened to need it first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StopReason {
    /// The turn did what was asked.
    Complete {
        /// Optional domain elaboration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<StopDetail>,
    },

    /// Cancel was delivered and the turn resolved. Cooperative — this does not
    /// assert that the underlying work stopped.
    Cancelled {
        /// Optional domain elaboration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<StopDetail>,
    },

    /// A considered NO — policy, permission denied, guardrail. Not an error.
    Refused {
        /// Optional domain elaboration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<StopDetail>,
    },

    /// A bound was hit: tokens, turns, time, size, rate.
    Limited {
        /// Optional domain elaboration — which bound, and by how much.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<StopDetail>,
    },

    /// A structured typed error.
    ///
    /// The payload is the error envelope build D will define; it is a
    /// `serde_json::Value` here so this type does not have to wait for that
    /// build, and so an IR document can round-trip an error it does not have a
    /// Rust type for.
    Failed {
        /// The structured error payload.
        error: serde_json::Value,
        /// Optional domain elaboration alongside the error.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<StopDetail>,
    },
}

impl StopReason {
    /// A bare successful completion.
    pub fn complete() -> Self {
        Self::Complete { detail: None }
    }

    /// A bare cancellation.
    pub fn cancelled() -> Self {
        Self::Cancelled { detail: None }
    }

    /// A refusal with domain detail.
    pub fn refused(detail: StopDetail) -> Self {
        Self::Refused {
            detail: Some(detail),
        }
    }

    /// A limit stop with domain detail.
    pub fn limited(detail: StopDetail) -> Self {
        Self::Limited {
            detail: Some(detail),
        }
    }

    /// A failure carrying a structured error payload.
    pub fn failed(error: serde_json::Value) -> Self {
        Self::Failed {
            error,
            detail: None,
        }
    }

    /// Attach (or replace) the domain detail on any kind.
    pub fn with_detail(mut self, d: StopDetail) -> Self {
        match &mut self {
            Self::Complete { detail }
            | Self::Cancelled { detail }
            | Self::Refused { detail }
            | Self::Limited { detail }
            | Self::Failed { detail, .. } => *detail = Some(d),
        }
        self
    }

    /// Project onto the closed core kind — what generic tooling matches on.
    pub fn kind(&self) -> StopKind {
        match self {
            Self::Complete { .. } => StopKind::Complete,
            Self::Cancelled { .. } => StopKind::Cancelled,
            Self::Refused { .. } => StopKind::Refused,
            Self::Limited { .. } => StopKind::Limited,
            Self::Failed { .. } => StopKind::Failed,
        }
    }

    /// The domain detail, if any.
    pub fn detail(&self) -> Option<&StopDetail> {
        match self {
            Self::Complete { detail }
            | Self::Cancelled { detail }
            | Self::Refused { detail }
            | Self::Limited { detail }
            | Self::Failed { detail, .. } => detail.as_ref(),
        }
    }

    /// The structured error payload, present only on [`StopReason::Failed`].
    pub fn error(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Failed { error, .. } => Some(error),
            _ => None,
        }
    }

    /// Whether the turn ended the way the caller asked for.
    ///
    /// `Refused` is deliberately **not** success and **not** an error — it is a
    /// considered NO, which is exactly the distinction PLX-73 recorded as being
    /// flattened away today.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

impl Default for StopReason {
    fn default() -> Self {
        Self::complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip(r: &StopReason) -> StopReason {
        let v = serde_json::to_value(r).unwrap();
        serde_json::from_value(v).unwrap()
    }

    /// PLX-77 AC7: every core kind round-trips losslessly, including `Failed`
    /// with a structured payload and `Limited` with detail.
    #[test]
    fn ac7_every_core_kind_round_trips_losslessly() {
        let samples = [
            StopReason::complete(),
            StopReason::complete().with_detail(StopDetail::new("acp:end_turn")),
            StopReason::cancelled(),
            StopReason::refused(
                StopDetail::new("acp:refusal")
                    .with_message("the user denied the permission request")
                    .with_data("tool", json!("fs/write_text_file")),
            ),
            StopReason::limited(
                StopDetail::new("acp:max_turn_requests")
                    .with_message("turn request budget exhausted")
                    .with_data("limit", json!(64))
                    .with_data("observed", json!(64)),
            ),
            StopReason::failed(json!({
                "code": "PLEXUS_UPSTREAM",
                "message": "upstream refused the connection",
                "retryable": true,
                "context": { "attempts": 3 },
            })),
            StopReason::failed(json!({"code": "X"}))
                .with_detail(StopDetail::new("acp:internal")),
        ];

        // Every core kind is exercised.
        let covered: Vec<StopKind> = StopKind::ALL
            .into_iter()
            .filter(|k| samples.iter().any(|s| s.kind() == *k))
            .collect();
        assert_eq!(covered.len(), StopKind::ALL.len(), "all kinds covered");

        for s in &samples {
            let back = round_trip(s);
            assert_eq!(&back, s, "lossless round-trip for {s:?}");
            assert_eq!(back.kind(), s.kind());
            assert_eq!(back.detail(), s.detail());
            assert_eq!(back.error(), s.error());
        }
    }

    #[test]
    fn ac7_wire_form_is_kind_tagged_and_omits_absent_detail() {
        assert_eq!(
            serde_json::to_value(StopReason::complete()).unwrap(),
            json!({"kind": "complete"})
        );
        assert_eq!(
            serde_json::to_value(StopReason::limited(StopDetail::new("acp:max_tokens"))).unwrap(),
            json!({"kind": "limited", "detail": {"code": "acp:max_tokens"}})
        );
        assert_eq!(
            serde_json::to_value(StopReason::failed(json!({"code": "E"}))).unwrap(),
            json!({"kind": "failed", "error": {"code": "E"}})
        );
    }

    /// Domain vocabulary rides in `detail`; the core set never grows for it.
    #[test]
    fn domain_vocabulary_needs_no_new_core_variant() {
        // The full ACP v1 stop-reason vocabulary, mapped onto the closed core.
        let acp: [(&str, StopKind); 5] = [
            ("end_turn", StopKind::Complete),
            ("cancelled", StopKind::Cancelled),
            ("refusal", StopKind::Refused),
            ("max_tokens", StopKind::Limited),
            ("max_turn_requests", StopKind::Limited),
        ];
        for (token, kind) in acp {
            let detail = StopDetail::new(format!("acp:{token}"));
            let r = match kind {
                StopKind::Complete => StopReason::complete().with_detail(detail),
                StopKind::Cancelled => StopReason::cancelled().with_detail(detail),
                StopKind::Refused => StopReason::refused(detail),
                StopKind::Limited => StopReason::limited(detail),
                StopKind::Failed => StopReason::failed(json!(null)).with_detail(detail),
            };
            assert_eq!(r.kind(), kind);
            assert_eq!(r.detail().unwrap().code, format!("acp:{token}"));
            assert_eq!(round_trip(&r), r);
        }
    }

    #[test]
    fn refused_is_neither_success_nor_error() {
        let r = StopReason::refused(StopDetail::new("policy:denied"));
        assert!(!r.is_success());
        assert!(r.error().is_none(), "a refusal carries no error payload");
        assert!(StopReason::complete().is_success());
        assert!(!StopReason::cancelled().is_success());
    }

    #[test]
    fn detail_data_order_is_insertion_independent() {
        let a = StopDetail::new("c").with_data("z", json!(1)).with_data("a", json!(2));
        let b = StopDetail::new("c").with_data("a", json!(2)).with_data("z", json!(1));
        assert_eq!(a, b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
