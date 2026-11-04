//! RETURNS-36 · a child that speaks plexus-wire's spec as main wrote it.
//!
//! plexus-core 0.8 writes the precise-returns wire (RETURNS-1): a method
//! schema states its `cardinality` and always has `returns`; a progress
//! frame carries the call's `content_type` and the method's typed `content`;
//! an error frame carries a typed `error` (a `RemoteError`) beside spec/05's
//! `message`, `code` and `error_kind` fields. Its types read nothing less.
//!
//! A child is another program, and plexus-wire's spec (spec/03, 05, 07) —
//! what every server kit implements, the reference children included — has
//! not moved to that wire yet: its schema says `streaming`, its progress
//! frame `{message, percentage}`, its error frame spec/05's fields alone. The
//! seam reads such a peer into the 0.8 types here, at the boundary, from
//! what the peer itself declared — never guessing:
//!
//! | the peer sends | read as |
//! |---|---|
//! | a method without `cardinality` | `"many"` when it says `"streaming": true`, `"one"` when `false` (its own declaration); one that says neither is refused |
//! | a method without `returns` | the empty schema: no type given (what `MethodSchema::new` starts at) |
//! | a progress frame without `content` | `content` = `{message, percentage}` (the default progress type, `Note`) |
//! | an error frame without `error` | `error` from its `error_kind` and fields, else its `code` ([`remote_error_of`]) |
//!
//! A peer that already speaks 0.8 passes through untouched: each rule only
//! fills a field the peer left out. An item that reads as 0.8 is never
//! looked at again (the relay's path stays one parse).

use plexus_client::{DenyReason, ParamProblem, RemoteError};
use serde_json::{Map, Value};

/// A child's schema (its JSON) with each method read into 0.8's shape; a
/// method that states neither `cardinality` nor `streaming` is refused,
/// naming it (plexus-protocol's `cardinalityOf`: one rule on both sides).
pub(super) fn schema(mut raw: Value) -> Result<Value, String> {
    if let Some(methods) = raw.get_mut("methods").and_then(Value::as_array_mut) {
        for m in methods.iter_mut().filter_map(Value::as_object_mut) {
            method(m)?;
        }
    }
    Ok(raw)
}

fn method(m: &mut Map<String, Value>) -> Result<(), String> {
    if !m.contains_key("cardinality") {
        let many = match m.get("streaming") {
            Some(Value::Bool(b)) => *b,
            _ => {
                let name = m.get("name").and_then(Value::as_str).unwrap_or("?");
                return Err(format!(
                    "its method `{name}` states neither cardinality (plexus 0.8) nor streaming (0.7.0)"
                ));
            }
        };
        m.insert("cardinality".into(), Value::from(if many { "many" } else { "one" }));
    }
    m.remove("streaming");
    m.entry("returns").or_insert(Value::Object(Map::new()));
    Ok(())
}

/// An item that did not read as 0.8: the same item in 0.8's shape, when it
/// is a progress or an error frame missing what 0.8 adds; `None` otherwise
/// (an item kind this service does not know is skipped, spec/03).
pub(super) fn item(raw: &str, content_type: &str) -> Option<Value> {
    let mut v: Value = serde_json::from_str(raw).ok()?;
    let o = v.as_object_mut()?;
    match o.get("type").and_then(Value::as_str)? {
        "progress" if !o.contains_key("content") => {
            let mut note = Map::new();
            note.insert("message".into(), o.remove("message").unwrap_or(Value::from("")));
            if let Some(p) = o.remove("percentage") {
                note.insert("percentage".into(), p);
            }
            o.insert("content".into(), Value::Object(note));
            o.entry("content_type").or_insert(Value::from(content_type));
        }
        "error" if !o.contains_key("error") => {
            let error = remote_error_of(o);
            o.insert("error".into(), serde_json::to_value(error).ok()?);
            o.entry("message").or_insert(Value::from(""));
        }
        _ => return None,
    }
    Some(v)
}

/// spec/05's error fields as the typed [`RemoteError`] they say: by
/// `error_kind` when there is one, else by `code`; what neither names is the
/// method failing (`execution`, its `message`).
pub(super) fn remote_error_of(o: &Map<String, Value>) -> RemoteError {
    let s = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let strings = |k: &str| -> Vec<String> {
        o.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
    };
    let message = s("message");
    let code = match o.get("code") {
        Some(Value::String(c)) => c.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    match o.get("error_kind").and_then(Value::as_str).unwrap_or(code.as_str()) {
        // spec/05: activation or method not found. RETURNS-36 (review #5).
        "-32601" => not_found(&message),
        "invalid_params" | "-32602" => RemoteError::InvalidParams { param: None, problem: ParamProblem::Malformed { detail: message } },
        "unauthenticated" | "-32001" => RemoteError::Unauthenticated,
        "forbidden" | "-32003" => RemoteError::Forbidden {
            reason: match o.get("reason").and_then(Value::as_str) {
                Some("missing_scope") => DenyReason::MissingScope { scope: s("scope") },
                Some("tenant_boundary") => DenyReason::TenantBoundary,
                Some("not_accepted") => DenyReason::NotAccepted,
                _ => DenyReason::MissingGrant { grant: s("grant"), scope: s("scope"), roles: strings("roles"), held_on: strings("held_on") },
            },
        },
        "too_many_calls" => RemoteError::TooManyCalls {
            max: o.get("max").and_then(Value::as_u64).unwrap_or_default(),
            child: o.get("child").and_then(Value::as_str).map(str::to_string),
        },
        "child_unavailable" => RemoteError::ChildUnavailable { child: s("child"), reason: s("reason") },
        "child_timeout" => RemoteError::ChildTimeout {
            child: s("child"),
            timeout_ms: o.get("timeout_ms").and_then(Value::as_u64).unwrap_or_default(),
        },
        // RETURNS-36 (review #4): a kind this build does not know, by its
        // `error_kind`, keeps it and its fields; with no kind at all, the
        // method failing.
        other if o.contains_key("error_kind") => {
            let mut fields = o.clone();
            fields.remove("error_kind");
            for k in ["type", "metadata", "code", "recoverable"] {
                fields.remove(k);
            }
            RemoteError::Other(plexus_client::OtherError { kind: other.to_string(), fields })
        }
        _ => RemoteError::Execution { message },
    }
}

/// `-32601`'s two meanings, from spec/05's message (`Activation not found:
/// x`, `Method not found: a.b`); a bare one is a method not found.
fn not_found(message: &str) -> RemoteError {
    if let Some(activation) = message.strip_prefix("Activation not found: ") {
        return RemoteError::ActivationNotFound { activation: activation.trim().to_string() };
    }
    let path = message.strip_prefix("Method not found: ").unwrap_or_default().trim();
    let (activation, method) = path.rsplit_once('.').unwrap_or(("", path));
    RemoteError::MethodNotFound { activation: activation.to_string(), method: method.to_string() }
}

/// A JSON-RPC refusal's code read as spec/05's (`refused` in link.rs):
/// the same typing as an error item's.
pub(super) fn remote_error_of_code(code: i64, message: &str) -> RemoteError {
    let mut o = Map::new();
    o.insert("code".into(), Value::from(code.to_string()));
    o.insert("message".into(), Value::from(message));
    remote_error_of(&o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plexus::types::PlexusStreamItem;
    use serde_json::json;

    #[test]
    fn a_main_wire_method_reads_by_its_own_declaration() {
        let s = schema(json!({"methods": [
            {"name": "echo", "streaming": true},
            {"name": "shout", "streaming": false},
            {"name": "now", "cardinality": "many", "returns": {"type": "string"}},
        ]})).unwrap();
        assert_eq!(s["methods"][0], json!({"name": "echo", "cardinality": "many", "returns": {}}));
        assert_eq!(s["methods"][1], json!({"name": "shout", "cardinality": "one", "returns": {}}));
        assert_eq!(s["methods"][2], json!({"name": "now", "cardinality": "many", "returns": {"type": "string"}}), "0.8 untouched");
    }

    #[test]
    fn a_main_wire_error_reads_typed() {
        let raw = r#"{"type":"error","metadata":{"provenance":["echo"],"plexus_hash":"h","timestamp":1},"code":"-32003","error_kind":"forbidden","grant":"echo.shout","scope":"*","roles":["editor","admin"],"held_on":[],"message":"needs echo.shout","recoverable":false}"#;
        assert!(serde_json::from_str::<PlexusStreamItem>(raw).is_err(), "0.8 alone does not read it");
        let item: PlexusStreamItem = serde_json::from_value(item(raw, "echo.shout").unwrap()).unwrap();
        assert_eq!(item.error_kind(), Some("forbidden"));
        assert_eq!(
            item.remote_error(),
            Some(&RemoteError::Forbidden {
                reason: DenyReason::MissingGrant {
                    grant: "echo.shout".into(),
                    scope: "*".into(),
                    roles: vec!["editor".into(), "admin".into()],
                    held_on: vec![],
                }
            })
        );
    }

    #[test]
    fn a_main_wire_progress_reads_as_a_note() {
        let raw = r#"{"type":"progress","metadata":{"provenance":["echo"],"plexus_hash":"h","timestamp":1},"message":"halfway","percentage":50.0}"#;
        let v = item(raw, "echo.count").unwrap();
        assert_eq!(v["content"], json!({"message": "halfway", "percentage": 50.0}));
        assert_eq!(v["content_type"], "echo.count");
        assert!(serde_json::from_value::<PlexusStreamItem>(v).is_ok());
    }

    /// RETURNS-36 (review #4): a kind this build does not know keeps its name
    /// and its fields — menger's `too_many_writes` with `retry_after_ms`.
    #[test]
    fn an_unknown_kind_passes_through_typed() {
        let o = json!({"code": "too_many_writes", "error_kind": "too_many_writes", "retry_after_ms": 250, "message": "slow down"});
        let e = remote_error_of(o.as_object().unwrap());
        assert_eq!(e.kind(), "too_many_writes");
        assert_eq!(serde_json::to_value(&e).unwrap()["retry_after_ms"], 250, "{e:?}");
    }

    /// RETURNS-36 (review #5): `-32601` is not found, as spec/05 says — so a
    /// REST caller through the seam gets 404, not 500.
    #[test]
    fn minus_32601_is_not_found() {
        let m = json!({"code": "-32601", "message": "Method not found: echo.nosuch"});
        assert_eq!(
            remote_error_of(m.as_object().unwrap()),
            RemoteError::MethodNotFound { activation: "echo".into(), method: "nosuch".into() }
        );
        let a = json!({"code": "-32601", "message": "Activation not found: nope"});
        assert_eq!(remote_error_of(a.as_object().unwrap()), RemoteError::ActivationNotFound { activation: "nope".into() });
        let bare = json!({"code": -32601, "message": "Method not found"});
        assert!(matches!(remote_error_of(bare.as_object().unwrap()), RemoteError::MethodNotFound { .. }));
    }

    #[test]
    fn other_items_are_not_rewritten() {
        assert!(item(r#"{"type":"data","content":1}"#, "x").is_none());
        assert!(item(r#"{"type":"error","error":{"kind":"unauthenticated"}}"#, "x").is_none());
        assert!(item(r#"{"type":"unheard_of"}"#, "x").is_none());
    }
}
