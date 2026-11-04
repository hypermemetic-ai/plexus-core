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

use plexus_client::RemoteError;
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
    let v: Value = serde_json::from_str(raw).ok()?;
    // RETURNS-36: plexus-client's rule (`spec05::item`), one for the client
    // and the seam; the seam also names the call's content type.
    let mut v = plexus_client::spec05::item(&v)?;
    let o = v.as_object_mut()?;
    if o.get("type").and_then(Value::as_str) == Some("progress") {
        o.entry("content_type").or_insert(Value::from(content_type));
    }
    Some(v)
}

/// spec/05's error fields as the typed [`RemoteError`] they say —
/// plexus-client's rule (`spec05::remote_error`), one for the client and the
/// seam.
pub(super) fn remote_error_of(o: &Map<String, Value>) -> RemoteError {
    plexus_client::spec05::remote_error(o)
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
    use plexus_client::DenyReason;
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
