//! SYNAPSE-CC-9 · `MethodSchema.input`, reserved for BIDIR-6: absent from the
//! wire while `None` (byte-identical to 0.6.1, but for RETURNS-5's
//! `streaming` → `cardinality` and `returns` always present), and
//! round-trips when set.

use plexus_core::plexus::schema::{Cardinality, HttpMethod, MethodExample, MethodRole, MethodSchema};
use schemars::schema_for;

const FIXTURE: &str = include_str!("fixtures/method_schema_0.6.1.json");

fn full() -> MethodSchema {
    MethodSchema::new("set_status", "Set a ticket's status", "h1")
        .with_params(schema_for!(String))
        .with_returns(schema_for!(u64))
        .with_cardinality(Cardinality::Many)
        .with_http_method(HttpMethod::Get)
        .with_request_type(schema_for!(bool))
        .with_response_type(schema_for!(i32))
        .with_role(MethodRole::Rpc)
        .with_grant("tickets.set_status")
        .with_target("id")
        .with_long_description("long")
        .with_group("write")
        .with_example(MethodExample::with_note(serde_json::json!({"id": "A-1"}), "note"))
}

/// 0.6.1's bytes as 0.8 writes the same schema: RETURNS-5's two changes and
/// nothing else — `streaming: b` is `cardinality` (`many` / `one`), and
/// `returns` is always present (`{}`, the empty schema, when none is set).
fn fixture_as_0_8() -> serde_json::Value {
    let mut v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    for m in v.as_object_mut().unwrap().values_mut() {
        let m = m.as_object_mut().unwrap();
        let many = m.remove("streaming").and_then(|s| s.as_bool()).unwrap_or(false);
        m.insert("cardinality".into(), serde_json::json!(if many { "many" } else { "one" }));
        m.entry("returns").or_insert(serde_json::json!({}));
    }
    v
}

#[test]
fn without_input_the_wire_is_byte_identical_to_0_6_1() {
    let bare = MethodSchema::new("bare", "d", "h");
    assert!(full().input.is_none());
    let now = serde_json::to_string_pretty(&serde_json::json!({"full": full(), "bare": bare})).unwrap();
    assert_eq!(now.trim_end(), serde_json::to_string_pretty(&fixture_as_0_8()).unwrap());
    // and 0.6.1's bytes (as 0.8) read back with input None
    let m: MethodSchema = serde_json::from_value(fixture_as_0_8()["full"].clone()).unwrap();
    assert!(m.input.is_none());
}

#[test]
fn with_input_it_round_trips() {
    let m = full().with_input(schema_for!(String));
    let text = serde_json::to_string(&m).unwrap();
    assert!(text.contains("\"input\":"), "{text}");
    let back: MethodSchema = serde_json::from_str(&text).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), serde_json::to_value(&m).unwrap());
    assert_eq!(back.input, Some(schema_for!(String)));
}
