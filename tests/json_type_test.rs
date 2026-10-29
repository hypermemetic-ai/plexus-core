//! SYNAPSE-CC-9 · a `serde_json::Value` is the JSON type, and the schema says
//! so one way: `{"type": ["null","boolean","number","string","array","object"]}`
//! (`JSON_TYPES`), inline, annotations beside it — written by
//! `spell_json_values`, which every `MethodSchema` schema setter applies. The
//! owner, 2026-10-29: nothing is opaque.
//!
//! And the two walks that hold a schema to IR 2.1: `untyped_sites` (a position
//! that is neither typed nor the JSON type, or an RPC method with no returns)
//! and `foreign_keywords` (a keyword outside the closed list). Site names are
//! the contract's (`<ns>.<Type>[.<variant>].<field>`, `<ns>.<method>(<param>)`,
//! `<ns>.<method> returns`, `[] ? {} .N`); `<ns>` is the plugin's own.

use plexus_core::plexus::schema::{
    foreign_keywords, is_json_type, schema_untyped_sites, spell_json_values, untyped_sites,
    MethodSchema, PluginSchema, SchemaResult, JSON_TYPES,
};
use plexus_core::plexus::types::PlexusStreamItem;
use plexus_core::plexus::{Activation, DynamicHub};
use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};

fn json_type() -> Value {
    json!({ "type": JSON_TYPES })
}

#[derive(JsonSchema)]
#[allow(dead_code)]
struct Doc {
    /// a payload, any JSON
    field: Value,
    maybe: Option<Value>,
    many: Vec<Value>,
    map: std::collections::BTreeMap<String, Value>,
    typed: String,
}

#[derive(JsonSchema)]
#[allow(dead_code)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Tagged {
    Data { content: Value, n: u32 },
    Other { name: String },
}

fn spelled<T: JsonSchema>() -> Value {
    let mut s = schema_for!(T);
    spell_json_values(&mut s);
    serde_json::to_value(s).unwrap()
}

#[test]
fn the_json_types_spelling() {
    assert_eq!(JSON_TYPES, ["null", "boolean", "number", "string", "array", "object"]);
    for any in [json!(true), json!({}), json!({"description": "d"}), json!({"default": null}), json_type()] {
        assert!(is_json_type(&any), "{any}");
    }
    for not in [json!({"type": "string"}), json!({"type": ["object", "boolean"]}), json!({"$ref": "#/$defs/X"}),
                json!({"x-plexus-source": {"from": "auth"}}), json!(false)] {
        assert!(!is_json_type(&not), "{not}");
    }
}

#[test]
fn every_value_position_is_spelled_the_json_type() {
    let v = spelled::<Doc>();
    let p = &v["properties"];
    assert_eq!(p["field"], json!({"description": "a payload, any JSON", "type": JSON_TYPES}));
    assert_eq!(p["maybe"], json_type());
    assert_eq!(p["many"]["items"], json_type());
    assert_eq!(p["map"]["additionalProperties"], json_type());
    assert_eq!(p["typed"], json!({"type": "string"}));
    let t = spelled::<Tagged>();
    let data = t["oneOf"].as_array().unwrap().iter().find(|x| x["properties"]["type"]["const"] == "data").unwrap();
    assert_eq!(data["properties"]["content"], json_type());
    // idempotent
    let mut s: schemars::Schema = serde_json::from_value(v.clone()).unwrap();
    spell_json_values(&mut s);
    assert_eq!(serde_json::to_value(s).unwrap(), v);
}

#[test]
fn the_setters_spell_it_and_leave_injected_params_alone() {
    let params = json!({
        "type": "object",
        "properties": {
            "blob": { "description": "anything" },
            "user": { "x-plexus-source": { "from": "auth", "resolver": "self.verify" } }
        },
        "required": ["blob"]
    });
    let m = MethodSchema::new("put", "d", "h").with_params(serde_json::from_value(params).unwrap());
    let p = serde_json::to_value(m.params.unwrap()).unwrap();
    assert_eq!(p["properties"]["blob"], json!({"description": "anything", "type": JSON_TYPES}));
    assert_eq!(p["properties"]["user"], json!({"x-plexus-source": {"from": "auth", "resolver": "self.verify"}}));
}

#[test]
fn a_value_is_typed_not_an_untyped_site() {
    assert_eq!(schema_untyped_sites("t", &schema_for!(Doc)), Vec::<String>::new());
    assert_eq!(schema_untyped_sites("t", &schema_for!(Tagged)), Vec::<String>::new());
}

#[test]
fn untyped_sites_names_what_is_neither_typed_nor_the_json_type() {
    let params = json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "bag": { "type": "object" },
            "list": { "type": "array" },
            "either": { "type": ["object", "boolean"] },
            "anything": { "description": "the JSON type" },
            "user": { "x-plexus-source": { "from": "auth", "resolver": "self.verify" } }
        },
        "required": ["id"]
    });
    let m = MethodSchema::new("put", "d", "h")
        .with_params(serde_json::from_value(params).unwrap())
        .with_returns(schema_for!(Tagged));
    let bare = MethodSchema::new("bare", "d", "h"); // an rpc method with no returns
    let p = PluginSchema::leaf("ns", "1.0", "d", vec![m, bare]);
    assert_eq!(untyped_sites(&p), vec!["ns.bare returns", "ns.put(bag)", "ns.put(either)", "ns.put(list)"]);
}

#[test]
fn untyped_site_names_carry_the_contracts_suffixes() {
    let ret = json!({
        "title": "T", "type": "object",
        "properties": {
            "o": { "type": ["object", "null"] },
            "v": { "type": "array", "items": { "type": "object" } },
            "m": { "type": "object", "additionalProperties": { "type": "array" } }
        },
        "required": ["v", "m"]
    });
    let m = MethodSchema::new("get", "d", "h").with_returns(serde_json::from_value(ret).unwrap());
    let p = PluginSchema::leaf("ns", "1.0", "d", vec![m]);
    assert_eq!(untyped_sites(&p), vec!["ns.T.m{}", "ns.T.o?", "ns.T.v[]"]);
}

#[test]
fn foreign_keywords_names_a_keyword_outside_the_closed_list() {
    #[derive(JsonSchema)]
    #[allow(dead_code)]
    struct Set {
        tags: std::collections::BTreeSet<String>,
    }
    let m = MethodSchema::new("put", "d", "h").with_returns(schema_for!(Set));
    let p = PluginSchema::leaf("ns", "1.0", "d", vec![m]);
    assert_eq!(foreign_keywords(&p), vec!["ns.Set.tags: uniqueItems"]);
}

/// The protocol root's carriers are the JSON type: typed generically.
#[test]
fn the_stream_items_carriers_are_the_json_type() {
    let m = MethodSchema::new("call", "d", "h").with_returns(schema_for!(PlexusStreamItem));
    let v = serde_json::to_value(m.returns.unwrap()).unwrap();
    let variant = |tag: &str| v["oneOf"].as_array().unwrap().iter().find(|x| x["properties"]["type"]["const"] == json!(tag)).cloned().unwrap();
    assert_eq!(variant("data")["properties"]["content"]["type"], json!(JSON_TYPES));
    assert_eq!(variant("request")["properties"]["requestData"]["type"], json!(JSON_TYPES));
    assert!(!v.to_string().contains("x-plexus-opaque"));
}

#[test]
fn schema_results_json_schema_fields_are_the_json_type() {
    let m = MethodSchema::new("schema", "d", "h").with_returns(schema_for!(SchemaResult));
    let v = serde_json::to_value(m.returns.as_ref().unwrap()).unwrap();
    for (ty, field) in [
        ("MethodSchema", "params"), ("MethodSchema", "returns"), ("MethodSchema", "request_type"),
        ("MethodSchema", "response_type"), ("MethodSchema", "input"), ("MethodSchema", "answer_by"),
        ("MethodExample", "params"), ("PluginSchema", "request"),
    ] {
        let prop = &v["$defs"][ty]["properties"][field];
        if field == "answer_by" {
            continue; // BIDIR-8's, typed; listed so a rename is noticed
        }
        assert_eq!(prop["type"], json!(JSON_TYPES), "{ty}.{field}: {prop}");
        assert!(prop.get("$ref").is_none() && prop.get("anyOf").is_none(), "{ty}.{field}: {prop}");
    }
    let p = PluginSchema::leaf("ns", "1.0", "d", vec![m]);
    assert_eq!(untyped_sites(&p), Vec::<String>::new());
    assert_eq!(foreign_keywords(&p), Vec::<String>::new());
}

/// The protocol service's own plugin schema: `call`, `hash`, `hashes`, `schema`.
#[test]
fn the_services_own_schema_is_typed() {
    let service = DynamicHub::new("plexus");
    let p = Activation::plugin_schema(&service);
    let names: Vec<&str> = p.methods.iter().map(|m| m.name.as_str()).collect();
    for n in ["call", "hash", "hashes", "schema"] {
        assert!(names.contains(&n), "{names:?}");
    }
    assert_eq!(untyped_sites(&p), Vec::<String>::new());
    assert_eq!(foreign_keywords(&p), Vec::<String>::new());
    let call = p.methods.iter().find(|m| m.name == "call").unwrap();
    let params = serde_json::to_value(call.params.as_ref().unwrap()).unwrap();
    assert_eq!(params["properties"]["params"]["type"], json!(JSON_TYPES), "{params}");
}

/// `.hashes` answers a `PluginHashes`: its returns root is that struct, named
/// by its title, every field typed (SYNAPSE-CC-8 reads a struct root as a type).
#[test]
fn hashes_returns_the_plugin_hashes_struct() {
    let service = DynamicHub::new("plexus");
    let p = Activation::plugin_schema(&service);
    let hashes = p.methods.iter().find(|m| m.name == "hashes").unwrap();
    let r = serde_json::to_value(hashes.returns.as_ref().unwrap()).unwrap();
    assert_eq!(r["title"], json!("PluginHashes"), "{r}");
    assert_eq!(r["type"], json!("object"));
    for f in ["namespace", "self_hash", "hash", "children_hash", "children"] {
        assert!(r["properties"].get(f).is_some(), "{f}: {r}");
    }
    assert_eq!(r["properties"]["children"]["items"]["$ref"], json!("#/$defs/ChildHashes"));
    assert!(r["$defs"]["ChildHashes"]["properties"]["hash"].is_object());
}
