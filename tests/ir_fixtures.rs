//! RETURNS-40: the IR plexus-core writes (`plexus::ir`) equals the IR
//! synapse's builder makes of the same schemas, byte for byte in synapse's
//! canonical form (keys sorted, two-space indent, one trailing newline).
//!
//! Both fixtures are read by sibling path, their goldens written by
//! synapse's `ir3-test` (`SYNAPSE_GOLDEN_ACCEPT=1`):
//!
//! - RETURNS-7's conformance fixture: `schema.json` at path `conformance`
//!   (`buildIRFromSchema`) is `ir.json`;
//! - RETURNS-40's ir-service fixture: every schema a walk reads
//!   (`schemas.json`, by dotted path) folded from the root
//!   (`buildIRFromSchemas`) is `ir.json`, from `alpha` is `ir.alpha.json`;
//!   the clash service's walk refuses `clash` (`clash.ir.json`), and that
//!   plugin alone fails as `clash.one.error.txt` says.

use std::collections::BTreeMap;
use std::path::PathBuf;

use plexus_core::plexus::ir::{self, IrBuildError};
use serde_json::Value;

fn macros_fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plexus-macros/fixtures").join(rel)
}

fn read(rel: &str) -> String {
    let path = macros_fixture(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// A fixture's schemas by path (`""`: the root).
fn schemas(rel: &str) -> BTreeMap<Vec<String>, Value> {
    let Value::Object(by_name) = json(rel) else { panic!("{rel}: an object") };
    by_name
        .into_iter()
        .map(|(k, v)| (if k.is_empty() { vec![] } else { k.split('.').map(str::to_string).collect() }, v))
        .collect()
}

fn same(golden: &str, built: &ir::Ir) {
    let mine = ir::canonical(&built.to_json());
    let theirs = read(golden);
    if mine != theirs {
        let at = mine.bytes().zip(theirs.bytes()).position(|(a, b)| a != b).unwrap_or(mine.len().min(theirs.len()));
        let from = at.saturating_sub(400);
        panic!(
            "{golden}: plexus-core's IR is not synapse's, from byte {at}\n--- plexus-core ---\n{}\n--- synapse ---\n{}",
            &mine[from..(at + 400).min(mine.len())],
            &theirs[from..(at + 400).min(theirs.len())]
        );
    }
}

#[test]
fn the_conformance_fixture() {
    let schema = json("conformance/expected/schema.json");
    let built = ir::build_one("conformance", &["conformance".to_string()], &schema).expect("the fixture's IR");
    same("conformance/expected/ir.json", &built);
}

#[test]
fn a_whole_service() {
    let built = ir::build("irsvc", &[vec![]], &schemas("ir-service/expected/schemas.json")).expect("the service's IR");
    same("ir-service/expected/ir.json", &built);
    assert!(!built.refusals.is_empty(), "the reader's refusals are carried");
}

#[test]
fn a_subtree_of_it() {
    let built = ir::build("irsvc", &[vec!["alpha".to_string()]], &schemas("ir-service/expected/schemas.json")).expect("alpha's IR");
    same("ir-service/expected/ir.alpha.json", &built);
}

/// RETURNS-36 review #9: the walk refuses the colliding activation (a
/// `title` refusal at its namespace naming both sites, its methods and types
/// left out) and builds the rest.
#[test]
fn a_title_collision_refuses_its_activation_as_synapse_does() {
    let built = ir::build("clashsvc", &[vec![]], &schemas("ir-service/expected/clash.schemas.json")).expect("the walk goes on");
    same("ir-service/expected/clash.ir.json", &built);
    assert_eq!(built.refusals.iter().filter(|r| r.keyword == "title").map(|r| r.site.as_str()).collect::<Vec<_>>(), ["clash"]);
}

/// The one-plugin entry (buildIRFromSchema) still fails, in synapse's words.
#[test]
fn one_colliding_plugin_alone_still_fails() {
    let schemas = schemas("ir-service/expected/clash.schemas.json");
    let err = ir::build_one("clashsvc", &["clash".to_string()], &schemas[&vec!["clash".to_string()]]).expect_err("two shapes under one title");
    assert!(matches!(err, IrBuildError::TitleCollision { .. }), "{err:?}");
    assert_eq!(err.to_string(), read("ir-service/expected/clash.one.error.txt").trim_end());
}

#[test]
fn a_root_no_schema_is_given_for_is_refused() {
    let err = ir::build("irsvc", &[vec!["delta".to_string()]], &schemas("ir-service/expected/schemas.json")).expect_err("no delta");
    assert_eq!(err.to_string(), "IR: no schema at delta");
}

/// synapse's canonical form, which every golden is written in.
#[test]
fn canonical_is_synapses_form() {
    let v: Value = serde_json::from_str(r#"{"b":[1,{"d":[],"c":{}}],"a":"x\u0001\n\"","n":0.05,"m":1.5,"k":18446744073709551615,"z":1e3}"#).unwrap();
    assert_eq!(
        ir::canonical(&v),
        "{\n  \"a\": \"x\\u0001\\n\\\"\",\n  \"b\": [\n    1,\n    {\n      \"c\": {},\n      \"d\": []\n    }\n  ],\n  \"k\": 1.8446744073709551615e19,\n  \"m\": 1.5,\n  \"n\": 5.0e-2,\n  \"z\": 1000.0\n}\n"
    );
}

/// ASK-1: IR 3.1 is 3.0 without the bidir keys and nothing in their place;
/// an older schema's `bidirectional` (the in-call question, gone) and its
/// request and response types are read and ignored.
#[test]
fn an_older_bidirectional_is_ignored() {
    let plain = json("conformance/expected/schema.json");
    let mut schema = plain.clone();
    for m in schema["methods"].as_array_mut().unwrap() {
        m["bidirectional"] = serde_json::json!(true);
        m["request_type"] = serde_json::json!({"type": "string"});
        m["response_type"] = serde_json::json!({"type": "string"});
    }
    let ns = &["conformance".to_string()];
    let built = ir::build_one("conformance", ns, &schema).expect("the fixture's IR").to_json();
    let want = ir::build_one("conformance", ns, &plain).expect("the fixture's IR").to_json();
    assert_eq!(built, want, "an older schema's bidir keys change nothing");
    assert_eq!(built["irVersion"], "3.1");
    for (path, m) in built["irMethods"].as_object().unwrap() {
        for gone in ["mdBidirType", "mdBidirResponseType", "mdBidirResponseSchema", "mdAsks"] {
            assert!(m.get(gone).is_none(), "{path}: {gone} in {m}");
        }
    }
}
