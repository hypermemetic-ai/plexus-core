//! PLX-75 acceptance tests for the activation IR.
//!
//! Each test names the acceptance criterion it discharges.

use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::capability::{Capability, Client, FsRead, FsWrite, Permission, Terminal};

/// The four callbacks an ACP `session/prompt`-shaped turn issues, derived from
/// the capability markers themselves — the same objects `Client<C>` would
/// declare, not a re-description of them.
fn acp_prompt_callbacks() -> Vec<CallbackIr> {
    Client::<(Permission, FsRead, FsWrite, Terminal)>::callbacks()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn schema(type_name: &str) -> SchemaRef {
    let s: schemars::Schema = serde_json::from_value(json!({
        "type": "object",
        "title": type_name,
        "properties": { "value": { "type": "string" } },
        "required": ["value"],
    }))
    .unwrap();
    SchemaRef::new(type_name, s).expect("fixture schema is representable")
}

fn string_schema(type_name: &str) -> SchemaRef {
    let s: schemars::Schema = serde_json::from_value(json!({ "type": "string" })).unwrap();
    SchemaRef::new(type_name, s).unwrap()
}

/// A 3-level tree:
///
/// ```text
/// root (backend "substrate")
///  ├─ static child  "claudecode"
///  │    ├─ indexed child "session"  → template "session_instance" (level 3)
///  │    └─ method chat (Bidirectional)
///  └─ dynamic child "jsexec"
/// ```
fn tree() -> ActivationIr {
    let instance = ActivationIr::new("session_instance", "1.0.0")
        .with_description("one live claudecode session")
        .with_method(
            MethodIr::new("history", "claudecode.session.history")
                .with_description("replay the transcript")
                .with_terminal(schema("Transcript")),
        )
        .with_method(
            MethodIr::new("close", "claudecode.session.close")
                .with_http_method(HttpMethodIr::Delete),
        );

    let claudecode = ActivationIr::new("claudecode", "0.9.1")
        .with_description("claude code sessions")
        .with_long_description("Long form docs for the claudecode activation.")
        .with_method(
            MethodIr::new("chat", "claudecode.chat")
                .with_description("interactive chat")
                .with_param(ParamIr::new("prompt", string_schema("String")))
                .with_param(
                    ParamIr::new("model", string_schema("String"))
                        .with_description("model override")
                        .optional(),
                )
                .with_updates(schema("ChatEvent"))
                .with_terminal(schema("ChatDone"))
                .with_callbacks(acp_prompt_callbacks())
                .with_auth(AuthRequirementIr::Required)
                .with_extension("acp_role", json!("prompt"))
                .with_extension("nostr_kind", json!(23194)),
        )
        .with_method(
            MethodIr::new("list", "claudecode.list")
                .with_description("list sessions")
                .with_terminal(schema("SessionList"))
                .with_http_method(HttpMethodIr::Get)
                .with_auth(AuthRequirementIr::Public),
        )
        .with_child(ChildEdge::Indexed {
            namespace: "session".into(),
            list_method: "claudecode.list".into(),
            search_method: Some("claudecode.search".into()),
            id_field: "session_id".into(),
            path_template: "session/{id}".into(),
            template: Box::new(instance),
            description: "live sessions".into(),
        });

    let mut root = ActivationIr::new("substrate", "0.6.0")
        .with_backend_name("substrate")
        .with_respond_method("respond")
        .with_description("the substrate root")
        .with_method(MethodIr::new("health", "substrate.health").with_http_method(HttpMethodIr::Get))
        .with_child(ChildEdge::Static(claudecode))
        .with_child(ChildEdge::Dynamic {
            namespace: "jsexec".into(),
            hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            description: "runtime-registered js executor".into(),
        })
        .with_deprecation(DeprecationIr::new("0.6", "use vNext").removed_in("0.8"));

    root.recompute_hashes();
    root
}

/// Borrow the `claudecode` static subtree.
fn claudecode(ir: &ActivationIr) -> &ActivationIr {
    match ir.child("claudecode").expect("static child present") {
        ChildEdge::Static(c) => c,
        other => panic!("expected Static, got {other:?}"),
    }
}

fn claudecode_mut(ir: &mut ActivationIr) -> &mut ActivationIr {
    match ir
        .children
        .iter_mut()
        .find(|c| c.namespace() == "claudecode")
        .unwrap()
    {
        ChildEdge::Static(c) => c,
        other => panic!("expected Static, got {other:?}"),
    }
}

fn session_template(ir: &ActivationIr) -> &ActivationIr {
    match claudecode(ir).child("session").expect("indexed child") {
        ChildEdge::Indexed { template, .. } => template,
        other => panic!("expected Indexed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// AC1 — serde round-trip of a 3-level tree with all three ChildEdge variants
// ---------------------------------------------------------------------------

#[test]
fn ac1_three_level_tree_round_trips_losslessly() {
    let ir = tree();

    // Sanity: the fixture really is 3 levels and really has all three variants.
    assert_eq!(ir.children.len(), 2);
    assert!(matches!(ir.children[0], ChildEdge::Static(_)));
    assert!(matches!(ir.children[1], ChildEdge::Dynamic { .. }));
    assert!(matches!(
        claudecode(&ir).children[0],
        ChildEdge::Indexed { .. }
    ));
    assert_eq!(session_template(&ir).namespace, "session_instance");

    let json = serde_json::to_string_pretty(&ir).unwrap();
    let back: ActivationIr = serde_json::from_str(&json).unwrap();

    assert_eq!(ir, back, "IR must survive serde structurally intact");

    // Spot-check the fields the completeness inventory added, so a lost field
    // fails loudly rather than being masked by `PartialEq` on a default.
    assert_eq!(back.backend_name.as_deref(), Some("substrate"));
    assert_eq!(back.respond_method.as_deref(), Some("respond"));
    assert_eq!(back.ir_hash, ir.ir_hash);
    assert_eq!(back.ir_version, Some(IR_VERSION));
    // §4.7 — the construction identifier rides on the wire with the hashes.
    assert_eq!(back.hash_algorithm.as_deref(), Some(HASH_ALGORITHM));
    assert!(back.deprecation.is_some());

    let cc = claudecode(&back);
    assert_eq!(
        cc.long_description.as_deref(),
        Some("Long form docs for the claudecode activation.")
    );
    let chat = cc.method("chat").unwrap();
    assert_eq!(chat.dotted_id, "claudecode.chat");
    assert!(chat.is_streaming());
    assert_eq!(chat.http_method, HttpMethodIr::Post);
    assert_eq!(chat.auth, AuthRequirementIr::Required);
    assert_eq!(chat.params.len(), 2);
    assert!(chat.params[0].required);
    assert!(!chat.params[1].required);
    assert_eq!(chat.extensions.len(), 2);
    assert_eq!(chat.extensions["acp_role"], json!("prompt"));

    match cc.child("session").unwrap() {
        ChildEdge::Indexed {
            list_method,
            search_method,
            id_field,
            path_template,
            template,
            ..
        } => {
            assert_eq!(list_method, "claudecode.list");
            assert_eq!(search_method.as_deref(), Some("claudecode.search"));
            assert_eq!(id_field, "session_id");
            assert_eq!(path_template, "session/{id}");
            assert_eq!(template.methods.len(), 2);
        }
        other => panic!("expected Indexed, got {other:?}"),
    }
}

#[test]
fn ac1_empty_optional_fields_are_omitted_from_the_wire() {
    let mut ir = ActivationIr::new("leaf", "1.0.0");
    ir.recompute_hashes();
    let v: serde_json::Value = serde_json::to_value(&ir).unwrap();
    let obj = v.as_object().unwrap();
    for absent in [
        "backend_name",
        "respond_method",
        "long_description",
        "description",
        "request_context",
        "methods",
        "children",
        "deprecation",
    ] {
        assert!(!obj.contains_key(absent), "`{absent}` should be omitted");
    }
    // §3.3 — the two MANDATORY root facts are the exception §3.5 does not reach.
    assert!(obj.contains_key("ir_version"));
    assert!(obj.contains_key("hash_algorithm"));
    let back: ActivationIr = serde_json::from_value(v).unwrap();
    assert_eq!(back, ir);
}

// ---------------------------------------------------------------------------
// AC2 — Merkle + locality
// ---------------------------------------------------------------------------

#[test]
fn ac2_hashing_is_merkle_and_locality_preserving() {
    let before = tree();

    // Snapshot every hash we care about.
    let root_hash = before.hash.clone();
    let ir_hash = before.ir_hash.clone().unwrap();
    let cc_hash = claudecode(&before).hash.clone();
    let tmpl_hash = session_template(&before).hash.clone();
    let chat_hash = claudecode(&before).method("chat").unwrap().hash.clone();
    let list_hash = claudecode(&before).method("list").unwrap().hash.clone();

    assert!(!root_hash.is_empty() && !cc_hash.is_empty() && !tmpl_hash.is_empty());

    // Mutate exactly one leaf method's description: `history`, which lives in
    // the level-3 indexed template.
    let mut after = before.clone();
    {
        let cc = claudecode_mut(&mut after);
        match cc.children.iter_mut().next().unwrap() {
            ChildEdge::Indexed { template, .. } => {
                template.methods[0].description = "replay the transcript (v2)".into();
            }
            other => panic!("expected Indexed, got {other:?}"),
        }
    }
    after.recompute_hashes();

    let after_cc = claudecode(&after);
    let after_tmpl = session_template(&after);

    // The mutated leaf method's own hash changed.
    assert_ne!(
        after_tmpl.methods[0].hash,
        before_tmpl_method_hash(&before),
        "the mutated method's hash must change"
    );

    // Every ancestor changed: template node → indexed edge → claudecode → root
    // → document.
    assert_ne!(after_tmpl.hash, tmpl_hash, "template node hash must change");
    assert_ne!(after_cc.hash, cc_hash, "parent node hash must change");
    assert_ne!(after.hash, root_hash, "root node hash must change");
    assert_ne!(
        after.ir_hash.clone().unwrap(),
        ir_hash,
        "ir_hash must change"
    );

    // Untouched siblings are byte-identical.
    assert_eq!(
        after_cc.method("chat").unwrap().hash,
        chat_hash,
        "untouched sibling method hash must be byte-identical"
    );
    assert_eq!(after_cc.method("list").unwrap().hash, list_hash);
    assert_eq!(
        after_tmpl.methods[1].hash,
        before_close_method_hash(&before),
        "untouched sibling in the mutated node must be byte-identical"
    );

    // And an untouched sibling SUBTREE (the Dynamic edge) contributes an
    // identical edge hash.
    assert_eq!(
        after.children[1].edge_hash(),
        before.children[1].edge_hash(),
        "untouched sibling subtree hash must be byte-identical"
    );
}

fn before_tmpl_method_hash(ir: &ActivationIr) -> String {
    session_template(ir).methods[0].hash.clone()
}

fn before_close_method_hash(ir: &ActivationIr) -> String {
    session_template(ir).methods[1].hash.clone()
}

#[test]
fn ac2_mutating_a_dynamic_edge_propagates_upward_only() {
    let before = tree();
    let cc_hash = claudecode(&before).hash.clone();

    let mut after = before.clone();
    match &mut after.children[1] {
        ChildEdge::Dynamic { hash, .. } => {
            *hash = "1".repeat(64);
        }
        other => panic!("expected Dynamic, got {other:?}"),
    }
    after.recompute_hashes();

    assert_ne!(after.hash, before.hash, "root must change");
    assert_ne!(after.ir_hash, before.ir_hash, "ir_hash must change");
    assert_eq!(
        claudecode(&after).hash,
        cc_hash,
        "the sibling static subtree must be untouched"
    );
}

#[test]
fn ac2_static_child_hash_is_folded_into_the_parent_verbatim() {
    // The parent hashes the child's `hash` field, not a re-serialization of the
    // child — that is what makes the fold a Merkle fold.
    let ir = tree();
    let cc = claudecode(&ir);
    let expected_edge = {
        let mut probe = ActivationIr::new("substrate", "0.6.0");
        probe.hash = cc.hash.clone();
        ChildEdge::Static(probe).edge_hash()
    };
    assert_eq!(ir.children[0].edge_hash(), expected_edge);
}

// ---------------------------------------------------------------------------
// AC3 — hashing stable across round-trips and independent of insertion order
// ---------------------------------------------------------------------------

#[test]
fn ac3_hashes_survive_serde_round_trip() {
    let ir = tree();
    let json = serde_json::to_string(&ir).unwrap();
    let mut back: ActivationIr = serde_json::from_str(&json).unwrap();

    // Stored hashes survived transport…
    assert_eq!(back.hash, ir.hash);
    assert_eq!(back.ir_hash, ir.ir_hash);

    // …and recomputing from the decoded document reproduces them exactly, so
    // every hash input is a field that round-trips.
    back.recompute_hashes();
    assert_eq!(back.hash, ir.hash, "root hash must be stable across serde");
    assert_eq!(back.ir_hash, ir.ir_hash, "ir_hash must be stable");
    assert_eq!(back, ir, "recomputation must be a no-op on a decoded document");
}

#[test]
fn ac3_hashes_are_deterministic_across_constructions() {
    assert_eq!(tree().ir_hash, tree().ir_hash);
    assert_eq!(tree().hash, tree().hash);
}

#[test]
fn ac3_extension_map_insertion_order_does_not_affect_hashes() {
    let build = |reversed: bool| {
        let mut ext: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let entries = [
            ("zeta".to_string(), json!({"b": 1, "a": [1, 2]})),
            ("alpha".to_string(), json!("first")),
            ("mid".to_string(), json!(7)),
        ];
        if reversed {
            for (k, v) in entries.into_iter().rev() {
                ext.insert(k, v);
            }
        } else {
            for (k, v) in entries {
                ext.insert(k, v);
            }
        }
        let mut m = MethodIr::new("m", "a.m");
        m.extensions = ext;
        m.recompute_hash();
        m
    };

    let a = build(false);
    let b = build(true);
    assert_eq!(a.hash, b.hash, "insertion order must be unobservable");
    assert_eq!(a, b);
}

#[test]
fn ac3_json_object_key_order_inside_a_schema_does_not_affect_hashes() {
    let one: schemars::Schema = serde_json::from_str(
        r#"{"type":"object","title":"T","properties":{"z":{"type":"string"},"a":{"type":"number"}}}"#,
    )
    .unwrap();
    let two: schemars::Schema = serde_json::from_str(
        r#"{"properties":{"a":{"type":"number"},"z":{"type":"string"}},"title":"T","type":"object"}"#,
    )
    .unwrap();

    let mut m1 = MethodIr::new("m", "a.m").with_terminal(SchemaRef::new("T", one).unwrap());
    let mut m2 = MethodIr::new("m", "a.m").with_terminal(SchemaRef::new("T", two).unwrap());
    m1.recompute_hash();
    m2.recompute_hash();
    assert_eq!(m1.hash, m2.hash);
}

#[test]
fn ac3_sequence_order_is_significant() {
    // RFC 002 §4.8 rules on which of the document's collections are sequences.
    // PARAMETERS are: a parameter is identified by its position to a positional
    // caller, so reordering them is a real content change.
    let mut a = MethodIr::new("m", "n.m")
        .with_param(ParamIr::new("x", string_schema("S")))
        .with_param(ParamIr::new("y", string_schema("T")));
    let mut b = MethodIr::new("m", "n.m")
        .with_param(ParamIr::new("y", string_schema("T")))
        .with_param(ParamIr::new("x", string_schema("S")));
    a.recompute_hash();
    b.recompute_hash();
    assert_ne!(a.hash, b.hash);
}

#[test]
fn rfc002_4_8_methods_and_child_edges_are_sets_not_sequences() {
    // The other half of §4.8, and a deliberate change from the pre-RFC-002
    // behaviour (finding F-15, on which "both readings are defensible").
    // §3.7 makes a method's local name and a child's namespace unique within an
    // activation, which makes both collections KEYED; a keyed collection's
    // declaration order is exactly the "non-canonical ordering" §4.4 forbids the
    // hash from depending on.
    let mut a = ActivationIr::new("n", "1")
        .with_method(MethodIr::new("x", "n.x"))
        .with_method(MethodIr::new("y", "n.y"));
    let mut b = ActivationIr::new("n", "1")
        .with_method(MethodIr::new("y", "n.y"))
        .with_method(MethodIr::new("x", "n.x"));
    a.recompute_hashes();
    b.recompute_hashes();
    assert_eq!(a.hash, b.hash, "method declaration order is not content");

    let k = || ChildEdge::Static(ActivationIr::new("k", "1"));
    let z = || ChildEdge::Static(ActivationIr::new("z", "1"));
    let mut kz = ActivationIr::new("n", "1").with_child(k()).with_child(z());
    let mut zk = ActivationIr::new("n", "1").with_child(z()).with_child(k());
    kz.recompute_hashes();
    zk.recompute_hashes();
    assert_eq!(kz.hash, zk.hash, "child edge order is not content");

    // Not vacuous: a different SET is still a different hash.
    let mut k_only = ActivationIr::new("n", "1").with_child(k());
    k_only.recompute_hashes();
    assert_ne!(kz.hash, k_only.hash);
}

// ---------------------------------------------------------------------------
// PLX-77 AC1 — a turn can be streaming AND bidirectional, with many callbacks
// ---------------------------------------------------------------------------

#[test]
fn ac1_turn_is_streaming_and_bidirectional_with_four_callbacks() {
    // The `chat` method in the fixture is ACP `session/prompt`-shaped: it
    // streams updates, resolves to a terminal value, AND issues four distinct
    // server-to-client callbacks. PLX-75's `MethodShape` could express at most
    // one of those three facts at a time.
    let ir = tree();
    let json = serde_json::to_string_pretty(&ir).unwrap();
    let back: ActivationIr = serde_json::from_str(&json).unwrap();

    let chat = claudecode(&back).method("chat").unwrap();

    // Streaming and bidirectional are independent axes, and both hold here.
    assert!(chat.is_streaming(), "the turn emits updates");
    assert!(chat.is_bidirectional(), "the turn issues callbacks");

    // Both schemas survived, and they are two DIFFERENT types — the defect
    // PLX-75's single `returns` field could not express.
    let updates = chat.updates.as_ref().expect("updates survived");
    let terminal = chat.terminal.as_ref().expect("terminal survived");
    assert_eq!(updates.type_name(), "ChatEvent");
    assert_eq!(terminal.type_name(), "ChatDone");
    assert_ne!(updates.type_name(), terminal.type_name());
    assert_eq!(updates.schema(), schema("ChatEvent").schema());
    assert_eq!(terminal.schema(), schema("ChatDone").schema());

    // All four callbacks survived, in order, with their names AND schemas.
    assert_eq!(chat.callbacks.len(), 4);
    assert_eq!(
        chat.callbacks
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        [
            "session/request_permission",
            "fs/read_text_file",
            "fs/write_text_file",
            "terminal/create",
        ]
    );
    assert_eq!(chat.callbacks, acp_prompt_callbacks());

    // Schemas are real, resolved schemas — not echoed type names.
    let fs_read = chat.callback("fs/read_text_file").expect("looked up by name");
    assert_eq!(fs_read.request.type_name(), "FsReadRequest");
    assert_eq!(fs_read.response.type_name(), "FsReadResponse");
    assert_eq!(
        fs_read.request.schema().as_value()["properties"]["path"]["type"],
        json!("string")
    );
}

#[test]
fn ac2_a_unary_method_carries_no_turn_ceremony_on_the_wire() {
    let ir = tree();
    let health = ir.method("health").expect("the unary fixture method");

    assert!(health.updates.is_none());
    assert!(health.callbacks.is_empty());
    assert!(!health.is_streaming());
    assert!(!health.is_bidirectional());

    let v = serde_json::to_value(health).unwrap();
    let obj = v.as_object().unwrap();
    for absent in ["updates", "callbacks", "terminal"] {
        assert!(
            !obj.contains_key(absent),
            "`{absent}` must be omitted for a unary method, got {v}"
        );
    }

    // …and a document that never mentions them decodes to the same thing.
    let decoded: MethodIr =
        serde_json::from_value(json!({"name": "health", "dotted_id": "substrate.health"})).unwrap();
    assert!(decoded.updates.is_none());
    assert!(decoded.terminal.is_none());
    assert!(decoded.callbacks.is_empty());
}

#[test]
fn a_turn_may_have_callbacks_without_updates_and_updates_without_callbacks() {
    // The two axes really are independent — "callbacks without updates" is the
    // case `MethodShape` could not express at all.
    let callbacks_only = MethodIr::new("elicit", "a.elicit")
        .with_terminal(schema("Answer"))
        .with_callbacks(Client::<(Permission,)>::callbacks());
    assert!(!callbacks_only.is_streaming());
    assert!(callbacks_only.is_bidirectional());

    let updates_only = MethodIr::new("tail", "a.tail").with_updates(schema("LogLine"));
    assert!(updates_only.is_streaming());
    assert!(!updates_only.is_bidirectional());

    let neither = MethodIr::new("ping", "a.ping");
    assert!(!neither.is_streaming());
    assert!(!neither.is_bidirectional());
}

#[test]
fn ac5_schema_ref_rejects_every_degenerate_form() {
    let good: schemars::Schema = serde_json::from_value(json!({"type": "string"})).unwrap();

    assert!(matches!(
        SchemaRef::new("", good.clone()),
        Err(SchemaRefError::EmptyTypeName)
    ));
    assert!(matches!(
        SchemaRef::new("   ", good.clone()),
        Err(SchemaRefError::EmptyTypeName)
    ));
    // The exact silent-degradation target.
    for unit in ["()", "unit", "!"] {
        assert!(
            matches!(
                SchemaRef::new(unit, good.clone()),
                Err(SchemaRefError::UnitTypeName(_))
            ),
            "`{unit}` must be rejected"
        );
    }
    // Uninformative schemas.
    for uninformative in [json!(true), json!(false), json!({})] {
        let s: schemars::Schema = serde_json::from_value(uninformative.clone()).unwrap();
        assert!(
            matches!(
                SchemaRef::new("T", s),
                Err(SchemaRefError::UninformativeSchema { .. })
            ),
            "{uninformative} must be rejected"
        );
    }
    // The `()` schema, whatever it is named.
    let null_schema: schemars::Schema = serde_json::from_value(json!({"type": "null"})).unwrap();
    assert!(matches!(
        SchemaRef::new("MyUnitAlias", null_schema),
        Err(SchemaRefError::NullSchema(_))
    ));

    // `Schema::default()` is the empty object schema — the "defaulted type"
    // case named in the acceptance criterion.
    assert!(matches!(
        SchemaRef::new("T", schemars::Schema::default()),
        Err(SchemaRefError::UninformativeSchema { .. })
    ));
}

#[test]
fn ac5_deserialization_cannot_smuggle_in_a_degraded_callback() {
    // There is no `SchemaRef::default`, no public field, and no `From<String>`,
    // so the only remaining route into an invalid value would be serde — and
    // `#[serde(try_from)]` closes it. A tampered document fails to decode
    // rather than decoding into a `()`-typed callback. PLX-75 proved this for
    // `MethodShape::Bidirectional`; the property must survive the move to
    // `callbacks` / `updates` / `terminal`.
    let ir = tree();
    let pristine = serde_json::to_value(&ir).unwrap();

    // The `chat` method lives on the Static `claudecode` child. `ChildEdge` is
    // internally tagged, so the child's own fields sit alongside `"edge"`.
    fn first_callback(v: &mut serde_json::Value) -> &mut serde_json::Value {
        &mut v["children"][0]["methods"][0]["callbacks"][0]
    }
    fn updates(v: &mut serde_json::Value) -> &mut serde_json::Value {
        &mut v["children"][0]["methods"][0]["updates"]
    }

    // Baseline: the pristine document decodes, and `chat` really has callbacks.
    {
        let mut v = pristine.clone();
        assert_eq!(pristine["children"][0]["edge"], json!("static"));
        assert_eq!(
            first_callback(&mut v)["name"],
            json!("session/request_permission")
        );
        assert!(serde_json::from_value::<ActivationIr>(pristine.clone()).is_ok());
    }

    // (a) blank a callback request's type name
    let mut v = pristine.clone();
    first_callback(&mut v)["request"]["type_name"] = json!("");
    let err = serde_json::from_value::<ActivationIr>(v).unwrap_err();
    assert!(err.to_string().contains("type name is empty"), "{err}");

    // (b) degrade a callback response to the unit type
    let mut v = pristine.clone();
    first_callback(&mut v)["response"]["type_name"] = json!("()");
    let err = serde_json::from_value::<ActivationIr>(v).unwrap_err();
    assert!(err.to_string().contains("unit type"), "{err}");

    // (c) degrade a callback schema to `{}`
    let mut v = pristine.clone();
    first_callback(&mut v)["request"]["schema"] = json!({});
    let err = serde_json::from_value::<ActivationIr>(v).unwrap_err();
    assert!(err.to_string().contains("no type information"), "{err}");

    // (d) degrade the UPDATES schema to the `()` schema — "emits nothing" is
    // `updates: null`, and is not reachable by degrading a real type.
    let mut v = pristine.clone();
    updates(&mut v)["schema"] = json!({"type": "null"});
    let err = serde_json::from_value::<ActivationIr>(v).unwrap_err();
    assert!(err.to_string().contains("null schema"), "{err}");

    // (e) drop a callback's request entirely — a callback has no optional
    // half, so there is no default to fall back to.
    let mut v = pristine.clone();
    first_callback(&mut v)
        .as_object_mut()
        .unwrap()
        .remove("request");
    assert!(serde_json::from_value::<ActivationIr>(v).is_err());
}

// ---------------------------------------------------------------------------
// PLX-77 AC6 — turn fields participate in Merkle hashing
// ---------------------------------------------------------------------------

#[test]
fn ac6_mutating_a_callback_changes_the_method_its_ancestors_and_ir_hash() {
    let before = tree();

    let root_hash = before.hash.clone();
    let ir_hash = before.ir_hash.clone().unwrap();
    let cc_hash = claudecode(&before).hash.clone();
    let chat_hash = claudecode(&before).method("chat").unwrap().hash.clone();
    let list_hash = claudecode(&before).method("list").unwrap().hash.clone();
    let tmpl_hash = session_template(&before).hash.clone();
    let dynamic_edge = before.children[1].edge_hash();

    // Mutate exactly ONE callback of ONE method, deep in the tree.
    let mut after = before.clone();
    {
        let cc = claudecode_mut(&mut after);
        let chat = cc.methods.iter_mut().find(|m| m.name == "chat").unwrap();
        chat.callbacks[2] = CallbackIr::new(
            "fs/write_text_file",
            schema("FsWriteRequestV2"),
            schema("FsWriteResponse"),
        );
    }
    after.recompute_hashes();

    // The owning method, its ancestors, and the document digest all changed.
    assert_ne!(
        claudecode(&after).method("chat").unwrap().hash,
        chat_hash,
        "the owning method hash must change"
    );
    assert_ne!(claudecode(&after).hash, cc_hash, "the parent must change");
    assert_ne!(after.hash, root_hash, "the root must change");
    assert_ne!(after.ir_hash.clone().unwrap(), ir_hash, "ir_hash must change");

    // Sibling subtrees are byte-identical.
    assert_eq!(
        claudecode(&after).method("list").unwrap().hash,
        list_hash,
        "a sibling method must be byte-identical"
    );
    assert_eq!(
        session_template(&after).hash,
        tmpl_hash,
        "the sibling indexed subtree must be byte-identical"
    );
    assert_eq!(
        after.children[1].edge_hash(),
        dynamic_edge,
        "the sibling dynamic subtree must be byte-identical"
    );
}

#[test]
fn ac6_updates_terminal_and_callback_count_all_participate() {
    let base = || {
        let mut m = MethodIr::new("m", "a.m")
            .with_updates(schema("U"))
            .with_terminal(schema("T"))
            .with_callbacks(Client::<(Permission,)>::callbacks());
        m.recompute_hash();
        m
    };
    let baseline = base().hash;

    // Different updates type.
    let mut a = base();
    a.updates = Some(schema("U2"));
    a.recompute_hash();
    assert_ne!(a.hash, baseline, "updates is content");

    // Different terminal type.
    let mut b = base();
    b.terminal = Some(schema("T2"));
    b.recompute_hash();
    assert_ne!(b.hash, baseline, "terminal is content");

    // An added callback.
    let mut c = base();
    c.callbacks.push(FsRead::descriptor());
    c.recompute_hash();
    assert_ne!(c.hash, baseline, "the callback set is content");

    // A renamed callback (same schemas).
    let mut d = base();
    d.callbacks[0].name = "session/request_permission_v2".into();
    d.recompute_hash();
    assert_ne!(d.hash, baseline, "a callback name is content");

    // Swapping updates and terminal is a real change, not a wash — the two
    // fields are distinguishable in the hash stream.
    let mut e = base();
    e.updates = Some(schema("T"));
    e.terminal = Some(schema("U"));
    e.recompute_hash();
    assert_ne!(e.hash, baseline);

    // …and "absent" is distinguishable from "present".
    let mut f = base();
    f.updates = None;
    f.recompute_hash();
    assert_ne!(f.hash, baseline);
    assert_ne!(f.hash, a.hash);
}

#[test]
fn turn_fields_default_to_the_unary_shape_and_survive_absence_on_the_wire() {
    let m = MethodIr::new("m", "a.m");
    assert!(m.updates.is_none());
    assert!(m.terminal.is_none());
    assert!(m.callbacks.is_empty());

    let decoded: MethodIr = serde_json::from_value(json!({"name": "m", "dotted_id": "a.m"})).unwrap();
    assert!(decoded.updates.is_none());
    assert!(decoded.terminal.is_none());
    assert!(decoded.callbacks.is_empty());
    assert_eq!(decoded.http_method, HttpMethodIr::Post);
    assert_eq!(decoded.auth, AuthRequirementIr::Required);
}

// ---------------------------------------------------------------------------
// Field-level checks for the completeness inventory
// ---------------------------------------------------------------------------

#[test]
fn completeness_root_identity_removes_the_info_probe() {
    // Inventory item 5: the client should not need an `_info` call to learn
    // which backend it is talking to.
    let ir = tree();
    assert_eq!(ir.backend_name.as_deref(), Some("substrate"));
    // Embedded subtree nodes inherit the document's identity; they do not
    // re-declare it.
    assert_eq!(claudecode(&ir).backend_name, None);
}

#[test]
fn completeness_every_embedded_node_carries_a_hash() {
    // Inventory item 2.
    fn walk(ir: &ActivationIr) {
        assert_eq!(ir.hash.len(), 64, "{} has no hash", ir.namespace);
        for m in &ir.methods {
            assert_eq!(m.hash.len(), 64, "{} has no hash", m.dotted_id);
        }
        for c in &ir.children {
            match c {
                ChildEdge::Static(child) => walk(child),
                ChildEdge::Indexed { template, .. } => walk(template),
                ChildEdge::Dynamic { hash, .. } => assert!(!hash.is_empty()),
            }
        }
    }
    walk(&tree());
}

#[test]
fn completeness_dotted_ids_are_explicit_not_reconstructed() {
    // Inventory item 6.
    let ir = tree();
    assert_eq!(
        session_template(&ir).methods[0].dotted_id,
        "claudecode.session.history"
    );
}

#[test]
fn completeness_http_method_is_an_enum_end_to_end() {
    let ir = tree();
    assert_eq!(
        claudecode(&ir).method("list").unwrap().http_method,
        HttpMethodIr::Get
    );
    // …and renders as the uppercase token a REST gateway expects.
    let v = serde_json::to_value(claudecode(&ir).method("list").unwrap()).unwrap();
    assert_eq!(v["http_method"], json!("GET"));
    assert_eq!(HttpMethodIr::Delete.as_str(), "DELETE");
}

#[test]
fn completeness_item_7_streaming_is_now_derived_from_updates() {
    // Inventory item 7 used to be carried by `MethodIr::streaming` (a stored
    // client-presentation hint) alongside `MethodShape::Streaming`. PLX-77
    // remaps it onto a single source of truth: `updates.is_some()`, exposed as
    // the DERIVED classifier `is_streaming()`. There is no stored field to
    // drift from it.
    let ir = tree();
    let chat = claudecode(&ir).method("chat").unwrap();
    let list = claudecode(&ir).method("list").unwrap();

    assert!(chat.is_streaming());
    assert_eq!(chat.is_streaming(), chat.updates.is_some());
    assert!(!list.is_streaming());
    assert_eq!(list.is_streaming(), list.updates.is_some());

    // The classifier is derived, never serialized: no `streaming` (and no
    // `shape`) key exists on the wire for anything to disagree with.
    let v = serde_json::to_value(chat).unwrap();
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("streaming"), "{v}");
    assert!(!obj.contains_key("shape"), "{v}");
    assert!(obj.contains_key("updates"), "{v}");
}

#[test]
fn completeness_item_8_the_reply_channel_is_declared_at_both_ends() {
    // Inventory item 8 is the bidirectional reply channel, previously a
    // hard-coded client-side `respond` convention plus a single
    // `MethodShape::Bidirectional { request, response }` pair. PLX-77 splits it
    // across two fields that together describe the whole channel:
    //
    //   * `ActivationIr::respond_method` — HOW the client answers (unchanged),
    //   * `MethodIr::callbacks`          — WHAT it may be asked, as a SET.
    let ir = tree();
    assert_eq!(ir.respond_method.as_deref(), Some("respond"));

    let chat = claudecode(&ir).method("chat").unwrap();
    assert_eq!(chat.callbacks.len(), 4, "a set, not a single pair");
    // Every callback names its own wire request and both of its types, so a
    // client knows what it is being asked before the turn starts.
    for c in &chat.callbacks {
        assert!(!c.name.is_empty());
        assert!(!c.request.type_name().is_empty());
        assert!(!c.response.type_name().is_empty());
    }
    // The declaration is exactly what the typed handle would advertise.
    assert_eq!(chat.callbacks, acp_prompt_callbacks());
}

#[test]
fn completeness_the_turn_terminal_is_distinct_from_the_update_stream() {
    // PLX-75's single `returns` field conflated the update-item type with the
    // turn's final value; a streaming method had no way to describe what it
    // resolved to. Both are present, and different.
    let ir = tree();
    let chat = claudecode(&ir).method("chat").unwrap();
    assert_eq!(chat.updates.as_ref().unwrap().type_name(), "ChatEvent");
    assert_eq!(chat.terminal.as_ref().unwrap().type_name(), "ChatDone");

    // A unary method has a terminal and no updates…
    let list = claudecode(&ir).method("list").unwrap();
    assert_eq!(list.terminal.as_ref().unwrap().type_name(), "SessionList");
    assert!(list.updates.is_none());

    // …and "returns nothing meaningful" stays distinguishable from "failed to
    // resolve", because a `SchemaRef` can never be `()` (PLX-75 residual #5).
    let health = ir.method("health").unwrap();
    assert!(health.terminal.is_none());
}

#[test]
fn completeness_indexed_edge_answers_all_three_client_questions() {
    // Inventory items 16 and 17: enumerate, form a path, know the shape.
    // Unchanged by PLX-77 — recorded here so the remap is explicit: items 16
    // and 17 stay on `ChildEdge::Indexed`, items 7 and 8 moved onto the turn
    // envelope (see the two tests above).
    let ir = tree();
    match claudecode(&ir).child("session").unwrap() {
        ChildEdge::Indexed {
            list_method,
            search_method,
            id_field,
            path_template,
            template,
            ..
        } => {
            // (a) enumerate
            assert!(!list_method.is_empty());
            assert!(search_method.is_some());
            // (b) form an instance path, without guessing the id field
            assert!(path_template.contains("{id}"));
            assert_eq!(id_field, "session_id");
            // (c) know the instance's shape with no round-trip
            assert!(template.method("history").is_some());
            assert!(template.method("close").is_some());
        }
        other => panic!("expected Indexed, got {other:?}"),
    }
}

#[test]
fn completeness_ir_version_is_carried_and_defaults_on_decode() {
    // Inventory item 18: no handshake, just a declared document version.
    //
    // RFC 002 §3.3 makes it a root fact rather than a field with a silent
    // default: a document that does not declare one has not declared one, and a
    // reader can tell. `recompute_hashes` is what establishes it on a root, and
    // §3.5 does not apply to it thereafter (finding F-01).
    let decoded: ActivationIr =
        serde_json::from_value(json!({"namespace": "n"})).expect("minimal document decodes");
    assert_eq!(decoded.ir_version, None);
    assert_eq!(decoded.version, "");
    assert!(decoded.methods.is_empty());

    let mut root = decoded;
    root.recompute_hashes();
    assert_eq!(root.ir_version, Some(IR_VERSION));
    let wire = serde_json::to_value(&root).unwrap();
    assert_eq!(
        wire.get("ir_version"),
        Some(&json!(IR_VERSION)),
        "§3.3: a mandatory root fact is emitted even at its default"
    );
}

// ---------------------------------------------------------------------------
// RFC 002 §3.3 / §3.5 — the two clauses stop contradicting each other
// ---------------------------------------------------------------------------

#[test]
fn rfc002_3_5_an_absent_description_is_omitted_not_emitted_as_an_empty_string() {
    // The §3.5 non-conformance PLX-86 found: `description` was emitted as `""`
    // on every activation, method and param, while the same encoder correctly
    // omitted `long_description` and `backend_name`. §3.5 forbids "an empty
    // placeholder".
    let mut ir = ActivationIr::new("leaf", "1.0.0").with_method(
        MethodIr::new("m", "leaf.m").with_param(ParamIr::new("p", string_schema("S"))),
    );
    ir.recompute_hashes();
    let v = serde_json::to_value(&ir).unwrap();

    assert!(
        !v.as_object().unwrap().contains_key("description"),
        "activation description must be omitted, not emitted as \"\""
    );
    let m = &v["methods"][0];
    assert!(
        !m.as_object().unwrap().contains_key("description"),
        "method description must be omitted, not emitted as \"\""
    );
    let p = &m["params"][0];
    assert!(
        !p.as_object().unwrap().contains_key("description"),
        "param description must be omitted, not emitted as \"\""
    );

    // The whole document contains no empty string anywhere.
    assert!(
        !serde_json::to_string(&ir).unwrap().contains(":\"\""),
        "no field may be emitted as an empty placeholder"
    );

    // And a described document still says so.
    let mut described = ActivationIr::new("leaf", "1.0.0").with_description("d");
    described.recompute_hashes();
    assert_eq!(
        serde_json::to_value(&described).unwrap()["description"],
        json!("d")
    );
}

#[test]
fn rfc002_3_3_root_facts_are_on_the_root_and_nowhere_else() {
    let ir = tree();
    assert_eq!(ir.ir_version, Some(IR_VERSION));
    assert_eq!(ir.hash_algorithm.as_deref(), Some(HASH_ALGORITHM));
    assert!(ir.ir_hash.is_some());

    // A Static child built by the same builder as a root must not carry any of
    // them, whatever it was constructed with.
    let mut root = ActivationIr::new("r", "1")
        .with_child(ChildEdge::Static(
            ActivationIr::new("c", "1")
                .with_backend_name("smuggled")
                .with_respond_method("smuggled"),
        ));
    root.recompute_hashes();
    let ChildEdge::Static(child) = &root.children[0] else {
        panic!("expected a static child")
    };
    assert_eq!(child.ir_version, None);
    assert_eq!(child.hash_algorithm, None);
    assert_eq!(child.ir_hash, None);
    assert_eq!(child.backend_name, None);
    assert_eq!(child.respond_method, None);
}

#[test]
fn rfc002_4_6_an_activation_hash_does_not_depend_on_the_root_facts() {
    // The property that makes a Static child's advertised hash comparable with
    // the hash it reports when fetched on its own: root facts belong to the
    // DOCUMENT hash, not the activation hash.
    let mut plain = ActivationIr::new("n", "1");
    plain.recompute_hashes();
    let mut identified = ActivationIr::new("n", "1")
        .with_backend_name("b")
        .with_respond_method("respond");
    identified.recompute_hashes();

    assert_eq!(plain.hash, identified.hash, "activation hash is unchanged");
    assert_ne!(
        plain.ir_hash, identified.ir_hash,
        "§4.5: the document hash still changes, so a consumer invalidates"
    );
}

// ---------------------------------------------------------------------------
// RFC 002 §4.4 + §7.1 — a capability SET has no order
// ---------------------------------------------------------------------------

#[test]
fn rfc002_7_1_capability_declaration_order_does_not_change_the_hash() {
    // The second Rust non-conformance PLX-86 found (fixtures b09/b10): §7.1
    // states the callback declaration is a SET, a set has no canonical order,
    // so §4.4's ban on depending on a non-canonical ordering applies.
    let cb1 = CallbackIr::new("cb1", string_schema("Q"), string_schema("A"));
    let cb2 = CallbackIr::new("cb2", string_schema("Q2"), string_schema("A2"));

    let mut forward = MethodIr::new("m", "a.m").with_callbacks([cb1.clone(), cb2.clone()]);
    let mut reverse = MethodIr::new("m", "a.m").with_callbacks([cb2, cb1]);
    forward.recompute_hash();
    reverse.recompute_hash();

    assert_eq!(
        forward.hash, reverse.hash,
        "two declaration orders of one capability SET must hash identically"
    );

    // Not vacuous: a genuinely different set still hashes differently.
    let mut one = MethodIr::new("m", "a.m")
        .with_callback(CallbackIr::new("cb1", string_schema("Q"), string_schema("A")));
    one.recompute_hash();
    assert_ne!(forward.hash, one.hash);
}

// ---------------------------------------------------------------------------
// RFC 002 §6.9 — the request context
// ---------------------------------------------------------------------------

#[test]
fn rfc002_6_9_request_context_is_declared_overridden_and_hashed() {
    let activation_ctx = schema("SessionRequest");
    let method_ctx = schema("UploadRequest");

    let inherits = MethodIr::new("read", "n.read");
    let overrides = MethodIr::new("upload", "n.upload").with_request_context(method_ctx.clone());
    let mut ir = ActivationIr::new("n", "1")
        .with_request_context(activation_ctx.clone())
        .with_method(inherits)
        .with_method(overrides);
    ir.recompute_hashes();

    // §6.9 resolution: the method's own declaration replaces the activation's;
    // a method without one takes the activation's; there is no merge.
    let read = ir.method("read").unwrap();
    let upload = ir.method("upload").unwrap();
    assert_eq!(
        ir.effective_request_context(read),
        Some(&activation_ctx),
        "a method with no declaration of its own takes the activation's"
    );
    assert_eq!(
        ir.effective_request_context(upload),
        Some(&method_ctx),
        "a method's own declaration replaces the activation's"
    );

    // §6.9 absence: no declaration anywhere means the method needs nothing.
    let bare = ActivationIr::new("n", "1").with_method(MethodIr::new("read", "n.read"));
    assert_eq!(
        bare.effective_request_context(bare.method("read").unwrap()),
        None
    );

    // It is content: it round-trips and it participates in the hashes.
    let json = serde_json::to_string(&ir).unwrap();
    let back: ActivationIr = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ir);
    assert_eq!(
        back.request_context.as_ref().map(|r| r.type_name()),
        Some("SessionRequest")
    );

    let mut without = ActivationIr::new("n", "1")
        .with_method(MethodIr::new("read", "n.read"))
        .with_method(MethodIr::new("upload", "n.upload").with_request_context(method_ctx));
    without.recompute_hashes();
    assert_ne!(
        ir.hash, without.hash,
        "dropping the activation-level declaration is a content change"
    );

    let mut method_only_changed = ActivationIr::new("n", "1")
        .with_method(MethodIr::new("upload", "n.upload"));
    method_only_changed.recompute_hashes();
    let mut method_only_declared = ActivationIr::new("n", "1")
        .with_method(MethodIr::new("upload", "n.upload").with_request_context(schema("Other")));
    method_only_declared.recompute_hashes();
    assert_ne!(
        method_only_changed.method("upload").unwrap().hash,
        method_only_declared.method("upload").unwrap().hash,
        "a method's request context participates in its own hash"
    );
}

#[test]
fn navigation_helpers_find_children_across_all_edge_kinds() {
    let ir = tree();
    assert!(matches!(ir.child("claudecode"), Some(ChildEdge::Static(_))));
    assert!(matches!(
        ir.child("jsexec"),
        Some(ChildEdge::Dynamic { .. })
    ));
    assert!(matches!(
        claudecode(&ir).child("session"),
        Some(ChildEdge::Indexed { .. })
    ));
    assert!(ir.child("nope").is_none());
}

// ---------------------------------------------------------------------------
// Fixture regeneration for the independent Haskell implementation
// ---------------------------------------------------------------------------

/// Re-emit the `connectome-hs` fixture corpus from this implementation.
///
/// The corpus in `connectome-hs/fixtures/rust/` is the only thing the Haskell
/// implementation ever learned from the Rust side, and RFC 002 changed both the
/// wire (§3.3 root facts, §3.5 omitted descriptions, §4.7 the construction
/// identifier) and every hash (§4.6 `CONNECTOME-HASH/1`). Rather than
/// hand-writing 40 documents again, each fixture is decoded into the model and
/// re-encoded, which preserves exactly the content the corpus was commissioned
/// to probe and updates only what RFC 002 changed.
///
/// Inert unless `CONNECTOME_FIXTURE_DIR` is set, so a normal `cargo test` never
/// writes to another repository:
///
/// ```sh
/// CONNECTOME_FIXTURE_DIR=../connectome-hs/fixtures/rust \
///   cargo test --lib regenerate_connectome_fixtures -- --nocapture
/// ```
#[test]
fn regenerate_connectome_fixtures() {
    let Ok(dir) = std::env::var("CONNECTOME_FIXTURE_DIR") else {
        return;
    };
    let root = std::path::PathBuf::from(dir);
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for d in [root.clone(), root.join("ablation")] {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            // 07 is a bag of stop reasons and 90 is a pre-IR golden; neither is
            // a document.
            if name.starts_with("07_") || name.starts_with("90_") {
                continue;
            }
            files.push(p);
        }
    }
    files.sort();
    assert!(files.len() > 30, "expected the whole corpus, found {}", files.len());

    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        let mut ir: ActivationIr = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        ir.recompute_hashes();
        let mut out = serde_json::to_string_pretty(&ir).unwrap();
        out.push('\n');
        std::fs::write(&path, out).unwrap();
        println!("regenerated {}", path.display());
    }
}
