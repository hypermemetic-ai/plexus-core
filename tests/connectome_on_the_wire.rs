//! PLX-142 — the Connectome is served, and serving it changes nothing else.
//!
//! These pin the two halves the ticket is judged on. The first is that a
//! document with the right shape now exists at a wire method; the second, and
//! the one that is easy to lose quietly, is that `{ns}.schema` is **byte for
//! byte** what it was. That path is the live decoder for 28 import sites in
//! `plexus-protocol` alone (PLX-119 c3) and retires when its consumers do, not
//! here.
//!
//! Conformance itself is not asserted here. It is not this implementation's to
//! assert: the judge is `connectome-hs`'s checker, run over a document
//! **fetched from a running substrate**, and a Rust test that agreed with the
//! Rust encoder would be self-attestation. What these tests pin are the
//! structural invariants a checker cannot see from one document — that the
//! embedded and standalone forms of the same subtree agree, and that nothing
//! was manufactured for a child that has no document.

use plexus_core::activations::health::Health;
use plexus_core::ir::{
    ActivationIr, AuthRequirementIr, ChildEdge, MethodIr, SchemaRef,
};
use plexus_core::plexus::DynamicHub;
use plexus_core::runtime::{ErasedHandler, HandlerTable, IrActivation, TurnOutcome};

fn schema_ref(name: &str) -> SchemaRef {
    SchemaRef::new(
        name,
        serde_json::from_value(serde_json::json!({ "type": "string" }))
            .expect("a JSON Schema"),
    )
    .expect("an informative schema")
}

/// A three-level subtree exercising all three edge kinds, so the invariants
/// below are not discharged by a bag of near-identical leaves.
fn subtree() -> ActivationIr {
    let grandchild = ActivationIr::new("leaf", "0.1.0")
        .with_description("a static grandchild")
        .with_method(
            MethodIr::new("ping", "widgets.leaf.ping")
                .with_auth(AuthRequirementIr::Public)
                .with_terminal(schema_ref("Pong")),
        );

    let instance = ActivationIr::new("widget_instance", "1.0.0")
        .with_description("one widget")
        .with_method(
            MethodIr::new("show", "widgets.item.show")
                .with_auth(AuthRequirementIr::Required)
                .with_terminal(schema_ref("Widget")),
        );

    ActivationIr::new("widgets", "2.3.4")
        .with_description("the widgets activation")
        .with_method(
            MethodIr::new("list", "widgets.list")
                .with_auth(AuthRequirementIr::Public)
                .with_terminal(schema_ref("WidgetList")),
        )
        .with_child(ChildEdge::Static(grandchild))
        .with_child(ChildEdge::Indexed {
            namespace: "item".into(),
            list_method: "widgets.list".into(),
            search_method: Some("widgets.search".into()),
            id_field: "widget_id".into(),
            path_template: "item/{id}".into(),
            template: Box::new(instance),
            description: "a family of widgets".into(),
        })
        .with_child(ChildEdge::Dynamic {
            namespace: "plugin".into(),
            // A hash, not a placeholder: §5.1 requires the edge to advertise
            // the child's identity, and §5.2 forbids recomputing one.
            hash: "a".repeat(64),
            description: "registered at runtime".into(),
        })
}

fn widgets() -> IrActivation {
    IrActivation::new(
        subtree(),
        HandlerTable::new([(
            "list",
            ErasedHandler::new(|_| async { TurnOutcome::serialize("[]") }),
        )]),
    )
}

/// A hub with one child that has a Connectome (`IrActivation` overrides
/// `connectome_subtree`) and one that does not (`Health` is hand-written and
/// inherits the `None` default).
fn hub() -> DynamicHub {
    DynamicHub::new("substrate")
        .register(widgets())
        .register(Health::new())
}

// ===========================================================================
// The document is served
// ===========================================================================

#[test]
fn the_hub_document_carries_the_mandatory_root_facts() {
    let doc = hub().connectome();

    assert_eq!(doc.namespace, "substrate");
    // §3.3.1 — the three MUST facts are emitted always, even at their default.
    assert_eq!(doc.ir_version, Some(plexus_core::ir::IR_VERSION));
    assert_eq!(doc.hash_algorithm.as_deref(), Some("CONNECTOME-HASH/1"));
    assert!(doc.ir_hash.is_some(), "a document carries an ir_hash");
    assert!(!doc.hash.is_empty(), "§4.1 — every activation carries a hash");
}

#[test]
fn a_child_with_a_connectome_is_embedded_and_one_without_is_advertised() {
    let doc = hub().connectome();

    // §5.1 Static — the subtree is embedded, so descending needs no round trip.
    let widgets = doc.child("widgets").expect("widgets is a child edge");
    let ChildEdge::Static(embedded) = widgets else {
        panic!("a child whose Connectome the hub holds must be embedded, got {widgets:?}");
    };
    assert_eq!(embedded.methods.len(), 1);
    assert_eq!(embedded.children.len(), 3);

    // §5.1 Dynamic + §5.2 — a child with no Connectome gets identity and
    // nothing else. Nothing is manufactured from its legacy schema.
    let health = doc.child("health").expect("health is a child edge");
    let ChildEdge::Dynamic { hash, .. } = health else {
        panic!("a child with no Connectome must not be embedded, got {health:?}");
    };
    assert!(!hash.is_empty(), "§5.1 — the edge advertises the child's hash");
}

#[test]
fn all_three_edge_kinds_survive_the_embedding() {
    let doc = hub().connectome();
    let ChildEdge::Static(widgets) = doc.child("widgets").unwrap() else {
        unreachable!()
    };

    assert!(matches!(widgets.child("leaf"), Some(ChildEdge::Static(_))));
    assert!(matches!(
        widgets.child("plugin"),
        Some(ChildEdge::Dynamic { .. })
    ));
    let Some(ChildEdge::Indexed {
        list_method,
        search_method,
        id_field,
        path_template,
        template,
        ..
    }) = widgets.child("item")
    else {
        panic!("the Indexed edge did not survive")
    };
    // §5.1's five facts, all present — this is what the legacy wire cannot
    // carry and what §5.2 forbids a client from inventing.
    assert_eq!(list_method, "widgets.list");
    assert_eq!(search_method.as_deref(), Some("widgets.search"));
    assert_eq!(id_field, "widget_id");
    assert_eq!(path_template, "item/{id}");
    assert!(!template.hash.is_empty());
}

#[test]
fn a_dynamic_edge_advertised_hash_is_folded_and_never_recomputed() {
    // §5.2 — "a parent MUST fold a Dynamic child's advertised hash and MUST NOT
    // recompute one". The hub round-trips it verbatim.
    let doc = hub().connectome();
    let ChildEdge::Static(widgets) = doc.child("widgets").unwrap() else {
        unreachable!()
    };
    let Some(ChildEdge::Dynamic { hash, .. }) = widgets.child("plugin") else {
        unreachable!()
    };
    assert_eq!(hash, &"a".repeat(64));
}

// ===========================================================================
// Root facts, and the hash that must not move (PLX-90 c3, on the wire path)
// ===========================================================================

#[test]
fn root_facts_live_on_the_root_and_on_no_embedded_node() {
    let hub = hub();
    let doc = hub.connectome();
    let ChildEdge::Static(embedded) = doc.child("widgets").unwrap() else {
        unreachable!()
    };

    // §3.3 — "non-root activations MUST NOT carry any of them; their presence
    // is what distinguishes a root from an embedded node."
    assert_eq!(embedded.ir_version, None);
    assert_eq!(embedded.hash_algorithm, None);
    assert_eq!(embedded.ir_hash, None);
    assert_eq!(embedded.backend_name, None);
    assert_eq!(embedded.respond_method, None);

    // ...and the same node fetched as a document of its own does carry them.
    let standalone = hub
        .child_connectome("widgets")
        .expect("widgets serves its own document");
    assert_eq!(standalone.ir_version, Some(plexus_core::ir::IR_VERSION));
    assert_eq!(
        standalone.hash_algorithm.as_deref(),
        Some("CONNECTOME-HASH/1")
    );
    assert!(standalone.ir_hash.is_some());
}

#[test]
fn the_same_subtree_hashes_identically_embedded_and_standalone() {
    // §4.6 — the root facts are deliberately outside the activation preimage,
    // "which would make a Static child's advertised hash incomparable with the
    // hash it reports when fetched on its own". This is that property, on the
    // two values a client can actually obtain.
    let hub = hub();
    let ChildEdge::Static(embedded) = hub.connectome().child("widgets").unwrap().clone() else {
        unreachable!()
    };
    let standalone = hub.child_connectome("widgets").unwrap();

    assert_eq!(embedded.hash, standalone.hash);
    assert!(!embedded.hash.is_empty());
}

#[test]
fn no_method_hash_moves_when_a_subtree_is_embedded() {
    fn method_hashes(ir: &ActivationIr, path: &str, out: &mut Vec<(String, String)>) {
        for m in &ir.methods {
            out.push((format!("{path}/{}", m.name), m.hash.clone()));
        }
        for c in &ir.children {
            match c {
                ChildEdge::Static(child) => {
                    method_hashes(child, &format!("{path}/{}", c.namespace()), out);
                }
                ChildEdge::Indexed { template, .. } => {
                    method_hashes(template, &format!("{path}/{}", c.namespace()), out);
                }
                ChildEdge::Dynamic { .. } => {}
            }
        }
    }

    let hub = hub();
    let ChildEdge::Static(embedded) = hub.connectome().child("widgets").unwrap().clone() else {
        unreachable!()
    };
    let standalone = hub.child_connectome("widgets").unwrap();

    let mut a = Vec::new();
    method_hashes(&embedded, "widgets", &mut a);
    let mut b = Vec::new();
    method_hashes(&standalone, "widgets", &mut b);

    assert!(!a.is_empty(), "the probe is not vacuous");
    assert_eq!(a, b, "a method hash moved between embedded and standalone");

    // And against the source of truth: the IR the activation itself built,
    // before any hub touched it.
    let mut c = Vec::new();
    let mut source = subtree();
    source.recompute_hashes();
    method_hashes(&source, "widgets", &mut c);
    assert_eq!(a, c, "a method hash moved when the hub composed the document");
}

#[test]
fn the_document_is_stable_across_recomposition() {
    // The hash is a cache key (PLX-121) or it is nothing. Two compositions of
    // the same hub must be byte-identical, including the order of a set (§4.8),
    // which is what makes a `HashMap` of activations safe to iterate here.
    let a = serde_json::to_string(&hub().connectome()).unwrap();
    let b = serde_json::to_string(&hub().connectome()).unwrap();
    assert_eq!(a, b);
}

// ===========================================================================
// The legacy path is untouched (criterion c3)
// ===========================================================================

#[test]
fn declaring_a_connectome_does_not_change_the_legacy_plugin_schema() {
    use plexus_core::Activation;

    let before = serde_json::to_value(Activation::plugin_schema(&hub())).unwrap();

    // Declaring an IR is exactly the operation that could leak into the legacy
    // path, because it is the only new input the hub takes.
    let after = serde_json::to_value(Activation::plugin_schema(
        &hub().declare_ir(subtree()),
    ))
    .unwrap();

    assert_eq!(
        before, after,
        "declaring a Connectome changed the legacy PluginSchema"
    );
}

#[tokio::test]
async fn the_legacy_schema_method_still_returns_a_plugin_schema() {
    use futures::StreamExt;
    use plexus_core::plexus::types::PlexusStreamItem;
    use plexus_core::plexus::PluginSchema;

    async fn fetch_schema(hub: &DynamicHub) -> serde_json::Value {
        let mut stream = hub
            .route("health.schema", serde_json::json!({}), None)
            .await
            .expect("health.schema routes");
        while let Some(item) = stream.next().await {
            if let PlexusStreamItem::Data { content, .. } = item {
                // The point of c3: it still decodes with the LEGACY type.
                let schema: PluginSchema = serde_json::from_value(content.clone())
                    .expect("{ns}.schema still returns a legacy PluginSchema");
                assert_eq!(schema.namespace, "health");
                return content;
            }
        }
        panic!("health.schema carried no payload");
    }

    let plain = fetch_schema(&hub()).await;
    let with_ir = fetch_schema(&hub().declare_ir(subtree())).await;
    assert_eq!(
        plain, with_ir,
        "{{ns}}.schema drifted once a Connectome was declared"
    );
}

#[test]
fn an_activation_declares_no_connectome_by_default() {
    use plexus_core::Activation;

    // The default is `None`, not a lift from the legacy schema. PLX-119
    // measured that a lifted legacy document is *conformant-looking* — the
    // dangerous kind of wrong — so the default must be silence.
    assert!(Health::new().connectome_subtree().is_none());
    assert!(widgets().connectome_subtree().is_some());
}

#[test]
fn a_child_that_declares_no_connectome_has_none_to_serve() {
    assert!(hub().child_connectome("health").is_none());
    assert!(hub().child_connectome("nonexistent").is_none());
}
