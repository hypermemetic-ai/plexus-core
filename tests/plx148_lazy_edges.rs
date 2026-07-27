//! PLX-148 — a Dynamic edge becomes fetchable, and the path resolves.
//!
//! RFC 002 §5.1 requires a Dynamic edge to be **sufficient to fetch and cache
//! the child lazily**. PLX-121 walked the served document and found 0 of 5
//! fetchable; PLX-124 re-measured it on the wire as 9 attempts, 9 unfetchable,
//! 0 cache hits. The letter of §5.1 was satisfied — every edge carried a
//! namespace and a hash — and the sufficiency clause was not.
//!
//! The cause was that `Dynamic` meant *"the hub does not have this subtree"*.
//! Under that meaning a Dynamic edge is unfetchable **by construction**: the
//! only way for the hub to answer is to hold the document, and holding it made
//! the edge `Static`. These tests pin the separation — *have it* and *embed it*
//! are now two questions — and pin that nothing else moved with it.
//!
//! What is deliberately **not** here: any assertion that a document is
//! conformant. That judgement belongs to `connectome-hs`, over a document
//! fetched from a running substrate, for the reason PLX-142 recorded — a Rust
//! test agreeing with the Rust encoder is self-attestation.

use plexus_core::activations::health::Health;
use plexus_core::ir::{ActivationIr, AuthRequirementIr, ChildEdge, MethodIr, SchemaRef};
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

/// The hash an edge **advertises** — the child's identity.
///
/// PLX-160 moved the three-arm match this used to be onto the type itself, as
/// `ChildEdge::advertised_hash`: it is a DELIVERY question (`Embedded` has the
/// subtree, `Lazy` has the digest) and never a shape one, so it needed one arm
/// per delivery and not one per variant.
///
/// Deliberately not `ChildEdge::edge_hash()`, which is a different quantity:
/// that is the digest of the edge's own §4.6 preimage tuple, i.e. the edge's
/// contribution to its parent's fold. Reading it as "the child's hash" is an
/// easy and silent mistake — the two are both 64 hex and neither equals the
/// other.
fn advertised(edge: &ChildEdge) -> String {
    edge.advertised_hash().to_string()
}

/// A leaf a hub can hold without embedding.
fn health_document() -> ActivationIr {
    let mut ir = ActivationIr::new("health", "1.0.0")
        .with_description("liveness")
        .with_method(
            MethodIr::new("check", "health.check")
                .with_auth(AuthRequirementIr::Public)
                .with_terminal(schema_ref("HealthStatus")),
        );
    ir.recompute_hashes();
    ir
}

/// The document behind a **nested** Dynamic edge — the shape a `#[child]` gate
/// declares and the macro reduces to a hash.
fn session_document() -> ActivationIr {
    let mut ir = ActivationIr::new("session", "1.0.0")
        .with_description("one session")
        .with_method(
            MethodIr::new("chat", "claudecode.session.chat")
                .with_auth(AuthRequirementIr::Required)
                .with_terminal(schema_ref("Update")),
        );
    ir.recompute_hashes();
    ir
}

/// `claudecode`: embedded, and carrying a nested Dynamic edge of its own.
fn claudecode() -> IrActivation {
    let ir = ActivationIr::new("claudecode", "1.0.0")
        .with_description("sessions")
        .with_method(
            MethodIr::new("list", "claudecode.list")
                .with_auth(AuthRequirementIr::Public)
                .with_terminal(schema_ref("Sessions")),
        )
        .with_child(
            ChildEdge::lazy("session", session_document().hash.clone())
                .with_description("one session"),
        );
    IrActivation::new(
        ir,
        HandlerTable::new([(
            "list",
            ErasedHandler::new(|_| async { TurnOutcome::serialize("[]") }),
        )]),
    )
}

fn hub() -> DynamicHub {
    bare_hub()
}

fn bare_hub() -> DynamicHub {
    DynamicHub::new("substrate")
        .register(claudecode())
        .register(Health::new())
}

// ===========================================================================
// 1. The hub-level Dynamic edge: advertised, not embedded, and fetchable
// ===========================================================================

/// Before this build, a registered activation with no subtree advertised its
/// 16-hex legacy `PluginSchema::hash` and answered *"no Connectome document is
/// declared"* when asked for. PLX-142 recorded exactly that as a residual:
/// *never compare a Dynamic edge's hash against a Connectome node hash.*
///
/// With a lazy declaration the comparison is not merely safe, it is the point.
#[test]
fn a_lazily_declared_child_stays_dynamic_and_advertises_its_connectome_hash() {
    let legacy = hub().connectome();
    let legacy_edge = legacy.child("health").expect("health is a child");
    assert!(
        legacy_edge.is_lazy(),
        "an undeclared child is advertised, not embedded"
    );
    // The legacy `PluginSchema::hash`, whatever width this build computes it
    // at — the point is that it is not the child's Connectome node hash, which
    // is why PLX-142 warned never to compare the two.
    let legacy_hash = advertised(legacy_edge);
    assert_ne!(
        legacy_hash,
        health_document().hash,
        "before this build the advertised hash was NOT a CONNECTOME-HASH/1 digest"
    );

    let doc = hub().declare_ir_lazy(health_document()).connectome();
    let edge = doc.child("health").expect("health is still a child");
    assert!(
        edge.is_lazy(),
        "a lazy declaration must NOT promote the edge to embedded — not embedding \
         it is the whole difference, and after PLX-160 it is the only difference: \
         the shape axis is untouched by it"
    );
    assert!(
        !edge.is_indexed(),
        "and the OTHER axis did not move either — a single child stays single"
    );
    assert_eq!(
        advertised(edge),
        health_document().hash,
        "the edge advertises the child's CONNECTOME-HASH/1 node hash"
    );
    assert_ne!(advertised(edge), legacy_hash);
}

/// §5.1's sufficiency clause, as a round trip: the hash the edge advertised is
/// the hash of the document the fetch returns. That equality is what makes the
/// hash usable as a cache key, which is the reason PLX-121 wanted it.
#[test]
fn the_advertised_hash_is_the_hash_of_the_document_that_comes_back() {
    let hub = hub().declare_ir_lazy(health_document());
    let doc = hub.connectome();
    let edge_hash = advertised(doc.child("health").expect("health is a child"));

    let fetched = hub
        .child_connectome("health")
        .expect("a lazily declared child answers");

    assert_eq!(fetched.hash, edge_hash);
    // A document, not an embedded node (§3.3).
    assert_eq!(fetched.hash_algorithm.as_deref(), Some("CONNECTOME-HASH/1"));
    assert!(fetched.ir_hash.is_some());
    assert_eq!(fetched.methods.len(), 1);
}

/// The gap, still visible when nothing supplies the document. This is the test
/// that would fail if anyone added a `{ns}.schema` fallback: an unfetchable
/// child must stay *visibly* unfetchable rather than be handed a document
/// lifted from the legacy schema, which PLX-119 measured as conformant-looking
/// and therefore the expensive kind of wrong.
#[test]
fn an_undeclared_child_is_still_unfetchable_and_nothing_is_lifted_for_it() {
    assert!(
        hub().child_connectome("health").is_none(),
        "no document was declared for health, and none may be manufactured"
    );
}

// ===========================================================================
// 2. The nested Dynamic edge: a path, where a namespace could not reach
// ===========================================================================

/// Three of substrate's five Dynamic edges are nested one level below a Static
/// edge. The `namespace` parameter resolved hub-level activations only, so they
/// had no wire route at all — whatever they carried, no client could ask.
#[test]
fn a_nested_dynamic_edge_had_no_route_and_now_resolves_by_path() {
    let plain = hub();
    assert!(
        plain
            .connectome()
            .child("claudecode")
            .and_then(|c| c.child().and_then(|sub| sub.child("session")))
            .is_some(),
        "the document advertises claudecode/session"
    );
    assert!(
        plain.child_connectome("claudecode/session").is_none(),
        "and cannot serve it without a declaration"
    );

    let hub = hub().declare_ir_at("claudecode/session", session_document());
    let fetched = hub
        .child_connectome("claudecode/session")
        .expect("the nested child answers by path");
    assert_eq!(fetched.namespace, "session");
    assert_eq!(fetched.hash, session_document().hash);
    assert_eq!(
        fetched.hash,
        hub.connectome()
            .child("claudecode")
            .and_then(|c| c.child().and_then(|sub| sub.child("session")))
            .map(advertised)
            .expect("the nested edge"),
        "the nested edge advertises exactly what the path fetch returns"
    );
}

/// Resolution walks the document the hub already serves, so a node it embeds is
/// addressable at the path it appears at — without anyone declaring it twice.
#[test]
fn an_embedded_node_is_addressable_by_the_path_it_appears_at() {
    let ir = ActivationIr::new("orcha", "1.0.0")
        .with_description("graphs")
        .with_child(ChildEdge::embedded(
            ActivationIr::new("pm", "1.0.0").with_method(
                MethodIr::new("plan", "orcha.pm.plan")
                    .with_auth(AuthRequirementIr::Public)
                    .with_terminal(schema_ref("Plan")),
            ),
        ));
    let hub = DynamicHub::new("substrate").register(IrActivation::new(
        ir,
        HandlerTable::new([] as [(&str, ErasedHandler); 0]),
    ));

    let nested = hub.child_connectome("orcha/pm").expect("orcha/pm resolves");
    assert_eq!(nested.namespace, "pm");
    assert_eq!(nested.methods.len(), 1);
    // Still a node hash, not a new one: §4.7 keeps the root facts out of the
    // preimage, so the same subtree hashes the same embedded and standalone.
    let embedded = advertised(
        hub.connectome()
            .child("orcha")
            .expect("orcha")
            .child()
            .expect("an embedded subtree")
            .child("pm")
            .expect("pm"),
    );
    assert_eq!(nested.hash, embedded);
}

/// A path a client cannot read off the document is not a path the hub invents
/// an answer for.
#[test]
fn a_path_the_document_does_not_contain_answers_nothing() {
    let hub = hub().declare_ir_lazy(health_document());
    assert!(hub.child_connectome("claudecode/nope").is_none());
    assert!(hub.child_connectome("nope").is_none());
    assert!(hub.child_connectome("health/deeper").is_none());
    assert!(
        hub.child_connectome("").is_none(),
        "the root is asked for by sending no namespace, not an empty one"
    );
}

// ===========================================================================
// 3. What must NOT move
// ===========================================================================

/// The movement a lazy declaration causes, enumerated: the edge's advertised
/// hash, the root node hash that folds it, and the document hash. Nothing else.
/// Every method hash and every other activation hash is byte-identical.
#[test]
fn declaring_lazily_moves_the_edge_and_the_root_and_no_method_hash() {
    fn methods(ir: &ActivationIr) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = ir
            .methods
            .iter()
            .map(|m| (m.name.clone(), m.hash.clone()))
            .collect();
        for c in &ir.children {
            if let Some(sub) = c.child() {
                out.extend(methods(sub));
            }
        }
        out.sort();
        out
    }

    let before = hub().connectome();
    let after = hub().declare_ir_lazy(health_document()).connectome();

    assert_eq!(methods(&before), methods(&after), "no method hash moved");

    let claudecode = |ir: &ActivationIr| {
        ir.child("claudecode")
            .expect("claudecode")
            .child()
            .expect("an embedded subtree")
            .hash
            .clone()
    };
    assert_eq!(
        claudecode(&before),
        claudecode(&after),
        "an unrelated activation's node hash is untouched"
    );

    assert_ne!(before.hash, after.hash, "the root folds the changed edge");
    assert_ne!(before.ir_hash, after.ir_hash, "and the document hash moves");
}

/// Declaring a document *at a nested path* changes the served bytes not at all:
/// it is a fetch route, not a fact. This is why the three nested edges cost no
/// hash movement whatsoever.
#[test]
fn declaring_a_nested_document_changes_no_byte_of_the_served_document() {
    let before = serde_json::to_vec(&hub().connectome()).expect("serializes");
    let after = serde_json::to_vec(
        &hub()
            .declare_ir_at("claudecode/session", session_document())
            .connectome(),
    )
    .expect("serializes");
    assert_eq!(before, after);
}

/// Embedding is strictly more information than advertising, so a child declared
/// both ways is embedded. The lazy entry then only duplicates a route the
/// embedded path already provides.
#[test]
fn an_embedded_declaration_wins_the_edge_over_a_lazy_one() {
    let hub = hub()
        .declare_ir_lazy(health_document())
        .declare_ir(health_document());
    let edge = hub.connectome().child("health").expect("health").clone();
    assert!(!edge.is_lazy(), "embedding wins over advertising");
    assert_eq!(
        hub.child_connectome("health").expect("still fetchable").hash,
        health_document().hash
    );
}

// ===========================================================================
// 4. A served child document is a document of this backend
// ===========================================================================

/// PLX-157 declared `backend_name` and `respond_method` on the hub and measured
/// substrate's document back from `connectome-hs` with **zero advisories**.
/// Making nine more documents fetchable made nine more documents checkable, and
/// each came back with exactly PLX-157's two §3.3/§7.6 SHOULD advisories — the
/// gap was not new, it was newly *reachable*.
///
/// A child document is served by this hub, so this hub's identity and reply
/// channel are its identity and reply channel. Stamping them is the same fact
/// PLX-157 established, reaching the documents the same hub hands out.
#[test]
fn a_served_child_document_carries_the_hubs_declared_root_facts() {
    let hub = hub()
        .with_backend_name("substrate")
        .with_respond_method("substrate.respond")
        .declare_ir_lazy(health_document())
        .declare_ir_at("claudecode/session", session_document());

    for path in ["health", "claudecode/session", "claudecode"] {
        let doc = hub.child_connectome(path).expect("fetchable");
        assert_eq!(doc.backend_name.as_deref(), Some("substrate"), "{path}");
        assert_eq!(
            doc.respond_method.as_deref(),
            Some("substrate.respond"),
            "{path}"
        );
    }

    // And a hub that declares neither is unchanged — the facts stay absent
    // rather than being invented per child.
    let plain = bare_hub().declare_ir_lazy(health_document());
    let doc = plain.child_connectome("health").expect("fetchable");
    assert_eq!(doc.backend_name, None);
    assert_eq!(doc.respond_method, None);
}

/// The stamp is a *document* fact and touches no node hash — which is exactly
/// what lets the advertised hash and the fetched hash still be compared.
#[test]
fn stamping_the_root_facts_moves_the_document_hash_and_not_the_node_hash() {
    let bare = hub().declare_ir_lazy(health_document());
    let named = hub()
        .with_backend_name("substrate")
        .declare_ir_lazy(health_document());

    let a = bare.child_connectome("health").expect("fetchable");
    let b = named.child_connectome("health").expect("fetchable");

    assert_eq!(a.hash, b.hash, "the node hash is the child's identity");
    assert_eq!(
        b.hash,
        advertised(named.connectome().child("health").expect("health")),
        "and it still equals what the edge advertises"
    );
    assert_ne!(a.ir_hash, b.ir_hash, "the document hash covers the root facts");
}
