//! PLX-160 — regenerate `connectome-hs`'s Rust fixture corpus for the two-axis
//! edge form, and add the cell that had no variant.
//!
//! This is a **regeneration**, not a hand-edit. The JSON→JSON step below is a
//! total, mechanical rewrite of the edge object's keys; every byte that is
//! written comes back out of `plexus_core`'s own `Serialize`, and every hash is
//! re-verified against `recompute_hashes` before anything is written. A file
//! whose stored hashes do not survive the round trip is a failure, not a
//! warning — which is what makes this run *evidence* that §4.6 tags 1/2/3 are
//! byte-identical across the change, measured on the whole 41-file corpus
//! rather than on a fixture of my own choosing.
//!
//! Usage: `cargo run --example plx160_regen_fixtures -- <fixtures/rust dir>`

use plexus_core::ir::{ActivationIr, ChildDelivery, MethodIr, SchemaRef};
use serde_json::{json, Map, Value};

/// Rewrite one edge object from the pre-PLX-160 form to the two-axis form.
fn port_edge(v: &Value) -> Value {
    let o = v.as_object().expect("an edge is an object");
    // The pre-PLX-160 parser defaulted a missing `edge` key to "static".
    let kind = o.get("edge").and_then(Value::as_str).unwrap_or("static");
    let mut out = Map::new();

    match kind {
        // A Static edge inlined the child's own fields alongside the tag. The
        // namespace was therefore implicit; it is explicit now, and the subtree
        // moves under `child` so that the delivery payload has one spelling
        // under both shapes.
        "static" => {
            let mut child = o.clone();
            child.remove("edge");
            let ns = child
                .get("namespace")
                .and_then(Value::as_str)
                .expect("an embedded child names itself")
                .to_string();
            out.insert("namespace".into(), json!(ns));
            out.insert("shape".into(), json!("single"));
            out.insert("delivery".into(), json!("embedded"));
            out.insert("child".into(), port_activation(&Value::Object(child)));
        }
        "dynamic" => {
            out.insert("namespace".into(), o["namespace"].clone());
            out.insert("shape".into(), json!("single"));
            out.insert("delivery".into(), json!("lazy"));
            out.insert("hash".into(), o["hash"].clone());
            if let Some(d) = o.get("description") {
                out.insert("description".into(), d.clone());
            }
        }
        "indexed" => {
            out.insert("namespace".into(), o["namespace"].clone());
            out.insert("shape".into(), json!("indexed"));
            out.insert("list_method".into(), o["list_method"].clone());
            if let Some(s) = o.get("search_method") {
                out.insert("search_method".into(), s.clone());
            }
            out.insert("id_field".into(), o["id_field"].clone());
            out.insert("path_template".into(), o["path_template"].clone());
            out.insert("delivery".into(), json!("embedded"));
            out.insert("child".into(), port_activation(&o["template"]));
            if let Some(d) = o.get("description") {
                out.insert("description".into(), d.clone());
            }
        }
        other => panic!("unknown pre-PLX-160 edge kind `{other}`"),
    }
    Value::Object(out)
}

fn port_activation(v: &Value) -> Value {
    let mut o = v.as_object().expect("an activation is an object").clone();
    if let Some(Value::Array(children)) = o.get("children") {
        let ported: Vec<Value> = children.iter().map(port_edge).collect();
        o.insert("children".into(), Value::Array(ported));
    }
    Value::Object(o)
}

fn schema_ref(name: &str) -> SchemaRef {
    SchemaRef::new(
        name,
        serde_json::from_value(json!({ "type": "string" })).expect("a JSON Schema"),
    )
    .expect("an informative schema")
}

/// The fourth cell, derived from an existing fixture by moving **one axis**.
///
/// No fixture in the corpus witnessed `(indexed, lazy)` because no producer
/// could emit it. Building it as a delivery-only mutation of an existing
/// indexed fixture is what makes the pair diagnostic: `05` and `08` differ in
/// exactly one axis and nothing else, as do `ablation/c04` and `ablation/c08`,
/// so a checker disagreeing about one and not the other has localised the
/// disagreement to the delivery axis by construction.
fn to_indexed_lazy(mut ir: ActivationIr) -> ActivationIr {
    for c in &mut ir.children {
        if let Some(child) = c.child() {
            // §5.1 — the advertised hash of a lazy family is its template's, so
            // a consumer fetches the template once for the whole family.
            let advertised = child.hash.clone();
            c.delivery = ChildDelivery::Lazy { hash: advertised };
        }
    }
    ir.recompute_hashes();
    ir
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: <fixtures/rust dir>");
    let mut ported = 0usize;
    let mut verified = 0usize;
    let mut untouched = 0usize;

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for sub in ["", "ablation"] {
        let d = std::path::Path::new(&dir).join(sub);
        for e in std::fs::read_dir(&d).expect("the fixture dir") {
            let p = e.expect("a dir entry").path();
            if p.extension().is_some_and(|x| x == "json") {
                files.push(p);
            }
        }
    }
    files.sort();

    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read_to_string(&path).expect("readable");
        let v: Value = serde_json::from_str(&raw).expect("valid JSON");

        // 07 is a StopReason map and 90 is a pre-IR golden — neither is an
        // ActivationIr and neither is touched.
        if !v.is_object() || !v.as_object().unwrap().contains_key("namespace") {
            untouched += 1;
            continue;
        }
        if !raw.contains("\"edge\"") {
            // No child edges — already conformant with the new form. Prove it
            // rather than assuming it.
            let ir: ActivationIr = serde_json::from_value(v).expect("decodes");
            let mut probe = ir.clone();
            probe.recompute_hashes();
            assert_eq!(probe, ir, "{name}: stored hashes do not reproduce");
            verified += 1;
            continue;
        }

        let new = port_activation(&v);
        let ir: ActivationIr =
            serde_json::from_value(new).unwrap_or_else(|e| panic!("{name}: {e}"));

        // THE CHECK THIS EXAMPLE EXISTS FOR. The stored digests were produced
        // by the pre-PLX-160 implementation. If tags 1/2/3 moved by so much as
        // a byte, this fails.
        let mut probe = ir.clone();
        probe.recompute_hashes();
        assert_eq!(
            probe, ir,
            "{name}: PLX-160 moved a hash it promised not to move"
        );

        let text = serde_json::to_string_pretty(&ir).expect("serializes");
        std::fs::write(&path, format!("{text}\n")).expect("writable");
        ported += 1;
    }

    // The fourth cell: one representative, one ablation, each a delivery-only
    // mutation of its indexed+embedded sibling.
    for (src, dst) in [
        ("05_child_indexed.json", "08_child_indexed_lazy.json"),
        ("ablation/c04.json", "ablation/c08.json"),
    ] {
        let raw = std::fs::read_to_string(std::path::Path::new(&dir).join(src)).expect("readable");
        let ir: ActivationIr = serde_json::from_str(&raw).expect("the sibling decodes");
        let doc = to_indexed_lazy(ir);

        let e = &doc.children[0];
        assert!(e.is_indexed() && e.is_lazy(), "{dst} must be (indexed, lazy)");
        assert!(e.child().is_none(), "{dst} must embed nothing (§5.2)");
        assert_eq!(e.advertised_hash().len(), 64, "{dst} must advertise a digest");

        let text = serde_json::to_string_pretty(&doc).expect("serializes");
        std::fs::write(std::path::Path::new(&dir).join(dst), format!("{text}\n"))
            .expect("writable");
    }
    let _ = (schema_ref, MethodIr::new("_", "_"));

    println!("ported={ported} hash-verified-unchanged={ported} already-new={verified} skipped={untouched} new-cell-fixtures=2");
}
