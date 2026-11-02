//! RETURNS-3 spike — the hashing half: canonical JSON, a stable hasher, the
//! proposed method hash, and today's two hashes (the macro's token hash and
//! `PluginSchema::compute_hashes`' roll-up) reproduced for comparison.
//!
//! Nothing here is plexus-core API; RETURNS-10 builds the real thing.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical JSON: object keys sorted by Unicode code point (Rust `String`
/// order), no insignificant whitespace, arrays kept in order, scalars as
/// serde_json writes them. Written by hand so the result does not depend on
/// which `Map` serde_json was compiled with (`BTreeMap` by default,
/// `IndexMap` when any crate in the graph enables `preserve_order`).
pub fn canonical(v: &Value) -> String {
    let mut out = String::with_capacity(1024);
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("a key serializes"));
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).expect("a scalar serializes")),
    }
}

/// The one schema-aware variant measured: sort every `required` array
/// (JSON Schema gives it set semantics), so declaration order stops
/// mattering. Measured to say what it buys; not recommended (see main.rs).
pub fn sort_required(v: &mut Value) {
    match v {
        Value::Object(map) => {
            if let Some(Value::Array(req)) = map.get_mut("required") {
                if req.iter().all(Value::is_string) {
                    req.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                }
            }
            for (_, child) in map.iter_mut() {
                sort_required(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(sort_required),
        _ => {}
    }
}

/// SHA-256, first 8 bytes, lowercase hex: 16 characters — the width of
/// today's `{:016x}` and of synapse's `plexus_hash` validator, and the
/// format hub-codegen's `hash.rs` and synapse-cc's `Merge.hs` already use.
pub fn hash16(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The proposed method hash: hash16 of the canonical JSON of the method's
/// schema object with its own `hash` field removed — so it covers name,
/// description, params, returns (T), error (E), progress (P), cardinality
/// and every other field the IR is built from.
pub fn method_hash(method_schema: &Value) -> String {
    let mut m = method_schema.clone();
    if let Some(obj) = m.as_object_mut() {
        obj.remove("hash");
    }
    hash16(canonical(&m).as_bytes())
}

/// `method_hash` with `required` arrays sorted (reorder-insensitive).
pub fn method_hash_required_sorted(method_schema: &Value) -> String {
    let mut m = method_schema.clone();
    if let Some(obj) = m.as_object_mut() {
        obj.remove("hash");
    }
    sort_required(&mut m);
    hash16(canonical(&m).as_bytes())
}

/// Today's method hash, as `plexus-macros/src/codegen/method_enum.rs:788-815`
/// computes it at compile time: `DefaultHasher` over the name, the
/// description, each param's (name, type tokens, description) and the item
/// type's token string. `params` = (name, `quote!(#ty).to_string()`, doc).
#[allow(deprecated)]
pub fn token_hash_today(
    name: &str,
    description: &str,
    params: &[(&str, &str, Option<&str>)],
    item_type_tokens: Option<&str>,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    name.hash(&mut h);
    description.hash(&mut h);
    for (pname, pty, pdesc) in params {
        pname.to_string().hash(&mut h);
        pty.to_string().hash(&mut h);
        if let Some(d) = pdesc {
            d.to_string().hash(&mut h);
        }
    }
    if let Some(t) = item_type_tokens {
        t.to_string().hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

/// Today's roll-up, `PluginSchema::compute_hashes`
/// (`plexus-core/src/plexus/schema.rs:752-784`): (self_hash, children_hash, hash).
pub fn rollup_default_hasher(
    method_hashes: &[String],
    child_hashes: Option<&[String]>,
) -> (String, Option<String>, String) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut s = DefaultHasher::new();
    for m in method_hashes {
        m.hash(&mut s);
    }
    let self_hash = format!("{:016x}", s.finish());
    let children_hash = child_hashes.map(|kids| {
        let mut c = DefaultHasher::new();
        for k in kids {
            k.hash(&mut c);
        }
        format!("{:016x}", c.finish())
    });
    let mut comp = DefaultHasher::new();
    self_hash.hash(&mut comp);
    if let Some(ch) = &children_hash {
        ch.hash(&mut comp);
    }
    (self_hash, children_hash, format!("{:016x}", comp.finish()))
}

/// The same roll-up on hash16, same structure and width: each part is the
/// hash of its inputs joined one per line (every input is fixed-width hex,
/// so the encoding is unambiguous).
pub fn rollup_sha256(
    method_hashes: &[String],
    child_hashes: Option<&[String]>,
) -> (String, Option<String>, String) {
    let lines = |xs: &[String]| xs.iter().map(|x| format!("{x}\n")).collect::<String>();
    let self_hash = hash16(lines(method_hashes).as_bytes());
    let children_hash = child_hashes.map(|kids| hash16(lines(kids).as_bytes()));
    let mut comp = format!("{self_hash}\n");
    if let Some(ch) = &children_hash {
        comp.push_str(ch);
        comp.push('\n');
    }
    let hash = hash16(comp.as_bytes());
    (self_hash, children_hash, hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_and_strips_whitespace() {
        let v = json!({"b": [3, {"z": 1, "a": null}], "a": "x\"y"});
        assert_eq!(canonical(&v), r#"{"a":"x\"y","b":[3,{"a":null,"z":1}]}"#);
    }

    #[test]
    fn hash16_is_sixteen_lowercase_hex() {
        let h = hash16(b"");
        assert_eq!(h, "e3b0c44298fc1c14"); // SHA-256("") prefix
    }
}
