//! Content hashes for schemas (RETURNS-10).
//!
//! A method's hash is the hash of its schema: [`MethodSchema::content_hash`]
//! serializes the whole [`MethodSchema`] except its own `hash`, writes it as
//! [canonical JSON](canonical_json) and takes [`hash16`] of the bytes. The
//! plugin roll-up ([`PluginSchema`]'s `self_hash` / `children_hash` / `hash`)
//! is [`hash16`] over the 16-hex inputs, one per line.
//!
//! Both are specified here precisely enough for another language to recompute
//! them from the JSON a server sends — Python's
//! `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
//! writes the same canonical bytes, and `hashlib.sha256(b).hexdigest()[:16]`
//! the same hash.
//!
//! What moves a method's hash is anything the schema says: its name,
//! description, params, the shape of `returns` (T), `error` (E) and
//! `progress` (P) down to every nested field, variant and doc comment,
//! cardinality, role, deprecation, credentials, auth posture… A type renamed
//! with the same shape moves it (the `title` and `$defs` key change); a Rust
//! field renamed under `#[serde(rename)]` does not (the wire is the same); a
//! schemars upgrade that changes its output moves it once.
//!
//! [`MethodSchema`]: super::schema::MethodSchema
//! [`MethodSchema::content_hash`]: super::schema::MethodSchema::content_hash
//! [`PluginSchema`]: super::schema::PluginSchema

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical JSON: object keys sorted by Unicode code point, no whitespace
/// outside strings, arrays in their order, strings and numbers exactly as
/// `serde_json` writes them.
///
/// Written by hand rather than with `serde_json::to_string`, whose key order
/// depends on how `serde_json` was compiled: sorted with its default `Map`,
/// insertion order once any crate in the build enables its `preserve_order`
/// feature (RETURNS-24 found the raw output differ between those two builds
/// for every method). Nothing schema-aware happens here — `required` arrays,
/// for instance, keep their order, so reordering a struct's fields moves the
/// hash once rather than a real change ever being missed.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // `str` orders by UTF-8 bytes, which is Unicode code point order.
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("a string serializes"));
                out.push(':');
                write_canonical(item, out);
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

/// SHA-256 of `bytes`, its first 8 bytes as 16 lowercase hex characters —
/// the width every Plexus hash has always had (`{:016x}`), and the format
/// synapse's `plexus_hash` check, hub-codegen and synapse-cc expect.
pub fn hash16(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// [`hash16`] of `hashes`, one per line (each followed by `\n`). Every input
/// is itself a fixed-width hash, so the encoding is unambiguous. The plugin
/// roll-up is built from it.
pub fn hash16_lines<'a>(hashes: impl IntoIterator<Item = &'a str>) -> String {
    let mut text = String::new();
    for h in hashes {
        text.push_str(h);
        text.push('\n');
    }
    hash16(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_and_drops_whitespace() {
        let v = json!({"b": [3, {"z": 1, "a": null}], "a": "x\"y", "é": true, "Z": 1.5});
        assert_eq!(
            canonical_json(&v),
            r#"{"Z":1.5,"a":"x\"y","b":[3,{"a":null,"z":1}],"é":true}"#
        );
    }

    #[test]
    fn canonical_json_ignores_insertion_order() {
        let mut a = serde_json::Map::new();
        a.insert("one".into(), json!(1));
        a.insert("two".into(), json!({"y": 2, "x": 1}));
        let mut b = serde_json::Map::new();
        b.insert("two".into(), json!({"x": 1, "y": 2}));
        b.insert("one".into(), json!(1));
        assert_eq!(canonical_json(&Value::Object(a)), canonical_json(&Value::Object(b)));
    }

    #[test]
    fn canonical_json_keeps_array_order() {
        assert_ne!(canonical_json(&json!(["a", "b"])), canonical_json(&json!(["b", "a"])));
    }

    #[test]
    fn hash16_is_the_sha256_prefix() {
        // SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 …
        assert_eq!(hash16(b""), "e3b0c44298fc1c14");
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de …
        assert_eq!(hash16(b"abc"), "ba7816bf8f01cfea");
    }

    #[test]
    fn hash16_lines_hashes_one_input_per_line() {
        assert_eq!(hash16_lines(["ab", "cd"]), hash16(b"ab\ncd\n"));
        assert_eq!(hash16_lines([]), hash16(b""));
    }
}
