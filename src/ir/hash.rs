//! Deterministic content hashing for the activation IR (PLX-75).
//!
//! # The algorithm
//!
//! Every IR node carries a `hash: String` — the lowercase hex SHA-256 digest of
//! a *canonical byte encoding* of that node's own content **folded together with
//! its children's hashes**. That makes the tree a Merkle tree:
//!
//! - mutating a leaf changes that leaf's hash,
//! - which changes every ancestor's hash (each parent hashes its children's
//!   hashes as content),
//! - while leaving sibling subtrees byte-identical (a sibling's hash never
//!   depends on anything outside its own subtree).
//!
//! ## Canonical encoding
//!
//! Hash inputs are built by [`Hasher`], which is a thin, *unambiguous* framing
//! layer over SHA-256. Every value written is length-prefixed and type-tagged,
//! so no two structurally different node contents can produce the same byte
//! stream (no `"ab" + "c"` == `"a" + "bc"` collisions):
//!
//! | writer | emitted bytes |
//! |---|---|
//! | [`Hasher::tag`] | `b'T'`, u64-LE length, UTF-8 bytes — a domain separator |
//! | [`Hasher::str`] | `b'S'`, u64-LE length, UTF-8 bytes |
//! | [`Hasher::opt_str`] | `b'0'` for `None`; `b'1'` + `str` encoding for `Some` |
//! | [`Hasher::bool`] | `b'B'`, `0x00` / `0x01` |
//! | [`Hasher::u64`] | `b'U'`, u64-LE |
//! | [`Hasher::seq`] | `b'L'`, u64-LE element count, then each element |
//! | [`Hasher::json`] | see below |
//!
//! ## Determinism rules (the two failure modes this must not have)
//!
//! 1. **No unordered iteration is ever hashed.** Every map in the IR is a
//!    [`std::collections::BTreeMap`], and `serde_json::Map` is a `BTreeMap` in
//!    this build (the `preserve_order` feature is off), so JSON object keys are
//!    visited in sorted order regardless of the order they were inserted in.
//!    [`Hasher::json`] additionally sorts defensively rather than trusting the
//!    map type. `HashMap` is never hashed.
//! 2. **No non-reproducible hasher.** `std::collections::hash_map::DefaultHasher`
//!    (used by the legacy `PluginSchema::compute_hashes`) is explicitly *not*
//!    guaranteed stable across Rust releases. The IR therefore hashes with
//!    SHA-256 (the [`sha2`] crate), verified against the FIPS 180-4 test vectors
//!    in the unit tests below. The digest is stable across runs, across
//!    processes, across toolchains, and across serialize/deserialize — every
//!    hash input is a field that survives serde round-tripping.
//!
//!    PLX-75 shipped a hand-rolled SHA-256 here purely because that ticket
//!    forbade a `Cargo.toml` edit (its residual #3). PLX-77 lifted that
//!    restriction and the hand-rolled compression function is gone; the framing
//!    layer is byte-for-byte unchanged, which the unit test
//!    `golden_digest_is_unchanged_by_the_sha2_swap` pins against a digest
//!    produced by the old implementation.
//!
//! ## JSON canonicalization
//!
//! [`Hasher::json`] encodes a [`serde_json::Value`] with a type tag per node:
//! `n` null, `b` bool, `i` u64 / `I` i64 / `d` f64-bits for numbers, `s`
//! strings, `a` arrays (length-prefixed, order preserved — array order is
//! meaningful), `o` objects (length-prefixed, keys sorted, each key hashed as a
//! string before its value). Numbers are discriminated by their concrete JSON
//! representation, so `1` and `1.0` hash differently — matching the fact that
//! serde_json round-trips them differently.
//!
//! Sequence order in the IR itself (`methods`, `children`, `params`) is
//! declaration order and *is* load-bearing: reordering a method list is a real
//! change to the document and correctly changes the hash.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// Domain-separated, length-prefixed SHA-256 accumulator for IR hashing.
///
/// See the [module docs](self) for the canonical encoding table.
#[derive(Debug, Clone)]
pub struct Hasher {
    inner: Sha256,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// Start an empty hash accumulator.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Write a domain-separation tag (e.g. `"plexus.ir.method.v1"`).
    pub fn tag(&mut self, tag: &str) -> &mut Self {
        self.framed(b'T', tag.as_bytes())
    }

    /// Write a string field.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.framed(b'S', s.as_bytes())
    }

    /// Write an optional string field (present/absent are distinguishable).
    pub fn opt_str(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => {
                self.inner.update(&[b'0']);
                self
            }
            Some(v) => {
                self.inner.update(&[b'1']);
                self.str(v)
            }
        }
    }

    /// Write a boolean field.
    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.inner.update(&[b'B', u8::from(b)]);
        self
    }

    /// Write an unsigned integer field.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.inner.update(&[b'U']);
        self.inner.update(&v.to_le_bytes());
        self
    }

    /// Write a length-prefixed sequence, hashing each element with `f`.
    ///
    /// Element order is preserved — IR sequences are declaration-ordered and
    /// reordering them is a genuine content change.
    pub fn seq<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.inner.update(&[b'L']);
        self.inner.update(&(items.len() as u64).to_le_bytes());
        for item in items {
            f(self, item);
        }
        self
    }

    /// Write a string-keyed map, keys visited in sorted order.
    pub fn map<V>(
        &mut self,
        map: &BTreeMap<String, V>,
        mut f: impl FnMut(&mut Self, &V),
    ) -> &mut Self {
        self.inner.update(&[b'M']);
        self.inner.update(&(map.len() as u64).to_le_bytes());
        // BTreeMap already iterates in sorted key order; insertion order is
        // therefore structurally unobservable here.
        for (k, v) in map {
            self.str(k);
            f(self, v);
        }
        self
    }

    /// Write a JSON value in canonical form (object keys sorted).
    pub fn json(&mut self, value: &serde_json::Value) -> &mut Self {
        use serde_json::Value;
        match value {
            Value::Null => {
                self.inner.update(&[b'n']);
            }
            Value::Bool(b) => {
                self.inner.update(&[b'b', u8::from(*b)]);
            }
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    self.inner.update(&[b'i']);
                    self.inner.update(&u.to_le_bytes());
                } else if let Some(i) = n.as_i64() {
                    self.inner.update(&[b'I']);
                    self.inner.update(&i.to_le_bytes());
                } else {
                    // f64 bit pattern: exact, and stable for any value
                    // serde_json can round-trip.
                    let f = n.as_f64().unwrap_or(f64::NAN);
                    self.inner.update(&[b'd']);
                    self.inner.update(&f.to_bits().to_le_bytes());
                }
            }
            Value::String(s) => {
                self.inner.update(&[b's']);
                self.framed_raw(s.as_bytes());
            }
            Value::Array(items) => {
                self.inner.update(&[b'a']);
                self.inner.update(&(items.len() as u64).to_le_bytes());
                for item in items {
                    self.json(item);
                }
            }
            Value::Object(obj) => {
                self.inner.update(&[b'o']);
                self.inner.update(&(obj.len() as u64).to_le_bytes());
                // `serde_json::Map` is a BTreeMap here (no `preserve_order`),
                // but sort explicitly so this stays correct even if a future
                // dependency turns that feature on.
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort_unstable();
                for k in keys {
                    self.inner.update(&[b's']);
                    self.framed_raw(k.as_bytes());
                    self.json(&obj[k]);
                }
            }
        }
        self
    }

    /// Finish and return the lowercase hex digest.
    pub fn finish(&self) -> String {
        to_hex(self.inner.clone().finalize().as_slice())
    }

    fn framed(&mut self, tag: u8, bytes: &[u8]) -> &mut Self {
        self.inner.update(&[tag]);
        self.framed_raw(bytes);
        self
    }

    fn framed_raw(&mut self, bytes: &[u8]) {
        self.inner.update(&(bytes.len() as u64).to_le_bytes());
        self.inner.update(bytes);
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(input: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(input);
        to_hex(h.finalize().as_slice())
    }

    /// FIPS 180-4 published vectors — this pins the digest so an IR hash
    /// computed today is reproducible by any other SHA-256 implementation.
    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// Multi-block input exercising the buffering path.
    #[test]
    fn sha256_handles_multi_block_and_chunked_input() {
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&million_a),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );

        // Same bytes fed in irregular chunks must give the same digest.
        let mut chunked = Sha256::new();
        for chunk in million_a.chunks(7) {
            chunked.update(chunk);
        }
        assert_eq!(to_hex(chunked.finalize().as_slice()), sha256_hex(&million_a));
    }

    /// PLX-77 AC8: the `sha2` swap must be digest-neutral.
    ///
    /// This golden was produced by PLX-75's hand-rolled SHA-256 *before* the
    /// crate was replaced, over an input that exercises every writer in the
    /// framing table. If a future change to the framing layer (or to `sha2`)
    /// moved a byte, this fails — which is the only mechanical way to state
    /// "byte-identical digests" once the old implementation is deleted.
    #[test]
    fn golden_digest_is_unchanged_by_the_sha2_swap() {
        let mut h = Hasher::new();
        h.tag("plexus.ir.golden.v1")
            .str("abc")
            .bool(true)
            .u64(7)
            .opt_str(None)
            .opt_str(Some("x"));
        h.map(&BTreeMap::from([("k".to_string(), 1u8)]), |h, v| {
            h.u64(*v as u64);
        });
        h.json(&serde_json::json!({"b":[1,2.5,"s",null,true],"a":{"z":1}}));
        assert_eq!(
            h.finish(),
            "aad0470ba1c1d7258d108a38d7800cb6fd9b695bc905270426d843406d685c94"
        );
    }

    #[test]
    fn framing_is_unambiguous() {
        let mut a = Hasher::new();
        a.str("ab").str("c");
        let mut b = Hasher::new();
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn none_and_empty_string_differ() {
        let mut a = Hasher::new();
        a.opt_str(None);
        let mut b = Hasher::new();
        b.opt_str(Some(""));
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn json_object_key_order_is_irrelevant() {
        let a: serde_json::Value = serde_json::json!({"z": 1, "a": 2, "m": {"y": 3, "b": 4}});
        let b: serde_json::Value = serde_json::json!({"a": 2, "m": {"b": 4, "y": 3}, "z": 1});
        let mut ha = Hasher::new();
        ha.json(&a);
        let mut hb = Hasher::new();
        hb.json(&b);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn json_array_order_is_significant() {
        let a = serde_json::json!([1, 2]);
        let b = serde_json::json!([2, 1]);
        let mut ha = Hasher::new();
        ha.json(&a);
        let mut hb = Hasher::new();
        hb.json(&b);
        assert_ne!(ha.finish(), hb.finish());
    }
}

