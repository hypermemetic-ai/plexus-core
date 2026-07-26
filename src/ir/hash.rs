//! `CONNECTOME-HASH/1` — the normative content-hash construction of
//! CONNECTOME RFC 002 §4.6 (PLX-89).
//!
//! # Why this module was rewritten
//!
//! RFC 001 §4 constrained hashing's *properties* (Merkle-ness, determinism,
//! order-canonicality) and named no *construction*: no hash function, no
//! preimage, no digest encoding. An independent Haskell implementation
//! (`connectome-hs`, PLX-86) written from RFC 001 alone searched ~26 million
//! candidate preimages across five digest functions and matched none of this
//! crate's hashes — proof that two implementations could satisfy every §4 MUST
//! and disagree on every digest (finding F-06).
//!
//! RFC 002 closes that by specifying `CONNECTOME-HASH/1` normatively. This
//! module is its Rust implementation; `Plexus.Connectome.Hash` in
//! `connectome-hs` is its Haskell implementation, and the two produce
//! byte-identical digests. The previous, unspecified framing (little-endian
//! lengths, `plexus.ir.*.v1` tags, root facts inside the activation preimage,
//! declaration-ordered method/child/capability folds) is gone.
//!
//! # The construction
//!
//! Digest: **SHA-256**, rendered as 64 lowercase hex characters.
//!
//! Primitives — every variable-length component is length-prefixed with a
//! **64-bit big-endian** count and every sum is one-byte tagged, so the preimage
//! is injective (without the prefix a namespace could borrow a character from a
//! version):
//!
//! | writer | emitted bytes |
//! |---|---|
//! | [`Encoder::u64`] | 8 bytes, big-endian |
//! | [`Encoder::bytes`] | `u64be(len)`, then the bytes |
//! | [`Encoder::text`] | `bytes(utf8(s))` |
//! | [`Encoder::bool`] | one byte, `0x00` / `0x01` |
//! | [`Encoder::tag`] | one byte |
//! | [`Encoder::opt_text`] | `tag(0)` for absent; `tag(1)` + `text` for present |
//! | [`Encoder::domain`] | `text(domain-string)` — leads every node preimage |
//! | [`Encoder::json`] | `bytes(canonical_json(v))` — see [`canonical_json`] |
//! | [`Encoder::seq`] | `u64be(count)`, then each element in order |
//! | [`Encoder::set`] | `u64be(count)`, then each element's encoded bytes, **sorted** |
//!
//! Each node's preimage is prefixed with a domain string
//! (`connectome/1:activation`, `:method`, `:document`, …), a node's own stored
//! hash is never part of its own preimage, and a Dynamic edge contributes its
//! namespace and its *advertised* hash — never a recomputation, which would be
//! the fabrication RFC §5.2 forbids.
//!
//! Unordered collections ([`set`](Encoder::set)) are canonicalized by sorting
//! members' **encoded bytes**, so no two distinct members can compare equal and
//! be reordered unstably. RFC 002 §4.8 rules on which collections those are:
//! callbacks (§7.1 says SET), extensions (a map), methods and child edges (§3.7
//! makes both keyed, hence maps) are unordered; parameters and turn updates are
//! sequences.
//!
//! # Canonical JSON
//!
//! [`canonical_json`] is `CONNECTOME-JCS/1` (RFC 002 §4.3): object keys sorted
//! by their UTF-8 bytes, no insignificant whitespace, integral numbers rendered
//! without a decimal point.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The identifier a document declares under RFC 002 §4.7 to say which
/// construction produced its hashes.
pub const HASH_ALGORITHM: &str = "CONNECTOME-HASH/1";

/// Domain string leading an activation preimage.
pub(crate) const DOMAIN_ACTIVATION: &str = "connectome/1:activation";
/// Domain string leading a method preimage.
pub(crate) const DOMAIN_METHOD: &str = "connectome/1:method";
/// Domain string leading a document preimage.
pub(crate) const DOMAIN_DOCUMENT: &str = "connectome/1:document";
/// Domain string leading a type-reference encoding.
pub(crate) const DOMAIN_TYPEREF: &str = "connectome/1:typeref";
/// Domain string leading a parameter encoding.
pub(crate) const DOMAIN_PARAM: &str = "connectome/1:param";
/// Domain string leading a capability encoding.
pub(crate) const DOMAIN_CAPABILITY: &str = "connectome/1:capability";
/// Domain string leading a deprecation-record encoding.
pub(crate) const DOMAIN_DEPRECATION: &str = "connectome/1:deprecation";

/// The canonical byte encoder of `CONNECTOME-HASH/1`.
///
/// It accumulates *bytes* rather than digest state, because
/// [`set`](Encoder::set) has to sort its members' encodings before they are
/// hashed. Call [`digest`](Encoder::digest) to finish.
#[derive(Debug, Clone, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// A fresh, empty encoder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Start an encoder whose first component is a domain string.
    pub fn with_domain(domain: &str) -> Self {
        let mut e = Self::new();
        e.domain(domain);
        e
    }

    /// The bytes written so far.
    pub fn bytes_written(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder, returning its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// A 64-bit big-endian integer. Big-endian so the encoding does not depend
    /// on host architecture — §4.3 requires determinism across processes.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Length-prefixed raw bytes. The prefix is what makes the encoding
    /// injective.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u64(b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    /// Length-prefixed UTF-8 text.
    pub fn text(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// A one-byte sum discriminant.
    pub fn tag(&mut self, t: u8) -> &mut Self {
        self.buf.push(t);
        self
    }

    /// A boolean, one byte.
    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.buf.push(u8::from(b));
        self
    }

    /// The domain string that leads a node preimage. It is ordinary
    /// length-prefixed text; the name records the intent.
    pub fn domain(&mut self, s: &str) -> &mut Self {
        self.text(s)
    }

    /// An optional string: absent and present-but-empty are distinguishable.
    ///
    /// §3.5 makes an empty optional and an absent optional the *same* document
    /// on the wire, so callers pass [`text_or_absent`] rather than
    /// `Some("")`.
    pub fn opt_text(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => self.tag(0),
            Some(v) => {
                self.tag(1);
                self.text(v)
            }
        }
    }

    /// An optional 64-bit integer.
    pub fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            None => self.tag(0),
            Some(n) => {
                self.tag(1);
                self.u64(n)
            }
        }
    }

    /// An optional sub-encoding.
    pub fn opt_with(&mut self, present: bool, f: impl FnOnce(&mut Self)) -> &mut Self {
        if present {
            self.tag(1);
            f(self);
        } else {
            self.tag(0);
        }
        self
    }

    /// A JSON value in canonical form ([`canonical_json`]), length-prefixed.
    pub fn json(&mut self, v: &Value) -> &mut Self {
        let s = canonical_json(v);
        self.bytes(s.as_bytes())
    }

    /// An ordered collection: count, then each element in declaration order.
    pub fn seq<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.u64(items.len() as u64);
        for item in items {
            f(self, item);
        }
        self
    }

    /// An **unordered** collection: count, then each element's encoded bytes in
    /// ascending byte order.
    ///
    /// Sorting the encodings (rather than a chosen key) is what makes the
    /// canonicalization total: two distinct members can never compare equal and
    /// be reordered unstably.
    pub fn set<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(items.len());
        for item in items {
            let mut e = Encoder::new();
            f(&mut e, item);
            encoded.push(e.into_bytes());
        }
        encoded.sort();
        self.u64(encoded.len() as u64);
        for e in encoded {
            self.buf.extend_from_slice(&e);
        }
        self
    }

    /// A 64-hex digest embedded in a parent's preimage — §4.2's Merkle fold.
    pub fn hash_ref(&mut self, h: &str) -> &mut Self {
        self.text(h)
    }

    /// Finish: the lowercase hex SHA-256 of everything written.
    pub fn digest(&self) -> String {
        sha256_hex(&self.buf)
    }
}

/// Backwards-compatible alias for the encoder.
pub type Hasher = Encoder;

/// §3.5 — an empty string on the wire *is* absence, so it hashes as absence.
///
/// This is the rule that makes `description: ""` (which RFC 002 §3.5 forbids
/// emitting) indistinguishable from an omitted `description`, and therefore the
/// rule that lets a Rust document and a Haskell document of the same content
/// agree.
pub fn text_or_absent(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// The lowercase hex SHA-256 of `input`.
pub fn sha256_hex(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    to_hex(h.finalize().as_slice())
}

/// `CONNECTOME-JCS/1` (RFC 002 §4.3): a deterministic serialization of an
/// arbitrary JSON value.
///
/// - object keys sorted ascending by their UTF-8 bytes;
/// - no insignificant whitespace;
/// - an integral number rendered as a decimal integer with no decimal point or
///   exponent, so `1` and `1.0` canonicalize identically;
/// - a non-integral number rendered as the shortest decimal that round-trips;
/// - strings escaped with the two-character forms for `"` `\` `\b` `\f` `\n`
///   `\r` `\t`, `\u00XX` for the remaining control characters, and the literal
///   UTF-8 character otherwise.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out),
        Value::String(s) => write_string(s, out),
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
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
    }
}

fn write_number(n: &serde_json::Number, out: &mut String) {
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return;
    }
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return;
    }
    let f = n.as_f64().unwrap_or(f64::NAN);
    // An integral float is an integral number: `1.0` and `1` canonicalize the
    // same way, which is what makes the encoding independent of whether a
    // producer's JSON reader kept the decimal point.
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 {
        out.push_str(&(f as i64).to_string());
        return;
    }
    out.push_str(&f.to_string());
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
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
    use serde_json::json;

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

    /// RFC 002 §4.6: lengths are 64-bit **big-endian**. This is the single fact
    /// that made the two implementations disagree, so it is pinned literally.
    #[test]
    fn length_prefixes_are_64_bit_big_endian() {
        let mut e = Encoder::new();
        e.text("ab");
        assert_eq!(e.bytes_written(), b"\x00\x00\x00\x00\x00\x00\x00\x02ab");
    }

    #[test]
    fn framing_is_unambiguous() {
        let mut a = Encoder::new();
        a.text("ab").text("c");
        let mut b = Encoder::new();
        b.text("a").text("bc");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn absent_and_empty_string_hash_alike_because_the_wire_cannot_tell_them_apart() {
        // §3.5: an empty optional MUST NOT be emitted, so `Some("")` is not a
        // document a conformant encoder can produce. `text_or_absent` maps it
        // onto absence, which is what keeps Rust and Haskell in agreement.
        let mut a = Encoder::new();
        a.opt_text(None);
        let mut b = Encoder::new();
        b.opt_text(text_or_absent(""));
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn a_set_is_order_independent_and_a_seq_is_not() {
        let items = ["b".to_string(), "a".to_string()];
        let reversed = ["a".to_string(), "b".to_string()];

        let mut s1 = Encoder::new();
        s1.set(&items, |e, s| {
            e.text(s);
        });
        let mut s2 = Encoder::new();
        s2.set(&reversed, |e, s| {
            e.text(s);
        });
        assert_eq!(s1.digest(), s2.digest());

        let mut q1 = Encoder::new();
        q1.seq(&items, |e, s| {
            e.text(s);
        });
        let mut q2 = Encoder::new();
        q2.seq(&reversed, |e, s| {
            e.text(s);
        });
        assert_ne!(q1.digest(), q2.digest());
    }

    #[test]
    fn canonical_json_sorts_keys_and_drops_whitespace() {
        assert_eq!(
            canonical_json(&json!({"z": 1, "a": {"y": 2, "b": [1, 2]}})),
            r#"{"a":{"b":[1,2],"y":2},"z":1}"#
        );
    }

    #[test]
    fn canonical_json_renders_integral_numbers_without_a_decimal_point() {
        assert_eq!(canonical_json(&json!(1)), "1");
        assert_eq!(canonical_json(&json!(1.0)), "1");
        assert_eq!(canonical_json(&json!(-3)), "-3");
        assert_eq!(canonical_json(&json!(2.5)), "2.5");
    }

    #[test]
    fn canonical_json_escapes_control_characters() {
        assert_eq!(canonical_json(&json!("a\nb\u{1}")), "\"a\\nb\\u0001\"");
    }

    #[test]
    fn json_object_key_order_is_irrelevant() {
        let a = json!({"z": 1, "a": 2, "m": {"y": 3, "b": 4}});
        let b = json!({"a": 2, "m": {"b": 4, "y": 3}, "z": 1});
        let mut ha = Encoder::new();
        ha.json(&a);
        let mut hb = Encoder::new();
        hb.json(&b);
        assert_eq!(ha.digest(), hb.digest());
    }

    #[test]
    fn json_array_order_is_significant() {
        let mut ha = Encoder::new();
        ha.json(&json!([1, 2]));
        let mut hb = Encoder::new();
        hb.json(&json!([2, 1]));
        assert_ne!(ha.digest(), hb.digest());
    }

    /// A golden over every writer in the framing table. If a future change moved
    /// a byte, this fails — and any implementation claiming
    /// `CONNECTOME-HASH/1` must reproduce it.
    #[test]
    fn connectome_hash_1_framing_golden() {
        let mut e = Encoder::with_domain("connectome/1:golden");
        e.text("abc")
            .bool(true)
            .u64(7)
            .opt_text(None)
            .opt_text(Some("x"))
            .tag(2);
        e.json(&json!({"b":[1,2.5,"s",null,true],"a":{"z":1}}));
        e.set(&["z".to_string(), "a".to_string()], |e, s| {
            e.text(s);
        });
        assert_eq!(
            e.digest(),
            "5fca38cf1d31f22b10d839623ea739f768ee1cba812bf8c7ab9e44ca7543312c"
        );
    }
}
