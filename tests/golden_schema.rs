//! IR-4 golden snapshot regression test.
//!
//! Asserts byte-identity of the serialized `PluginSchema` JSON before and
//! after IR-4's changes. The fixture `tests/golden/solar.json` is captured
//! from substrate's Solar activation at IR-3's tip (commit `b6285a8` in
//! plexus-macros, 1.0.0 Solar).
//!
//! # How the test works
//!
//! The snapshot is read verbatim from disk, deserialized into a
//! `PluginSchema`, and re-serialized via `serde_json::to_string_pretty`.
//! The test asserts the re-serialized output equals the on-disk bytes.
//!
//! # Why this approximates byte-identity of substrate's output
//!
//! `plexus-core` can't depend on `plexus-substrate` (it would create a
//! cycle), so this test can't construct a `Solar` activation directly.
//! Instead, it pins **serializer stability** end-to-end: if any of IR-4's
//! changes caused a wire-format shift — a field rename, a reordering of
//! `PluginSchema` members, a new default that skipped serialization
//! differently — the round-trip here would diverge from the committed
//! bytes.
//!
//! The companion acceptance check for "substrate Solar serializes to
//! byte-identity with this fixture" is covered by substrate's test
//! harness (`print_solar_schema` in the Solar activation test module)
//! against the same JSON file. Diff those bytes against this fixture to
//! verify the full round-trip.
//!
//! Per IR-4's scope this ticket adds the fixture and the serializer-
//! stability test here; migrating substrate's test to read this fixture
//! is a follow-up (IR-8, which is the Solar test migration ticket).

use plexus_core::plexus::schema::PluginSchema;

/// Solar's snapshot captured at IR-3's tip. Used both as the input for
/// serializer-stability testing (this file) and as the reference for
/// substrate's byte-identity check (out-of-tree).
const SOLAR_GOLDEN: &str = include_str!("golden/solar.json");

#[test]
fn ir4_solar_schema_is_byte_identical_roundtrip() {
    let schema: PluginSchema =
        serde_json::from_str(SOLAR_GOLDEN).expect("Solar golden JSON deserializes");

    let re_serialized =
        serde_json::to_string_pretty(&schema).expect("Solar schema re-serializes");

    // Byte-identity (after normalizing trailing newlines, since
    // `to_string_pretty` doesn't emit a trailing newline but text
    // editors commonly add one).
    let expected = SOLAR_GOLDEN.trim_end_matches('\n');
    let actual = re_serialized.trim_end_matches('\n');

    if expected != actual {
        // On mismatch, print both sides so the operator can diff.
        eprintln!("--- golden (expected) ---\n{expected}\n");
        eprintln!("--- produced (actual)  ---\n{actual}\n");
        panic!("Solar golden snapshot mismatch — IR-4 changed PluginSchema wire format");
    }
}

/// IR-4 AC #8: on every method list in today's substrate activations, the
/// deprecated `is_hub()` method agrees with the derived `is_hub_by_role()`
/// query. This test checks that on the committed Solar snapshot.
#[test]
#[allow(deprecated)]
fn ir4_solar_is_hub_matches_is_hub_by_role() {
    let schema: PluginSchema =
        serde_json::from_str(SOLAR_GOLDEN).expect("Solar golden JSON deserializes");

    assert_eq!(
        schema.is_hub(),
        schema.is_hub_by_role(),
        "is_hub() and is_hub_by_role() must agree on Solar's schema"
    );
    assert!(schema.is_hub_by_role(), "Solar is a hub");
}

/// IR-4: the deprecated `children` field remains present on the wire and
/// the count matches the count of non-`Rpc` methods the derivation helper
/// would produce (for role-tagged schemas).
///
/// On Solar, `children` is 8 (planets) and methods with a child role is 1
/// (the `body` DynamicChild gate). This divergence is expected: Solar
/// hand-writes `plugin_children()` to enumerate the live planet set,
/// whereas the `body` method is the gate for the dynamic-child lookup.
/// The test pins that shape so IR-4's shim doesn't accidentally
/// rewrite either side.
#[test]
#[allow(deprecated)]
fn ir4_solar_children_preserved_alongside_role_tagged_method() {
    let schema: PluginSchema =
        serde_json::from_str(SOLAR_GOLDEN).expect("Solar golden JSON deserializes");

    // Deprecated side-table still has all 8 planets.
    let kids = schema.children.as_ref().expect("Solar is a hub");
    assert_eq!(kids.len(), 8, "Solar has 8 planets");

    // Methods list carries the `body` gate with DynamicChild role.
    let body_method = schema
        .methods
        .iter()
        .find(|m| m.name == "body")
        .expect("Solar exposes a `body` method");
    use plexus_core::MethodRole;
    assert!(
        matches!(body_method.role, MethodRole::DynamicChild { .. }),
        "Solar's `body` method must carry DynamicChild role; got {:?}",
        body_method.role
    );
}
