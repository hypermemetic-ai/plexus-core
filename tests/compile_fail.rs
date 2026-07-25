//! PLX-77 compile-fail acceptance criteria.
//!
//! Two of this build's guarantees cannot be observed at runtime, because what
//! they assert is the *absence* of a program:
//!
//! * **AC3 — membership gating.** `Client<(Permission,)>::fs_read(..)` must not
//!   compile. A runtime test cannot call a method that does not exist for that
//!   type, so the only way to test it is to try to compile it and require the
//!   attempt to fail.
//! * **AC5 — the capability set is closed.** An external type must not be able
//!   to implement the marker trait.
//!
//! The committed `.stderr` goldens pin the *reason* each fixture fails, not
//! merely that it did — a fixture that started failing for an unrelated reason
//! (a typo, a moved import) would silently keep "passing" otherwise.
//!
//! Regenerate the goldens after an intentional change with:
//! `TRYBUILD=overwrite cargo test --test compile_fail`.

#[test]
fn capability_misuse_does_not_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
