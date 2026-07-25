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
//! * **PLX-78 — a set is a set.** `Client<(FsRead, FsRead)>` must not compile,
//!   and must fail with a message that names the *duplication*.
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

    // Load-bearing, not decorative. `trybuild` uses `cargo check` for a suite
    // of pure compile-fail cases and `cargo build` as soon as one `pass` case
    // is present. PLX-78's duplicate assertion is a *post-monomorphization*
    // const evaluation, and `cargo check` does not instantiate generic bodies,
    // so under check mode `duplicate_capability.rs` would compile clean and its
    // golden would be empty. This case is what puts the suite in build mode —
    // and it independently pins that well-formed sets of arity 0, 1, 2 and 4
    // still construct, derive and gate.
    t.pass("tests/ui/pass/*.rs");

    t.compile_fail("tests/ui/*.rs");
}
