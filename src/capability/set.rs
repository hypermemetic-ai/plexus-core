//! Capability **sets** and compile-time membership.
//!
//! # The problem
//!
//! `Client<C>`'s guarantee is that an accessor for a capability exists **only**
//! when that capability is in `C`. `Client<(Permission,)>::fs_read(..)` must be
//! a compile error, not a runtime `None`.
//!
//! The obvious encoding does not work. Writing
//!
//! ```text
//! impl<A, B> Has<A> for (A, B) {}
//! impl<A, B> Has<B> for (A, B) {}
//! ```
//!
//! is two impls of the *same* trait for the *same* type `(A, B)` whenever `A`
//! and `B` unify — rustc rejects them as overlapping, and there is no
//! specialization or negative-reasoning escape hatch on stable.
//!
//! # The encoding used here
//!
//! [`Has`] carries a second, *disambiguating* type parameter: the **position**
//! of the marker in the tuple, as a type-level Peano numeral
//! ([`Here`], [`There<Here>`](There), …).
//!
//! ```text
//! impl<A, B> Has<A, Here>        for (A, B) {}
//! impl<A, B> Has<B, There<Here>> for (A, B) {}
//! ```
//!
//! These no longer overlap — they are impls of *different* traits
//! (`Has<_, Here>` and `Has<_, There<Here>>`) — so the whole 0..=8 range is
//! expressible with no coherence conflict at all. The accessors are generic
//! over the index and never mention it:
//!
//! ```text
//! pub fn fs_read<I>(&self, ..) -> ..  where C: Has<FsRead, I>
//! ```
//!
//! and rustc infers `I` from whichever impl matches. This is the same
//! index-disambiguated selector `frunk` uses for heterogeneous lists.
//!
//! ## Duplicates (PLX-78)
//!
//! A tuple that lists the same marker twice — `Client<(FsRead, FsRead)>` — has
//! two applicable [`Has`] impls with different indices, so `I` is ambiguous and
//! an accessor call fails with a type-annotation error. Failing is correct — a
//! capability set is a *set* — but "cannot infer type" is not a message an
//! author can act on.
//!
//! So the malformedness is now detected directly, using the identity a
//! capability already has: its wire name. Every set exposes its members' names
//! as [`CapabilitySet::NAMES`], [`has_duplicate_names`] scans that slice in a
//! `const fn`, and `Client<C>` hangs a
//! [`NO_DUPLICATES`](super::client::Client::NO_DUPLICATES) const assertion on
//! the result, forcing its evaluation on every path that uses a set. A
//! duplicated capability now fails at compile time with a message that says
//! so.
//!
//! Names are a sound identity precisely because
//! [`declare_capabilities!`](super::markers) proves them pairwise distinct with
//! a crate-level `const _` assertion — so "same name" can only ever mean "same
//! capability", never "two capabilities that were given the same id by
//! accident".
//!
//! # Derivation
//!
//! [`CapabilitySet`] turns `C` into `Vec<CallbackIr>`. Both it and [`Has`] are
//! sealed (`Has` through its `CapabilitySet` supertrait, `CapabilitySet`
//! through [`sealed::Sealed`](super::markers::sealed::Sealed)), so the only
//! capability sets that exist are tuples of the markers this crate defines.
//! That is what makes the declared set and the usable set the same object.

use std::marker::PhantomData;

use crate::ir::CallbackIr;

use super::markers::{sealed, Capability};

/// Are two wire names the same string, comparable in a `const fn`?
///
/// `==` on `&str` is not const on stable; byte comparison is.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Does this list of wire names contain the same name twice?
///
/// A capability's identity *is* its wire name (see [`Capability::NAME`]), so
/// this is the whole duplicate test. `const fn`, because the point is to run
/// it during compilation — over [`CapabilitySet::NAMES`] for a set, and over
/// every declared marker for the distinctness proof in
/// [`super::markers`](super::markers).
///
/// Quadratic and allocation-free: sets are 0..=8 long, and a naive scan is
/// both fast enough and the only shape expressible without sorting in a const
/// context.
///
/// ```
/// use plexus_core::capability::{has_duplicate_names, Capability, FsRead, Permission};
///
/// assert!(!has_duplicate_names(&[Permission::NAME, FsRead::NAME]));
/// assert!(has_duplicate_names(&[FsRead::NAME, FsRead::NAME]));
/// assert!(!has_duplicate_names(&[]));
/// ```
pub const fn has_duplicate_names(names: &[&str]) -> bool {
    let mut i = 0;
    while i < names.len() {
        let mut j = i + 1;
        while j < names.len() {
            if str_eq(names[i], names[j]) {
                return true;
            }
            j += 1;
        }
        i += 1;
    }
    false
}

/// Type-level index: position zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Here;

/// Type-level index: one position past `I`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct There<I>(PhantomData<I>);

/// A tuple of [`Capability`] markers, viewed as a set.
///
/// Sealed: implemented for `()` and for 1..=8-tuples of markers, and nothing
/// else. [`callbacks`](Self::callbacks) is the `C -> Vec<CallbackIr>` bridge a
/// later build uses to populate [`crate::ir::MethodIr::callbacks`] straight
/// from a method signature.
pub trait CapabilitySet: sealed::Sealed {
    /// How many capabilities are in the set.
    const ARITY: usize;

    /// Every member's wire name, in declaration order — the `const` twin of
    /// [`names`](Self::names).
    ///
    /// The raw material for the compile-time duplicate check: because it is a
    /// `const` rather than a function, [`has_duplicate_names`] can be evaluated
    /// over it before the program runs. Deliberately *not* deduplicated — its
    /// job is to make a duplicate visible, not to hide one.
    const NAMES: &'static [&'static str];

    /// The IR descriptors for every capability in the set, in declaration
    /// order. Each comes from that marker's own
    /// [`Capability::descriptor`], so the declaration cannot drift from what
    /// the handle can actually call.
    fn callbacks() -> Vec<CallbackIr>;

    /// Just the wire names, in declaration order.
    fn names() -> Vec<&'static str>;
}

/// The declared set `Self` covers the requested set `Requested` — which, a set
/// being its own and only cover, means they are the same set (PLX-102).
///
/// Identity, expressed as a bound. The only implementation is the blanket
/// `impl<C: CapabilitySet> Declares<C> for C`, so `C: Declares<D>` holds
/// exactly when `D` and `C` are the same set.
///
/// # The direction is load-bearing
///
/// The bound is written `C: Declares<D>` — *declared* set in self position,
/// *requested* set as the parameter — and not the mirror image `D:
/// DeclaredAs<C>`, because only this direction infers. With the declared set
/// concrete in self position, rustc resolves `(FsRead,): Declares<?D>` against
/// the single blanket impl and gets `?D = (FsRead,)`; with the unknown in self
/// position it reports `E0283: cannot satisfy _: DeclaredAs<(FsRead,)>` and
/// demands an annotation — which would have forced every handler to name its
/// set by hand, reintroducing at the call site the very restatement this build
/// removes.
///
/// # Why a trait and not just `-> Client<C>`
///
/// A method with no type parameter (`fn client(&self) -> Client<C>`) would
/// also be unwidenable, but `turn.client::<(FsWrite,)>()` would then fail with
/// *"this method takes 0 generic arguments but 1 was supplied"* — a message
/// about turbofish syntax, not about capabilities. Routing the widening
/// through an unsatisfiable bound lets
/// [`#[diagnostic::on_unimplemented]`](https://doc.rust-lang.org/reference/attributes/diagnostics.html)
/// name both sets and say what the author actually did wrong. PLX-78's
/// standard: for a guarantee expressed as a compile error, the message *is*
/// the deliverable.
///
/// Sealed through its [`CapabilitySet`] supertrait, exactly as [`Has`] is: no
/// downstream crate can add an impl that makes two different sets
/// interchangeable.
#[diagnostic::on_unimplemented(
    message = "capability set widening: this handler's method declares `{Self}`, so it may mint only `Client<{Self}>` — `{Requested}` is a different capability set",
    label = "`{Requested}` is not the declared set `{Self}`",
    note = "a handler may use exactly the set its method declares. Write `turn.client()` and let the declared set be inferred; to use another capability, add it to the method's `Client<..>` declaration so the runtime's pre-flight check can verify the peer serves it (PLX-102)."
)]
pub trait Declares<Requested: CapabilitySet>: CapabilitySet {}

impl<C: CapabilitySet> Declares<C> for C {}

/// `C` contains marker `M` at position `I`.
///
/// Never written by hand: it appears only as a bound on `Client<C>`'s
/// accessors, where `I` is inferred. See the [module docs](self) for why the
/// index parameter is load-bearing.
pub trait Has<M: Capability, I>: CapabilitySet {}

macro_rules! set_impl {
    ( $($name:ident),* ) => {
        impl<$($name: Capability),*> sealed::Sealed for ($($name,)*) {}

        impl<$($name: Capability),*> CapabilitySet for ($($name,)*) {
            const ARITY: usize = <[()]>::len(&[$(set_impl!(@unit $name)),*]);

            const NAMES: &'static [&'static str] = &[$($name::NAME),*];

            fn callbacks() -> Vec<CallbackIr> {
                vec![$($name::descriptor()),*]
            }

            fn names() -> Vec<&'static str> {
                vec![$($name::NAME),*]
            }
        }
    };
    (@unit $name:ident) => { () };
}

macro_rules! has_impl {
    ( ($($all:ident),*), $target:ident, $idx:ty ) => {
        impl<$($all: Capability),*> Has<$target, $idx> for ($($all,)*) {}
    };
}

// --- generated by the `has_impl!` / `set_impl!` macros below ---
set_impl!();
set_impl!(A);
set_impl!(A, B);
set_impl!(A, B, C);
set_impl!(A, B, C, D);
set_impl!(A, B, C, D, E);
set_impl!(A, B, C, D, E, F);
set_impl!(A, B, C, D, E, F, G);
set_impl!(A, B, C, D, E, F, G, H);
has_impl!((A), A, Here);
has_impl!((A, B), A, Here);
has_impl!((A, B), B, There<Here>);
has_impl!((A, B, C), A, Here);
has_impl!((A, B, C), B, There<Here>);
has_impl!((A, B, C), C, There<There<Here>>);
has_impl!((A, B, C, D), A, Here);
has_impl!((A, B, C, D), B, There<Here>);
has_impl!((A, B, C, D), C, There<There<Here>>);
has_impl!((A, B, C, D), D, There<There<There<Here>>>);
has_impl!((A, B, C, D, E), A, Here);
has_impl!((A, B, C, D, E), B, There<Here>);
has_impl!((A, B, C, D, E), C, There<There<Here>>);
has_impl!((A, B, C, D, E), D, There<There<There<Here>>>);
has_impl!((A, B, C, D, E), E, There<There<There<There<Here>>>>);
has_impl!((A, B, C, D, E, F), A, Here);
has_impl!((A, B, C, D, E, F), B, There<Here>);
has_impl!((A, B, C, D, E, F), C, There<There<Here>>);
has_impl!((A, B, C, D, E, F), D, There<There<There<Here>>>);
has_impl!((A, B, C, D, E, F), E, There<There<There<There<Here>>>>);
has_impl!((A, B, C, D, E, F), F, There<There<There<There<There<Here>>>>>);
has_impl!((A, B, C, D, E, F, G), A, Here);
has_impl!((A, B, C, D, E, F, G), B, There<Here>);
has_impl!((A, B, C, D, E, F, G), C, There<There<Here>>);
has_impl!((A, B, C, D, E, F, G), D, There<There<There<Here>>>);
has_impl!((A, B, C, D, E, F, G), E, There<There<There<There<Here>>>>);
has_impl!((A, B, C, D, E, F, G), F, There<There<There<There<There<Here>>>>>);
has_impl!((A, B, C, D, E, F, G), G, There<There<There<There<There<There<Here>>>>>>);
has_impl!((A, B, C, D, E, F, G, H), A, Here);
has_impl!((A, B, C, D, E, F, G, H), B, There<Here>);
has_impl!((A, B, C, D, E, F, G, H), C, There<There<Here>>);
has_impl!((A, B, C, D, E, F, G, H), D, There<There<There<Here>>>);
has_impl!((A, B, C, D, E, F, G, H), E, There<There<There<There<Here>>>>);
has_impl!((A, B, C, D, E, F, G, H), F, There<There<There<There<There<Here>>>>>);
has_impl!((A, B, C, D, E, F, G, H), G, There<There<There<There<There<There<Here>>>>>>);
has_impl!((A, B, C, D, E, F, G, H), H, There<There<There<There<There<There<There<Here>>>>>>>);
