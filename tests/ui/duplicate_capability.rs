//! PLX-78: a capability set that lists the same capability twice is a COMPILE
//! error, and the error says *that* — not "cannot infer type parameter `I`".
//!
//! A capability set is a set. `(FsRead, FsRead)` is a malformed declaration,
//! and the author who wrote it needs to be told which mistake they made.
//!
//! Note what this fixture deliberately does *not* do: call an accessor on the
//! malformed handle. `client.fs_read(..)` on `(FsRead, FsRead)` matches two
//! `Has` impls, so it is an ordinary type-inference error (E0283) — and a
//! type error aborts the compile before the duplicate assertion, which is a
//! post-monomorphization const evaluation, ever runs. Construction and
//! declaration-derivation are the paths that reach the good message, and they
//! are also the paths an author hits first.

use plexus_core::capability::{Client, FsRead};

fn main() {
    // Constructing the malformed handle is enough on its own.
    let _client: Client<(FsRead, FsRead)> = Client::unwired();

    // …and so is deriving its declaration.
    let _declared = Client::<(FsRead, FsRead)>::callbacks();
}
