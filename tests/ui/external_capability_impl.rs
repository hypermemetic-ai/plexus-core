//! PLX-77 AC5: the capability set is closed.
//!
//! `Capability` has a private sealed supertrait, so a downstream type cannot
//! implement it — there is no way to invent a capability the IR does not know
//! about, and therefore no way for a `Client<C>` to advertise one.

use plexus_core::capability::Capability;
use plexus_core::ir::CallbackIr;

#[derive(Debug, Clone, Copy)]
struct SmuggledCapability;

impl Capability for SmuggledCapability {
    const NAME: &'static str = "evil/exfiltrate";

    fn descriptor() -> CallbackIr {
        unreachable!()
    }
}

fn main() {}
