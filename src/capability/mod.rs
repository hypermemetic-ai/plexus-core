//! Typed capability handles (PLX-77 / M1·A2) — the handle's **type** is the
//! declaration.
//!
//! # What this is for
//!
//! A method's callback set must not be a hand-maintained attribute list beside
//! the code: that drifts, silently, from what the body actually calls. So the
//! declaration and the use are made the same object.
//!
//! ```rust
//! use plexus_core::capability::{Client, FsRead, FsReadRequest, Permission};
//!
//! // The author writes this signature. `C` IS the callback declaration.
//! fn prompt(client: &Client<(Permission, FsRead)>) {
//!     let _ = client.fs_read(FsReadRequest { path: "/etc/hosts".into() });
//!     // client.fs_write(..) does not compile — FsWrite is not in C.
//! }
//!
//! // …and the IR declaration is derived from the very same type.
//! let declared = Client::<(Permission, FsRead)>::callbacks();
//! assert_eq!(
//!     declared.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
//!     ["session/request_permission", "fs/read_text_file"],
//! );
//! ```
//!
//! The union of those declarations across the IR is what a service advertises,
//! which is what lets a peer that cannot serve a required callback be rejected
//! **pre-flight** rather than surprised mid-turn.
//!
//! # The three pieces
//!
//! - [`markers`] — the closed marker set ([`Permission`], [`FsRead`],
//!   [`FsWrite`], [`Terminal`]) and the **sealed** [`Capability`] trait each
//!   implements. Sealed means an external type cannot invent a capability.
//! - [`set`] — [`CapabilitySet`] (`C -> Vec<CallbackIr>`) and [`Has`], the
//!   index-disambiguated membership trait that makes calling an undeclared
//!   capability a *compile* error across the whole 0..=8 tuple range without a
//!   coherence conflict. Read that module's docs for why the index parameter
//!   exists.
//! - [`client`] — [`Client<C>`](Client) itself, with one gated accessor per
//!   capability.
//!
//! # A set is a set (PLX-78)
//!
//! `Client<(FsRead, FsRead)>` is a malformed declaration, and it now says so:
//! [`Client::NO_DUPLICATES`] is a const assertion over
//! [`CapabilitySet::NAMES`], forced on every path that uses a set, so the error
//! an author sees names the duplication instead of complaining about an
//! ambiguous position index. A capability's *identity* is its wire name, and
//! `declare_capabilities!` proves every declared name pairwise distinct with a
//! crate-level `const _` assertion — so there is no second id to keep in sync
//! and no way to add a marker that escapes the check.
//!
//! # Scope (PLX-76 `q-acp-callbacks`, PLX-77)
//!
//! The **typing** is real. The **transport** is not: without a
//! [`CallbackTransport`] every accessor returns
//! [`CallbackError::NotWired`]. Correlation, delivery, cancellation and
//! capability *negotiation* are build C. The counterfactual this deletes is
//! substrate's `claudecode_loopback`, which correlates through a URL query
//! param plus an env var and blocks in a 1s × 300s poll loop.

pub mod client;
pub mod markers;
pub mod set;

#[cfg(test)]
mod tests;

pub use client::{CallbackError, CallbackTransport, Client};
pub use markers::{
    Capability, FsRead, FsReadRequest, FsReadResponse, FsWrite, FsWriteRequest, FsWriteResponse,
    Permission, PermissionOutcome, PermissionRequest, Terminal, TerminalCreateRequest,
    TerminalCreateResponse, ALL_CAPABILITY_NAMES,
};
pub use set::{has_duplicate_names, CapabilitySet, Has, Here, There};
