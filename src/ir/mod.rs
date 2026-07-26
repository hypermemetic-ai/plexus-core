//! The plexus activation IR (PLX-75 / M1·A) — the vNext spine.
//!
//! # What this is
//!
//! One recursive, serializable document describing a whole activation tree:
//! [`ActivationIr`] with [`MethodIr`]s and [`ChildEdge`]s, hashed as a Merkle
//! tree so any node can be cached and invalidated independently.
//!
//! # What it replaces, and why
//!
//! `plexus::MethodSchema` / `plexus::PluginSchema` (`src/plexus/schema.rs`) are
//! **shallow**: a child appears only as a `ChildSummary` of
//! `{namespace, description, hash}`. A client that wants to know a child's
//! methods must make another `.schema` call — one network round-trip *per tree
//! level*. That is the drill-down bug class PLX-73 set out to delete, and it is
//! why [`ChildEdge::Static`] embeds the whole subtree.
//!
//! The three recursion mechanisms that were previously indistinguishable on the
//! wire — compile-time `#[child]`, runtime `DynamicHub::register`, and indexed
//! `session/{id}` families — become three explicit [`ChildEdge`] variants, each
//! carrying exactly what a client needs to act without another fetch.
//!
//! Similarly, the two distinct structs both named `HubMethodAttrs` plus
//! `MethodInfo` collapse into one [`MethodIr`].
//!
//! # What this build deliberately does NOT do
//!
//! These are **inert data types**. There is no parser, no `quote!`, no codegen,
//! no dispatch, and no auth wiring here — those are M1·B/C/D/E/J.
//!
//! There is also **no conversion to or from `MethodSchema`/`PluginSchema`**.
//! The two representations coexist without adapters, on purpose: PLX-73
//! `q-migration-bridge` decided against shims (the in-tree evidence being that
//! plexus-macros 0.6 still ships `#[deprecated(since = "0.5.0")]` aliases a full
//! generation later). `schema.rs` is untouched and keeps working for substrate
//! and hyperforge until their own cuts in M2+.
//!
//! # Hashing
//!
//! See [`hash`] for the full algorithm, which is **`CONNECTOME-HASH/1`**, the
//! construction CONNECTOME RFC 002 §4.6 specifies normatively (PLX-89). In one
//! line: each node's `hash` is a SHA-256 over a length-prefixed, domain-tagged
//! encoding of its own content folded with its methods' and children's hashes,
//! so mutating a leaf changes that leaf, every ancestor, and the document's
//! [`ActivationIr::ir_hash`] — and nothing else. Call
//! [`ActivationIr::recompute_hashes`] on the root; it also establishes the §3.3
//! root facts and the §4.7 [`ActivationIr::hash_algorithm`] declaration.
//!
//! The construction is shared with the independent Haskell implementation
//! (`connectome-hs`), and the two produce byte-identical digests. Before RFC 002
//! they could not: §4 named no construction at all, so the two implementations'
//! digests had nothing to agree on (finding F-06).
//!
//! # The request context (RFC 002 §6.9)
//!
//! [`ActivationIr::request_context`] and [`MethodIr::request_context`] declare
//! what the *transport* knows about a call — headers, origin, peer address,
//! trace identifiers — as opposed to [`MethodIr::params`], which is what the
//! caller sends deliberately. The method-level declaration overrides the
//! activation-level one; see [`ActivationIr::effective_request_context`].
//! Absence at both levels means the method needs nothing.
//!
//! # The no-silent-degradation rule
//!
//! Every type reference in the IR is a [`SchemaRef`]: a validated pair of
//! canonical type name and resolved JSON Schema, with a private constructor.
//! It replaces `BidirType::Custom`, which stored type *names* as strings and
//! re-parsed them with a fallback that silently degraded an unresolvable type
//! to `()`. A `SchemaRef` cannot be empty, cannot be uninformative, and can
//! never denote `()` — which is what makes [`CallbackIr`]'s non-optional
//! `request`/`response` fields a compile-time guarantee instead of a
//! convention, and what keeps `updates: None` / `terminal: None` meaning
//! "nothing" rather than "unresolved".
//!
//! # The turn envelope (PLX-77)
//!
//! Adopting ACP turn semantics (PLX-73 `q-acp-as-communication-model`) made
//! every call a **turn**: zero or more updates, then exactly one terminal value
//! carrying a [`StopReason`]. So [`MethodIr`] carries
//! [`updates`](MethodIr::updates), [`terminal`](MethodIr::terminal) and
//! [`callbacks`](MethodIr::callbacks) rather than PLX-75's single `returns`
//! plus a `MethodShape` enum. Streaming and bidirectionality were never
//! alternatives — they are independent axes, and one method routinely issues
//! several distinct callbacks. Classifiers like
//! [`MethodIr::is_streaming`] are *derived* from those fields, never stored.
//!
//! The callback set is produced from a method signature's
//! [`Client<C>`](crate::capability::Client) handle — see
//! [`crate::capability`], where the handle's type *is* the declaration.
//!
//! # Example
//!
//! ```rust
//! use plexus_core::ir::{ActivationIr, ChildEdge, MethodIr};
//!
//! let mut ir = ActivationIr::new("claudecode", "1.0.0")
//!     .with_backend_name("substrate")
//!     .with_respond_method("respond")
//!     .with_method(MethodIr::new("list", "claudecode.list"))
//!     .with_child(ChildEdge::Dynamic {
//!         namespace: "jsexec".into(),
//!         hash: "deadbeef".into(),
//!         description: "runtime-registered".into(),
//!     });
//!
//! ir.recompute_hashes();
//! assert!(ir.ir_hash.is_some());
//! ```

pub mod hash;
mod stop;
mod types;

#[cfg(test)]
mod tests;

pub use hash::{canonical_json, Encoder, Hasher, HASH_ALGORITHM};
pub use stop::{StopDetail, StopKind, StopReason};
pub use types::{
    ActivationIr, AuthRequirementIr, CallbackIr, ChildEdge, DeprecationIr, HttpMethodIr, MethodIr,
    ParamIr, SchemaRef, SchemaRefError, IR_VERSION,
};
