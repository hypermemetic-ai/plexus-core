//! Namespaced identity for plexus vNext (PLX-75 / M1·A).
//!
//! # Why a namespaced subject
//!
//! Today's identity is a bare `user_id: String` — a UUID v4 *minted* by
//! plexus-idp at `plexus-idp/src/core.rs:95` and reused verbatim as the JWT
//! `sub` claim. That shape assumes identity is always issued by a server.
//!
//! A nostr pubkey is the opposite: it is **presented**, not minted —
//! self-sovereign, proven by signature, and never assigned by us. A bare UUID
//! field cannot hold one without lying about what it is.
//!
//! [`Principal`] resolves that by making the *issuer* part of the identity:
//! today's UUID becomes `idp:<uuid>` — one issuer's format rather than *the*
//! format — alongside `nostr:<pubkey>` and `apikey:<id>`. PLX-73
//! `q-principal-unification` places this in M1 core types, so `AuthContext`
//! carries a namespaced principal from day one; M4 then deals only with what
//! *admits* a principal to a tenant (membership as a record), not with who it
//! is.
//!
//! # Naming note
//!
//! `plexus_core::plexus::Principal` (re-exported from `plexus-auth-core`) is a
//! **different, pre-existing** type: a sealed `Anonymous | User | Service`
//! caller-stamp enum. It is untouched by PLX-75. This one is reached as
//! `plexus_core::identity::Principal` and is never re-exported at the crate
//! root, so neither name shadows the other. Reconciling the two is M1·J's job
//! (`AuthContext` carries a `Principal` instead of a bare `user_id`).

mod principal;

pub use principal::{Issuer, Principal, PrincipalParseError};
