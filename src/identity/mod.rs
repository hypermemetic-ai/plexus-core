//! Namespaced identity for plexus vNext (PLX-75 / M1·A, PLX-87).
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
//! # Where the type actually lives, and why this module is a re-export
//!
//! PLX-75 defined the type *here*, in plexus-core. PLX-82 then found that
//! placement unusable where the type is most needed: **plexus-core depends on
//! plexus-auth-core and never the reverse** — that inversion is the entire
//! point of the auth-core crate — and [`AuthContext`] lives in auth-core, so
//! auth-core could not name a plexus-core type. It mirrored the definition
//! instead, and an equivalence test in plexus-idp held the two copies in step.
//!
//! Two definitions of one concept, kept in sync by a test, is a drift hazard:
//! a test catches divergence only after someone writes it. PLX-87 therefore
//! moved the single definition **down** to [`plexus_auth_core::identity`] —
//! the lowest crate that everything else can see — and this module became a
//! re-export of it. `plexus_core::identity::Principal` is unchanged as a
//! public path and unchanged in grammar, validation, and wire form; it is now
//! literally the same type as `plexus_auth_core::identity::Principal`, so
//! they cannot disagree.
//!
//! # Naming note
//!
//! `plexus_core::plexus::Principal` (re-exported from plexus-auth-core) is a
//! **different, pre-existing** type: a sealed `Anonymous | User | Service`
//! caller-stamp enum, untouched by PLX-75, PLX-82, and PLX-87. The
//! subject-name type is reached as `plexus_core::identity::Principal` and is
//! never re-exported at the crate root, so neither name shadows the other.
//! `plexus_auth_core::principal::Principal::subject()` is the bridge that
//! states the relationship in code: a caller-stamp of `User(..)` names an
//! actor whose subject is one of these.
//!
//! [`AuthContext`]: plexus_auth_core::AuthContext

pub use plexus_auth_core::identity::{Issuer, Principal, PrincipalParseError};
