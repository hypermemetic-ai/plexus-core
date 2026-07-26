//! `plexus_core::identity::Principal` still works, and is now ONE type (PLX-87).
//!
//! PLX-75 established `plexus_core::identity::Principal` as a public path and
//! downstream code writes against it. PLX-87 moved the definition down into
//! plexus-auth-core (the crate plexus-core depends on, never the reverse) and
//! left this module as a `pub use`. This file is an **external consumer** —
//! an integration test sees plexus-core exactly as a downstream crate does —
//! so it fails to compile if that path ever stops resolving, and fails to
//! compile if the re-exported type stops being the same type as auth-core's.

use std::str::FromStr;

use plexus_core::identity::{Issuer, Principal, PrincipalParseError};

const UUID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const PUBKEY: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

/// The exact PLX-75 path, used exactly as PLX-75's own tests used it.
#[test]
fn the_plx_75_public_path_still_builds_parses_and_renders() {
    let p = Principal::new(Issuer::Idp, UUID).expect("idp uuid is valid");
    assert_eq!(p.issuer(), Issuer::Idp);
    assert_eq!(p.subject(), UUID);
    assert_eq!(p.to_string(), format!("idp:{UUID}"));

    let parsed = Principal::from_str(&format!("nostr:{PUBKEY}")).expect("nostr pubkey is valid");
    assert_eq!(parsed.issuer(), Issuer::Nostr);

    let u = uuid::Uuid::parse_str(UUID).unwrap();
    assert_eq!(Principal::idp(&u), p);

    // The error type is reachable by the same path and still matchable
    // exhaustively — it is not `#[non_exhaustive]`.
    assert!(matches!(
        "ldap:someone".parse::<Principal>(),
        Err(PrincipalParseError::UnknownIssuer(i)) if i == "ldap"
    ));

    // Wire form is still a bare string.
    assert_eq!(
        serde_json::to_string(&p).unwrap(),
        format!("\"idp:{UUID}\"")
    );
}

/// The point of PLX-87: one definition. A function typed against the
/// auth-core path accepts a value built through the plexus-core path with no
/// conversion, which only typechecks if they are literally the same type.
#[test]
fn the_two_public_paths_name_the_same_type() {
    fn takes_auth_core(p: plexus_auth_core::identity::Principal) -> String {
        p.to_string()
    }

    let via_core: Principal = Principal::new(Issuer::ApiKey, "ak_live_01HQ8ZQK").unwrap();
    assert_eq!(takes_auth_core(via_core), "apikey:ak_live_01HQ8ZQK");

    // ...and the same in the other direction, including for `Issuer`.
    let via_auth: plexus_auth_core::identity::Principal =
        Principal::new(Issuer::Idp, UUID).unwrap();
    let _: Issuer = plexus_auth_core::identity::Issuer::Idp;
    assert_eq!(via_auth.issuer(), Issuer::Idp);
}

/// The *other* `Principal` — the sealed caller-stamp — is a distinct concept
/// at a distinct path, and PLX-87 did not disturb it or its `subject()`
/// bridge. Both names are usable in one scope; neither shadows the other.
#[test]
fn the_caller_stamp_principal_is_undisturbed() {
    fn _is_caller_stamp(p: &plexus_core::plexus::Principal) -> bool {
        p.is_anonymous()
    }
    fn _same_type_from_auth_core(p: &plexus_auth_core::Principal) -> bool {
        p.is_anonymous()
    }

    // The caller-stamp is sealed — no external crate can mint one — so the
    // assertion here is at the type level, which is where it belongs: the
    // `subject()` bridge still exists and still yields *this* module's
    // `Principal`, i.e. the collapse rewired nothing about it.
    fn _bridge_still_returns_the_subject_name(
        p: &plexus_core::plexus::Principal,
    ) -> Option<Principal> {
        p.subject()
    }
}
