//! KEEL-31, second pass (the review's `k31.rs` probe, N1): a method that
//! acts `everywhere` is held to `*` however it is reached — not only where a
//! gate indexed it.
//!
//! - **Through an untyped (`#[peer]`) slot** the gate decides the slot's
//!   whole grant, held anywhere; the method itself runs only when that reach
//!   is held on `*` (the macro's check, `call::admits_everywhere`).
//! - **The far side**: an activation serving a call whose reach is not held
//!   on `*` (a hop's ceiling, a slot's verdict) refuses it, typed; outside any
//!   call it runs, as before.
//! - **The host side**: a mounted child whose kept schema marks a method
//!   `everywhere` is not forwarded such a call — a far side built before the
//!   rule (`tests/fixtures/old_far_side.py`) would run it.

use std::path::PathBuf;

use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{ChildOptions, ChildSpec, PlexusError, RemoteChild};
use plexus_testkit::parts::who;
use plexus_testkit::{Caller, Forbidden, Host, World, ADMIN};
use serde_json::{json, Value};

#[derive(Clone)]
struct LeafActivation {
    name: String,
}

/// An instance.
#[plexus_macros::activation(namespace = "leaf", version = "1.0.0")]
impl LeafActivation {
    /// Acts on the whole service, inside a slot.
    #[plexus_macros::method(everywhere)]
    async fn wipe(&self) -> Value {
        json!(format!("wiped {}", self.name))
    }

    /// An ordinary method.
    #[plexus_macros::method]
    async fn look(&self) -> Value {
        json!(format!("looked {}", self.name))
    }
}

#[derive(Clone)]
struct VaultActivation {
    /// A mounted child the peer slot hands out as `old`.
    old: Option<RemoteChild>,
}

/// A vault with a typed slot and an untyped one.
#[plexus_macros::activation(namespace = "vault", version = "1.0.0")]
impl VaultActivation {
    /// Whole service.
    #[plexus_macros::method(everywhere)]
    async fn nuke(&self) -> Value {
        json!("nuked")
    }

    /// A typed dynamic child.
    #[plexus_macros::child]
    fn item(&self, name: &str) -> Option<LeafActivation> {
        Some(LeafActivation { name: name.into() })
    }

    /// An untyped peer slot: `real` in this process, `old` a mounted child.
    #[plexus_macros::peer]
    async fn far(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        match (name, &self.old) {
            ("real", _) => Ok(Box::new(LeafActivation { name: name.into() })),
            ("old", Some(c)) => Ok(Box::new(c.clone())),
            _ => Err(PeerError::NotFound { name: name.into() }),
        }
    }
}

/// `admin` on the scope `X` alone.
const SCOPED: &str = "key:5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
/// Holds the peer slot whole (`vault.{far}`) on `*`, not admin.
const SLOTTER: &str = "key:5151515151515151515151515151515151515151515151515151515151515151";

async fn host(old: Option<RemoteChild>) -> Host {
    World::new()
        .host()
        .named("svc")
        .with(VaultActivation { old })
        .role("slotter", ["vault.{far}"])
        .member_at(SCOPED, "admin", "X")
        .member(SLOTTER, "slotter")
        .await
}

#[tokio::test]
async fn through_an_untyped_slot_it_needs_the_slot_on_everywhere() {
    let host = host(None).await;
    // The probe: admin@X, `wipe` inside the peer slot.
    host.as_(SCOPED).call("vault.far.real.wipe", json!({})).await.refused(Forbidden).naming("leaf.wipe").at("*").held_on(["X"]);
    // The ordinary method beside it: the slot's verdict, as before.
    assert_eq!(host.as_(SCOPED).call("vault.far.real.look", json!({})).await.answer::<String>(), "looked real");
    // Held on `*`: admin, or the slot's own grant.
    assert_eq!(host.as_(ADMIN).call("vault.far.real.wipe", json!({})).await.answer::<String>(), "wiped real");
    assert_eq!(host.as_(SLOTTER).call("vault.far.real.wipe", json!({})).await.answer::<String>(), "wiped real");
    // The typed slot and the activation itself: the gate, as before.
    host.as_(SCOPED).call("vault.foo.wipe", json!({})).await.refused(Forbidden).at("*");
    host.as_(SCOPED).call("vault.nuke", json!({})).await.refused(Forbidden).at("*");
    assert_eq!(host.as_(ADMIN).call("vault.foo.wipe", json!({})).await.answer::<String>(), "wiped foo");
}

#[tokio::test]
async fn the_far_side_runs_it_only_for_a_reach_held_on_everywhere() {
    use plexus_core::plexus::Activation;
    let host = host(None).await;
    let leaf = LeafActivation { name: "far".into() };
    let ada = who(SCOPED);
    // A reach on `X` alone, as a hop's ceiling or a slot's verdict gives it.
    let narrow = host.gate().check(Some(&ada), &plexus_auth_core::grants::Grant::new("vault.{far}"), None).unwrap();
    assert!(!narrow.is_everywhere());
    let refused = plexus_core::call::test::in_call(Some(&ada), narrow, Activation::call(&leaf, "wipe", json!({}), Some(&ada), None)).await;
    match refused {
        Err(PlexusError::Forbidden { .. }) => {}
        Err(other) => panic!("refused, not forbidden: {other}"),
        Ok(_) => panic!("ran for a reach on X"),
    }
    let nowhere = plexus_core::call::test::in_call(None, plexus_core::plexus::Reach::nowhere(), Activation::call(&leaf, "wipe", json!({}), None, None)).await;
    assert!(matches!(nowhere, Err(PlexusError::Forbidden { .. })), "a hop no gate decided");
    // Held on `*`: runs.
    let ran = plexus_core::call::test::in_call(Some(&ada), plexus_core::plexus::Reach::everywhere(), Activation::call(&leaf, "wipe", json!({}), Some(&ada), None)).await;
    assert!(ran.is_ok());
    // Outside any call (code calling the activation directly): as before.
    assert!(Activation::call(&leaf, "wipe", json!({}), None, None).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_host_does_not_forward_it_to_an_older_far_side() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/old_far_side.py");
    let spec = ChildSpec::Stdio { name: "old".into(), argv: vec!["python3".into(), "-I".into(), fixture.to_string_lossy().into_owned()] };
    let child = RemoteChild::connect(spec, ChildOptions::for_service("svc")).await.expect("the old far side mounts");
    assert!(plexus_core::plexus::Activation::plugin_schema(&child).methods.iter().any(|m| m.name == "wipe" && m.everywhere));
    let host = host(Some(child.clone())).await;
    let calls = child.stats().calls;
    let scoped: &Caller = &host.as_(SCOPED);
    scoped.call("vault.far.old.wipe", json!({})).await.refused(Forbidden).naming("old.wipe").at("*");
    assert_eq!(child.stats().calls, calls, "nothing crossed the hop");
    // The ordinary method, and `wipe` for a holder on `*`, go through.
    assert_eq!(scoped.call("vault.far.old.ping", json!({})).await.answer::<String>(), "py.ping ran");
    assert_eq!(host.as_(ADMIN).call("vault.far.old.wipe", json!({})).await.answer::<String>(), "py.wipe ran");
}
