//! KEEL-31 — a method that acts on the whole service says so
//! (`#[plexus_macros::method(everywhere)]`), and the gate admits it only
//! where its grant is held on `*`, within every ceiling layer. A method with
//! no target and no such word keeps its meaning: held anywhere, answered
//! from there.
//!
//! The review's probe (`scoped_admin.rs`, KEEL-28): `admin@MENGER-5` called
//! `dyn.grow`, which names no target, and was admitted.

use futures::stream::Stream;
use plexus_auth_core::grants::CEILING_KEY;
use plexus_core::plexus::{AuthContext, Reach};
use plexus_testkit::parts::Shortcodes;
use plexus_testkit::{Caller, Forbidden, Host, Unauthenticated, World, ADMIN, VIEWER};
use serde_json::{json, Value};

#[derive(Clone)]
struct OpsActivation;

/// A service's machinery: what only an admin of the whole service may do,
/// and what is answered from where the caller holds it.
#[plexus_macros::activation(namespace = "ops", version = "1.0.0", roles(viewer = ["tally"]))]
impl OpsActivation {
    /// Run code on the host: acts on the whole service.
    #[plexus_macros::method(everywhere)]
    async fn grow(&self, name: String) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::once(async move { format!("grown {name}") })
    }

    /// The service's signing key, rotated: acts on the whole service.
    #[plexus_macros::method(everywhere)]
    async fn rotate_key(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::once(async { "rotated".to_string() })
    }

    /// A read with no target: answered from where it is held.
    #[plexus_macros::method]
    async fn tally(&self, reach: Reach) -> impl Stream<Item = String> + Send + 'static {
        let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        futures::stream::once(async move { held.join(",") })
    }
}

/// `admin` on the ticket MENGER-5 alone — an admin of one corner.
const CORNER: &str = "key:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
/// Holds `ops.grow` itself, by a role, on MENGER alone.
const GROWER: &str = "key:9090909090909090909090909090909090909090909090909090909090909090";

async fn host() -> Host {
    World::new()
        .host()
        .with(OpsActivation)
        .resolving(Shortcodes)
        .role("grower", ["ops.grow"])
        .member_at(CORNER, "admin", "MENGER-5")
        .member_at(GROWER, "grower", "MENGER")
        .await
}

/// `who`, in a session minted with `ceiling` (`role@SCOPE` entries).
fn capped(host: &Host, who: &str, ceiling: &[&str]) -> Caller {
    let ctx = AuthContext::for_principal(&who.parse().unwrap(), "capped", vec![], json!({ CEILING_KEY: ceiling }));
    Caller::new(host.service().clone(), Some(ctx))
}

#[tokio::test]
async fn a_scoped_admin_is_refused_a_method_that_acts_everywhere() {
    let host = host().await;
    // The probe: admin on one ticket, a method with no target.
    host.as_(CORNER).call("ops.grow", json!({ "name": "x" })).await.refused(Forbidden).naming("ops.grow").at("*");
    host.as_(CORNER).call("ops.rotate_key", json!({})).await.refused(Forbidden).naming("ops.rotate_key").at("*");
    // A role that lists the grant, held on one scope: the same.
    host.as_(GROWER).call("ops.grow", json!({ "name": "x" })).await.refused(Forbidden).naming("ops.grow").held_on(["MENGER"]);
    // Held on `*`: admitted.
    assert_eq!(host.as_(ADMIN).call("ops.grow", json!({ "name": "x" })).await.answer::<String>(), "grown x");
    assert_eq!(host.as_(ADMIN).call("ops.rotate_key", json!({})).await.answer::<String>(), "rotated");
    // Anonymous: sign in first, as ever.
    host.anonymous().call("ops.grow", json!({ "name": "x" })).await.refused(Unauthenticated);
}

#[tokio::test]
async fn a_ceiling_narrower_than_everywhere_is_refused() {
    let host = host().await;
    // admin@* minted admin@MENGER-5: the session reaches one ticket.
    capped(&host, ADMIN, &["admin@MENGER-5"]).call("ops.grow", json!({ "name": "x" })).await.refused(Forbidden).naming("ops.grow");
    // A ceiling that names the grant on `*` keeps it.
    let kept = capped(&host, ADMIN, &["ops.grow@*"]).call("ops.grow", json!({ "name": "x" })).await;
    assert_eq!(kept.answer::<String>(), "grown x");
    // A ceiling of `admin@*` over a scoped holder never widens it.
    capped(&host, CORNER, &["admin@*"]).call("ops.grow", json!({ "name": "x" })).await.refused(Forbidden);
}

#[tokio::test]
async fn a_method_with_no_target_and_no_word_keeps_its_meaning() {
    let host = host().await;
    // Held on one scope: admitted, and answered from there.
    assert_eq!(host.as_(CORNER).call("ops.tally", json!({})).await.answer::<String>(), "MENGER-5");
    assert_eq!(host.as_(VIEWER).call("ops.tally", json!({})).await.answer::<String>(), "*");
    capped(&host, ADMIN, &["admin@MENGER-5"]).call("ops.tally", json!({})).await.answers(1);
}

/// The method names `ns.schema` lists for `caller`.
async fn listed(caller: &Caller) -> Vec<String> {
    let schema: Value = caller.call("ops.schema", json!({})).await.answer();
    schema["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn the_view_shows_it_only_where_it_is_held_everywhere() {
    let host = host().await;
    let corner = listed(&host.as_(CORNER)).await;
    assert!(corner.contains(&"tally".to_string()) && !corner.contains(&"grow".to_string()), "{corner:?}");
    let admin = listed(&host.as_(ADMIN)).await;
    assert!(admin.contains(&"grow".to_string()) && admin.contains(&"rotate_key".to_string()), "{admin:?}");
    // The schema says it, so a client and `auth.requires` can too.
    let grow: Value = host.as_(ADMIN).call("ops.grow.schema", json!({})).await.answer();
    assert_eq!(grow["everywhere"], json!(true), "{grow}");
    let tally: Value = host.as_(ADMIN).call("ops.tally.schema", json!({})).await.answer();
    assert!(tally.get("everywhere").is_none(), "absent unless said: {tally}");
}
