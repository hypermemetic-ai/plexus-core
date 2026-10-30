//! PERF-15: `_info`, `{ns}.hash` and `{ns}.schema` answered from a cache
//! keyed by the caller's view (its grants' fingerprint, or anonymous), the
//! grants generation and the schema generation — and still exactly what
//! AUTH-4 says each caller may see.
//!
//! - asked again, nothing is rebuilt: no activation builds its schema, the
//!   gate looks up no role;
//! - two callers holding the same share one answer, computed once;
//! - a view is never served to another caller — every answer equals what a
//!   service that never answered anyone says to that caller;
//! - a revoke, a role edit, a sign-out and a mount each change the next
//!   answer.
//!
//! Two services (`describe_support`): `world()`, one activation behind a gate
//! of its own, and `auth_world()`, AUTH-5's, with the auth activation
//! mounted. Each answers the same from one service to the next (PERF-21,
//! `describe_starts.rs`), so a test compares `world()`'s answers with a fresh
//! service's. `describe_golden.rs` holds both services' answers to their bytes.

mod describe_support;

use describe_support::*;
use plexus_core::plexus::AuthContext;
use serde_json::{json, Value};

/// Every ask in `asks()`, for `who`, on its own connection.
async fn all(w: &World, who: Option<&AuthContext>) -> Vec<Value> {
    let module = module_for(w, who);
    let mut out = Vec::new();
    for ask in asks() {
        out.push(ask.answer(w, &module, who).await);
    }
    out
}

/// Every answer `who` gets from `w` equals what `fresh` — a service that has
/// answered nobody, brought to the same state — gives it.
async fn as_fresh(w: &World, fresh: &World, who: Option<&AuthContext>, why: &str) {
    let (got, want) = (all(w, who).await, all(fresh, who).await);
    for ((g, f), ask) in got.iter().zip(&want).zip(asks()) {
        assert_eq!(g, f, "{why}: {} is not this caller's answer", ask.label());
    }
}

#[tokio::test]
async fn asked_again_nothing_is_rebuilt() {
    let w = auth_world();
    let narrow = session_for(&w, &key(ADA, "worker-1"), Some(vec!["editor@MENGER-12"])).await;
    let callers = [None, Some(key(ADA, "worker-1")), Some(key(ROOT, "root")), Some(narrow)];
    let mut first = Vec::new();
    for who in &callers {
        first.push(all(&w, who.as_ref()).await);
    }
    w.reset();
    let mut again = Vec::new();
    for who in &callers {
        again.push(all(&w, who.as_ref()).await);
    }
    assert_eq!(again, first, "asked again: the same answers");
    assert_eq!(
        (w.built(), w.asked()),
        (0, 0),
        "asked again: no schema built, no role looked up (schemas built, role lookups)"
    );
}

#[tokio::test]
async fn the_same_holdings_share_one_entry() {
    let w = auth_world();
    let (ada, bob, cat) = (key(ADA, "a"), key(BOB, "b"), key(CAT, "c"));
    let a = all(&w, Some(&ada)).await;
    w.reset();
    let b = all(&w, Some(&bob)).await;
    assert_eq!(b, a, "BOB holds what ADA holds: ADA's answers");
    assert_eq!(w.asked(), 0, "and nothing was decided again for BOB: one entry for both");
    let c = all(&w, Some(&cat)).await;
    assert_ne!(c, a, "CAT holds the same role elsewhere: another view");
    assert!(w.asked() > 0, "CAT's view is its own, decided for it");
}

#[tokio::test]
async fn a_view_is_never_served_to_another() {
    let w = world();
    // One service, one generation, the callers in turn — each answer is the
    // one a service that has answered nobody gives that caller.
    let turns = [
        ("root", Some(key(ROOT, "r"))),
        ("anonymous", None),
        ("ada", Some(key(ADA, "a"))),
        ("cat", Some(key(CAT, "c"))),
        ("ada within editor@MENGER-12", Some(within(ADA, "a", &["editor@MENGER-12"]))),
        ("dan", Some(key(DAN, "d"))),
        ("anonymous", None),
        ("root", Some(key(ROOT, "r"))),
        ("cat", Some(key(CAT, "c"))),
        ("ada", Some(key(ADA, "a"))),
    ];
    let g0 = w.gate().generation().current();
    for (name, who) in &turns {
        as_fresh(&w, &world(), who.as_ref(), name).await;
    }
    assert_eq!(w.gate().generation().current(), g0, "one generation throughout");
    // Anonymous and signed in, side by side: the door only, and the caller's own.
    let (anon, ada) = (w.service.info(None), w.service.info(Some(&key(ADA, "a"))));
    assert_eq!((anon["view"].as_str(), ada["view"].as_str()), (Some("anonymous"), Some("caller")));
    assert_ne!(anon["view_hash"], ada["view_hash"]);
    assert_eq!(routed(&w, "tickets.schema", json!({}), None).await, json!({"refused": "Activation not found: tickets"}));
}

#[tokio::test]
async fn a_revoke_changes_the_next_answer() {
    let w = world();
    let ada = key(ADA, "a");
    let before = all(&w, Some(&ada)).await;
    assert_eq!(all(&w, Some(&ada)).await, before, "kept");
    w.revoke(ADA, "MENGER").await;
    assert_ne!(all(&w, Some(&ada)).await, before, "the revoke reaches the next answer");
    assert_eq!(routed(&w, "tickets.schema", json!({}), Some(&ada)).await, json!({"refused": "Activation not found: tickets"}));
    let fresh = world();
    fresh.revoke(ADA, "MENGER").await;
    as_fresh(&w, &fresh, Some(&ada), "after a revoke").await;
    // BOB held what ADA held: still his.
    as_fresh(&w, &fresh, Some(&key(BOB, "b")), "after ADA's revoke, BOB").await;
}

#[tokio::test]
async fn a_role_edit_changes_the_next_answer() {
    let w = world();
    let ada = key(ADA, "a");
    let before = all(&w, Some(&ada)).await;
    assert_eq!(all(&w, Some(&ada)).await, before, "kept");
    // ADA's memberships stay as they were: only the grants generation says
    // that what they hold changed.
    w.role_set("editor", &["tickets.get"]).await;
    assert_ne!(all(&w, Some(&ada)).await, before, "the role edit reaches the next answer");
    let t = routed(&w, "tickets.schema", json!({}), Some(&ada)).await;
    let names: Vec<&str> =
        t["items"][0]["content"]["methods"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["get", "schema"]);
    let fresh = world();
    fresh.role_set("editor", &["tickets.get"]).await;
    as_fresh(&w, &fresh, Some(&ada), "after a role edit").await;
}

#[tokio::test]
async fn the_auth_writes_reach_the_next_answer() {
    // AUTH-5's activation writing, the gate's generation moving with it.
    let w = auth_world();
    let (ada, root) = (key(ADA, "a"), key(ROOT, "r"));
    let module = module_for(&w, Some(&ada));
    let info = |w: &World| w.service.info(Some(&ada));
    let h0 = info(&w)["view_hash"].clone();
    assert_eq!(over_module(&module, "menger.hash", json!({})).await["frames"][0]["content"]["value"], h0);
    let out = routed(&w, "auth.role_set", json!({"role": "editor", "grants": ["tickets.get"]}), Some(&root)).await;
    assert_eq!(out["items"][0]["content"]["grants"], json!(["tickets.get"]), "{out}");
    let h1 = info(&w)["view_hash"].clone();
    assert_ne!(h1, h0, "a role edit: another view");
    assert_eq!(over_module(&module, "menger.hash", json!({})).await["frames"][0]["content"]["value"], h1);
    let out = routed(&w, "auth.revoke", json!({"principal": ADA, "scope": "MENGER"}), Some(&root)).await;
    assert_eq!(out["items"][0]["content"]["roles"], json!(["editor"]), "{out}");
    let h2 = info(&w)["view_hash"].clone();
    assert_ne!(h2, h1, "a revoke: another view");
    assert_eq!(over_module(&module, "menger.hash", json!({})).await["frames"][0]["content"]["value"], h2);
    assert_eq!(routed(&w, "tickets.schema", json!({}), Some(&ada)).await, json!({"refused": "Activation not found: tickets"}));
    // DAN holds nothing either: the same view as ADA's now.
    assert_eq!(info(&w), w.service.info(Some(&key(DAN, "d"))));
}

#[tokio::test]
async fn a_sign_out_is_anonymous_at_once() {
    let w = auth_world();
    let session = session_for(&w, &key(ADA, "worker-1"), None).await;
    let signed_in = all(&w, Some(&session)).await;
    assert_eq!(all(&w, Some(&session)).await, signed_in, "kept");
    assert_eq!(routed(&w, "auth.logout", json!({}), Some(&session)).await["items"][0]["content"]["type"], "logged_out");
    // The connection still carries the ended session: it sees the door.
    assert_eq!(all(&w, Some(&session)).await, all(&w, None).await, "a session that ended sees the anonymous view");
    assert_eq!(w.service.info(Some(&session))["view"], "anonymous");
}

#[tokio::test]
async fn a_mount_drops_what_was_kept() {
    // Built, asked, then a child mounted: the next answer has it.
    let (unshared, _) = service();
    let root = key(ROOT, "r");
    let before = unshared.info(Some(&root));
    assert!(!unshared.view(Some(&root)).activations.contains_key("notes"));
    let mounted = unshared.register(NotesActivation);
    let view = mounted.view(Some(&root));
    assert!(view.activations.contains_key("notes"), "the mounted child is in the view");
    assert_ne!(mounted.info(Some(&root))["view_hash"], before["view_hash"]);
    assert_eq!(mounted.info(Some(&root))["view_hash"], json!(view.hash));
}

#[tokio::test]
async fn schema_moved_drops_what_was_kept() {
    // A child mounted or gone while the service serves (no build does that
    // yet; HYPERFORGE-7's would): `schema_moved` says so, and the next ask
    // builds what it describes again — the same answers, built anew.
    let w = auth_world();
    let ada = key(ADA, "a");
    let first = all(&w, Some(&ada)).await;
    w.reset();
    assert_eq!(all(&w, Some(&ada)).await, first);
    assert_eq!(w.built(), 0, "kept");
    w.service.schema_moved();
    assert_eq!(all(&w, Some(&ada)).await, first, "the same answers, built again");
    assert!(w.built() > 0, "built again after schema_moved");
}
