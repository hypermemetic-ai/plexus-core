//! KEEL-54 — a call is decided and routed by one path. The gate decides the
//! path the router routes, the router runs only what the gate decided, and
//! the platform's own grant and revoke check, in their bodies, the scope they
//! write. A spelling of a method — the service's name in front, twice, in
//! another case, with a stray dot — is the method, or nothing: never a door
//! around the gate.
//!
//! The class closed: a path the gate's index did not know was decided as
//! "held anywhere" on a grant made from its spelling — which `admin` on any
//! scope holds — and routed on into the method it named.

use futures::{Stream, StreamExt};
use plexus_auth_core::grants::CEILING_KEY;
use plexus_core::plexus::{AuthContext, PlexusStreamItem, Reach};
use plexus_core::DynamicHub;
use plexus_testkit::parts::Shortcodes;
use plexus_testkit::{Caller, Forbidden, Host, NotFound, Unauthenticated, World, ADMIN, EDITOR, NOBODY, USER, VIEWER};
use serde_json::{json, Value};

#[derive(Clone)]
struct HiddenActivation;

/// A static child.
#[plexus_macros::activation(namespace = "hidden", version = "1.0.0")]
impl HiddenActivation {
    /// Rotate the master key.
    #[plexus_macros::method]
    async fn rotate(&self) -> Value {
        json!("rotated")
    }
}

#[derive(Clone)]
struct LeafActivation;

/// What a vault's slot, or a nested service, holds.
#[plexus_macros::activation(namespace = "leaf", version = "1.0.0")]
impl LeafActivation {
    /// Answer.
    #[plexus_macros::method]
    async fn ping(&self) -> Value {
        json!("pong")
    }
}

#[derive(Clone)]
struct VaultActivation;

/// A vault: a ticket read on its target, a whole-service wipe, a tally
/// answered from where it is held, a static child and a slot.
#[plexus_macros::activation(namespace = "vault", version = "1.0.0", roles(viewer = ["get", "tally"]))]
impl VaultActivation {
    /// Read one ticket.
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: String) -> Value {
        json!(id)
    }

    /// Wipe everything.
    #[plexus_macros::method(everywhere)]
    async fn wipe(&self) -> Value {
        json!("wiped")
    }

    /// Where the caller holds it.
    #[plexus_macros::method]
    async fn tally(&self, reach: Reach) -> impl Stream<Item = String> + Send + 'static {
        let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
        futures::stream::once(async move { held.join(",") })
    }

    /// The static child.
    #[plexus_macros::child]
    fn hidden(&self) -> HiddenActivation {
        HiddenActivation
    }

    /// A slot: one leaf per name.
    #[plexus_macros::child]
    fn item(&self, _name: &str) -> Option<LeafActivation> {
        Some(LeafActivation)
    }
}

/// Admin of the data scope KILN, and nothing else.
const KILN_ADMIN: &str = "key:4b494c4e4b494c4e4b494c4e4b494c4e4b494c4e4b494c4e4b494c4e4b494c4e";
/// The principal the probes try to raise; never a caller.
const TARGET: &str = "key:7474747474747474747474747474747474747474747474747474747474747474";

/// `svc`: login on, the vault, and a whole service registered inside it as
/// an entry (`inner`, whose own routing no schema of `svc` describes).
async fn host() -> Host {
    let inner = DynamicHub::new("inner").register(LeafActivation);
    World::new()
        .host()
        .named("svc")
        .with_auth()
        .with(VaultActivation)
        .with(inner)
        .resolving(Shortcodes)
        .member_at(KILN_ADMIN, "admin", "KILN")
        .await
}

/// `who` in a session minted under `ceiling`.
fn capped(host: &Host, who: &str, ceiling: &[&str]) -> Caller {
    let ctx = AuthContext::for_principal(&who.parse().unwrap(), "capped", vec![], json!({ CEILING_KEY: ceiling }));
    Caller::new(host.service().clone(), Some(ctx))
}

/// Every spelling of `path` a caller might try: the service's name in front
/// once and twice, other cases, stray and empty segments, padding.
fn spellings(path: &str) -> Vec<String> {
    let (first, rest) = path.split_once('.').unwrap();
    vec![
        format!("svc.svc.{path}"),
        format!("SVC.{path}"),
        format!("svc.{}.{rest}", first.to_uppercase()),
        format!("{}.{rest}", first.to_uppercase()),
        path.to_uppercase(),
        format!(".{path}"),
        format!("{path}."),
        format!("svc..{path}"),
        format!("{first}..{rest}"),
        format!("{first}.{path}"),
        format!(" {path}"),
        format!("{path} "),
        format!("svc.{path}.{}", rest.rsplit('.').next().unwrap()),
    ]
}

/// What the service did with a call: admitted it (an answer), or refused it
/// — before it opened, or in its stream.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Decision {
    Admitted,
    Refused,
}

async fn decision(caller: &Caller, path: &str, params: Value) -> Decision {
    let Ok(stream) = caller.stream(path, params).await else { return Decision::Refused };
    let items: Vec<PlexusStreamItem> = stream.collect().await;
    let answered = matches!(items.last(), Some(PlexusStreamItem::Done { .. }))
        && items.iter().all(|i| match i {
            PlexusStreamItem::Error { .. } => false,
            PlexusStreamItem::Data { content, .. } => content.clone().into_value().get("type") != Some(&json!("error")),
            _ => true,
        });
    if answered { Decision::Admitted } else { Decision::Refused }
}

/// Whether `TARGET` holds admin on `*` now.
fn raised(host: &Host) -> bool {
    host.members().0.lock().unwrap().iter().any(|m| m.principal.to_string() == TARGET && m.scope.is_everywhere())
}

fn grant_everything() -> Value {
    json!({ "principal": TARGET, "role": "admin", "scope": "*" })
}

#[tokio::test]
async fn an_admin_of_one_scope_cannot_grant_admin_of_everything_however_the_method_is_spelled() {
    let host = host().await;
    let kiln_admin = host.as_(KILN_ADMIN);
    for path in std::iter::once("auth.grant".to_string()).chain(["svc.auth.grant".to_string()]).chain(spellings("auth.grant")) {
        assert_eq!(decision(&kiln_admin, &path, grant_everything()).await, Decision::Refused, "{path}");
        assert!(!raised(&host), "{path} raised a principal to admin on *");
    }
    // The service's own name in front is the method itself, decided as it is.
    kiln_admin.call("svc.auth.grant", grant_everything()).await.refused(Forbidden).naming("auth.grant").at("*");
    // Within KILN it grants, by either spelling.
    let within = json!({ "principal": TARGET, "role": "viewer", "scope": "KILN" });
    assert_eq!(kiln_admin.call("auth.grant", within.clone()).await.answers(1)[0]["type"], "granted");
    assert_eq!(kiln_admin.call("svc.auth.grant", within).await.answers(1)[0]["type"], "granted");
    // And the revoke the same: not of everything, by any spelling.
    for path in ["auth.revoke".to_string(), "svc.auth.revoke".to_string()].into_iter().chain(spellings("auth.revoke")) {
        let all = json!({ "principal": ADMIN, "scope": "*" });
        assert_eq!(decision(&kiln_admin, &path, all).await, Decision::Refused, "{path}");
    }
    assert_eq!(host.as_(ADMIN).call("vault.wipe", json!({})).await.answer::<String>(), "wiped", "the admin of everything still is");
}

#[tokio::test]
async fn a_capped_session_cannot_escape_its_cap_by_spelling() {
    let host = host().await;
    let session = capped(&host, ADMIN, &["admin@KILN"]);
    for path in ["auth.grant".to_string(), "svc.auth.grant".to_string()].into_iter().chain(spellings("auth.grant")) {
        assert_eq!(decision(&session, &path, grant_everything()).await, Decision::Refused, "{path}");
    }
    assert!(!raised(&host));
    for path in ["vault.wipe", "svc.vault.wipe", "svc.svc.vault.wipe", "auth.waiting", "svc.auth.waiting"] {
        assert_eq!(decision(&session, path, json!({})).await, Decision::Refused, "{path}");
    }
    // Within its cap it acts, by either spelling.
    let within = json!({ "principal": TARGET, "role": "viewer", "scope": "KILN" });
    assert_eq!(session.call("svc.auth.grant", within).await.answers(1)[0]["type"], "granted");
    assert_eq!(session.call("svc.vault.get", json!({ "id": "KILN-1" })).await.answer::<String>(), "KILN-1");
}

/// Layer 1: the service's own name in front is the bare path — the same
/// decision, the same method, for everyone. `svc.auth.waiting` refused even
/// the admin of everything, decided on one grant and backstopped on another.
#[tokio::test]
async fn the_services_own_name_in_front_is_the_method_itself() {
    let host = host().await;
    host.as_(ADMIN).call("svc.auth.waiting", json!({})).await.answers(0);
    assert_eq!(host.as_(ADMIN).call("svc.vault.wipe", json!({})).await.answer::<String>(), "wiped");
    assert_eq!(host.as_(VIEWER).call("svc.vault.get", json!({ "id": "KILN-1" })).await.answer::<String>(), "KILN-1");
    assert_eq!(host.as_(VIEWER).call("svc.vault.tally", json!({})).await.answer::<String>(), "*");
    assert_eq!(host.as_(KILN_ADMIN).call("svc.vault.tally", json!({})).await.answer::<String>(), "KILN");
    host.as_(KILN_ADMIN).call("svc.vault.get", json!({ "id": "ACME-1" })).await.refused(Forbidden).naming("vault.get").at("ACME");
    host.as_(KILN_ADMIN).call("svc.vault.wipe", json!({})).await.refused(Forbidden).naming("vault.wipe").at("*");
    // A static child's and a slot's paths, with the service's name in front.
    assert_eq!(host.as_(ADMIN).call("svc.vault.hidden.rotate", json!({})).await.answer::<String>(), "rotated");
    assert_eq!(host.as_(ADMIN).call("svc.vault.box1.ping", json!({})).await.answer::<String>(), "pong");
    host.as_(VIEWER).call("svc.vault.hidden.rotate", json!({})).await.refused(Forbidden).naming("vault.hidden.rotate");
    // The service's own methods keep their names.
    host.as_(VIEWER).call("svc.hash", json!({})).await.answers(1);
}

/// Layer 2: a path no schema of the service describes, and no slot holds,
/// is never held anywhere — `admin` of one scope does not reach into a
/// whole service registered as an entry, whose own routing the gate cannot
/// see. Only one who holds its literal grant on `*` may call it.
#[tokio::test]
async fn a_path_nobody_declared_is_held_on_everything_or_not_at_all() {
    let host = host().await;
    for who in [KILN_ADMIN, VIEWER, EDITOR, USER, NOBODY] {
        host.as_(who).call("inner.leaf.ping", json!({})).await.refused(Forbidden).naming("inner.leaf.ping").at("*");
        host.as_(who).call("vault.nope", json!({})).await.refused(Forbidden).at("*");
    }
    capped(&host, ADMIN, &["admin@KILN"]).call("inner.leaf.ping", json!({})).await.refused(Forbidden).at("*");
    host.anonymous().call("inner.leaf.ping", json!({})).await.refused(Unauthenticated);
    // The admin of everything reaches it, and a made-up method is not found.
    assert_eq!(host.as_(ADMIN).call("inner.leaf.ping", json!({})).await.answer::<String>(), "pong");
    host.as_(ADMIN).call("vault.nope", json!({})).await.refused(NotFound);
}

/// Layer 3: the router routes the service's own namespace to the service's
/// own methods alone — a doubled name is not found, even for the admin of
/// everything, rather than a second way into `auth`.
#[tokio::test]
async fn a_doubled_name_is_not_found_even_for_the_admin_of_everything() {
    let host = host().await;
    host.as_(ADMIN).call("svc.svc.auth.grant", grant_everything()).await.refused(NotFound);
    host.as_(ADMIN).call("svc.svc.vault.wipe", json!({})).await.refused(NotFound);
    host.as_(ADMIN).call("svc.svc.hash", json!({})).await.refused(NotFound);
    assert!(!raised(&host));
}

/// The sweep: for every method the service serves, every caller, and every
/// spelling, the spelling is decided as the method is, or refused — never
/// admitted where the method is not. The service's own name in front once
/// is the method: decided exactly as it is.
#[tokio::test]
async fn every_spelling_of_every_method_is_that_method_or_nothing() {
    let host = host().await;
    let mut paths: Vec<String> = host.service().list_methods().into_iter().filter(|m| !m.ends_with(".schema") && m != "auth.logout").collect();
    paths.extend(["vault.hidden.rotate", "vault.box1.ping", "inner.leaf.ping"].map(String::from));
    let callers = [
        ("admin", host.as_(ADMIN)),
        ("kiln admin", host.as_(KILN_ADMIN)),
        ("viewer", host.as_(VIEWER)),
        ("nobody", host.as_(NOBODY)),
        ("capped", capped(&host, ADMIN, &["admin@KILN"])),
        ("anonymous", host.anonymous()),
    ];
    let params = |path: &str| match path {
        "auth.grant" => json!({ "principal": TARGET, "role": "viewer", "scope": "*" }),
        "auth.revoke" => json!({ "principal": TARGET, "scope": "*" }),
        "auth.requires" => json!({ "method": "vault.get" }),
        "auth.role_set" => json!({ "role": "reader", "grants": ["vault.get"] }),
        "auth.login" => json!({ "flow": { "session": {} } }),
        "vault.get" => json!({ "id": "KILN-1" }),
        "svc.call" => json!({ "method": "vault.tally" }),
        "inner.call" => json!({ "method": "leaf.ping" }),
        _ => json!({}),
    };
    let mut checked = 0;
    for path in &paths {
        for (name, caller) in &callers {
            let canonical = decision(caller, path, params(path)).await;
            if !path.starts_with("svc.") {
                let prefixed = format!("svc.{path}");
                assert_eq!(decision(caller, &prefixed, params(path)).await, canonical, "{name}: {prefixed} against {path}");
            }
            for spelled in spellings(path) {
                let d = decision(caller, &spelled, params(path)).await;
                assert!(d == Decision::Refused || d == canonical, "{name}: {spelled} admitted where {path} is {canonical:?}");
                checked += 1;
            }
        }
    }
    assert!(checked > 1000, "{checked}");
}
