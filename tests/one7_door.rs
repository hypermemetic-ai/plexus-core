//! ONE-7 — **a role held on an address opens that activation's door.**
//!
//! Owner, 2026-11-11: "activation and data scopes are separate. we can only
//! generally handle activation scopes. data scopes must be handled by the
//! application". The gate passes the address of the call it dispatches for
//! the two shapes that touch no data here — a method marked `everywhere`
//! with no target, and a call into an untyped peer slot — and decides them
//! at the door. Everything with data is decided on its data, as before.
//!
//! The people:
//!
//! - the **operator** holds `operator` on `/ops` — ops' own methods;
//! - the **gardener** holds `operator` on `/ops.*` — ops and all beneath;
//! - the **corner admin** holds `admin` on the data scope `KILN`;
//! - the **kiln operator** holds `operator` on `KILN`, a role listing the
//!   peer slot's grant;
//! - the **shopkeeper** holds `operator` on `/vault.far.shop.*` — one peer.

use futures::stream::Stream;
use plexus_auth_core::grants::{Grant, CEILING_KEY};
use plexus_core::plexus::peer::{Peer, PeerError};
use plexus_core::plexus::{AuthContext, PlexusError, Reach};
use plexus_testkit::parts::{who, Shortcodes};
use plexus_testkit::{Caller, Forbidden, Host, NotFound, World, ADMIN};
use serde_json::{json, Value};

// ------------------------------------------------------------------ the service

#[derive(Clone)]
struct OpsActivation;

/// A service's machinery: whole-activation methods beside data ones.
#[plexus_macros::activation(namespace = "ops", version = "1.0.0")]
impl OpsActivation {
    /// Acts on the whole activation: answers what its reach says.
    #[plexus_macros::method(everywhere)]
    async fn grow(&self, reach: Reach) -> Value {
        said(&reach)
    }

    /// One ticket, by id: a data method.
    #[plexus_macros::method(target = "id")]
    async fn get(&self, id: String) -> Value {
        json!(id)
    }

    /// A read with no target: answered from where it is held.
    #[plexus_macros::method]
    async fn tally(&self, reach: Reach) -> Value {
        said(&reach)
    }
}

/// What a reach says of itself.
fn said(reach: &Reach) -> Value {
    let held: Vec<String> = reach.held_on().iter().map(|s| s.to_string()).collect();
    json!({ "activation": reach.holds_activation(), "everywhere": reach.is_everywhere(), "held_on": held })
}

#[derive(Clone)]
struct LeafActivation {
    name: String,
}

/// A peer's surface, in process.
#[plexus_macros::activation(namespace = "leaf", version = "1.0.0")]
impl LeafActivation {
    /// An ordinary method: who it is.
    #[plexus_macros::method]
    async fn look(&self) -> Value {
        json!(format!("looked {}", self.name))
    }

    /// The peer's own whole-activation method.
    #[plexus_macros::method(everywhere)]
    async fn wipe(&self) -> Value {
        json!(format!("wiped {}", self.name))
    }
}

#[derive(Clone)]
struct VaultActivation;

/// A vault: an untyped peer slot `far`, an opaque dynamic child `box`.
#[plexus_macros::activation(namespace = "vault", version = "1.0.0")]
impl VaultActivation {
    /// How full it is.
    #[plexus_macros::method]
    async fn count(&self) -> Value {
        json!(2)
    }

    /// Peers, by any name.
    #[plexus_macros::peer]
    async fn far(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        Ok(Box::new(LeafActivation { name: name.into() }))
    }

    /// A box of this service's own, by name: opaque, untyped — not a peer.
    #[plexus_macros::child(opaque)]
    fn bin(&self, name: &str) -> Option<LeafActivation> {
        Some(LeafActivation { name: name.into() })
    }
}

const OPERATOR: &str = "key:0101010101010101010101010101010101010101010101010101010101010101";
const GARDENER: &str = "key:0202020202020202020202020202020202020202020202020202020202020202";
const CORNER_ADMIN: &str = "key:0303030303030303030303030303030303030303030303030303030303030303";
const KILN_OPERATOR: &str = "key:0404040404040404040404040404040404040404040404040404040404040404";
const SHOPKEEPER: &str = "key:0505050505050505050505050505050505050505050505050505050505050505";

/// The operator's role: ops' machinery and the vault's peers and boxes.
const OPERATOR_GRANTS: [&str; 5] = ["ops.grow", "ops.get", "ops.tally", "vault.{far}", "vault.{bin}"];

async fn service() -> Host {
    World::new()
        .host()
        .named("svc")
        .with(OpsActivation)
        .with(VaultActivation)
        .resolving(Shortcodes)
        .role("operator", OPERATOR_GRANTS)
        .member_at(OPERATOR, "operator", "/ops")
        .member_at(GARDENER, "operator", "/ops.*")
        .member_at(GARDENER, "operator", "/vault.*")
        .member_at(CORNER_ADMIN, "admin", "KILN")
        .member_at(KILN_OPERATOR, "operator", "KILN")
        .member_at(SHOPKEEPER, "operator", "/vault.far.shop.*")
        .await
}

/// `who`, its session capped by `ceiling`.
fn capped(host: &Host, p: &str, ceiling: &[&str]) -> Caller {
    let ctx = AuthContext::for_principal(&p.parse().unwrap(), "capped", vec![], json!({ CEILING_KEY: ceiling }));
    Caller::new(host.service().clone(), Some(ctx))
}

// ------------------------------------------------------------------ the door

#[tokio::test]
async fn an_operator_of_an_activation_runs_its_whole_activation_methods() {
    let host = service().await;
    let grown = host.as_(OPERATOR).call("ops.grow", json!({})).await.answer::<Value>();
    assert_eq!(grown, json!({ "activation": true, "everywhere": false, "held_on": [] }), "admitted at the door, holding no data");
    assert_eq!(host.as_(GARDENER).call("ops.grow", json!({})).await.answer::<Value>()["activation"], true);
    // An admin of every scope is admitted, as ever, and holds data everywhere.
    assert_eq!(host.as_(ADMIN).call("ops.grow", json!({})).await.answer::<Value>()["held_on"], json!(["*"]));
}

#[tokio::test]
async fn an_admin_of_a_data_scope_opens_no_door() {
    let host = service().await;
    // KEEL-31 kept: refused, said as KEEL-31 says it.
    host.as_(CORNER_ADMIN).call("ops.grow", json!({})).await.refused(Forbidden).naming("ops.grow").at("*").held_on(["KILN"]);
    host.as_(KILN_OPERATOR).call("ops.grow", json!({})).await.refused(Forbidden).naming("ops.grow").at("*");
}

#[tokio::test]
async fn an_address_holds_no_data() {
    let host = service().await;
    // A data method is decided on its target: an address counts for nothing.
    host.as_(OPERATOR).call("ops.get", json!({ "id": "KILN-3" })).await.refused(Forbidden).naming("ops.get").at("KILN");
    // A read with no target is "held anywhere" — on data. An address is not data.
    host.as_(OPERATOR).call("ops.tally", json!({})).await.refused(Forbidden).naming("ops.tally");
    // Where data is held, as before.
    assert_eq!(host.as_(KILN_OPERATOR).call("ops.get", json!({ "id": "KILN-3" })).await.answer::<String>(), "KILN-3");
    assert_eq!(host.as_(KILN_OPERATOR).call("ops.tally", json!({})).await.answer::<Value>()["held_on"], json!(["KILN"]));
}

#[tokio::test]
async fn a_capped_session_opens_only_the_doors_its_ceiling_names() {
    let host = service().await;
    // The admin capped to `/ops`: ops' door, no data.
    let ops_only = capped(&host, ADMIN, &["operator@/ops"]);
    assert_eq!(ops_only.call("ops.grow", json!({})).await.answer::<Value>()["held_on"], json!([]));
    ops_only.call("ops.get", json!({ "id": "KILN-3" })).await.refused(Forbidden);
    ops_only.call("vault.far.shop.look", json!({})).await.refused(Forbidden);
    // Capped to a data scope: data there, and no door.
    let kiln_only = capped(&host, ADMIN, &["operator@KILN"]);
    kiln_only.call("ops.grow", json!({})).await.refused(Forbidden).at("*");
    kiln_only.call("vault.far.shop.look", json!({})).await.refused(Forbidden);
    assert_eq!(kiln_only.call("ops.get", json!({ "id": "KILN-3" })).await.answer::<String>(), "KILN-3");
}

// ------------------------------------------------------------------ a peer's door

#[tokio::test]
async fn an_operator_of_one_peer_calls_into_that_peer_alone() {
    let host = service().await;
    let shopkeeper = host.as_(SHOPKEEPER);
    assert_eq!(shopkeeper.call("vault.far.shop.look", json!({})).await.answer::<String>(), "looked shop");
    // The peer's whole-activation method too: the door covers the call.
    assert_eq!(shopkeeper.call("vault.far.shop.wipe", json!({})).await.answer::<String>(), "wiped shop");
    shopkeeper.call("vault.far.till.look", json!({})).await.refused(Forbidden).naming("vault.{far}").at("*");
    shopkeeper.call("ops.grow", json!({})).await.refused(Forbidden);
}

#[tokio::test]
async fn an_operator_of_every_peer_calls_into_each() {
    let host = service().await;
    for peer in ["shop", "till"] {
        assert_eq!(host.as_(GARDENER).call(&format!("vault.far.{peer}.look"), json!({})).await.answer::<String>(), format!("looked {peer}"));
    }
    // `/ops` alone is not `/ops.*`: no prefix rule.
    host.as_(OPERATOR).call("vault.far.shop.look", json!({})).await.refused(Forbidden);
}

/// KEEL-44: a role listing the peer slot's grant, held on a data scope, no
/// longer reaches every peer through the slot grant. (Until 0.11.4 the
/// kiln operator was admitted to every peer, `held_on [KILN]`.)
#[tokio::test]
async fn a_data_scope_reaches_no_peer_through_the_slot() {
    let host = service().await;
    for peer in ["shop", "till"] {
        host.as_(KILN_OPERATOR).call(&format!("vault.far.{peer}.look"), json!({})).await.refused(Forbidden).naming("vault.{far}").held_on(["KILN"]);
    }
}

/// Not closed by this build, said so: `admin` lists every grant, a peer's
/// literal path among them (`vault.far.shop.look`, the grant consent's
/// `callers` give), and a literal path is decided as before — held
/// anywhere. So an admin of a data scope still reaches a peer's ordinary
/// methods by the literal path; its whole-activation methods it does not
/// (KEEL-31: `*` alone). KEEL-31's own rows rely on this
/// (`keel31_through_slots`).
#[tokio::test]
async fn an_admin_of_a_data_scope_still_reaches_a_peer_by_its_literal_path() {
    let host = service().await;
    assert_eq!(host.as_(CORNER_ADMIN).call("vault.far.shop.look", json!({})).await.answer::<String>(), "looked shop");
    host.as_(CORNER_ADMIN).call("vault.far.shop.wipe", json!({})).await.refused(Forbidden).naming("leaf.wipe").at("*");
}

/// An opaque dynamic child is this service's own (its names may be data):
/// its slot grant is decided as before, held anywhere — never at a door.
#[tokio::test]
async fn a_dynamic_child_slot_is_not_a_door() {
    let host = service().await;
    assert_eq!(host.as_(KILN_OPERATOR).call("vault.a.look", json!({})).await.answer::<String>(), "looked a");
    host.as_(GARDENER).call("vault.a.look", json!({})).await.refused(Forbidden).naming("vault.{bin}");
}

/// A key the address cannot hold — `*`, `@`, a space, non-ASCII, empty — has
/// no address: its door is `*`'s alone, never a shorter address's, never a
/// data scope's.
#[tokio::test]
async fn a_key_with_no_address_opens_no_door_but_everywhere() {
    let host = service().await;
    for key in ["sh*p", "sh@p", "sh p", "shöp", ""] {
        let path = format!("vault.far.{key}.look");
        host.as_(GARDENER).call(&path, json!({})).await.refused(Forbidden).naming("vault.{far}").at("*");
        host.as_(KILN_OPERATOR).call(&path, json!({})).await.refused(Forbidden);
        // `*` passes the gate; what the peer makes of the name is its own.
        assert!(!matches!(host.as_(ADMIN).stream(&path, json!({})).await, Err(PlexusError::Forbidden { .. })), "{path}");
    }
}

/// A key holding a dot is two segments to every router of the path — this
/// service's, the peer's — so the address agrees with where the call goes:
/// `/vault.far.shop.*` covers what the peer `shop` routes, and only that.
#[tokio::test]
async fn a_dotted_key_is_two_names_everywhere() {
    let host = service().await;
    let deeper = host.as_(SHOPKEEPER).stream("vault.far.shop.v2.look", json!({})).await;
    assert!(!matches!(deeper, Err(PlexusError::Forbidden { .. })), "the gate admits it; shop routes `v2.look` as its own");
    host.as_(SHOPKEEPER).call("vault.far.shop-v2.look", json!({})).await.refused(Forbidden);
}

// ------------------------------------------------------------------ inside a call

/// L1: a door is one call's. A door reach handed into a call that holds no
/// door is refused; one of another grant too.
#[tokio::test]
async fn a_door_is_not_handed_to_another_call() {
    use plexus_core::plexus::with_reach;
    let host = service().await;
    let gate = host.gate();
    let operator = who(OPERATOR);
    let kiln = who(KILN_OPERATOR);
    let at = |path: &str, grant: &str| {
        let (activation, method) = path.rsplit_once('.').unwrap();
        let segments: Vec<&str> = activation.split('.').collect();
        plexus_auth_core::grants::DispatchedCall::new(plexus_auth_core::grants::CallAddress::of_segments(&segments, method).unwrap(), Grant::new(grant))
    };
    let door = gate.check_everywhere_at(Some(&operator), &at("ops.grow", "ops.grow")).unwrap();
    assert!(door.holds_activation() && !door.is_everywhere());
    // Inside a data call (the kiln operator's tally): refused.
    let data = gate.check(Some(&kiln), &Grant::new("ops.tally"), None).unwrap();
    let handed = plexus_core::call::test::in_call(Some(&kiln), data, with_reach(door.clone(), async {})).await;
    assert!(matches!(handed, Err(PlexusError::Unauthenticated(m)) if m.contains("holds the activation")));
    // Inside another door (the gardener's grow): another grant, refused.
    let gardener = who(GARDENER);
    let other = gate.check_everywhere_at(Some(&gardener), &at("ops.grow", "ops.grow")).unwrap();
    let foreign = gate.check_everywhere_at(Some(&gardener), &at("vault.far.shop.look", "vault.{far}")).unwrap();
    let handed = plexus_core::call::test::in_call(Some(&gardener), other.clone(), with_reach(foreign, async {})).await;
    assert!(matches!(handed, Err(PlexusError::Unauthenticated(m)) if m.contains("another grant")));
    // The call's own door, handed back: taken.
    assert!(plexus_core::call::test::in_call(Some(&gardener), other.clone(), with_reach(other, async {})).await.is_ok());
}

/// The backstop inside a whole-activation method asks for this call's door:
/// a door reach of another method's grant runs nothing.
#[tokio::test]
async fn the_backstop_takes_the_door_of_its_own_call_alone() {
    use plexus_core::plexus::Activation;
    let host = service().await;
    let operator = who(OPERATOR);
    let at = plexus_auth_core::grants::DispatchedCall::new(plexus_auth_core::grants::CallAddress::new("ops", "grow").unwrap(), Grant::new("ops.grow"));
    let door = host.gate().check_everywhere_at(Some(&operator), &at).unwrap();
    let leaf = LeafActivation { name: "x".into() };
    let ran = plexus_core::call::test::in_call(Some(&operator), door, Activation::call(&leaf, "wipe", json!({}), Some(&operator), None)).await;
    assert!(matches!(ran, Err(PlexusError::Forbidden { .. })), "leaf.wipe ran on ops.grow's door");
}

// ------------------------------------------------------------------ what a caller sees

fn shown(view: &plexus_core::plexus::View, ns: &str) -> Vec<String> {
    view.activations.get(ns).map(|s| s.methods.iter().map(|m| m.name.clone()).collect()).unwrap_or_default()
}

#[tokio::test]
async fn a_caller_sees_the_doors_it_opens_and_nothing_else() {
    let host = service().await;
    let operator = host.service().view(Some(&who(OPERATOR)));
    assert!(shown(&operator, "ops").contains(&"grow".to_string()), "{:?}", shown(&operator, "ops"));
    assert!(!shown(&operator, "ops").contains(&"get".to_string()) && !shown(&operator, "ops").contains(&"tally".to_string()));
    assert!(shown(&operator, "vault").is_empty(), "the operator of /ops opens no vault door");
    // The gardener (`/vault.*`) sees the peer slot; the shopkeeper calls one peer, and reads its schema.
    assert!(shown(&host.service().view(Some(&who(GARDENER))), "vault").contains(&"far".to_string()));
    let corner = host.service().view(Some(&who(CORNER_ADMIN)));
    assert!(!shown(&corner, "ops").contains(&"grow".to_string()), "a data admin is not shown a door");
    let schema = host.as_(SHOPKEEPER).call("vault.far.shop.schema", json!({})).await.answer::<Value>();
    assert!(schema["methods"].as_array().unwrap().iter().any(|m| m["name"] == "look"), "{schema}");
    // KEEL-32: a schema not shown is not found, never routed.
    host.as_(KILN_OPERATOR).call("vault.far.shop.schema", json!({})).await.refused(NotFound);
}

// ------------------------------------------------------------------ registration

#[derive(Clone)]
struct TwiceActivation;

/// A method and a peer slot of one name.
#[plexus_macros::activation(namespace = "twice", version = "1.0.0")]
impl TwiceActivation {
    /// Named `far`, as the slot is.
    #[plexus_macros::method(name = "far")]
    async fn far_method(&self) -> impl Stream<Item = String> + Send + 'static {
        futures::stream::once(async { "method".to_string() })
    }

    /// Peers, by name.
    #[plexus_macros::peer]
    async fn far(&self, name: &str) -> Result<Box<dyn Peer>, PeerError> {
        Ok(Box::new(LeafActivation { name: name.into() }))
    }
}

/// Already impossible for an activation the macro writes: its schema is
/// refused as it is built (`PluginSchema::validate_no_collisions`), before
/// anything registers it. A schema read from elsewhere (a mounted child's)
/// is refused at registration, and has no address at dispatch.
#[test]
#[should_panic(expected = "Name collision in plugin 'twice': duplicate method 'far'")]
fn a_method_and_a_child_of_one_name_are_refused() {
    let _ = plexus_core::DynamicHub::new("svc").register(TwiceActivation);
}

// ------------------------------------------------------------------ writing a scope

/// Holds `admin` on `/auth`: the owner's "a role which gives a grant for
/// /auth is admin".
const AUTH_ADMIN: &str = "key:0606060606060606060606060606060606060606060606060606060606060606";

async fn with_login() -> Host {
    World::new()
        .host()
        .named("svc")
        .with(OpsActivation)
        .with_auth()
        .role("operator", ["ops.grow", "ops.get", "ops.tally"])
        .member_at(CORNER_ADMIN, "admin", "KILN")
        .member_at(AUTH_ADMIN, "admin", "/auth")
        .await
}

fn grant(principal: &str, role: &str, scope: &str) -> Value {
    json!({ "principal": principal, "role": role, "scope": scope })
}

#[tokio::test]
async fn an_address_is_granted_as_the_gate_reads_it() {
    let host = with_login().await;
    let admin = host.as_(ADMIN);
    // Granted by an admin of everything, it opens its door at once.
    let granted = admin.call("auth.grant", grant(OPERATOR, "operator", "/ops")).await.answer::<Value>();
    assert_eq!(granted, json!({ "type": "granted", "principal": OPERATOR, "role": "operator", "scope": "/ops" }));
    assert_eq!(host.as_(OPERATOR).call("ops.grow", json!({})).await.answer::<Value>()["activation"], true);
    // An address of nothing served yet is granted too: it holds nothing until a call it covers is dispatched.
    assert_eq!(admin.call("auth.grant", grant(OPERATOR, "operator", "/dyn.peer.shop.*")).await.answer::<Value>()["scope"], "/dyn.peer.shop.*");
    // `self` is the service called: `*`.
    assert_eq!(admin.call("auth.grant", grant(GARDENER, "operator", "self")).await.answer::<Value>()["scope"], "*");
}

#[tokio::test]
async fn a_malformed_address_is_refused_naming_the_rule() {
    let host = with_login().await;
    for bad in ["/ops..grow", "/", "/ops.*.x", "/ops grow", "/öps"] {
        let said = host.as_(ADMIN).call("auth.grant", grant(OPERATOR, "operator", bad)).await.answer::<Value>();
        assert_eq!(said["type"], "error", "{bad}: {said}");
        assert!(said["message"].as_str().unwrap().contains("is not an address scope"), "{bad}: {said}");
    }
}

/// Granting an address is decided on `*` alone: an address holds no data,
/// so no data scope lies above it — nor does an address of `/auth`.
#[tokio::test]
async fn only_an_admin_of_everything_grants_an_address() {
    let host = with_login().await;
    host.as_(CORNER_ADMIN).call("auth.grant", grant(OPERATOR, "operator", "/ops")).await.refused(Forbidden).at("*");
    host.as_(AUTH_ADMIN).call("auth.grant", grant(OPERATOR, "operator", "/ops")).await.refused(Forbidden).at("*");
}

/// `auth.role_set` acts on the whole of `auth`: at its door for one who holds
/// `admin` on `/auth`, refused to an admin of a data scope.
#[tokio::test]
async fn an_admin_of_auth_sets_a_role_at_its_door() {
    let host = with_login().await;
    let set = json!({ "role": "operator", "grants": ["ops.grow"] });
    assert_eq!(host.as_(AUTH_ADMIN).call("auth.role_set", set.clone()).await.answer::<Value>()["grants"], json!(["ops.grow"]));
    host.as_(CORNER_ADMIN).call("auth.role_set", set).await.refused(Forbidden).at("*");
}

/// A session's ceiling minted is written as a grant is: `self` is `*`, a
/// malformed address refused, naming the rule.
#[tokio::test]
async fn a_minted_ceiling_is_written_as_the_gate_reads_it() {
    let host = with_login().await;
    let session = |ceiling: &[&str]| json!({ "flow": { "session": { "ceiling": ceiling } } });
    let minted = host.as_(ADMIN).call("auth.login", session(&["operator@self", "operator@/ops.*"])).await.answer::<Value>();
    assert_eq!(minted["ceiling"], json!(["operator@*", "operator@/ops.*"]), "{minted}");
    let refused = host.as_(ADMIN).call("auth.login", session(&["operator@/ops..x"])).await.answer::<Value>();
    assert!(refused["message"].as_str().is_some_and(|m| m.contains("is not an address scope")), "{refused}");
}
