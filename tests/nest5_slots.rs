//! NEST-5 · slot types and slot grants, in-process.
//!
//! A dynamic child's slot is described and granted once: the parent's schema
//! carries the slot's type (`role.child`), and `solar.{planet}.info` is one
//! grant for `info` on every name in the slot — so a role can list it.
//!
//! The `solar` example: a typed slot (`planet`, of `Planet`, with a nested
//! slot `moon`), a static child (`sun`, which wins over the slot), and an
//! opaque slot on another activation (`belt.{rock}`, untyped: admitted
//! whole).

use async_stream::stream;
use futures::stream::Stream;
use plexus_core::plexus::{Activation, AuthEvent, MethodRole};
use plexus_testkit::parts::who;
use plexus_testkit::{Forbidden, Host, World, VIEWER};
use serde_json::json;
use std::future::IntoFuture;

// ------------------------------------------------------------------ the kids

#[derive(Clone)]
pub struct MoonActivation;

/// A moon.
#[plexus_macros::activation]
impl MoonActivation {
    /// Its phase.
    pub async fn phase(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "full".to_string(); }
    }
}

#[derive(Clone)]
pub struct PlanetActivation {
    name: String,
}

/// A planet.
#[plexus_macros::activation]
impl PlanetActivation {
    /// What it is.
    pub async fn info(&self) -> impl Stream<Item = String> + Send + 'static {
        let n = self.name.clone();
        stream! { yield format!("planet {n}"); }
    }

    /// Rename it.
    pub async fn rename(&self, to: String) -> impl Stream<Item = String> + Send + 'static {
        let n = self.name.clone();
        stream! { yield format!("{n} -> {to}"); }
    }

    /// Its moons: a nested slot.
    #[plexus_macros::child]
    fn moon(&self, name: &str) -> Option<MoonActivation> {
        (name == "luna").then_some(MoonActivation)
    }
}

// ------------------------------------------------------------------ the parents

#[derive(Clone)]
pub struct SolarActivation;

/// The system.
#[plexus_macros::activation(roles(viewer = ["names", "solar.{planet}.info", "{planet}.{moon}.phase"]))]
impl SolarActivation {
    /// Every planet's name.
    pub async fn names(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "earth".to_string(); yield "mars".to_string(); }
    }

    /// A planet by name: a typed slot.
    #[plexus_macros::child(list = "names")]
    fn planet(&self, name: &str) -> Option<PlanetActivation> {
        (name != "pluto").then(|| PlanetActivation { name: name.to_string() })
    }

    /// The sun: a static child, which wins over the slot.
    #[plexus_macros::child]
    fn sun(&self) -> PlanetActivation {
        PlanetActivation { name: "sun".into() }
    }
}

#[derive(Clone)]
pub struct BeltActivation;

/// The asteroid belt.
#[plexus_macros::activation(roles(viewer = ["{rock}"]))]
impl BeltActivation {
    /// How many.
    pub async fn count(&self) -> impl Stream<Item = String> + Send + 'static {
        stream! { yield "many".to_string(); }
    }

    /// A rock by name: an opaque, untyped slot.
    #[plexus_macros::child(opaque)]
    fn rock(&self, name: &str) -> Option<PlanetActivation> {
        Some(PlanetActivation { name: name.to_string() })
    }
}

// ------------------------------------------------------------------ the world

const LITERAL: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// `space`, logged in: VIEWER holds viewer; LITERAL holds `literal`, a
/// grant written as a literal path, which still decides (the slot grant is
/// additive).
fn space() -> Host {
    let host = World::new().host().named("space").with(SolarActivation).with(BeltActivation).with_auth();
    futures::executor::block_on(host.role("literal", ["solar.mars.rename"]).member(LITERAL, "literal").into_future())
}

/// What a row expects: the one item it answers, or the grant it is refused
/// for.
enum Then {
    Answers(&'static str),
    RefusedFor(&'static str),
}
use Then::{Answers, RefusedFor};

// ------------------------------------------------------------------ the rows

/// Row 1: `#[child] fn planet(&self, name: &str) -> Option<Planet>` → the
/// role carries `Planet`'s schema; row 2: `#[child(opaque)]` → no `child`.
#[test]
fn the_slots_type_is_on_its_role() {
    let solar = SolarActivation.plugin_schema();
    let planet = solar.methods.iter().find(|m| m.name == "planet").unwrap();
    match &planet.role {
        MethodRole::DynamicChild { list_method, child: Some(child), .. } => {
            assert_eq!(list_method.as_deref(), Some("names"));
            assert_eq!(child.namespace, "planet");
            let names: Vec<_> = child.methods.iter().map(|m| m.name.as_str()).collect();
            assert!(names.contains(&"info") && names.contains(&"rename") && names.contains(&"moon"), "{names:?}");
            // The nested slot is typed too.
            let moon = child.methods.iter().find(|m| m.name == "moon").unwrap();
            assert!(matches!(&moon.role, MethodRole::DynamicChild { child: Some(c), .. } if c.namespace == "moon"));
        }
        other => panic!("planet's role: {other:?}"),
    }
    // On the wire: `role.child`.
    let wire = serde_json::to_value(&planet.role).unwrap();
    assert_eq!(wire["kind"], "dynamic_child");
    assert_eq!(wire["child"]["namespace"], "planet");

    let belt = BeltActivation.plugin_schema();
    let rock = belt.methods.iter().find(|m| m.name == "rock").unwrap();
    assert!(matches!(&rock.role, MethodRole::DynamicChild { child: None, .. }), "{:?}", rock.role);
    assert!(serde_json::to_value(&rock.role).unwrap().get("child").is_none());
}

/// A schema without `role.child` still reads.
#[test]
fn a_schema_without_role_child_still_reads() {
    let role: MethodRole = serde_json::from_value(json!({ "kind": "dynamic_child", "list_method": "names" })).unwrap();
    assert!(matches!(role, MethodRole::DynamicChild { child: None, .. }));
}

/// Acceptance 2: `roles(viewer = ["solar.{planet}.info"])` lets a viewer call
/// `solar.earth.info` and refuses `solar.earth.rename`; rows 3–5, 8 and 9.
#[tokio::test]
async fn one_grant_per_slot_decides_every_name_in_it() {
    let space = space();
    let rows = [
        // (method, params, who, then)
        ("solar.earth.info", json!({}), VIEWER, Answers("planet earth")),
        ("solar.mars.info", json!({}), VIEWER, Answers("planet mars")),
        ("solar.earth.rename", json!({"to": "terra"}), VIEWER, RefusedFor("solar.{planet}.rename")),
        // A static child named in the slot's place wins, as in routing: its own grant.
        ("solar.sun.info", json!({}), VIEWER, RefusedFor("solar.sun.info")),
        // A nested slot: the same rule one level at a time.
        ("solar.earth.luna.phase", json!({}), VIEWER, Answers("full")),
        // An untyped slot is admitted whole.
        ("belt.ceres.info", json!({}), VIEWER, Answers("planet ceres")),
        ("belt.ceres.rename", json!({"to": "x"}), VIEWER, Answers("ceres -> x")),
        // A literal-path grant still decides as before.
        ("solar.mars.rename", json!({"to": "red"}), LITERAL, Answers("mars -> red")),
        ("solar.earth.rename", json!({"to": "terra"}), LITERAL, RefusedFor("solar.{planet}.rename")),
    ];
    for (method, params, who, then) in rows {
        let got = space.as_(who).call(method, params).await;
        match then {
            Answers(item) => assert_eq!(got.answer::<String>(), item, "{got}"),
            RefusedFor(grant) => {
                got.refused(Forbidden).naming(grant);
            }
        }
    }
}

/// The roles list the slot grants, qualified by the slot's path.
#[test]
fn roles_list_the_slot_grant() {
    let declared = space().service().declared_roles();
    let viewer = &declared["viewer"];
    for g in ["solar.names", "solar.{planet}.info", "solar.{planet}.{moon}.phase", "belt.{rock}"] {
        assert!(viewer.contains(&g.to_string()), "viewer lists {g}: {viewer:?}");
    }
}

/// Row 6: `auth.requires --method solar.earth.info` answers the slot grant.
#[tokio::test]
async fn auth_requires_answers_the_slot_grant() {
    let viewer = space().as_(VIEWER);
    let requires = |method: &'static str| {
        let viewer = viewer.clone();
        async move {
            match viewer.call("auth.requires", json!({ "method": method })).await.answer::<AuthEvent>() {
                AuthEvent::Requires { grant, roles, .. } => (grant, roles),
                other => panic!("auth.requires {method} answered {other:?}"),
            }
        }
    };
    let (grant, roles) = requires("solar.earth.info").await;
    assert_eq!(grant, "solar.{planet}.info");
    assert!(roles.iter().any(|r| r == "viewer"), "{roles:?}");
    assert_eq!(requires("solar.earth.luna.phase").await.0, "solar.{planet}.{moon}.phase");
    assert_eq!(requires("belt.ceres.info").await.0, "belt.{rock}");
    assert_eq!(requires("solar.sun.info").await.0, "solar.sun.info");
}

/// Row 7: a caller's view keeps the slot's entry when the caller holds a
/// method of the slot.
#[test]
fn a_callers_view_keeps_the_slot() {
    let space = space();
    let hub = space.service();
    let view = hub.view(Some(&who(VIEWER)));
    let solar = view.schema_of("solar").expect("viewer sees solar");
    let names: Vec<&str> = solar.methods.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"planet"), "{names:?}");
    // The literal role holds nothing in the slot of `solar` but `mars.rename`,
    // a literal path: the slot entry is not shown for it.
    let view = hub.view(Some(&who(LITERAL)));
    let shown = view.schema_of("solar").map(|s| s.methods.iter().map(|m| m.name.clone()).collect::<Vec<_>>());
    assert!(!shown.unwrap_or_default().contains(&"planet".to_string()));
}
