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
use futures::stream::{Stream, StreamExt};
use plexus_core::plexus::{
    Activation, AuthContext, AuthSetup, MemoryAuthBackend, MemoryMemberships, MemoryRoles, MethodRole, PlexusStream,
    PlexusStreamItem, Resolve, ScopeRef,
};
use plexus_core::{DynamicHub, PlexusError};
use serde_json::{json, Value};
use std::sync::Arc;

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

const VIEWER: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LITERAL: &str = "key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Everywhere;
impl Resolve for Everywhere {
    fn chain(&self, _target: &str) -> Option<Vec<ScopeRef>> {
        Some(vec![ScopeRef::Everywhere])
    }
}

fn hub() -> Arc<DynamicHub> {
    let roles = Arc::new(MemoryRoles::default());
    let members = MemoryMemberships::new().with(VIEWER, "viewer", "*").with(LITERAL, "literal", "*");
    let hub = DynamicHub::new("space")
        .register(SolarActivation)
        .register(BeltActivation)
        .with_auth(AuthSetup::new(Arc::new(MemoryAuthBackend::new("http://x/login")), roles.clone(), Arc::new(members), Arc::new(Everywhere)));
    let mut declared = hub.declared_roles();
    // A grant written as a literal path still decides (the slot grant is additive).
    declared.insert("literal".into(), vec!["solar.mars.rename".into()]);
    roles.seed(&declared);
    Arc::new(hub)
}

fn who(p: &str) -> AuthContext {
    AuthContext::for_principal(&p.parse().unwrap(), "s1", vec![], json!({}))
}

async fn items(stream: PlexusStream) -> Vec<Value> {
    stream
        .filter_map(|i| async move {
            match i {
                PlexusStreamItem::Data { content, .. } => Some(content.into_value()),
                PlexusStreamItem::Error { message, fields, .. } => Some(json!({ "error": message, "fields": fields })),
                _ => None,
            }
        })
        .collect()
        .await
}

/// `ok:<first item>` or `refused:<grant>`.
async fn call(hub: &DynamicHub, method: &str, params: Value, p: &str) -> String {
    match hub.route(method, params, Some(&who(p))).await {
        Ok(s) => {
            let got = items(s).await;
            match got.first() {
                Some(Value::String(s)) => format!("ok:{s}"),
                other => format!("other:{other:?}"),
            }
        }
        Err(PlexusError::Forbidden { reason: plexus_core::AuthzDenyReason::MissingGrant { grant, .. } }) => {
            format!("refused:{}", grant.as_str())
        }
        Err(e) => format!("err:{e}"),
    }
}

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
    let hub = hub();
    let rows = [
        // (method, params, who, expected)
        ("solar.earth.info", json!({}), VIEWER, "ok:planet earth"),
        ("solar.mars.info", json!({}), VIEWER, "ok:planet mars"),
        ("solar.earth.rename", json!({"to": "terra"}), VIEWER, "refused:solar.{planet}.rename"),
        // A static child named in the slot's place wins, as in routing: its own grant.
        ("solar.sun.info", json!({}), VIEWER, "refused:solar.sun.info"),
        // A nested slot: the same rule one level at a time.
        ("solar.earth.luna.phase", json!({}), VIEWER, "ok:full"),
        // An untyped slot is admitted whole.
        ("belt.ceres.info", json!({}), VIEWER, "ok:planet ceres"),
        ("belt.ceres.rename", json!({"to": "x"}), VIEWER, "ok:ceres -> x"),
        // A literal-path grant still decides as before.
        ("solar.mars.rename", json!({"to": "red"}), LITERAL, "ok:mars -> red"),
        ("solar.earth.rename", json!({"to": "terra"}), LITERAL, "refused:solar.{planet}.rename"),
    ];
    let mut bad = Vec::new();
    for (m, p, w, want) in rows {
        let got = call(&hub, m, p, w).await;
        if got != want {
            bad.push(format!("{m} as {}: want {want}, got {got}", if w == VIEWER { "viewer" } else { "literal" }));
        }
    }
    assert!(bad.is_empty(), "\n{}", bad.join("\n"));
}

/// The roles list the slot grants, qualified by the slot's path.
#[test]
fn roles_list_the_slot_grant() {
    let hub = hub();
    let declared = hub.declared_roles();
    let viewer = &declared["viewer"];
    for g in ["solar.names", "solar.{planet}.info", "solar.{planet}.{moon}.phase", "belt.{rock}"] {
        assert!(viewer.contains(&g.to_string()), "viewer lists {g}: {viewer:?}");
    }
}

/// Row 6: `auth.requires --method solar.earth.info` answers the slot grant.
#[tokio::test]
async fn auth_requires_answers_the_slot_grant() {
    let hub = hub();
    let ask = |m: &'static str| {
        let hub = hub.clone();
        async move {
            let s = hub.route("auth.requires", json!({ "method": m }), Some(&who(VIEWER))).await.expect("requires");
            items(s).await.into_iter().next().unwrap()
        }
    };
    let r = ask("solar.earth.info").await;
    assert_eq!(r["grant"], "solar.{planet}.info", "{r}");
    assert!(r["roles"].as_array().unwrap().iter().any(|x| x == "viewer"), "{r}");
    let r = ask("solar.earth.luna.phase").await;
    assert_eq!(r["grant"], "solar.{planet}.{moon}.phase", "{r}");
    let r = ask("belt.ceres.info").await;
    assert_eq!(r["grant"], "belt.{rock}", "{r}");
    let r = ask("solar.sun.info").await;
    assert_eq!(r["grant"], "solar.sun.info", "{r}");
}

/// Row 7: a caller's view keeps the slot's entry when the caller holds a
/// method of the slot.
#[test]
fn a_callers_view_keeps_the_slot() {
    let hub = hub();
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
