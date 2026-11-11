//! NEST-5 — **a dynamic child's slot is described and granted once.**
//!
//! A dynamic child (`#[child] fn planet(&self, name: &str) -> Option<Planet>`)
//! hangs in a *slot*: its parent's path plus the child function's name,
//! written `solar.{planet}`. Its names are open (known only at call time),
//! but its shape is fixed when its code compiles, so the parent's schema
//! carries the slot's type (`MethodRole::DynamicChild { child }`: `Planet`'s
//! schema) and the hub grants the slot once:
//!
//! | the slot | its grant | decides |
//! |---|---|---|
//! | typed (`child` set) | `solar.{planet}.info` | `info` on every name in the slot |
//! | untyped (`#[child(opaque)]`, a hand-written router) | `solar.{planet}` | every method on every name, the child deciding again |
//!
//! A call to `solar.earth.info` matches the slot `solar.{planet}` (a static
//! child named `earth` still wins, as in routing) and is decided on
//! `solar.{planet}.info`. A nested slot is the same rule one level at a time
//! (`solar.{planet}.{moon}.info`). A grant written as a literal path
//! (`solar.earth.info`) still decides as before: the slot grant is additive —
//! it applies only where the gate would otherwise know nothing of the path.
//!
//! [`slot_schemas`] turns a schema's slots into schemas the hub treats like a
//! static child's ([`super::children`]): namespace the slot's path, every
//! grant (methods' and roles') qualified by it — so the grant gate's index,
//! [`DynamicHub::declared_roles`](super::DynamicHub::declared_roles),
//! `auth.requires` and the caller's view all read a slot as they read a
//! static child. [`Slots`] resolves a literal path to its slot's.

use std::collections::{HashMap, HashSet};

use super::children::qualified;
use super::schema::{MethodRole, PluginSchema};

/// A slot's path: `parent.{slot}`.
pub fn slot_path(parent: &str, slot: &str) -> String {
    format!("{parent}.{{{slot}}}")
}

/// How deep [`slot_schemas`] follows a slot's type into its own slots — a
/// bound, not a rule: a type that names itself stops at its first repeat
/// already (the macro gives the repeat no type).
const MAX_DEPTH: usize = 8;

/// Every slot below `schema` (whose namespace is its whole path,
/// `tickets` or `tickets.commits`), to any depth: each typed slot as a
/// schema whose namespace is the slot's path (`tickets.{item}`) and whose
/// grants are qualified by it, and each untyped slot's path in `untyped`.
pub fn slot_schemas(schema: &PluginSchema, typed: &mut Vec<PluginSchema>, untyped: &mut Vec<String>) {
    walk(schema, typed, untyped, 0);
}

fn walk(schema: &PluginSchema, typed: &mut Vec<PluginSchema>, untyped: &mut Vec<String>, depth: usize) {
    if depth >= MAX_DEPTH {
        return;
    }
    for m in &schema.methods {
        if !m.role.is_slot() {
            continue;
        }
        let rel = format!("{{{}}}", m.name);
        match m.role.slot_schema() {
            Some(child) => {
                for q in qualified(&schema.namespace, vec![(rel, child)]) {
                    walk(&q, typed, untyped, depth + 1);
                    typed.push(q);
                }
            }
            None => untyped.push(slot_path(&schema.namespace, &m.name)),
        }
    }
}

std::thread_local! {
    /// The method enums whose schemas this thread is computing: a slot
    /// whose type is one of them (a type that names itself, or two that name
    /// each other) is published untyped there, not recursed into.
    static BUILDING: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Held while a method enum's schemas are computed (the macro's
/// `compute_method_schemas`); see [`slot_type`].
#[doc(hidden)]
pub struct Building(());

impl Drop for Building {
    fn drop(&mut self) {
        BUILDING.with(|b| {
            b.borrow_mut().pop();
        });
    }
}

/// Mark `name` (a method enum's `type_name`) as being computed on this
/// thread until the guard drops.
#[doc(hidden)]
pub fn building(name: &'static str) -> Building {
    BUILDING.with(|b| b.borrow_mut().push(name));
    Building(())
}

/// NEST-5: the slot type of a dynamic child whose type is `T` — `T`'s own
/// schema, without an instance ([`Activation::slot_schema`]). `None` when
/// `T`'s schemas are being computed on this thread already (a recursive
/// type: the repeat is an untyped slot), or `T` was not written by the
/// macro.
///
/// [`Activation::slot_schema`]: super::Activation::slot_schema
pub fn slot_type<T: super::Activation>() -> Option<Box<PluginSchema>> {
    let name = std::any::type_name::<<T as super::Activation>::Methods>();
    if BUILDING.with(|b| b.borrow().contains(&name)) {
        return None;
    }
    T::slot_schema().map(Box::new)
}

/// The slots of a service, for resolving a literal path to its slot's.
#[derive(Debug, Default, Clone)]
pub struct Slots {
    /// A parent's dynamic child (reached as `parent.<name>`): its slot's
    /// name and whether it is typed.
    by_parent: HashMap<String, (String, bool)>,
    /// NEST-7: a parent's peer slots (reached as `parent.<slot>.<name>`), by
    /// slot name: whether each is typed.
    peers: HashMap<(String, String), bool>,
    /// Every path the service describes: activations, static children and
    /// slots (`tickets.{item}`) — a literal segment that names one wins.
    known: HashSet<String>,
}

impl Slots {
    /// The slots of `schemas` (each namespace its whole path: activations,
    /// static children, typed slots) and of the untyped slots' paths.
    pub fn of<'a>(schemas: impl IntoIterator<Item = &'a PluginSchema>, untyped: &[String]) -> Self {
        let mut s = Slots::default();
        for schema in schemas {
            s.add(schema);
        }
        for u in untyped {
            s.add_untyped(u);
        }
        s
    }

    /// Add one schema's slots (its namespace its whole path).
    pub fn add(&mut self, schema: &PluginSchema) {
        self.known.insert(schema.namespace.clone());
        for m in &schema.methods {
            let typed = m.role.slot_schema().is_some();
            match &m.role {
                MethodRole::Peer { .. } => {
                    self.peers.insert((schema.namespace.clone(), m.name.clone()), typed);
                }
                MethodRole::DynamicChild { .. } => {
                    self.by_parent.entry(schema.namespace.clone()).or_insert((m.name.clone(), typed));
                }
                _ => {}
            }
        }
    }

    /// Add an untyped slot's path (`tickets.{item}`).
    pub fn add_untyped(&mut self, path: &str) {
        self.known.insert(path.to_string());
    }

    /// ONE-7: whether the slot at `path` (`dyn.{peer}`) is an untyped peer
    /// slot — a `#[peer]` slot whose names route on into another service, so
    /// no data of this one is reached through it: the gate decides it at the
    /// door of the call dispatched. A typed peer slot, and a dynamic child's
    /// slot of either kind, are not.
    pub fn is_untyped_peer_slot(&self, path: &str) -> bool {
        let Some((parent, slot)) = path.strip_suffix('}').and_then(|p| p.rsplit_once(".{")) else { return false };
        self.peers.get(&(parent.to_string(), slot.to_string())) == Some(&false)
    }

    /// Whether no slot is known.
    pub fn is_empty(&self) -> bool {
        self.by_parent.is_empty() && self.peers.is_empty()
    }

    /// The slot grant's key for the literal `method` (`solar.earth.info` →
    /// `solar.{planet}.info`; a peer slot's `host.integration.github.repos`
    /// → `host.{integration}.repos`; through an untyped slot, the slot
    /// itself, `solar.{planet}`), or `None` when no slot is on its way — a
    /// static child that names a segment wins over the slot.
    pub fn resolve(&self, method: &str) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let segs: Vec<&str> = method.split('.').collect();
        if segs.len() < 3 {
            return None;
        }
        let last = segs.len() - 1;
        let mut cur = segs[0].to_string();
        let mut through = false;
        let mut i = 1;
        while i < last {
            let seg = segs[i];
            let literal = format!("{cur}.{seg}");
            if self.known.contains(&literal) {
                cur = literal;
                i += 1;
                continue;
            }
            // NEST-7: a peer slot is named in the path, then the peer's name.
            if let Some(typed) = self.peers.get(&(cur.clone(), seg.to_string())) {
                if i + 1 >= last {
                    return None;
                }
                cur = slot_path(&cur, seg);
                through = true;
                i += 2;
                if !typed {
                    return Some(cur);
                }
                continue;
            }
            let (slot, typed) = self.by_parent.get(&cur)?;
            cur = slot_path(&cur, slot);
            through = true;
            i += 1;
            if !typed {
                return Some(cur);
            }
        }
        through.then(|| format!("{cur}.{}", segs[last]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plexus::schema::{MethodSchema, PluginSchema};

    fn planet() -> PluginSchema {
        let mut p = PluginSchema::leaf(
            "planet",
            "1.0",
            "a planet",
            vec![MethodSchema::new("info", "d", "h"), MethodSchema::new("rename", "d", "h")],
        );
        p.roles.insert("viewer".into(), vec!["planet.info".into()]);
        p
    }

    fn solar(typed: bool) -> PluginSchema {
        let role = MethodRole::DynamicChild {
            list_method: Some("names".into()),
            search_method: None,
            child: typed.then(|| Box::new(planet())),
        };
        PluginSchema::leaf(
            "solar",
            "1.0",
            "the system",
            vec![MethodSchema::new("names", "d", "h"), MethodSchema::new("planet", "d", "h").with_role(role)],
        )
    }

    #[test]
    fn a_typed_slot_is_a_schema_at_its_path() {
        let (mut typed, mut untyped) = (vec![], vec![]);
        slot_schemas(&solar(true), &mut typed, &mut untyped);
        assert!(untyped.is_empty());
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].namespace, "solar.{planet}");
        let grants: Vec<_> = typed[0].methods.iter().map(|m| m.grant.clone().unwrap()).collect();
        assert_eq!(grants, ["solar.{planet}.info", "solar.{planet}.rename"]);
        assert_eq!(typed[0].roles["viewer"], ["solar.{planet}.info"]);
    }

    #[test]
    fn an_untyped_slot_is_its_path() {
        let (mut typed, mut untyped) = (vec![], vec![]);
        slot_schemas(&solar(false), &mut typed, &mut untyped);
        assert!(typed.is_empty());
        assert_eq!(untyped, ["solar.{planet}"]);
    }

    #[test]
    fn a_literal_path_resolves_to_its_slot_and_a_static_child_wins() {
        let (mut typed, mut untyped) = (vec![], vec![]);
        let s = solar(true);
        slot_schemas(&s, &mut typed, &mut untyped);
        let mut moons = PluginSchema::leaf("solar.luna", "1.0", "a static child", vec![]);
        moons.methods.push(MethodSchema::new("info", "d", "h"));
        let all: Vec<PluginSchema> = vec![s, moons].into_iter().chain(typed).collect();
        let slots = Slots::of(all.iter(), &untyped);
        assert_eq!(slots.resolve("solar.earth.info").as_deref(), Some("solar.{planet}.info"));
        assert_eq!(slots.resolve("solar.luna.info"), None, "a static child wins");
        assert_eq!(slots.resolve("solar.names"), None);
        assert_eq!(slots.resolve("other.earth.info"), None);
    }

    #[test]
    fn an_untyped_slot_resolves_to_the_slot_whole() {
        let (mut typed, mut untyped) = (vec![], vec![]);
        let s = solar(false);
        slot_schemas(&s, &mut typed, &mut untyped);
        let slots = Slots::of([&s], &untyped);
        assert_eq!(slots.resolve("solar.earth.info").as_deref(), Some("solar.{planet}"));
        assert_eq!(slots.resolve("solar.earth.deep.er").as_deref(), Some("solar.{planet}"));
    }

    #[test]
    fn a_nested_slot_is_the_same_rule_one_level_at_a_time() {
        let moon = PluginSchema::leaf("moon", "1.0", "a moon", vec![MethodSchema::new("phase", "d", "h")]);
        let mut p = planet();
        p.methods.push(MethodSchema::new("moon", "d", "h").with_role(MethodRole::DynamicChild {
            list_method: None,
            search_method: None,
            child: Some(Box::new(moon)),
        }));
        let s = PluginSchema::leaf(
            "solar",
            "1.0",
            "the system",
            vec![MethodSchema::new("planet", "d", "h").with_role(MethodRole::DynamicChild {
                list_method: None,
                search_method: None,
                child: Some(Box::new(p)),
            })],
        );
        let (mut typed, mut untyped) = (vec![], vec![]);
        slot_schemas(&s, &mut typed, &mut untyped);
        let names: Vec<_> = typed.iter().map(|t| t.namespace.as_str()).collect();
        assert_eq!(names, ["solar.{planet}.{moon}", "solar.{planet}"]);
        assert_eq!(typed[0].methods[0].grant.as_deref(), Some("solar.{planet}.{moon}.phase"));
        let all: Vec<PluginSchema> = std::iter::once(s).chain(typed).collect();
        let slots = Slots::of(all.iter(), &untyped);
        assert_eq!(slots.resolve("solar.earth.luna.phase").as_deref(), Some("solar.{planet}.{moon}.phase"));
    }
}
