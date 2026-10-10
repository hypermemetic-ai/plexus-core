//! AUTH-4 — **the caller's view**: what a caller can discover of a gated hub
//! is exactly what it can use.
//!
//! A hub with a gate ([`DynamicHub::with_gate`](super::DynamicHub::with_gate))
//! answers `_info`, its own `schema` / `hash` / `hashes`, and every
//! `<activation>.schema` from the caller's [`View`]:
//!
//! - **anonymous** (no principal): only the `public` methods — the auth
//!   activation's door (`auth.providers`, `auth.login`, `auth.signup`);
//! - **caller** (signed in): only the methods whose grant some role the
//!   caller holds lists (within its session's ceiling), each with `held_on`
//!   — where it is held; plus the public methods, and the methods every
//!   signed-in caller reaches (the auth activation's `whoami`, `logout`,
//!   `requires`). A method the caller cannot use is **absent**, not marked;
//!   an activation left with none is absent too.
//!
//! The hub's own methods (`call`, `hash`, `hashes`, `schema`) are in every
//! view: they are how a client reaches anything at all. Each activation's
//! `schema` entry stays beside its visible methods (introspection is open).
//! An activation's declared `roles` are left out of a gated view (they name
//! methods the caller may not see); `auth.roles` answers them to whoever
//! holds it.
//!
//! **Hashes.** Every schema in a view carries a hash of what *it* shows —
//! its methods (with `held_on`) and, for the hub, its children's view
//! hashes — so two callers with identical holdings share a view hash, and
//! a client's schema cache (synapse keeps IR by hash) never mixes two
//! callers' views. The hub's view hash is `v-anon-<hex>` for the anonymous
//! view and `v-<hex>` for a caller's.
//!
//! A hub **without a gate** never builds a view on the wire: `_info` and
//! every schema answer exactly as before. [`DynamicHub::view`](super::DynamicHub::view)
//! there returns the whole hub as a [`ViewKind::Caller`] view whose hash is
//! the hub's own.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use plexus_auth_core::grants::{Gate, Grant};

use super::auth::AuthContext;
use super::schema::{ChildHashes, ChildSummary, MethodRole, PluginHashes, PluginSchema, ViewKind};

/// The hub as one caller may see it (AUTH-4).
#[derive(Debug, Clone)]
pub struct View {
    /// Anonymous (the door only) or the caller's own.
    pub kind: ViewKind,
    /// The hub's own schema in this view: its methods, and a child summary
    /// for each activation the view keeps, carrying that activation's view
    /// hash. `hash` is the view's hash.
    pub schema: PluginSchema,
    /// The view's hash: deterministic over what the view shows.
    pub hash: String,
    /// Each activation the view keeps, by namespace, as its
    /// `<ns>.schema` answers in this view.
    pub activations: BTreeMap<String, PluginSchema>,
}

impl View {
    /// The schema `<ns>.schema` answers in this view: the hub's own for its
    /// namespace, else the activation's — `None` when the view does not
    /// show it.
    pub fn schema_of(&self, ns: &str) -> Option<&PluginSchema> {
        if ns == self.schema.namespace {
            Some(&self.schema)
        } else {
            self.activations.get(ns)
        }
    }

    /// The grants of the `public` methods this view shows, activation by
    /// activation (in namespace order), each in declaration order —
    /// `_info`'s `auth.methods` for an anonymous caller.
    pub fn public_methods(&self) -> Vec<String> {
        self.activations
            .values()
            .flat_map(|s| {
                let ns = s.namespace.clone();
                s.methods.iter().filter(|m| m.public).map(move |m| m.grant_or(&ns)).collect::<Vec<_>>()
            })
            .collect()
    }

    /// The hub's `hashes` answer in this view.
    #[allow(deprecated)]
    pub fn hashes(&self) -> PluginHashes {
        PluginHashes {
            namespace: self.schema.namespace.clone(),
            self_hash: self.schema.self_hash.clone(),
            children_hash: self.schema.children_hash.clone(),
            hash: self.schema.hash.clone(),
            children: self
                .schema
                .children
                .as_ref()
                .map(|kids| kids.iter().map(|c| ChildHashes { namespace: c.namespace.clone(), hash: c.hash.clone() }).collect()),
        }
    }
}

/// A stable 64-bit digest of `value`'s JSON, as 16 hex digits. The JSON of
/// a schema is deterministic (struct fields in order; maps sorted), so equal
/// views digest equally.
fn digest(value: &impl serde::Serialize) -> String {
    let text = serde_json::to_string(value).unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// What the gate needs to say about one caller, computed once per view.
struct Asker<'a> {
    gate: &'a Gate,
    caller: Option<&'a AuthContext>,
    signed_in: bool,
    /// Grants every signed-in caller reaches (the auth activation's
    /// `whoami`, `logout`, `requires`), whatever its roles or ceiling.
    signed_in_grants: &'a BTreeSet<String>,
}

impl Asker<'_> {
    /// Whether the view keeps a method, and its `held_on` there.
    fn keep(&self, grant: &str, public: bool) -> Option<Option<Vec<String>>> {
        if !self.signed_in {
            return public.then_some(None);
        }
        let caller = self.caller.expect("signed in");
        let held: Vec<String> =
            self.gate.held_on(caller, &Grant::new(grant)).iter().map(|s| s.as_str().to_string()).collect();
        if !held.is_empty() {
            return Some(Some(held));
        }
        (public || self.signed_in_grants.contains(grant)).then_some(None)
    }
}

/// One activation's schema as the view shows it, or `None` when it keeps
/// no method of it.
fn activation_view(asker: &Asker<'_>, kind: ViewKind, mut schema: PluginSchema) -> Option<PluginSchema> {
    let ns = schema.namespace.clone();
    let mut kept = Vec::new();
    let mut schema_entry = None;
    for mut m in std::mem::take(&mut schema.methods) {
        let is_schema_entry = m.name == "schema" && matches!(m.role, MethodRole::Rpc) && m.hash == "auto_schema";
        if is_schema_entry {
            schema_entry = Some(m);
            continue;
        }
        let grant = m.grant_or(&ns);
        if let Some(held) = asker.keep(&grant, m.public) {
            m.held_on = held;
            kept.push(m);
        }
    }
    if kept.is_empty() {
        return None;
    }
    kept.extend(schema_entry);
    schema.methods = kept;
    #[allow(deprecated)]
    if let Some(children) = schema.children.as_mut() {
        // A child summary names a nested router; it stays only when the
        // method that reaches it does.
        let names: BTreeSet<&str> = schema.methods.iter().map(|m| m.name.as_str()).collect();
        children.retain(|c| names.contains(c.namespace.as_str()));
    }
    schema.roles = BTreeMap::new();
    schema.view = Some(kind);
    rehash(&mut schema, None);
    Some(schema)
}

/// Recompute `self_hash`, `children_hash` and `hash` over what the schema
/// shows. `prefix` marks the hub's view hash.
#[allow(deprecated)]
fn rehash(schema: &mut PluginSchema, prefix: Option<&str>) {
    schema.self_hash = String::new();
    schema.children_hash = None;
    schema.hash = String::new();
    let self_hash = digest(&(&schema.namespace, &schema.methods, &schema.view));
    let children_hash = schema.children.as_ref().map(|kids| digest(kids));
    let composite = digest(&(&self_hash, &children_hash, &*schema));
    schema.self_hash = self_hash;
    schema.children_hash = children_hash;
    schema.hash = match prefix {
        Some(p) => format!("{p}{composite}"),
        None => composite,
    };
}

/// Build the view of a gated hub. `hub` is the hub's own schema (its
/// methods and child summaries), `activations` every registered
/// activation's schema.
pub(crate) fn build(
    gate: &Gate,
    signed_in_grants: &BTreeSet<String>,
    caller: Option<&AuthContext>,
    mut hub: PluginSchema,
    activations: Vec<PluginSchema>,
) -> View {
    let signed_in = caller.and_then(|c| c.principal()).is_some();
    let kind = if signed_in { ViewKind::Caller } else { ViewKind::Anonymous };
    let asker = Asker { gate, caller: if signed_in { caller } else { None }, signed_in, signed_in_grants };

    let kept: BTreeMap<String, PluginSchema> = activations
        .into_iter()
        .filter_map(|s| activation_view(&asker, kind, s))
        .map(|s| (s.namespace.clone(), s))
        .collect();

    #[allow(deprecated)]
    {
        let mut children: Vec<ChildSummary> = hub.children.take().unwrap_or_default();
        children.retain(|c| kept.contains_key(&c.namespace));
        for c in children.iter_mut() {
            c.hash = kept[&c.namespace].hash.clone();
        }
        hub.children = Some(children);
    }
    // The hub's own methods are how a client reaches anything: in every view.
    for m in hub.methods.iter_mut() {
        m.held_on = None;
    }
    hub.roles = BTreeMap::new();
    hub.view = Some(kind);
    rehash(&mut hub, Some(if signed_in { "v-" } else { "v-anon-" }));
    let hash = hub.hash.clone();
    View { kind, schema: hub, hash, activations: kept }
}

/// The view of a hub without a gate: everything, as today.
pub(crate) fn whole(hub: PluginSchema, activations: Vec<PluginSchema>) -> View {
    let hash = hub.hash.clone();
    View {
        kind: ViewKind::Caller,
        schema: hub,
        hash,
        activations: activations.into_iter().map(|s| (s.namespace.clone(), s)).collect(),
    }
}
