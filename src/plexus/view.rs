//! AUTH-4 — **the caller's view**: what a caller can discover of a gated service
//! is exactly what it can use.
//!
//! A service with a gate ([`DynamicHub::with_gate`](super::DynamicHub::with_gate))
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
//! The service's own methods (`call`, `hash`, `hashes`, `schema`) are in every
//! view: they are how a client reaches anything at all. Each activation's
//! `schema` entry stays beside its visible methods (introspection is open).
//! An activation's declared `roles` are left out of a gated view (they name
//! methods the caller may not see); `auth.roles` answers them to whoever
//! holds it.
//!
//! **Hashes.** Every schema in a view carries a hash of what *it* shows —
//! its methods (with `held_on`) and, for the service, its children's view
//! hashes — so two callers with identical holdings share a view hash, and
//! a client's schema cache (synapse keeps IR by hash) never mixes two
//! callers' views. The service's view hash is `v-anon-<hex>` for the anonymous
//! view and `v-<hex>` for a caller's. PERF-21: the service lists its children
//! by namespace, so a view hash is the same at every start of the same build,
//! and a cache keeps its schema across a restart.
//!
//! A service **without a gate** never builds a view on the wire: `_info` and
//! every schema answer exactly as before. [`DynamicHub::view`](super::DynamicHub::view)
//! there returns the whole service as a [`ViewKind::Caller`] view whose hash is
//! the service's own.
//!
//! **Kept, not rebuilt** (PERF-15). Building a view asks every activation for
//! its schema and the gate for every method — 150–520 ms on menger, on every
//! `_info`, `hash` and `schema`. A service keeps instead ([`Cache`]): what its
//! schemas show whoever asks ([`Described`]), built once per *schema
//! generation* — moved by every change to the service while it is built (a
//! mount) and by [`DynamicHub::schema_moved`](super::DynamicHub::schema_moved)
//! after; and each view of it ([`Shaped`]), built once per *view key* — the
//! caller's grants' [`Fingerprint`], or anonymous — and *grants generation*,
//! which every write that could change one of the gate's answers moves
//! (BIDIR-8). Callers holding the same share one view. A view is kept as what
//! it decided — which methods, each `held_on`, and the hashes — not as copies
//! of the schemas, and is rebuilt from [`Described`] exactly as it was built.
//! A caller's sign-in is asked whether it still stands on every ask (AUTH-11):
//! one that ended is anonymous at once.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use plexus_auth_core::grants::{Fingerprint, Gate, Grant};
use serde_json::Value;

use super::context::PlexusContext;
use super::schema::{ChildHashes, ChildSummary, MethodRole, MethodSchema, PluginHashes, PluginSchema, ViewKind};
use super::types::{PlexusStreamItem, StreamMetadata};

/// The service as one caller may see it (AUTH-4).
#[derive(Debug, Clone)]
pub struct View {
    /// Anonymous (the door only) or the caller's own.
    pub kind: ViewKind,
    /// The service's own schema in this view: its methods, and a child summary
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
    /// The schema `<ns>.schema` answers in this view: the service's own for its
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

    /// The service's `hashes` answer in this view.
    pub fn hashes(&self) -> PluginHashes {
        hashes_of(&self.schema)
    }
}

/// The service's `hashes` answer, from its schema.
#[allow(deprecated)]
fn hashes_of(service: &PluginSchema) -> PluginHashes {
    PluginHashes {
        namespace: service.namespace.clone(),
        self_hash: service.self_hash.clone(),
        children_hash: service.children_hash.clone(),
        hash: service.hash.clone(),
        children: service
            .children
            .as_ref()
            .map(|kids| kids.iter().map(|c| ChildHashes { namespace: c.namespace.clone(), hash: c.hash.clone() }).collect()),
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
    /// The caller's grants ([`Gate::fingerprint`]); `None` when anonymous.
    who: Option<&'a Fingerprint>,
    /// Grants every signed-in caller reaches (the auth activation's
    /// `whoami`, `logout`, `requires`), whatever its roles or ceiling.
    signed_in_grants: &'a BTreeSet<String>,
}

impl Asker<'_> {
    /// Whether the view keeps a method, and its `held_on` there.
    fn keep(&self, grant: &str, public: bool) -> Option<Option<Vec<String>>> {
        let Some(who) = self.who else {
            return public.then_some(None);
        };
        let held: Vec<String> = self.gate.held_on_by(who, &Grant::new(grant)).iter().map(|s| s.as_str().to_string()).collect();
        if !held.is_empty() {
            return Some(Some(held));
        }
        (public || self.signed_in_grants.contains(grant)).then_some(None)
    }
}

/// What a service's schemas show whoever asks: its own schema, every registered
/// activation's and every static child's (MACRO-20) — built once per schema
/// generation, and every view of the service is decided over it.
pub(crate) struct Described {
    /// The service's own schema ([`Activation::plugin_schema`](super::Activation::plugin_schema)).
    pub(crate) service: PluginSchema,
    /// Each registered activation's schema, in namespace order (PERF-21).
    pub(crate) activations: Vec<PluginSchema>,
    /// The static children, by their whole path — what a view reads of them.
    below: Vec<Below>,
    /// Each activation's schema without its methods — what a view's schema
    /// is rebuilt from, beside the methods it keeps.
    hollow: Vec<PluginSchema>,
    /// Introspection answers' envelopes, by method and params ([`Shell`]).
    shells: Mutex<HashMap<String, Arc<Shell>>>,
}

/// A static child (MACRO-20) as a view reads it: its whole path, and the
/// grant of each method it answers, `public` or not — not its schema, which
/// on menger is as large as `tickets.schema` itself.
struct Below {
    namespace: String,
    grants: Vec<(String, bool)>,
}

impl Below {
    fn of(child: &PluginSchema) -> Self {
        let grants = child
            .methods
            .iter()
            .filter(|m| matches!(m.role, MethodRole::Rpc) && !m.is_auto_schema())
            .map(|m| (m.grant_or(&child.namespace), m.public))
            .collect();
        Below { namespace: child.namespace.clone(), grants }
    }
}

/// At most this many envelopes are kept; past it each new one is routed
/// every time, as before PERF-15.
const SHELLS: usize = 256;

impl Described {
    pub(crate) fn new(service: PluginSchema, activations: Vec<PluginSchema>, children: Vec<PluginSchema>) -> Self {
        let hollow = activations
            .iter()
            .map(|s| {
                let mut h = s.clone();
                h.methods = Vec::new();
                h
            })
            .collect();
        let below = children.iter().map(Below::of).collect();
        Self { service, activations, below, hollow, shells: Mutex::new(HashMap::new()) }
    }

    /// The view of a service without a gate: everything, as today.
    pub(crate) fn whole(&self) -> View {
        View {
            kind: ViewKind::Caller,
            schema: self.service.clone(),
            hash: self.service.hash.clone(),
            activations: self.activations.iter().map(|s| (s.namespace.clone(), s.clone())).collect(),
        }
    }

    /// RETURNS-40: every static child's whole path (`tickets.commits`), as
    /// the service describes it — what `ir` may be asked for below an
    /// activation.
    pub(crate) fn nested(&self) -> impl Iterator<Item = &str> {
        self.below.iter().map(|b| b.namespace.as_str())
    }

    /// The envelope kept for an introspection answer (`key`: its method and params).
    pub(crate) fn shell(&self, key: &str) -> Option<Arc<Shell>> {
        self.shells.lock().unwrap_or_else(|p| p.into_inner()).get(key).cloned()
    }

    /// Keep `shell` for `key` — while there is room.
    pub(crate) fn keep_shell(&self, key: String, shell: Shell) {
        let mut shells = self.shells.lock().unwrap_or_else(|p| p.into_inner());
        if shells.len() < SHELLS {
            shells.insert(key, Arc::new(shell));
        }
    }
}

/// One caller's view, kept as what it decided over [`Described`]: the service's
/// own schema in the view (small: its methods and the kept activations'
/// summaries), and for each activation it keeps which of its methods, in the
/// order shown, each with its `held_on`, and its hashes — not a copy of the
/// schemas. [`Shaped::view`] rebuilds exactly the [`View`] it decided.
pub(crate) struct Shaped {
    pub(crate) kind: ViewKind,
    /// The view's hash ([`View::hash`]).
    pub(crate) hash: String,
    /// The service's own schema in this view ([`View::schema`]).
    pub(crate) service: PluginSchema,
    kept: BTreeMap<String, Kept>,
    /// `_info`'s content for this view, once asked.
    pub(crate) info: OnceLock<Value>,
}

/// One activation as a view keeps it.
struct Kept {
    /// Where it is in [`Described::activations`].
    at: usize,
    /// The methods shown, in order: each one's index in the activation's
    /// methods, and the `held_on` the view gives it.
    methods: Vec<(usize, Option<Vec<String>>)>,
    /// The child summaries kept (`None`: the activation lists none).
    children: Option<Vec<ChildSummary>>,
    self_hash: String,
    children_hash: Option<String>,
    hash: String,
}

impl Kept {
    /// The activation's schema as the view shows it.
    fn schema(&self, base: &Described, kind: ViewKind) -> PluginSchema {
        let source = &base.activations[self.at];
        let mut s = base.hollow[self.at].clone();
        s.methods = self.methods.iter().map(|(i, held)| Self::shown(source, *i, held)).collect();
        #[allow(deprecated)]
        {
            s.children = self.children.clone();
        }
        s.roles = BTreeMap::new();
        s.view = Some(kind);
        s.self_hash = self.self_hash.clone();
        s.children_hash = self.children_hash.clone();
        s.hash = self.hash.clone();
        s
    }

    /// The method named `name` as the view shows it, if it does.
    fn method(&self, base: &Described, name: &str) -> Option<MethodSchema> {
        let source = &base.activations[self.at];
        self.methods.iter().find(|(i, _)| source.methods[*i].name == name).map(|(i, held)| Self::shown(source, *i, held))
    }

    fn shown(source: &PluginSchema, i: usize, held: &Option<Vec<String>>) -> MethodSchema {
        let mut m = source.methods[i].clone();
        m.held_on = held.clone();
        m
    }
}

impl Shaped {
    /// The view, whole.
    pub(crate) fn view(&self, base: &Described) -> View {
        View {
            kind: self.kind,
            schema: self.service.clone(),
            hash: self.hash.clone(),
            activations: self.kept.iter().map(|(ns, k)| (ns.clone(), k.schema(base, self.kind))).collect(),
        }
    }

    /// Whether the view shows `ns`: the service's own namespace, or an activation it keeps.
    pub(crate) fn shows(&self, ns: &str) -> bool {
        ns == self.service.namespace || self.kept.contains_key(ns)
    }

    /// [`View::schema_of`]: the schema `<ns>.schema` answers in this view.
    pub(crate) fn schema_of(&self, base: &Described, ns: &str) -> Option<PluginSchema> {
        if ns == self.service.namespace {
            Some(self.service.clone())
        } else {
            self.kept.get(ns).map(|k| k.schema(base, self.kind))
        }
    }

    /// The method `name` of `ns`'s schema in this view, as it shows it.
    pub(crate) fn method_of(&self, base: &Described, ns: &str, name: &str) -> Option<MethodSchema> {
        if ns == self.service.namespace {
            self.service.methods.iter().find(|m| m.name == name).cloned()
        } else {
            self.kept.get(ns)?.method(base, name)
        }
    }

    /// [`View::public_methods`].
    pub(crate) fn public_methods(&self, base: &Described) -> Vec<String> {
        self.kept
            .values()
            .flat_map(|k| {
                let source = &base.activations[k.at];
                k.methods.iter().map(|(i, _)| &source.methods[*i]).filter(|m| m.public).map(|m| m.grant_or(&source.namespace))
            })
            .collect()
    }

    /// [`View::hashes`].
    pub(crate) fn hashes(&self) -> PluginHashes {
        hashes_of(&self.service)
    }
}

/// One activation as the view keeps it, or `None` when it keeps no method
/// of it.
fn activation_view(asker: &Asker<'_>, kind: ViewKind, base: &Described, at: usize) -> Option<Kept> {
    let schema = &base.activations[at];
    let ns = &schema.namespace;
    let mut kept = Vec::new();
    let mut schema_entry = None;
    for (i, m) in schema.methods.iter().enumerate() {
        let is_schema_entry = m.is_auto_schema();
        if is_schema_entry {
            schema_entry = Some((i, m.held_on.clone()));
            continue;
        }
        // MACRO-20: a static child's entry (`tickets.commits`) names no
        // method of its own; it stays when the caller can use a method
        // somewhere below it (`tickets.commits.link`), so the caller can
        // navigate to what it holds.
        // A child that describes nothing (a hand-written router) is
        // decided as before, by the entry's own grant.
        if matches!(m.role, MethodRole::StaticChild) {
            if let Some(reached) = reaches_below(asker, &format!("{ns}.{}", m.name), &base.below) {
                if reached {
                    kept.push((i, None));
                }
                continue;
            }
        }
        let grant = m.grant_or(ns);
        if let Some(held) = asker.keep(&grant, m.public) {
            kept.push((i, held));
        }
    }
    if kept.is_empty() {
        return None;
    }
    kept.extend(schema_entry);
    // A child summary names a nested router; it stays only when the
    // method that reaches it does.
    let names: BTreeSet<&str> = kept.iter().map(|(i, _)| schema.methods[*i].name.as_str()).collect();
    #[allow(deprecated)]
    let children = schema
        .children
        .as_ref()
        .map(|kids| kids.iter().filter(|c| names.contains(c.namespace.as_str())).cloned().collect());
    let mut k = Kept { at, methods: kept, children, self_hash: String::new(), children_hash: None, hash: String::new() };
    let mut shown = k.schema(base, kind);
    rehash(&mut shown, None);
    (k.self_hash, k.children_hash, k.hash) = (shown.self_hash, shown.children_hash, shown.hash);
    Some(k)
}

/// MACRO-20: whether the caller can use a method of a static child at
/// `path` or of one below it (`children`: the service's qualified static
/// children, [`super::children`], as [`Below`]).
/// `None` when no child at `path` describes itself.
fn reaches_below(asker: &Asker<'_>, path: &str, children: &[Below]) -> Option<bool> {
    let below = format!("{path}.");
    let mut known = children.iter().filter(|c| c.namespace == path || c.namespace.starts_with(&below)).peekable();
    known.peek()?;
    Some(known.flat_map(|c| c.grants.iter()).any(|(grant, public)| asker.keep(grant, *public).is_some()))
}

/// Recompute `self_hash`, `children_hash` and `hash` over what the schema
/// shows. `prefix` marks the service's view hash.
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

/// Decide the view of a gated service for whoever has `who` (`None`:
/// anonymous) over what the service describes.
pub(crate) fn shape(gate: &Gate, signed_in_grants: &BTreeSet<String>, who: Option<&Fingerprint>, base: &Described) -> Shaped {
    let kind = if who.is_some() { ViewKind::Caller } else { ViewKind::Anonymous };
    let asker = Asker { gate, who, signed_in_grants };

    let kept: BTreeMap<String, Kept> = (0..base.activations.len())
        .filter_map(|at| activation_view(&asker, kind, base, at))
        .map(|k| (base.activations[k.at].namespace.clone(), k))
        .collect();

    let mut service = base.service.clone();
    #[allow(deprecated)]
    {
        let mut children: Vec<ChildSummary> = service.children.take().unwrap_or_default();
        children.retain(|c| kept.contains_key(&c.namespace));
        for c in children.iter_mut() {
            c.hash = kept[&c.namespace].hash.clone();
        }
        service.children = Some(children);
    }
    // The service's own methods are how a client reaches anything: in every view.
    for m in service.methods.iter_mut() {
        m.held_on = None;
    }
    service.roles = BTreeMap::new();
    service.view = Some(kind);
    rehash(&mut service, Some(if who.is_some() { "v-" } else { "v-anon-" }));
    let hash = service.hash.clone();
    Shaped { kind, hash, service, kept, info: OnceLock::new() }
}

// ---------------------------------------------------------------------------
// PERF-15: the cache
// ---------------------------------------------------------------------------

/// At most this many views are kept at once; past it the kept views are
/// dropped and built again as they are asked.
const VIEWS: usize = 1024;

/// A service's self-description cache: what its schemas show ([`Described`]),
/// kept for the schema generation it was built at, and each view of it
/// ([`Shaped`]), kept for its key — the caller's [`Fingerprint`], or `None`
/// for anonymous — and the grants generation it was decided at. A
/// generation that moves drops what was kept for the one before; a reader
/// that read a generation older than the cache's builds its own and keeps
/// nothing. Each entry is built once, by its first asker.
#[derive(Default)]
pub(crate) struct Cache {
    /// Moved by [`Cache::schema_moved`]: something the service describes changed.
    schema_generation: AtomicU64,
    state: Mutex<State>,
}

type Cell<T> = Arc<OnceLock<Arc<T>>>;

#[derive(Default)]
struct State {
    /// The schema generation `base` and `views` are for.
    schema_at: u64,
    /// The grants generation `views` are for.
    grants_at: u64,
    base: Cell<Described>,
    views: HashMap<Option<Fingerprint>, Cell<Shaped>>,
}

impl Cache {
    /// The schema generation now.
    pub(crate) fn schema_generation(&self) -> u64 {
        self.schema_generation.load(Ordering::Acquire)
    }

    /// Something the service describes changed: what was kept is dropped at the next ask.
    pub(crate) fn schema_moved(&self) {
        self.schema_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// The service is changed while it is built: nothing kept stands.
    pub(crate) fn reset(&mut self) {
        let next = self.schema_generation.get_mut().wrapping_add(1);
        *self = Cache { schema_generation: AtomicU64::new(next), state: Mutex::new(State { schema_at: next, ..State::default() }) };
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cell for what the service describes at `schema_at`; `None` for a
    /// stale reader.
    pub(crate) fn base(&self, schema_at: u64) -> Option<Cell<Described>> {
        let mut st = self.state();
        if schema_at < st.schema_at {
            return None;
        }
        if schema_at > st.schema_at {
            *st = State { schema_at, grants_at: st.grants_at, ..State::default() };
        }
        Some(st.base.clone())
    }

    /// The cells for what the service describes at `schema_at` and for `who`'s
    /// view of it at `grants_at`; `None` for a stale reader.
    pub(crate) fn view(&self, schema_at: u64, grants_at: u64, who: &Option<Fingerprint>) -> Option<(Cell<Described>, Cell<Shaped>)> {
        let mut st = self.state();
        if schema_at < st.schema_at || grants_at < st.grants_at {
            return None;
        }
        if schema_at > st.schema_at {
            *st = State { schema_at, grants_at, ..State::default() };
        } else if grants_at > st.grants_at {
            st.grants_at = grants_at;
            st.views.clear();
        }
        let cell = match st.views.get(who) {
            Some(cell) => cell.clone(),
            None => {
                if st.views.len() >= VIEWS {
                    st.views.clear();
                }
                st.views.entry(who.clone()).or_default().clone()
            }
        };
        Some((st.base.clone(), cell))
    }
}

// ---------------------------------------------------------------------------
// PERF-15: an introspection answer's envelope
// ---------------------------------------------------------------------------

/// Everything an introspection answer carries but its content and its
/// clock: each item's kind, provenance, `plexus_hash` and content type —
/// learned from the one answer routed for its method and params, and
/// carrying the view's content after. Only an answer of `data` and `done`
/// items has one; any other is routed every time, as before.
pub(crate) struct Shell(Vec<ShellItem>);

enum ShellItem {
    Data { provenance: Vec<String>, plexus_hash: HashOf, content_type: std::borrow::Cow<'static, str> },
    Done { provenance: Vec<String>, plexus_hash: HashOf },
}

/// An item's `plexus_hash`: the process's own ([`PlexusContext::hash`], read
/// when the answer is made, as the item read it), or another it carried.
enum HashOf {
    Context,
    Carried(String),
}

impl HashOf {
    fn of(carried: &str, context: &str) -> Self {
        if carried == context {
            HashOf::Context
        } else {
            HashOf::Carried(carried.to_string())
        }
    }

    fn now(&self, context: &str) -> String {
        match self {
            HashOf::Context => context.to_string(),
            HashOf::Carried(h) => h.clone(),
        }
    }
}

impl Shell {
    /// The envelope of `items`, a routed answer; `None` unless every item
    /// is `data` or `done`.
    pub(crate) fn of(items: &[PlexusStreamItem]) -> Option<Self> {
        let context = PlexusContext::hash();
        items
            .iter()
            .map(|item| match item {
                PlexusStreamItem::Data { metadata, content_type, .. } => Some(ShellItem::Data {
                    provenance: metadata.provenance.clone(),
                    plexus_hash: HashOf::of(&metadata.plexus_hash, &context),
                    content_type: content_type.clone(),
                }),
                PlexusStreamItem::Done { metadata } => Some(ShellItem::Done {
                    provenance: metadata.provenance.clone(),
                    plexus_hash: HashOf::of(&metadata.plexus_hash, &context),
                }),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(Shell)
    }

    /// The answer: these items, `content` in each `data` one (moved into the
    /// last, cloned for any before it), stamped now.
    pub(crate) fn answer(&self, content: Value) -> Vec<PlexusStreamItem> {
        let (context, timestamp) = (PlexusContext::hash(), chrono::Utc::now().timestamp());
        let meta = |provenance: &Vec<String>, hash: &HashOf| StreamMetadata {
            provenance: provenance.clone(),
            plexus_hash: hash.now(&context),
            timestamp,
        };
        let last = self.0.iter().rposition(|item| matches!(item, ShellItem::Data { .. }));
        let mut content = Some(content);
        self.0
            .iter()
            .enumerate()
            .map(|(at, item)| match item {
                ShellItem::Data { provenance, plexus_hash, content_type } => PlexusStreamItem::Data {
                    metadata: meta(provenance, plexus_hash).into(),
                    content_type: content_type.clone(),
                    content: if Some(at) == last { content.take() } else { content.clone() }.unwrap_or_default().into(),
                },
                ShellItem::Done { provenance, plexus_hash } => PlexusStreamItem::Done { metadata: meta(provenance, plexus_hash) },
            })
            .collect()
    }
}
