//! The builder: synapse's `Synapse.IR.Builder`, ported — a plugin's types
//! and methods read from its schema (one title, one shape: else the build
//! fails), the walk's fold over a node and its children, and the IR made
//! whole: identical types in different namespaces deduplicated, each placed
//! where it is referred to most, every ref that names no type turned to
//! `RefUnknown`, the refusals deduplicated and sorted by site.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{Map, Value};

use super::read::{self, Doc, Reader};
use super::schema::{self, MethodIn, PluginIn};
use super::types::*;

/// Where a type was read: a method, and which of its schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeSource {
    pub method: String,
    /// `params`, `returns`, `error`, `progress` or `input`.
    pub schema: String,
}

/// Why no IR can be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrBuildError {
    /// Two different shapes carry one name in one namespace (RETURNS-13):
    /// a conflict the activation's author resolves; the IR never picks one.
    /// Only [`build_one`] fails so; [`build`]'s walk refuses that activation.
    TitleCollision { namespace: String, title: String, first: TypeSource, second: TypeSource },
    /// A walk's root no schema was given for.
    MissingSchema { path: Vec<String> },
    /// A walk's root whose schema synapse could not read.
    Unreadable { path: Vec<String>, detail: String },
}

fn show_path(path: &[String]) -> String {
    if path.is_empty() {
        "the root".into()
    } else {
        path.join(".")
    }
}

/// synapse's `renderIRBuildError`, word for word.
impl std::fmt::Display for IrBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrBuildError::TitleCollision { namespace, title, first, second } => {
                let ns = if namespace.is_empty() { "(root)".to_string() } else { format!("\"{namespace}\"") };
                write!(
                    f,
                    "IR: two different types are titled \"{title}\" in namespace {ns}: method {} ({}) and method {} ({}). One title in one namespace is one type; rename one of them.",
                    first.method, first.schema, second.method, second.schema
                )
            }
            IrBuildError::MissingSchema { path } => write!(f, "IR: no schema at {}", show_path(path)),
            IrBuildError::Unreadable { path, detail } => write!(f, "IR: the schema at {} is unreadable: {detail}", show_path(path)),
        }
    }
}

impl std::error::Error for IrBuildError {}

/// The IR of one plugin schema at `path`, children aside (synapse's
/// `buildIRFromSchema`).
pub fn build_one(backend: &str, path: &[String], schema: &Value) -> Result<Ir, IrBuildError> {
    let parsed = schema::plugin(schema).map_err(|detail| IrBuildError::Unreadable { path: path.to_vec(), detail })?;
    let raw = plugin_ir(path, &parsed, vec![])?;
    Ok(Ir { backend: backend.into(), ..finalize(raw) })
}

/// What synapse's walk builds from each of `roots`, every schema it would
/// fetch given by path (the root at `[]`): a node's IR from its schema and
/// its children's (in its `children` order; a child with no schema, or one
/// synapse could not read, skipped as a walk skips a failed fetch; one whose
/// schemas put two shapes under one title refused, not the walk), each
/// root's merged left to right, then made whole (synapse's
/// `buildIRFromSchemas`). Only a root with no schema, or one that cannot be
/// read, fails.
pub fn build(backend: &str, roots: &[Vec<String>], schemas: &BTreeMap<Vec<String>, Value>) -> Result<Ir, IrBuildError> {
    let mut irs = Vec::new();
    for root in roots {
        let schema = schemas.get(root).ok_or_else(|| IrBuildError::MissingSchema { path: root.clone() })?;
        let parsed = schema::plugin(schema).map_err(|detail| IrBuildError::Unreadable { path: root.clone(), detail })?;
        irs.push(walk(root, &parsed, schemas)?);
    }
    let raw = irs.into_iter().rev().fold(Ir::empty(), |acc, ir| merge(ir, acc));
    Ok(Ir { backend: backend.into(), ..finalize(raw) })
}

fn walk(path: &[String], schema: &PluginIn<'_>, schemas: &BTreeMap<Vec<String>, Value>) -> Result<Ir, IrBuildError> {
    let mut child_irs = Vec::new();
    for ns in schema.children.iter().flatten() {
        let mut child = path.to_vec();
        child.push(ns.clone());
        let Some(v) = schemas.get(&child) else { continue };
        let Ok(parsed) = schema::plugin(v) else { continue };
        child_irs.push(walk(&child, &parsed, schemas)?);
    }
    Ok(plugin_ir_refusing(path, schema, child_irs))
}

/// synapse's `pluginIRRefusing` (RETURNS-36 review #9): one node as the
/// walk builds it. A plugin whose schemas put two shapes under one title is
/// refused, not the walk: its methods and types are left out, a `title`
/// refusal at its namespace names both sites, and its children are built
/// as ever.
fn plugin_ir_refusing(path: &[String], schema: &PluginIn<'_>, child_irs: Vec<Ir>) -> Ir {
    match plugin_ir(path, schema, child_irs.clone()) {
        Ok(ir) => ir,
        Err(err) => {
            let bare_schema = PluginIn {
                hash: schema.hash.clone(),
                methods: Vec::new(),
                children: schema.children.clone(),
                request: schema.request,
                roles: schema.roles.clone(),
            };
            let mut bare = plugin_ir(path, &bare_schema, child_irs).unwrap_or_else(|_| Ir::empty());
            let rendered = err.to_string();
            let why = rendered.strip_prefix("IR: ").unwrap_or(&rendered);
            bare.refusals.insert(
                0,
                Refusal { site: path.join("."), keyword: "title".into(), variant: None, detail: format!("{why} The activation is left out.") },
            );
            bare
        }
    }
}

/// synapse's `mergeIR`: left-biased.
fn merge(a: Ir, b: Ir) -> Ir {
    fn union<K: Ord, V>(mut a: BTreeMap<K, V>, b: BTreeMap<K, V>) -> BTreeMap<K, V> {
        for (k, v) in b {
            a.entry(k).or_insert(v);
        }
        a
    }
    fn opt_union<K: Ord, V>(a: Option<BTreeMap<K, V>>, b: Option<BTreeMap<K, V>>) -> Option<BTreeMap<K, V>> {
        match (a, b) {
            (Some(a), Some(b)) => Some(union(a, b)),
            (a, None) => a,
            (None, b) => b,
        }
    }
    let mut plugins = a.plugins;
    for (k, v) in b.plugins {
        plugins.entry(k).or_default().extend(v);
    }
    let mut refusals = a.refusals;
    refusals.extend(b.refusals);
    Ir {
        version: a.version,
        backend: a.backend,
        hash: a.hash.or(b.hash),
        types: union(a.types, b.types),
        methods: union(a.methods, b.methods),
        plugins,
        plugin_hashes: opt_union(a.plugin_hashes, b.plugin_hashes),
        plugin_requests: opt_union(a.plugin_requests, b.plugin_requests),
        plugin_roles: opt_union(a.plugin_roles, b.plugin_roles),
        refusals,
    }
}

/// One plugin node: its own types and methods, merged with its children's.
fn plugin_ir(path: &[String], schema: &PluginIn<'_>, child_irs: Vec<Ir>) -> Result<Ir, IrBuildError> {
    let namespace = path.join(".");
    let (local_types, local_methods, local_refusals) = extract_from_plugin(&namespace, schema)?;
    let child = child_irs.into_iter().rev().fold(Ir::empty(), |acc, ir| merge(ir, acc));
    let plugin_methods: Vec<String> = local_methods.values().map(|m| m.name.clone()).collect();
    let hash = if path.is_empty() { Some(schema.hash.clone()) } else { child.hash.clone() };
    let mut hashes = child.plugin_hashes.unwrap_or_default();
    hashes.insert(
        namespace.clone(),
        PluginHashInfo { hash: schema.hash.clone(), self_hash: schema.hash.clone(), children_hash: schema.hash.clone() },
    );
    let mut requests = child.plugin_requests.unwrap_or_default();
    if let Some(r) = schema.request {
        requests.insert(namespace.clone(), r.clone());
    }
    let roles = match &schema.roles {
        None => child.plugin_roles,
        Some(roles) => {
            let mut all = child.plugin_roles.unwrap_or_default();
            all.insert(namespace.clone(), roles.clone());
            Some(all)
        }
    };
    let mut types = local_types;
    for (k, v) in child.types {
        types.entry(k).or_insert(v);
    }
    let mut methods = local_methods;
    for (k, v) in child.methods {
        methods.entry(k).or_insert(v);
    }
    let mut plugins = child.plugins;
    plugins.insert(namespace, plugin_methods);
    let mut refusals = local_refusals;
    refusals.extend(child.refusals);
    Ok(Ir {
        version: IR_VERSION.into(),
        backend: String::new(),
        hash,
        types,
        methods,
        plugins,
        plugin_hashes: Some(hashes),
        plugin_requests: if requests.is_empty() { None } else { Some(requests) },
        plugin_roles: roles,
        refusals,
    })
}

// ---------------------------------------------------------------------------
// One plugin
// ---------------------------------------------------------------------------

type Extracted = (BTreeMap<String, TypeDef>, BTreeMap<String, MethodDef>, Vec<Refusal>);

fn extract_from_plugin(namespace: &str, schema: &PluginIn<'_>) -> Result<Extracted, IrBuildError> {
    check_titles(namespace, &schema.methods)?;
    // every method's documents share one namespace's $defs: read once
    let docs: Vec<&Map<String, Value>> =
        schema.methods.iter().flat_map(|m| m.docs()).filter_map(|(_, v)| v.as_object()).collect();
    let defs = read::shared_defs(&docs);
    let shared = Doc { namespace, defs: &defs, root: None };
    let mut r = Reader::default();
    let mut types = read::read_defs(&mut r, &shared);
    let mut methods = BTreeMap::new();
    for m in &schema.methods {
        let (ts, md) = method_def(&mut r, &shared, namespace, m);
        for (k, v) in ts {
            types.entry(k).or_insert(v);
        }
        methods.insert(md.full_path.clone(), md);
    }
    Ok((types, methods, r.refusals))
}

/// The fallback name of a method's untitled named root, by schema.
fn root_fallback(m: &MethodIn<'_>, which: &str) -> String {
    match which {
        "returns" => format!("{}Result", m.name),
        "error" => format!("{}Error", m.name),
        "progress" => format!("{}Progress", m.name),
        "input" => format!("{}Input", m.name),
        other => format!("{}{other}", m.name),
    }
}

/// One name in one namespace is one type (RETURNS-13): every name the
/// methods' schemas define — each `$defs` entry, each named root — compared
/// in name order; two shapes under one name fail, naming the first and the
/// second.
fn check_titles(namespace: &str, methods: &[MethodIn<'_>]) -> Result<(), IrBuildError> {
    let mut by_name: BTreeMap<String, Vec<(Value, &Map<String, Value>, TypeSource)>> = BTreeMap::new();
    for m in methods {
        for (which, doc) in m.docs() {
            let Value::Object(doc_obj) = doc else { continue };
            let source = || TypeSource { method: m.name.clone(), schema: which.to_string() };
            // `$defs`, else `definitions` — whichever key is there, as long as it is an object
            let defs = doc_obj.get("$defs").or_else(|| doc_obj.get("definitions"));
            if let Some(Value::Object(d)) = defs {
                for (k, v) in read::sorted(d) {
                    by_name.entry(k.clone()).or_default().push((v.clone(), doc_obj, source()));
                }
            }
            if which != "params" {
                if let Some((name, body)) = read::root_named(&root_fallback(m, which), doc) {
                    by_name.entry(name).or_default().push((body, doc_obj, source()));
                }
            }
        }
    }
    for (name, occurrences) in &by_name {
        let mut iter = occurrences.iter();
        let Some((b0, d0, s0)) = iter.next() else { continue };
        let mut k0: Option<Option<TypeKind>> = None;
        for (b, d, s) in iter {
            if b == b0 {
                continue;
            }
            let kind0 = k0.get_or_insert_with(|| read::read_kind_in(namespace, d0, name, b0)).clone();
            let kind = read::read_kind_in(namespace, d, name, b);
            if !same_shape(&kind0, &kind) {
                return Err(IrBuildError::TitleCollision {
                    namespace: namespace.into(),
                    title: name.clone(),
                    first: s0.clone(),
                    second: s.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Two readings of a name are one type when they agree on everything but
/// their documentation.
fn same_shape(a: &Option<TypeKind>, b: &Option<TypeKind>) -> bool {
    fn undocumented(k: &TypeKind) -> TypeKind {
        let field = |f: &FieldDef| FieldDef { description: None, ..f.clone() };
        match k {
            TypeKind::Struct { fields } => TypeKind::Struct { fields: fields.iter().map(field).collect() },
            TypeKind::Enum { discriminator, variants, repr } => TypeKind::Enum {
                discriminator: discriminator.clone(),
                variants: variants
                    .iter()
                    .map(|v| VariantDef { description: None, fields: v.fields.iter().map(field).collect(), ..v.clone() })
                    .collect(),
                repr: *repr,
            },
            other => other.clone(),
        }
    }
    a.as_ref().map(undocumented) == b.as_ref().map(undocumented)
}

fn method_def(r: &mut Reader, shared: &Doc<'_>, namespace: &str, m: &MethodIn<'_>) -> (BTreeMap<String, TypeDef>, MethodDef) {
    let full_path = format!("{namespace}.{}", m.name);
    let (param_types, params, injected) = read_params(r, shared, &full_path, m);
    let returns = match m.role {
        MethodRole::Rpc => read::read_root(r, Some(shared), namespace, &read::site_returns(&full_path), &root_fallback(m, "returns"), &m.returns),
        _ => read::RootRead { types: BTreeMap::new(), r#ref: TypeRef::Child(full_path.clone()) },
    };
    let error = m.error.map(|e| read::read_root(r, Some(shared), namespace, &read::site_error(&full_path), &root_fallback(m, "error"), e));
    let progress =
        m.progress.map(|p| read::read_root(r, Some(shared), namespace, &read::site_progress(&full_path), &root_fallback(m, "progress"), p));
    let input = m.input.map(|i| read::read_root(r, Some(shared), namespace, &read::site_input(&full_path), &root_fallback(m, "input"), i));
    let mut types = param_types;
    let mut add = |ts: BTreeMap<String, TypeDef>| {
        for (k, v) in ts {
            types.entry(k).or_insert(v);
        }
    };
    let returns_ref = returns.r#ref;
    add(returns.types);
    let error_ref = error.map(|e| {
        add(e.types);
        e.r#ref
    });
    let progress_ref = progress.map(|p| {
        add(p.types);
        p.r#ref
    });
    let input_ref = input.map(|i| {
        add(i.types);
        i.r#ref
    });
    let md = MethodDef {
        name: m.name.clone(),
        full_path,
        namespace: namespace.into(),
        description: Some(m.description.clone()),
        params,
        returns: returns_ref,
        error: error_ref,
        progress: progress_ref,
        cardinality: m.cardinality,
        // StandardBidirChannel's T = serde_json::Value
        bidir_type: m.bidirectional.then_some(TypeRef::Json),
        bidir_response_type: None,
        bidir_response_schema: m.response_type.cloned(),
        role: m.role.clone(),
        grant: m.grant.clone(),
        target: m.target.clone(),
        long_description: m.long_description.clone(),
        injected,
        input: input_ref,
    };
    (types, md)
}

/// The params schema read: the params a client sends, and those the server
/// injects (`x-plexus-source` other than rpc — not read as types).
fn read_params(r: &mut Reader, shared: &Doc<'_>, full_path: &str, m: &MethodIn<'_>) -> (BTreeMap<String, TypeDef>, Vec<ParamDef>, Vec<InjectedParam>) {
    let Some(Value::Object(o)) = m.params else { return (BTreeMap::new(), vec![], vec![]) };
    let props: Vec<(&String, &Value)> = match o.get("properties") {
        Some(Value::Object(p)) => read::sorted(p),
        _ => vec![],
    };
    let required = read::required_of(o);
    let deprecation_of = |name: &str| {
        m.param_schemas.as_ref().and_then(|ps| ps.iter().find(|p| p.name == name)).and_then(|p| p.deprecation.clone())
    };
    let mut params = Vec::new();
    let mut injected = Vec::new();
    for (name, v) in props {
        let source = match v {
            Value::Object(po) => po.get("x-plexus-source").cloned(),
            _ => None,
        };
        let server_supplied = matches!(&source, Some(Value::Object(src)) if src.get("from") != Some(&Value::String("rpc".into())));
        if server_supplied {
            injected.push(InjectedParam { name: name.clone(), source: source.unwrap_or(Value::Null), description: read::description_of(v) });
            continue;
        }
        let ty = read::read_type(r, shared, &read::site_param(full_path, name), v);
        let values = match v {
            Value::Object(po) => match po.get("x-plexus-values") {
                Some(Value::Array(vs)) => Some(vs.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()),
                _ => None,
            },
            _ => None,
        };
        params.push(ParamDef {
            name: name.clone(),
            ty,
            description: read::description_of(v),
            required: required.contains(name),
            default: read::default_of(v),
            deprecation: deprecation_of(name),
            source,
            values,
        });
    }
    (BTreeMap::new(), params, injected)
}

// ---------------------------------------------------------------------------
// The IR made whole
// ---------------------------------------------------------------------------

/// synapse's `finalizeIR`.
fn finalize(raw: Ir) -> Ir {
    let placed = deduplicate(raw);
    let refused: HashSet<String> = placed.refusals.iter().map(|r| r.site.clone()).collect();
    let (mut fixed, dangling) = unknown_where_unnamed(&refused, placed);
    let mut all = std::mem::take(&mut fixed.refusals);
    all.extend(dangling);
    let mut refusals: Vec<Refusal> = Vec::new();
    for r in all {
        if !refusals.contains(&r) {
            refusals.push(r);
        }
    }
    refusals.sort_by(|a, b| a.site.cmp(&b.site));
    fixed.refusals = refusals;
    fixed
}

fn strip_namespace(t: TypeRef) -> TypeRef {
    t.map(&|t| match t {
        TypeRef::Named(qn) => TypeRef::Named(QualifiedName { namespace: String::new(), local: qn.local }),
        other => other,
    })
}

/// Deduplicate types by structure (name and kind, namespaces stripped from
/// refs), each kept once, in the namespace that refers to it most.
fn deduplicate(mut ir: Ir) -> Ir {
    // groups of structurally identical types: (name, normalized kind) → copies
    let mut groups: Vec<((String, TypeKind), Vec<(String, TypeDef)>)> = Vec::new();
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (full, td) in std::mem::take(&mut ir.types) {
        let key = (td.name.clone(), td.kind.clone().map_refs(&strip_namespace));
        let slot = by_name.get(&td.name).and_then(|ix| ix.iter().copied().find(|&i| groups[i].0 == key));
        match slot {
            Some(i) => groups[i].1.push((full, td)),
            None => {
                by_name.entry(td.name.clone()).or_default().push(groups.len());
                groups.push((key, vec![(full, td)]));
            }
        }
    }
    let contested: HashSet<(String, String)> = groups
        .iter()
        .filter(|(_, g)| g.len() > 1)
        .flat_map(|(_, g)| g.iter().map(|(_, td)| (td.namespace.clone(), td.name.clone())))
        .collect();
    let counts = ref_counts(&contested, &ir, &groups);
    let mut redirects: HashMap<String, String> = HashMap::new();
    let mut canonical: Vec<(String, TypeDef)> = Vec::new();
    for (_, group) in groups {
        let at = select_canonical(&counts, &group);
        let name = group[at].0.clone();
        for (old, _) in &group {
            if *old != name {
                redirects.insert(old.clone(), name.clone());
            }
        }
        let td = group.into_iter().nth(at).expect("the canonical copy").1;
        canonical.push((name, td));
    }
    let update = |t: TypeRef| update_ref(&redirects, t);
    ir.types = canonical.into_iter().map(|(k, td)| (k, TypeDef { kind: td.kind.map_refs(&update), ..td })).collect();
    for md in ir.methods.values_mut() {
        for p in md.params.iter_mut() {
            p.ty = update(std::mem::replace(&mut p.ty, TypeRef::Unknown));
        }
        md.returns = update(std::mem::replace(&mut md.returns, TypeRef::Unknown));
        md.error = md.error.take().map(update);
        md.progress = md.progress.take().map(update);
        md.bidir_type = md.bidir_type.take().map(update);
        md.input = md.input.take().map(update);
    }
    ir
}

/// How often each contested type is named, by (namespace, name): in every
/// method's params, returns, error, progress, input and bidirectional type,
/// and every type's fields, before deduplication.
fn ref_counts(contested: &HashSet<(String, String)>, ir: &Ir, groups: &[((String, TypeKind), Vec<(String, TypeDef)>)]) -> HashMap<(String, String), usize> {
    let mut counts = HashMap::new();
    if contested.is_empty() {
        return counts;
    }
    fn keys<'a>(t: &'a TypeRef, out: &mut Vec<&'a QualifiedName>) {
        match t {
            TypeRef::Named(qn) => out.push(qn),
            other => other.children().into_iter().for_each(|c| keys(c, out)),
        }
    }
    let mut names: Vec<&QualifiedName> = Vec::new();
    for md in ir.methods.values() {
        for p in &md.params {
            keys(&p.ty, &mut names);
        }
        keys(&md.returns, &mut names);
        for t in [&md.error, &md.progress, &md.input, &md.bidir_type].into_iter().flatten() {
            keys(t, &mut names);
        }
    }
    for (_, group) in groups {
        for (_, td) in group {
            match &td.kind {
                TypeKind::Struct { fields } => fields.iter().for_each(|f| keys(&f.ty, &mut names)),
                TypeKind::Enum { variants, .. } => {
                    for v in variants {
                        v.fields.iter().for_each(|f| keys(&f.ty, &mut names));
                        if let Some(r) = &v.vref {
                            keys(r, &mut names);
                        }
                    }
                }
                TypeKind::Alias { target } => keys(target, &mut names),
                _ => {}
            }
        }
    }
    for qn in names {
        let k = (qn.namespace.clone(), qn.local.clone());
        if contested.contains(&k) {
            *counts.entry(k).or_insert(0) += 1;
        }
    }
    counts
}

/// The copy in the namespace that refers to it most; a tie to the namespace
/// that is an ancestor of every other tied one, then the shortest name, then
/// alphabetical order; the root `""` never when a generated namespace has
/// a copy.
fn select_canonical(counts: &HashMap<(String, String), usize>, group: &[(String, TypeDef)]) -> usize {
    if group.len() == 1 {
        return 0;
    }
    let generated: Vec<usize> = (0..group.len()).filter(|&i| !group[i].1.namespace.is_empty()).collect();
    let candidates: Vec<usize> = if generated.is_empty() { (0..group.len()).collect() } else { generated };
    let count_of = |i: usize| counts.get(&(group[i].1.namespace.clone(), group[i].1.name.clone())).copied().unwrap_or(0);
    let best = candidates.iter().map(|&i| count_of(i)).max().unwrap_or(0);
    let tied: Vec<usize> = candidates.into_iter().filter(|&i| count_of(i) == best).collect();
    let ns = |i: usize| group[i].1.namespace.as_str();
    let ancestor_of_all = |c: usize| tied.iter().all(|&o| ns(o) == ns(c) || ns(o).starts_with(&format!("{}.", ns(c))));
    if let Some(&c) = tied.iter().find(|&&c| ancestor_of_all(c)) {
        return c;
    }
    *tied.iter().min_by(|&&a, &&b| (ns(a).chars().count(), ns(a)).cmp(&(ns(b).chars().count(), ns(b)))).expect("a tied copy")
}

/// synapse's `parseQualifiedName`: split at the last dot.
fn parse_qualified_name(t: &str) -> Option<QualifiedName> {
    let i = t.rfind('.')?;
    let local = &t[i + 1..];
    if local.is_empty() {
        return None;
    }
    Some(QualifiedName { namespace: t[..i].to_string(), local: local.to_string() })
}

/// A ref to its canonical name — every named ref re-parsed from its full
/// name, as synapse's `updateTypeRef` does.
fn update_ref(redirects: &HashMap<String, String>, t: TypeRef) -> TypeRef {
    t.map(&|t| match t {
        TypeRef::Named(qn) => {
            let full = qn.key();
            let canonical = redirects.get(&full).cloned().unwrap_or(full);
            match parse_qualified_name(&canonical) {
                Some(q) => TypeRef::Named(q),
                None => TypeRef::Named(qn),
            }
        }
        other => other,
    })
}

/// Every named ref that names no type becomes `RefUnknown`: one naming a
/// type the reader refused needs nothing more; any other is refused at its
/// own site.
fn unknown_where_unnamed(refused: &HashSet<String>, mut ir: Ir) -> (Ir, Vec<Refusal>) {
    let known: HashSet<String> = ir.types.keys().cloned().collect();
    fn fix(known: &HashSet<String>, refused: &HashSet<String>, site: &str, t: TypeRef, out: &mut Vec<Refusal>) -> TypeRef {
        match t {
            TypeRef::Named(qn) => {
                let full = qn.key();
                if known.contains(&full) {
                    TypeRef::Named(qn)
                } else {
                    if !refused.contains(&full) {
                        out.push(Refusal {
                            site: site.into(),
                            keyword: "$ref".into(),
                            variant: None,
                            detail: format!("names {full}, which no $defs defines"),
                        });
                    }
                    TypeRef::Unknown
                }
            }
            TypeRef::Array(i) => TypeRef::Array(Box::new(fix(known, refused, &format!("{site}[]"), *i, out))),
            TypeRef::Optional(i) => TypeRef::Optional(Box::new(fix(known, refused, &format!("{site}?"), *i, out))),
            TypeRef::Map(i) => TypeRef::Map(Box::new(fix(known, refused, &format!("{site}{{}}"), *i, out))),
            TypeRef::Refined(i, r) => TypeRef::Refined(Box::new(fix(known, refused, site, *i, out)), r),
            TypeRef::Tuple(ts) => {
                TypeRef::Tuple(ts.into_iter().enumerate().map(|(n, x)| fix(known, refused, &format!("{site}.{n}"), x, out)).collect())
            }
            other => other,
        }
    }
    let mut out = Vec::new();
    let fields = |site: &str, fs: Vec<FieldDef>, out: &mut Vec<Refusal>| -> Vec<FieldDef> {
        fs.into_iter()
            .map(|f| {
                let ty = fix(&known, refused, &format!("{site}.{}", f.name), f.ty.clone(), out);
                FieldDef { ty, ..f }
            })
            .collect()
    };
    let types = std::mem::take(&mut ir.types);
    let mut fixed_types = BTreeMap::new();
    for (name, td) in types {
        let kind = match td.kind {
            TypeKind::Struct { fields: fs } => TypeKind::Struct { fields: fields(&name, fs, &mut out) },
            TypeKind::Enum { discriminator, variants, repr } => {
                let variants = variants
                    .into_iter()
                    .map(|v| {
                        let vsite = format!("{name}.{}", v.name);
                        let fs = fields(&vsite, v.fields, &mut out);
                        let vref = v.vref.map(|x| fix(&known, refused, &vsite, x, &mut out));
                        VariantDef { fields: fs, vref, name: v.name, description: v.description }
                    })
                    .collect();
                TypeKind::Enum { discriminator, variants, repr }
            }
            TypeKind::Alias { target } => TypeKind::Alias { target: fix(&known, refused, &name, target, &mut out) },
            other => other,
        };
        fixed_types.insert(name, TypeDef { kind, ..td });
    }
    ir.types = fixed_types;
    for md in ir.methods.values_mut() {
        let path = md.full_path.clone();
        for p in md.params.iter_mut() {
            let ty = std::mem::replace(&mut p.ty, TypeRef::Unknown);
            p.ty = fix(&known, refused, &read::site_param(&path, &p.name), ty, &mut out);
        }
        let ret = std::mem::replace(&mut md.returns, TypeRef::Unknown);
        md.returns = fix(&known, refused, &read::site_returns(&path), ret, &mut out);
        md.error = md.error.take().map(|t| fix(&known, refused, &read::site_error(&path), t, &mut out));
        md.progress = md.progress.take().map(|t| fix(&known, refused, &read::site_progress(&path), t, &mut out));
        md.input = md.input.take().map(|t| fix(&known, refused, &read::site_input(&path), t, &mut out));
    }
    (ir, out)
}
