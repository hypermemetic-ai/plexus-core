//! The schema reader: synapse's `Synapse.IR.Read`, ported. Every JSON Schema
//! met in a type position is read whole, or refused by name — a
//! [`Refusal`] naming the site, the keyword and why — and nothing is
//! dropped. Its rules, its order and its words are synapse's; a difference
//! from them is a bug here.
//!
//! Where synapse iterates a JSON object it iterates aeson's `KeyMap`, which
//! is ordered by key; so does this module, whatever order the
//! `serde_json::Map` keeps.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

use serde_json::{Map, Number, Value};

use super::types::*;

/// What a read carries along: the refusals met, and the named roots
/// already read (by site — the first schema read under a name stands for
/// every later root of it).
#[derive(Default)]
pub(crate) struct Reader {
    pub(crate) refusals: Vec<Refusal>,
    roots: HashMap<String, Option<TypeKind>>,
}

impl Reader {
    pub(crate) fn refuse(&mut self, site: &str, keyword: &str, variant: Option<i64>, detail: impl Into<String>) {
        self.refusals.push(Refusal { site: site.into(), keyword: keyword.into(), variant, detail: detail.into() });
    }

    fn unknown_at(&mut self, site: &str, keyword: &str, variant: Option<i64>, detail: impl Into<String>) -> TypeRef {
        self.refuse(site, keyword, variant, detail);
        TypeRef::Unknown
    }
}

fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: OnceLock<Map<String, Value>> = OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

/// One JSON Schema document: the namespace its types land in, its `$defs`
/// by name, and the root's name (what `"$ref": "#"` names).
#[derive(Clone)]
pub(crate) struct Doc<'a> {
    pub(crate) namespace: &'a str,
    pub(crate) defs: &'a Map<String, Value>,
    pub(crate) root: Option<String>,
}

impl<'a> Doc<'a> {
    /// synapse's `docOf`: `$defs` when it is an object, else `definitions`.
    pub(crate) fn of(namespace: &'a str, o: &'a Map<String, Value>) -> Doc<'a> {
        let defs = match o.get("$defs") {
            Some(Value::Object(d)) => d,
            _ => match o.get("definitions") {
                Some(Value::Object(d)) => d,
                _ => empty_map(),
            },
        };
        Doc { namespace, defs, root: None }
    }

    fn lookup(&self, r: &str) -> Option<&'a Value> {
        if r == "#" {
            return None;
        }
        self.defs.get(ref_name(r))
    }
}

/// synapse's `sharedDoc`: every `$defs` entry of a namespace's documents,
/// the first of each name winning.
pub(crate) fn shared_defs(docs: &[&Map<String, Value>]) -> Map<String, Value> {
    let mut out = Map::new();
    for o in docs {
        let d = Doc::of("", o);
        for (k, v) in d.defs {
            if !out.contains_key(k) {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

/// An object's entries in key order (aeson's `KeyMap.toList`).
pub(crate) fn sorted(o: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut v: Vec<(&String, &Value)> = o.iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    v
}

pub(crate) fn ref_name(r: &str) -> &str {
    r.rsplit('/').next().unwrap_or(r)
}

fn qualified(doc: &Doc<'_>, r: &str) -> TypeRef {
    let local = if r == "#" {
        doc.root.clone().unwrap_or_else(|| "#".into())
    } else {
        ref_name(r).to_string()
    };
    TypeRef::Named(QualifiedName { namespace: doc.namespace.to_string(), local })
}

fn type_site(doc: &Doc<'_>, name: &str) -> String {
    format!("{}.{}", doc.namespace, name)
}

pub(crate) fn site_param(path: &str, name: &str) -> String {
    format!("{path}({name})")
}
pub(crate) fn site_returns(path: &str) -> String {
    format!("{path} returns")
}
pub(crate) fn site_error(path: &str) -> String {
    format!("{path} error")
}
pub(crate) fn site_progress(path: &str) -> String {
    format!("{path} progress")
}
pub(crate) fn site_input(path: &str) -> String {
    format!("{path} input")
}

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

const KNOWN: &[&str] = &[
    "type", "$ref", "properties", "required", "additionalProperties", "items", "prefixItems",
    "oneOf", "anyOf", "allOf", "enum", "const", "format",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "pattern", "minItems", "maxItems",
    "default", "description", "title", "examples", "deprecated",
    "$schema", "$defs", "definitions",
    "x-plexus-source", "x-plexus-values",
];

const STRUCTURAL: &[&str] =
    &["type", "$ref", "properties", "additionalProperties", "items", "prefixItems", "oneOf", "anyOf", "allOf", "enum", "const"];

/// Refuse each keyword outside the list; `true` when there were none.
fn keywords_ok(r: &mut Reader, site: &str, o: &Map<String, Value>) -> bool {
    let bad: Vec<&String> = sorted(o).into_iter().map(|(k, _)| k).filter(|k| !KNOWN.contains(&k.as_str())).collect();
    for k in &bad {
        r.refuse(site, k, None, format!("`{k}` is not a keyword synapse reads"));
    }
    bad.is_empty()
}

/// The JSON type, as a schema says it: annotations only, or `type` naming
/// all six JSON types and nothing else that types.
fn is_json_schema(o: &Map<String, Value>) -> bool {
    !STRUCTURAL.iter().any(|k| o.contains_key(*k)) || all_six(o)
}

fn all_six(o: &Map<String, Value>) -> bool {
    match o.get("type") {
        Some(Value::Array(ts)) => {
            let got: HashSet<&str> = ts.iter().filter_map(Value::as_str).collect();
            let six: HashSet<&str> = ["null", "boolean", "number", "string", "array", "object"].into_iter().collect();
            got == six && !STRUCTURAL.iter().filter(|k| **k != "type").any(|k| o.contains_key(*k))
        }
        _ => false,
    }
}

fn json_value(v: &Value) -> bool {
    match v {
        Value::Bool(true) => true,
        Value::Object(o) => is_json_schema(o),
        _ => false,
    }
}

fn is_json_ref(r: &str) -> bool {
    ref_name(r) == "Json"
}

// ---------------------------------------------------------------------------
// Type positions
// ---------------------------------------------------------------------------

/// The type of a schema in a type position, at a site.
pub(crate) fn read_type(r: &mut Reader, doc: &Doc<'_>, site: &str, v: &Value) -> TypeRef {
    match v {
        Value::Bool(true) => TypeRef::Json,
        Value::Object(o) => {
            if !keywords_ok(r, site, o) {
                TypeRef::Unknown
            } else if is_json_schema(o) {
                TypeRef::Json
            } else {
                read_type_object(r, doc, site, o)
            }
        }
        _ => r.unknown_at(site, "type", None, "not a schema"),
    }
}

fn read_type_object(r: &mut Reader, doc: &Doc<'_>, site: &str, o: &Map<String, Value>) -> TypeRef {
    if let Some(Value::String(rf)) = o.get("$ref") {
        return if is_json_ref(rf) { TypeRef::Json } else { qualified(doc, rf) };
    }
    if let Some(members) = all_of_of(o) {
        if members.len() == 1 && !["properties", "type", "oneOf", "anyOf"].iter().any(|k| o.contains_key(*k)) {
            return read_type(r, doc, site, &members[0]);
        }
        return r.unknown_at(site, "allOf", None, "allOf is read only as one schema, or beside a tag as a newtype variant's struct");
    }
    if let Some((kw, members)) = union_of(o) {
        return read_inline_union(r, doc, site, kw, members);
    }
    if let Some(Value::Array(ts)) = o.get("type") {
        let types: Vec<&str> = ts.iter().filter_map(Value::as_str).collect();
        let non_null: Vec<&str> = types.iter().copied().filter(|t| *t != "null").collect();
        let has_null = types.contains(&"null");
        return match non_null.as_slice() {
            [t] => {
                let at = if has_null { format!("{site}?") } else { site.to_string() };
                let base = read_typed(r, doc, &at, t, o);
                if has_null {
                    TypeRef::Optional(Box::new(base))
                } else {
                    base
                }
            }
            [] => TypeRef::Primitive("null".into(), None),
            _ => r.unknown_at(site, "type", None, "a type list that is neither one type (with null or without) nor the JSON type (all six)"),
        };
    }
    if let Some(Value::String(t)) = o.get("type") {
        return read_typed(r, doc, site, t, o);
    }
    if o.contains_key("enum") || o.contains_key("const") {
        return TypeRef::Primitive(literal_type(o).into(), None);
    }
    if o.contains_key("items") || o.contains_key("prefixItems") {
        return read_typed(r, doc, site, "array", o);
    }
    read_typed(r, doc, site, "object", o)
}

/// The JSON type of an enum's or const's values.
fn literal_type(o: &Map<String, Value>) -> &'static str {
    let mut values: Vec<&Value> = Vec::new();
    if let Some(Value::Array(a)) = o.get("enum") {
        values.extend(a.iter());
    }
    if let Some(c) = o.get("const") {
        values.push(c);
    }
    match values.first() {
        Some(Value::Number(_)) => "number",
        Some(Value::Bool(_)) => "boolean",
        _ => "string",
    }
}

/// A schema of one JSON type.
fn read_typed(r: &mut Reader, doc: &Doc<'_>, site: &str, t: &str, o: &Map<String, Value>) -> TypeRef {
    match t {
        "array" => {
            if let Some(Value::Array(prefix)) = o.get("prefixItems") {
                return read_tuple(r, doc, site, prefix, o);
            }
            if let Some(items) = o.get("items") {
                let inner = read_type(r, doc, &format!("{site}[]"), items);
                return refined(TypeRef::Array(Box::new(inner)), item_bounds(o));
            }
            TypeRef::Array(Box::new(r.unknown_at(&format!("{site}[]"), "items", None, "an array with no items")))
        }
        "object" => {
            if o.contains_key("properties") {
                return r.unknown_at(site, "properties", None, "an object with properties in a type position has no name: give it one in $defs");
            }
            if let Some(ap) = o.get("additionalProperties") {
                if *ap != Value::Bool(false) {
                    return TypeRef::Map(Box::new(read_type(r, doc, &format!("{site}{{}}"), ap)));
                }
            }
            r.unknown_at(site, "type", None, "an object with neither properties nor additionalProperties")
        }
        _ => {
            let base = TypeRef::Primitive(t.into(), format_of(o));
            refined(base, scalar_bounds(format_of(o).as_deref(), o))
        }
    }
}

/// `prefixItems` with `minItems = maxItems = n`: a tuple of n.
fn read_tuple(r: &mut Reader, doc: &Doc<'_>, site: &str, prefix: &[Value], o: &Map<String, Value>) -> TypeRef {
    let n = prefix.len() as i64;
    let no_extra = matches!(o.get("items"), None | Some(Value::Bool(false)));
    if int_at("minItems", o) == Some(n) && int_at("maxItems", o) == Some(n) && no_extra {
        let parts = prefix.iter().enumerate().map(|(i, v)| read_type(r, doc, &format!("{site}.{i}"), v)).collect();
        return TypeRef::Tuple(parts);
    }
    r.unknown_at(site, "prefixItems", None, "prefixItems is read only as a tuple: minItems = maxItems = its length, no further items")
}

fn format_of(o: &Map<String, Value>) -> Option<String> {
    match o.get("format") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Data.Scientific's `toBoundedInteger` into an `Int`: an integral value in range.
fn int_at(k: &str, o: &Map<String, Value>) -> Option<i64> {
    match o.get(k) {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else if n.is_u64() {
                None
            } else {
                let f = n.as_f64()?;
                (f.fract() == 0.0 && f >= i64::MIN as f64 && f < i64::MAX as f64).then_some(f as i64)
            }
        }
        _ => None,
    }
}

fn num_at(k: &str, o: &Map<String, Value>) -> Option<Number> {
    match o.get(k) {
        Some(Value::Number(n)) => Some(n.clone()),
        _ => None,
    }
}

fn refined(t: TypeRef, r: Refinements) -> TypeRef {
    if r.is_none() {
        t
    } else {
        TypeRef::Refined(Box::new(t), r)
    }
}

fn item_bounds(o: &Map<String, Value>) -> Refinements {
    Refinements { min_items: int_at("minItems", o), max_items: int_at("maxItems", o), ..Refinements::default() }
}

/// Whether `n` is exactly `implied` (Scientific's equality).
fn num_is(n: &Number, implied: i128) -> bool {
    if let Some(i) = n.as_i64() {
        return i as i128 == implied;
    }
    if let Some(u) = n.as_u64() {
        return u as i128 == implied;
    }
    match n.as_f64() {
        Some(f) => f.fract() == 0.0 && f.abs() < 9.0e15 && f as i128 == implied,
        None => false,
    }
}

/// A scalar's bounds, less those its format already says.
fn scalar_bounds(fmt: Option<&str>, o: &Map<String, Value>) -> Refinements {
    if !["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "pattern"].iter().any(|k| o.contains_key(*k)) {
        return Refinements::default();
    }
    let (implied_min, implied_max) = format_bounds(fmt);
    let unless = |v: Option<Number>, implied: Option<i128>| match (&v, implied) {
        (Some(n), Some(i)) if num_is(n, i) => None,
        _ => v,
    };
    Refinements {
        minimum: unless(num_at("minimum", o), implied_min),
        maximum: unless(num_at("maximum", o), implied_max),
        exclusive_minimum: num_at("exclusiveMinimum", o),
        exclusive_maximum: num_at("exclusiveMaximum", o),
        min_length: int_at("minLength", o),
        max_length: int_at("maxLength", o),
        pattern: match o.get("pattern") {
            Some(Value::String(p)) => Some(p.clone()),
            _ => None,
        },
        min_items: None,
        max_items: None,
    }
}

/// The bounds an integer format implies (schemars writes them out).
fn format_bounds(fmt: Option<&str>) -> (Option<i128>, Option<i128>) {
    match fmt {
        Some("uint8") => (Some(0), Some(255)),
        Some("uint16") => (Some(0), Some(65535)),
        Some("uint32") => (Some(0), Some(4294967295)),
        Some("uint64") => (Some(0), Some(18446744073709551615)),
        Some("uint128") => (Some(0), None),
        Some("uint") => (Some(0), None),
        Some("int8") => (Some(-128), Some(127)),
        Some("int16") => (Some(-32768), Some(32767)),
        Some("int32") => (Some(-2147483648), Some(2147483647)),
        Some("int64") => (Some(-9223372036854775808), Some(9223372036854775807)),
        _ => (None, None),
    }
}

// ---------------------------------------------------------------------------
// Unions
// ---------------------------------------------------------------------------

fn all_of_of(o: &Map<String, Value>) -> Option<&Vec<Value>> {
    match o.get("allOf") {
        Some(Value::Array(ms)) => Some(ms),
        _ => None,
    }
}

/// What a newtype variant (or a struct) wraps: a `$ref` beside its
/// properties, or `allOf [{"$ref": …}]`.
fn wrapped_ref(m: &Map<String, Value>) -> Option<Value> {
    if let Some(r) = m.get("$ref") {
        return Some(r.clone());
    }
    match all_of_of(m).map(Vec::as_slice) {
        Some([Value::Object(x)]) => match x.get("$ref") {
            Some(r @ Value::String(_)) => Some(r.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn union_of(o: &Map<String, Value>) -> Option<(&'static str, &Vec<Value>)> {
    if let Some(Value::Array(ms)) = o.get("oneOf") {
        return Some(("oneOf", ms));
    }
    if let Some(Value::Array(ms)) = o.get("anyOf") {
        return Some(("anyOf", ms));
    }
    None
}

fn read_inline_union(r: &mut Reader, doc: &Doc<'_>, site: &str, kw: &str, members: &[Value]) -> TypeRef {
    if let Some(inner) = nullable_member(members) {
        return TypeRef::Optional(Box::new(read_type(r, doc, &format!("{site}?"), inner)));
    }
    if string_enum_values(members).is_some() {
        return TypeRef::Primitive("string".into(), None);
    }
    r.unknown_at(site, kw, None, "a union in a type position has no name: give it one in $defs")
}

/// `[X, {"type": "null"}]` (either order) is a nullable X.
fn nullable_member(members: &[Value]) -> Option<&Value> {
    match members {
        [a, b] if is_null_schema(a) => Some(b),
        [a, b] if is_null_schema(b) => Some(a),
        _ => None,
    }
}

fn is_null_schema(v: &Value) -> bool {
    matches!(v, Value::Object(o) if o.get("type") == Some(&Value::String("null".into())))
}

fn string_enum_values(members: &[Value]) -> Option<Vec<String>> {
    if members.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for m in members {
        out.extend(string_literals(m)?);
    }
    Some(out)
}

fn string_literals(v: &Value) -> Option<Vec<String>> {
    let Value::Object(m) = v else { return None };
    let string_typed = match m.get("type") {
        None => true,
        Some(Value::String(t)) => t == "string",
        _ => false,
    };
    if string_typed {
        if let Some(Value::String(c)) = m.get("const") {
            return Some(vec![c.clone()]);
        }
        if let Some(Value::Array(vs)) = m.get("enum") {
            if !vs.is_empty() {
                return vs.iter().map(|x| x.as_str().map(str::to_string)).collect();
            }
        }
    }
    None
}

/// A named union's kind, read whole or refused.
fn read_union_kind(r: &mut Reader, doc: &Doc<'_>, site: &str, kw: &str, members: &[Value]) -> Option<TypeKind> {
    if let Some(inner) = nullable_member(members) {
        let t = read_type(r, doc, &format!("{site}?"), inner);
        return Some(TypeKind::Alias { target: TypeRef::Optional(Box::new(t)) });
    }
    if let Some(values) = string_enum_values(members) {
        return Some(TypeKind::StringEnum { values });
    }
    if let Some(shapes) = members.iter().map(|m| variant_shape(doc, MAX_DEPTH, m)).collect::<Option<Vec<_>>>() {
        if let Some(tag) = discriminator_of(&shapes) {
            return Some(tagged_enum(r, doc, site, &tag, &shapes));
        }
    }
    if let Some(vs) = members.iter().map(external_member).collect::<Option<Vec<_>>>() {
        return Some(external_enum(r, doc, site, vs));
    }
    if let Some(refs) = members.iter().map(ref_only).collect::<Option<Vec<_>>>() {
        if !refs.is_empty() {
            return Some(TypeKind::Enum {
                discriminator: String::new(),
                repr: EnumRepr::Untagged,
                variants: refs
                    .into_iter()
                    .map(|(rf, d)| VariantDef { name: ref_name(&rf).to_string(), description: d, fields: vec![], vref: Some(qualified(doc, &rf)) })
                    .collect(),
            });
        }
    }
    let (i, why) = first_unreadable(doc, members);
    r.refuse(site, kw, Some(i), why);
    None
}

/// The first member a union could not be read past, and why.
fn first_unreadable(doc: &Doc<'_>, members: &[Value]) -> (i64, String) {
    let Some(m0) = members.first() else { return (0, "an empty union".into()) };
    let pick = |ok: &dyn Fn(&Value) -> bool, why: &str| match members.iter().position(|m| !ok(m)) {
        Some(i) => (i as i64, format!("variant {i} {why}")),
        None => (0, "no string-const property tells the variants apart".into()),
    };
    if string_literals(m0).is_some() {
        return pick(&|m| string_literals(m).is_some(), "is not a string, as the members before it are");
    }
    if let Some(s0) = variant_shape(doc, MAX_DEPTH, m0) {
        let tags: Vec<String> = variant_consts(&s0).into_iter().map(|(k, _)| k).collect();
        let fits = |m: &Value| match variant_shape(doc, MAX_DEPTH, m) {
            Some(s) => variant_consts(&s).iter().any(|(k, _)| tags.contains(k)),
            None => false,
        };
        return pick(&fits, "shares no string-const property with the others and is not a string");
    }
    (0, "variant 0 is neither a string, an object nor a $ref to one".into())
}

/// `{"$ref": X}` (a description or title beside it) as a member.
fn ref_only(v: &Value) -> Option<(String, Option<String>)> {
    let Value::Object(m) = v else { return None };
    match m.get("$ref") {
        Some(Value::String(rf)) if m.keys().all(|k| ["$ref", "description", "title"].contains(&k.as_str())) => {
            Some((rf.clone(), description_of(v)))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tagged enums
// ---------------------------------------------------------------------------

/// One member of a union, its references resolved.
struct VariantShape {
    props: Vec<(String, Value)>,
    required: Vec<String>,
    wrapped: Option<Value>,
    desc: Option<String>,
}

const MAX_DEPTH: i32 = 8;

fn variant_shape(doc: &Doc<'_>, depth: i32, member: &Value) -> Option<VariantShape> {
    let Value::Object(m) = member else { return None };
    if let Some(Value::String(rf)) = m.get("$ref") {
        if !m.contains_key("properties") && depth > 0 {
            let target = doc.lookup(rf)?;
            let mut shape = variant_shape(doc, depth - 1, target)?;
            shape.desc = description_of(member).or(shape.desc);
            return Some(shape);
        }
    }
    if let Some(Value::Object(props)) = m.get("properties") {
        return Some(VariantShape {
            props: sorted(props).into_iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            required: required_of(m),
            wrapped: wrapped_ref(m),
            desc: description_of(member),
        });
    }
    None
}

/// The string consts a variant gives its own properties (a one-value
/// `enum` counts).
fn variant_consts(s: &VariantShape) -> Vec<(String, String)> {
    s.props
        .iter()
        .filter_map(|(k, v)| {
            let Value::Object(p) = v else { return None };
            let c = match (p.get("const"), p.get("enum")) {
                (Some(Value::String(c)), _) => Some(c.clone()),
                (_, Some(Value::Array(vs))) => match vs.as_slice() {
                    [Value::String(c)] => Some(c.clone()),
                    _ => None,
                },
                _ => None,
            };
            c.map(|c| (k.clone(), c))
        })
        .collect()
}

/// The tag: the property every variant gives a const, no two the same
/// one; of several, the first in the first variant's `required`.
fn discriminator_of(shapes: &[VariantShape]) -> Option<String> {
    let first = shapes.first()?;
    let consts: Vec<Vec<(String, String)>> = shapes.iter().map(variant_consts).collect();
    let mut candidates: Vec<String> = variant_consts(first)
        .into_iter()
        .map(|(k, _)| k)
        .filter(|k| {
            let values: Option<Vec<&String>> = consts.iter().map(|cs| cs.iter().find(|(ck, _)| ck == k).map(|(_, v)| v)).collect();
            match values {
                Some(vs) => {
                    let distinct: HashSet<&&String> = vs.iter().collect();
                    distinct.len() == vs.len()
                }
                None => false,
            }
        })
        .collect();
    let rank = |k: &String| first.required.iter().position(|x| x == k).unwrap_or(usize::MAX);
    candidates.sort_by_key(|k| rank(k));
    candidates.into_iter().next()
}

fn tagged_enum(r: &mut Reader, doc: &Doc<'_>, site: &str, tag: &str, shapes: &[VariantShape]) -> TypeKind {
    let variants = shapes
        .iter()
        .map(|s| {
            let name = variant_consts(s).into_iter().find(|(k, _)| k == tag).map(|(_, c)| c).unwrap_or_default();
            let vsite = format!("{site}.{name}");
            let own_props: Vec<(String, Value)> = s.props.iter().filter(|(k, _)| k != tag).cloned().collect();
            let mut fields = fields_of(r, doc, &vsite, &s.required, &own_props);
            if let Some(w) = &s.wrapped {
                fields.extend(wrapped_fields(r, doc, &vsite, w));
            }
            VariantDef { name, description: s.desc.clone(), fields: nub_fields(fields), vref: None }
        })
        .collect();
    TypeKind::Enum { discriminator: tag.into(), variants, repr: EnumRepr::Internal }
}

/// `nubBy` on the field's name: the first of each name.
fn nub_fields(fields: Vec<FieldDef>) -> Vec<FieldDef> {
    let mut seen = HashSet::new();
    fields.into_iter().filter(|f| seen.insert(f.name.clone())).collect()
}

/// The fields of the struct a newtype variant wraps, flattened; refused
/// when it wraps no struct.
fn wrapped_fields(r: &mut Reader, doc: &Doc<'_>, site: &str, w: &Value) -> Vec<FieldDef> {
    let mut depth = MAX_DEPTH;
    let mut current = w.clone();
    loop {
        let target = match &current {
            Value::String(rf) if depth > 0 => match doc.lookup(rf) {
                Some(Value::Object(t)) => Some(t),
                _ => None,
            },
            _ => None,
        };
        let Some(t) = target else { break };
        if let Some(Value::String(r2)) = t.get("$ref") {
            if !t.contains_key("properties") {
                depth -= 1;
                current = Value::String(r2.clone());
                continue;
            }
        }
        if t.contains_key("properties") {
            return fields_of(r, doc, site, &required_of(t), &props_of(t));
        }
        if t.get("type") == Some(&Value::String("object".into())) {
            return vec![];
        }
        break;
    }
    r.refuse(site, "$ref", None, "a newtype variant wraps no struct whose fields it could carry");
    vec![]
}

/// An externally tagged member: one property, required, and not a const.
fn external_member(v: &Value) -> Option<(String, Value, Option<String>)> {
    let Value::Object(m) = v else { return None };
    let Some(Value::Object(props)) = m.get("properties") else { return None };
    if props.len() != 1 {
        return None;
    }
    let (k, inner) = props.iter().next()?;
    if required_of(m) != vec![k.clone()] || is_const_schema(inner) {
        return None;
    }
    Some((k.clone(), inner.clone(), description_of(v)))
}

fn is_const_schema(v: &Value) -> bool {
    matches!(v, Value::Object(p) if p.contains_key("const"))
}

fn external_enum(r: &mut Reader, doc: &Doc<'_>, site: &str, members: Vec<(String, Value, Option<String>)>) -> TypeKind {
    let variants = members
        .into_iter()
        .map(|(name, v, desc)| {
            let vsite = format!("{site}.{name}");
            match &v {
                Value::Object(inner) if inner.contains_key("properties") && !inner.contains_key("$ref") => {
                    let _ = keywords_ok(r, &vsite, inner);
                    let fields = fields_of(r, doc, &vsite, &required_of(inner), &props_of(inner));
                    VariantDef { name, description: desc, fields, vref: None }
                }
                _ => {
                    let t = read_type(r, doc, &vsite, &v);
                    VariantDef { name, description: desc, fields: vec![], vref: Some(t) }
                }
            }
        })
        .collect();
    TypeKind::Enum { discriminator: String::new(), variants, repr: EnumRepr::External }
}

// ---------------------------------------------------------------------------
// Structs and fields
// ---------------------------------------------------------------------------

fn props_of(o: &Map<String, Value>) -> Vec<(String, Value)> {
    match o.get("properties") {
        Some(Value::Object(p)) => sorted(p).into_iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => vec![],
    }
}

pub(crate) fn required_of(o: &Map<String, Value>) -> Vec<String> {
    match o.get("required") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

fn fields_of(r: &mut Reader, doc: &Doc<'_>, site: &str, required: &[String], props: &[(String, Value)]) -> Vec<FieldDef> {
    props
        .iter()
        .map(|(k, v)| FieldDef {
            ty: read_type(r, doc, &format!("{site}.{k}"), v),
            name: k.clone(),
            description: description_of(v),
            required: required.contains(k),
            default: default_of(v),
        })
        .collect()
}

pub(crate) fn description_of(v: &Value) -> Option<String> {
    match v {
        Value::Object(o) => match o.get("description") {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn default_of(v: &Value) -> Option<Value> {
    match v {
        Value::Object(o) => o.get("default").cloned(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Named types
// ---------------------------------------------------------------------------

/// Every `$defs` entry of a document, as types of its namespace; one the
/// reader refuses is left out.
pub(crate) fn read_defs(r: &mut Reader, doc: &Doc<'_>) -> BTreeMap<String, TypeDef> {
    let mut out = BTreeMap::new();
    for (k, v) in sorted(doc.defs) {
        if k == "Json" && json_value(v) {
            continue;
        }
        if let Some(td) = read_named(r, doc, k, v) {
            out.insert(td.full_name(), td);
        }
    }
    out
}

fn read_named(r: &mut Reader, doc: &Doc<'_>, name: &str, v: &Value) -> Option<TypeDef> {
    let kind = read_kind(r, doc, &type_site(doc, name), v)?;
    Some(TypeDef { name: name.into(), namespace: doc.namespace.into(), description: description_of(v), kind })
}

fn read_kind(r: &mut Reader, doc: &Doc<'_>, site: &str, v: &Value) -> Option<TypeKind> {
    match v {
        Value::Bool(true) => Some(TypeKind::Alias { target: TypeRef::Json }),
        Value::Object(o) => {
            if !keywords_ok(r, site, o) {
                None
            } else if is_json_schema(o) {
                Some(TypeKind::Alias { target: TypeRef::Json })
            } else {
                read_kind_object(r, doc, site, o)
            }
        }
        _ => {
            r.refuse(site, "type", None, "not a schema");
            None
        }
    }
}

fn read_kind_object(r: &mut Reader, doc: &Doc<'_>, site: &str, o: &Map<String, Value>) -> Option<TypeKind> {
    if let Some((kw, members)) = union_of(o) {
        if o.contains_key("properties") {
            r.refuse(site, kw, None, "a struct with a union flattened into it has no IR form");
            return None;
        }
        return read_union_kind(r, doc, site, kw, members);
    }
    if let Some(Value::Array(values)) = o.get("enum") {
        let strings: Option<Vec<String>> = values.iter().map(|v| v.as_str().map(str::to_string)).collect();
        return match strings {
            Some(vs) if !vs.is_empty() => Some(TypeKind::StringEnum { values: vs }),
            _ => {
                r.refuse(site, "enum", None, "an enum of values that are not all strings");
                None
            }
        };
    }
    if o.contains_key("properties") {
        if let Some(ap) = o.get("additionalProperties") {
            if *ap != Value::Bool(false) {
                r.refuse(site, "additionalProperties", None, "a map beside properties (a flattened map) has no IR form");
            }
        }
        let mut fields = fields_of(r, doc, site, &required_of(o), &props_of(o));
        if let Some(w) = wrapped_ref(o) {
            fields.extend(wrapped_fields(r, doc, site, &w));
        }
        return Some(TypeKind::Struct { fields: nub_fields(fields) });
    }
    if let Some(Value::String(rf)) = o.get("$ref") {
        return Some(TypeKind::Alias { target: if is_json_ref(rf) { TypeRef::Json } else { qualified(doc, rf) } });
    }
    if let Some(Value::String(t)) = o.get("type") {
        if t != "array" && t != "object" {
            let rf = scalar_bounds(format_of(o).as_deref(), o);
            return Some(if rf.is_none() {
                TypeKind::Primitive { ty: t.clone(), format: format_of(o) }
            } else {
                TypeKind::Alias { target: TypeRef::Refined(Box::new(TypeRef::Primitive(t.clone(), format_of(o))), rf) }
            });
        }
    }
    if o.contains_key("const") && (!o.contains_key("type") || o.get("type") == Some(&Value::String("string".into()))) {
        if let Some(vs) = string_literals(&Value::Object(o.clone())) {
            return Some(TypeKind::StringEnum { values: vs });
        }
    }
    match read_type_object(r, doc, site, o) {
        TypeRef::Unknown => None,
        t => Some(TypeKind::Alias { target: t }),
    }
}

// ---------------------------------------------------------------------------
// A document's root
// ---------------------------------------------------------------------------

/// What a document's root (a method's `returns`, `error`, `progress` or
/// `input`) reads as.
pub(crate) struct RootRead {
    pub(crate) types: BTreeMap<String, TypeDef>,
    pub(crate) r#ref: TypeRef,
}

/// The schema less its `$defs` / `definitions`.
fn without_defs(o: &Map<String, Value>) -> Map<String, Value> {
    o.iter().filter(|(k, _)| *k != "$defs" && *k != "definitions").map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// A document's root as a type of its own, when it is one: its name (its
/// title, else `fallback`) and its schema less its `$defs`.
pub(crate) fn root_named(fallback: &str, v: &Value) -> Option<(String, Value)> {
    let Value::Object(o) = v else { return None };
    let title = match o.get("title") {
        Some(Value::String(t)) if !t.is_empty() => Some(t.clone()),
        _ => None,
    };
    let named = union_of(o).is_some_and(|(_, ms)| nullable_member(ms).is_none()) || o.contains_key("properties") || o.contains_key("enum");
    if named {
        return Some((title.unwrap_or_else(|| fallback.to_string()), Value::Object(without_defs(o))));
    }
    if let (Some(Value::String(rf)), false, Some(t)) = (o.get("$ref"), o.contains_key("properties"), &title) {
        if t != ref_name(rf) && rf != "#" {
            return Some((t.clone(), Value::Object(without_defs(o))));
        }
    }
    None
}

/// A named type's kind read alone, in its own document, its refusals
/// dropped: what the builder compares when two schemas give one name two
/// bodies.
pub(crate) fn read_kind_in(namespace: &str, doc_obj: &Map<String, Value>, name: &str, v: &Value) -> Option<TypeKind> {
    let mut doc = Doc::of(namespace, doc_obj);
    doc.root = Some(name.to_string());
    let mut r = Reader::default();
    read_kind(&mut r, &doc, &type_site(&doc, name), v)
}

/// A document's root: a named one is a type of its own; anything else is
/// the plain ref.
pub(crate) fn read_root(r: &mut Reader, shared: Option<&Doc<'_>>, namespace: &str, site: &str, fallback: &str, v: &Value) -> RootRead {
    match v {
        Value::Object(o) => {
            let doc0 = match shared {
                Some(d) => d.clone(),
                None => Doc::of(namespace, o),
            };
            let defs = if shared.is_none() { read_defs(r, &doc0) } else { BTreeMap::new() };
            match root_named(fallback, v) {
                Some((name, body)) => {
                    let mut doc = doc0.clone();
                    doc.root = Some(name.clone());
                    let tsite = type_site(&doc, &name);
                    let kind = match r.roots.get(&tsite) {
                        Some(k) => k.clone(),
                        None => {
                            let k = read_kind(r, &doc, &tsite, &body);
                            r.roots.insert(tsite.clone(), k.clone());
                            k
                        }
                    };
                    let rf = TypeRef::Named(QualifiedName { namespace: namespace.into(), local: name.clone() });
                    match kind {
                        Some(k) => {
                            let td = TypeDef { name, namespace: namespace.into(), description: description_of(v), kind: k };
                            let mut types = defs;
                            types.insert(td.full_name(), td);
                            RootRead { types, r#ref: rf }
                        }
                        None => RootRead { types: defs, r#ref: TypeRef::Unknown },
                    }
                }
                None => {
                    let t = read_type(r, &doc0, site, &Value::Object(without_defs(o)));
                    RootRead { types: defs, r#ref: t }
                }
            }
        }
        other => {
            let doc = Doc { namespace, defs: empty_map(), root: None };
            let t = read_type(r, &doc, site, other);
            RootRead { types: BTreeMap::new(), r#ref: t }
        }
    }
}
