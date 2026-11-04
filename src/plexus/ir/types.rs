//! The IR's types, and their JSON as synapse writes it — aeson's generic
//! encoding of `Synapse.IR.Types` (a sum is `{"tag": …, "contents": …}`, a
//! record's fields by name, `Nothing` as `null`), with the fields synapse
//! leaves out when empty left out here too.

use std::collections::BTreeMap;

use serde_json::{json, Map, Number, Value};

/// The IR format written: 3.0 (RETURNS-13), synapse's `currentIrVersion`.
pub const IR_VERSION: &str = "3.0";

/// A type's name: its namespace (`""` for the service's root) and its name
/// there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QualifiedName {
    pub namespace: String,
    pub local: String,
}

impl QualifiedName {
    /// The name as [`Ir::types`] keys it: `<namespace>.<local>` (the root's
    /// types are `.Name`).
    pub fn key(&self) -> String {
        format!("{}.{}", self.namespace, self.local)
    }

    fn to_json(&self) -> Value {
        json!({ "qnNamespace": self.namespace, "qnLocalName": self.local })
    }
}

/// A reference to a type (synapse's `TypeRef`).
#[derive(Debug, Clone, PartialEq)]
pub enum TypeRef {
    /// A named type, with a [`TypeDef`] in [`Ir::types`].
    Named(QualifiedName),
    /// A primitive and its format (`integer`, `uint32`).
    Primitive(String, Option<String>),
    Array(Box<TypeRef>),
    Optional(Box<TypeRef>),
    /// The JSON type: any JSON value.
    Json,
    /// Not typed: only at a site [`Ir::refusals`] names.
    Unknown,
    /// An object of string keys and these values.
    Map(Box<TypeRef>),
    Tuple(Vec<TypeRef>),
    /// A type with bounds its format does not imply.
    Refined(Box<TypeRef>, Refinements),
    /// A child's return: that child's client, by its full path.
    Child(String),
}

impl TypeRef {
    /// The refs directly inside this one.
    pub fn children(&self) -> Vec<&TypeRef> {
        match self {
            TypeRef::Array(t) | TypeRef::Optional(t) | TypeRef::Map(t) | TypeRef::Refined(t, _) => vec![t],
            TypeRef::Tuple(ts) => ts.iter().collect(),
            _ => vec![],
        }
    }

    /// Apply `f` to every ref, bottom up (synapse's `mapRef`).
    pub(crate) fn map(self, f: &impl Fn(TypeRef) -> TypeRef) -> TypeRef {
        let inner = match self {
            TypeRef::Array(t) => TypeRef::Array(Box::new(t.map(f))),
            TypeRef::Optional(t) => TypeRef::Optional(Box::new(t.map(f))),
            TypeRef::Map(t) => TypeRef::Map(Box::new(t.map(f))),
            TypeRef::Tuple(ts) => TypeRef::Tuple(ts.into_iter().map(|t| t.map(f)).collect()),
            TypeRef::Refined(t, r) => TypeRef::Refined(Box::new(t.map(f)), r),
            other => other,
        };
        f(inner)
    }

    pub fn to_json(&self) -> Value {
        let tagged = |tag: &str, contents: Value| json!({ "tag": tag, "contents": contents });
        match self {
            TypeRef::Named(qn) => tagged("RefNamed", qn.to_json()),
            TypeRef::Primitive(t, f) => tagged("RefPrimitive", json!([t, f])),
            TypeRef::Array(t) => tagged("RefArray", t.to_json()),
            TypeRef::Optional(t) => tagged("RefOptional", t.to_json()),
            TypeRef::Json => json!({ "tag": "RefJson" }),
            TypeRef::Unknown => json!({ "tag": "RefUnknown" }),
            TypeRef::Map(t) => tagged("RefMap", t.to_json()),
            TypeRef::Tuple(ts) => tagged("RefTuple", Value::Array(ts.iter().map(TypeRef::to_json).collect())),
            TypeRef::Refined(t, r) => tagged("RefRefined", json!([t.to_json(), r.to_json()])),
            TypeRef::Child(path) => tagged("RefChild", json!(path)),
        }
    }
}

/// The bounds of a [`TypeRef::Refined`] — only those its format does not
/// already imply. Each is a JSON Schema keyword, left out when absent.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Refinements {
    pub minimum: Option<Number>,
    pub maximum: Option<Number>,
    pub exclusive_minimum: Option<Number>,
    pub exclusive_maximum: Option<Number>,
    pub min_length: Option<i64>,
    pub max_length: Option<i64>,
    pub pattern: Option<String>,
    pub min_items: Option<i64>,
    pub max_items: Option<i64>,
}

impl Refinements {
    pub fn is_none(&self) -> bool {
        *self == Refinements::default()
    }

    fn to_json(&self) -> Value {
        let mut o = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                o.insert(k.into(), v);
            }
        };
        put("minimum", self.minimum.clone().map(Value::Number));
        put("maximum", self.maximum.clone().map(Value::Number));
        put("exclusiveMinimum", self.exclusive_minimum.clone().map(Value::Number));
        put("exclusiveMaximum", self.exclusive_maximum.clone().map(Value::Number));
        put("minLength", self.min_length.map(Value::from));
        put("maxLength", self.max_length.map(Value::from));
        put("pattern", self.pattern.clone().map(Value::from));
        put("minItems", self.min_items.map(Value::from));
        put("maxItems", self.max_items.map(Value::from));
        Value::Object(o)
    }
}

/// How an enum's variants are told apart on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumRepr {
    /// The tag is a property of each variant (the default; left out of the JSON).
    Internal,
    /// `{"variant": {…}}`; the discriminator is `""`.
    External,
    /// The variant's own shape; each names its type in `vdRef`.
    Untagged,
}

/// What kind of type a [`TypeDef`] is.
#[derive(Debug, Clone, PartialEq)]
pub enum TypeKind {
    Struct { fields: Vec<FieldDef> },
    Enum { discriminator: String, variants: Vec<VariantDef>, repr: EnumRepr },
    StringEnum { values: Vec<String> },
    Alias { target: TypeRef },
    Primitive { ty: String, format: Option<String> },
}

impl TypeKind {
    /// Apply `g` to every ref the kind holds (synapse's `mapKindRefs`).
    pub(crate) fn map_refs(self, g: &impl Fn(TypeRef) -> TypeRef) -> TypeKind {
        let field = |f: FieldDef| FieldDef { ty: g(f.ty), ..f };
        match self {
            TypeKind::Struct { fields } => TypeKind::Struct { fields: fields.into_iter().map(field).collect() },
            TypeKind::Enum { discriminator, variants, repr } => TypeKind::Enum {
                discriminator,
                variants: variants
                    .into_iter()
                    .map(|v| VariantDef { fields: v.fields.into_iter().map(field).collect(), vref: v.vref.map(g), ..v })
                    .collect(),
                repr,
            },
            TypeKind::Alias { target } => TypeKind::Alias { target: g(target) },
            other => other,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            TypeKind::Struct { fields } => json!({ "tag": "KindStruct", "ksFields": fields.iter().map(FieldDef::to_json).collect::<Vec<_>>() }),
            TypeKind::Enum { discriminator, variants, repr } => {
                let mut o = json!({
                    "tag": "KindEnum",
                    "keDiscriminator": discriminator,
                    "keVariants": variants.iter().map(VariantDef::to_json).collect::<Vec<_>>(),
                });
                match repr {
                    EnumRepr::Internal => {}
                    EnumRepr::External => {
                        o["keRepr"] = json!("external");
                    }
                    EnumRepr::Untagged => {
                        o["keRepr"] = json!("untagged");
                    }
                }
                o
            }
            TypeKind::StringEnum { values } => json!({ "tag": "KindStringEnum", "kseValues": values }),
            TypeKind::Alias { target } => json!({ "tag": "KindAlias", "kaTarget": target.to_json() }),
            TypeKind::Primitive { ty, format } => json!({ "tag": "KindPrimitive", "kpType": ty, "kpFormat": format }),
        }
    }
}

/// A field of a struct or a variant.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDef {
    pub name: String,
    pub ty: TypeRef,
    pub description: Option<String>,
    pub required: bool,
    pub default: Option<Value>,
}

impl FieldDef {
    fn to_json(&self) -> Value {
        json!({
            "fdName": self.name,
            "fdType": self.ty.to_json(),
            "fdDescription": self.description,
            "fdRequired": self.required,
            "fdDefault": self.default,
        })
    }
}

/// A variant of an enum.
#[derive(Debug, Clone, PartialEq)]
pub struct VariantDef {
    pub name: String,
    pub description: Option<String>,
    pub fields: Vec<FieldDef>,
    /// An untagged (or external non-struct) variant's type; left out when absent.
    pub vref: Option<TypeRef>,
}

impl VariantDef {
    fn to_json(&self) -> Value {
        let mut o = json!({
            "vdName": self.name,
            "vdDescription": self.description,
            "vdFields": self.fields.iter().map(FieldDef::to_json).collect::<Vec<_>>(),
        });
        if let Some(r) = &self.vref {
            o["vdRef"] = r.to_json();
        }
        o
    }
}

/// A named type.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDef {
    pub name: String,
    pub namespace: String,
    pub description: Option<String>,
    pub kind: TypeKind,
}

impl TypeDef {
    /// `<namespace>.<name>`, as [`Ir::types`] keys it.
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.namespace, self.name)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "tdName": self.name,
            "tdNamespace": self.namespace,
            "tdDescription": self.description,
            "tdKind": self.kind.to_json(),
        })
    }
}

/// One item or many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    One,
    Many,
}

/// A method's structural role (synapse's `MethodRole`, the schema's `role`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodRole {
    Rpc,
    StaticChild,
    DynamicChild { list_method: Option<String>, search_method: Option<String> },
}

impl MethodRole {
    fn to_json(&self) -> Value {
        match self {
            MethodRole::Rpc => json!({ "kind": "rpc" }),
            MethodRole::StaticChild => json!({ "kind": "static_child" }),
            MethodRole::DynamicChild { list_method, search_method } => {
                let mut o = json!({ "kind": "dynamic_child" });
                if let Some(l) = list_method {
                    o["list_method"] = json!(l);
                }
                if let Some(s) = search_method {
                    o["search_method"] = json!(s);
                }
                o
            }
        }
    }
}

/// A parameter's deprecation (the schema's `param_schemas[].deprecation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deprecation {
    pub since: String,
    pub removed_in: String,
    pub message: String,
}

/// A parameter a client sends.
#[derive(Debug, Clone, PartialEq)]
pub struct ParamDef {
    pub name: String,
    pub ty: TypeRef,
    pub description: Option<String>,
    pub required: bool,
    pub default: Option<Value>,
    pub deprecation: Option<Deprecation>,
    /// Its `x-plexus-source`, as written.
    pub source: Option<Value>,
    /// Its `x-plexus-values`; left out when absent.
    pub values: Option<Vec<String>>,
}

impl ParamDef {
    fn to_json(&self) -> Value {
        let mut o = json!({
            "pdName": self.name,
            "pdType": self.ty.to_json(),
            "pdDescription": self.description,
            "pdRequired": self.required,
            "pdDefault": self.default,
            "pdDeprecation": self.deprecation.as_ref().map(|d| json!({ "since": d.since, "removed_in": d.removed_in, "message": d.message })),
            "pdSource": self.source,
        });
        if let Some(vs) = &self.values {
            o["pdValues"] = json!(vs);
        }
        o
    }
}

/// A parameter the server supplies (its `x-plexus-source` is not `rpc`).
#[derive(Debug, Clone, PartialEq)]
pub struct InjectedParam {
    pub name: String,
    pub source: Value,
    pub description: Option<String>,
}

/// A method: its contract read from its schema, never inferred.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodDef {
    pub name: String,
    pub full_path: String,
    pub namespace: String,
    pub description: Option<String>,
    pub params: Vec<ParamDef>,
    pub returns: TypeRef,
    pub error: Option<TypeRef>,
    pub progress: Option<TypeRef>,
    pub cardinality: Cardinality,
    pub bidir_type: Option<TypeRef>,
    pub bidir_response_type: Option<TypeRef>,
    pub bidir_response_schema: Option<Value>,
    pub role: MethodRole,
    pub grant: Option<String>,
    pub target: Option<String>,
    pub long_description: Option<String>,
    pub injected: Vec<InjectedParam>,
    pub input: Option<TypeRef>,
}

impl MethodDef {
    pub fn to_json(&self) -> Value {
        let r = |t: &Option<TypeRef>| t.as_ref().map(TypeRef::to_json);
        let mut o = json!({
            "mdName": self.name,
            "mdFullPath": self.full_path,
            "mdNamespace": self.namespace,
            "mdDescription": self.description,
            "mdParams": self.params.iter().map(ParamDef::to_json).collect::<Vec<_>>(),
            "mdReturns": self.returns.to_json(),
            "mdError": r(&self.error),
            "mdProgress": r(&self.progress),
            "mdCardinality": match self.cardinality { Cardinality::One => "one", Cardinality::Many => "many" },
            "mdBidirType": r(&self.bidir_type),
            "mdBidirResponseType": r(&self.bidir_response_type),
            "mdBidirResponseSchema": self.bidir_response_schema,
            "mdRole": self.role.to_json(),
        });
        if let Some(g) = &self.grant {
            o["mdGrant"] = json!(g);
        }
        if let Some(t) = &self.target {
            o["mdTarget"] = json!(t);
        }
        if let Some(l) = &self.long_description {
            o["mdLongDescription"] = json!(l);
        }
        if !self.injected.is_empty() {
            o["mdInjected"] = Value::Array(
                self.injected
                    .iter()
                    .map(|i| json!({ "ipName": i.name, "ipSource": i.source, "ipDescription": i.description }))
                    .collect(),
            );
        }
        if let Some(i) = &self.input {
            o["mdInput"] = i.to_json();
        }
        o
    }
}

/// A site the reader could not type, named (synapse's `Refusal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Where: `ns.Type[.variant].field`, `path(param)`, `path returns`, …
    pub site: String,
    /// The keyword it could not read.
    pub keyword: String,
    /// For a union, the first member it could not read.
    pub variant: Option<i64>,
    pub detail: String,
}

impl Refusal {
    fn to_json(&self) -> Value {
        json!({ "rfSite": self.site, "rfKeyword": self.keyword, "rfVariant": self.variant, "rfDetail": self.detail })
    }
}

/// A plugin's hashes (synapse's `PluginHashInfo`: its one hash, three times).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHashInfo {
    pub hash: String,
    pub self_hash: String,
    pub children_hash: String,
}

/// The IR of a service, or of part of it: its types once each, its methods
/// referring to them.
#[derive(Debug, Clone, PartialEq)]
pub struct Ir {
    pub version: String,
    pub backend: String,
    pub hash: Option<String>,
    pub types: BTreeMap<String, TypeDef>,
    pub methods: BTreeMap<String, MethodDef>,
    pub plugins: BTreeMap<String, Vec<String>>,
    pub plugin_hashes: Option<BTreeMap<String, PluginHashInfo>>,
    pub plugin_requests: Option<BTreeMap<String, Value>>,
    pub plugin_roles: Option<BTreeMap<String, BTreeMap<String, Vec<String>>>>,
    pub refusals: Vec<Refusal>,
}

impl Ir {
    /// synapse's `emptyIR`.
    pub(crate) fn empty() -> Ir {
        Ir {
            version: IR_VERSION.into(),
            backend: String::new(),
            hash: None,
            types: BTreeMap::new(),
            methods: BTreeMap::new(),
            plugins: BTreeMap::new(),
            plugin_hashes: None,
            plugin_requests: None,
            plugin_roles: None,
            refusals: Vec::new(),
        }
    }

    /// The IR as synapse writes it (`irMetadata` is `null`: the toolchain
    /// and the clock are the client's to record).
    pub fn to_json(&self) -> Value {
        let mut o = json!({
            "irVersion": self.version,
            "irBackend": self.backend,
            "irHash": self.hash,
            "irMetadata": null,
            "irTypes": self.types.iter().map(|(k, t)| (k.clone(), t.to_json())).collect::<Map<_, _>>(),
            "irMethods": self.methods.iter().map(|(k, m)| (k.clone(), m.to_json())).collect::<Map<_, _>>(),
            "irPlugins": self.plugins,
            "irPluginHashes": self.plugin_hashes.as_ref().map(|hs| hs.iter().map(|(k, h)| (k.clone(), json!({
                "phiHash": h.hash, "phiSelfHash": h.self_hash, "phiChildrenHash": h.children_hash,
            }))).collect::<Map<_, _>>()),
            "irPluginRequests": self.plugin_requests,
        });
        if let Some(roles) = &self.plugin_roles {
            o["irPluginRoles"] = json!(roles);
        }
        if !self.refusals.is_empty() {
            o["irRefusals"] = Value::Array(self.refusals.iter().map(Refusal::to_json).collect());
        }
        o
    }
}
