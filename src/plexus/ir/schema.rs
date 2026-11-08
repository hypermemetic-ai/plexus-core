//! A plugin schema as synapse reads it: plexus-protocol's `FromJSON
//! PluginSchema` / `MethodSchema`, over the JSON a `<path>.schema` call
//! answers — its defaults (`description` `""`, `role` rpc, a 0.7.0 method's
//! `streaming` for its cardinality), its `null` as absent, and its refusals:
//! a schema synapse cannot parse is no schema.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::types::{Cardinality, Deprecation, MethodRole};

pub(crate) struct PluginIn<'a> {
    pub(crate) hash: String,
    pub(crate) methods: Vec<MethodIn<'a>>,
    /// Each child summary's namespace (`None`: a leaf).
    pub(crate) children: Option<Vec<String>>,
    pub(crate) request: Option<&'a Value>,
    pub(crate) roles: Option<BTreeMap<String, Vec<String>>>,
}

pub(crate) struct ParamIn {
    pub(crate) name: String,
    pub(crate) deprecation: Option<Deprecation>,
}

pub(crate) struct MethodIn<'a> {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) params: Option<&'a Value>,
    pub(crate) returns: Cow<'a, Value>,
    pub(crate) error: Option<&'a Value>,
    pub(crate) progress: Option<&'a Value>,
    pub(crate) input: Option<&'a Value>,
    pub(crate) cardinality: Cardinality,
    pub(crate) param_schemas: Option<Vec<ParamIn>>,
    pub(crate) role: MethodRole,
    pub(crate) long_description: Option<String>,
    pub(crate) grant: Option<String>,
    pub(crate) target: Option<String>,
}

impl MethodIn<'_> {
    /// The method's schema documents, each by the name a title collision
    /// gives it: `params`, `returns`, `error`, `progress`, `input`.
    pub(crate) fn docs(&self) -> Vec<(&'static str, &Value)> {
        let mut out = Vec::new();
        if let Some(p) = self.params {
            out.push(("params", p));
        }
        out.push(("returns", self.returns.as_ref()));
        if let Some(e) = self.error {
            out.push(("error", e));
        }
        if let Some(p) = self.progress {
            out.push(("progress", p));
        }
        if let Some(i) = self.input {
            out.push(("input", i));
        }
        out
    }
}

/// `o .:? k`: absent or `null` is `None`.
fn opt<'a>(o: &'a Map<String, Value>, k: &str) -> Option<&'a Value> {
    match o.get(k) {
        None | Some(Value::Null) => None,
        Some(v) => Some(v),
    }
}

fn opt_str(o: &Map<String, Value>, k: &str) -> Result<Option<String>, String> {
    match opt(o, k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("`{k}` is not a string")),
    }
}

fn deprecation(v: Option<&Value>) -> Result<Option<Deprecation>, String> {
    let Some(v) = v else { return Ok(None) };
    let Value::Object(o) = v else { return Err("a deprecation is not an object".into()) };
    let field = |k: &str| match o.get(k) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("a deprecation's `{k}` is not a string")),
    };
    Ok(Some(Deprecation { since: field("since")?, removed_in: field("removed_in")?, message: field("message")? }))
}

fn role(v: Option<&Value>) -> Result<MethodRole, String> {
    let Some(v) = v else { return Ok(MethodRole::Rpc) };
    let Value::Object(o) = v else { return Err("a role is not an object".into()) };
    match o.get("kind") {
        Some(Value::String(k)) if k == "rpc" => Ok(MethodRole::Rpc),
        Some(Value::String(k)) if k == "static_child" => Ok(MethodRole::StaticChild),
        Some(Value::String(k)) if k == "dynamic_child" => Ok(MethodRole::DynamicChild {
            list_method: opt_str(o, "list_method")?,
            search_method: opt_str(o, "search_method")?,
        }),
        Some(Value::String(k)) => Err(format!("Unknown MethodRole kind: {k}")),
        _ => Err("a role names no kind".into()),
    }
}

fn method(v: &Value) -> Result<MethodIn<'_>, String> {
    let Value::Object(o) = v else { return Err("a method is not an object".into()) };
    let name = match o.get("name") {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("a method names no name".into()),
    };
    // RETURNS-36: a 0.8 method states its cardinality and returns; a 0.7.0
    // one its streaming flag, and its missing returns is `{}`.
    let cardinality = match o.get("cardinality") {
        Some(Value::String(c)) if c == "one" => Cardinality::One,
        Some(Value::String(c)) if c == "many" => Cardinality::Many,
        Some(other) => return Err(format!("unknown cardinality: {other}")),
        None => match o.get("streaming") {
            Some(Value::Bool(true)) => Cardinality::Many,
            Some(Value::Bool(false)) => Cardinality::One,
            _ => return Err("a method states neither cardinality (plexus 0.8) nor streaming (0.7.0)".into()),
        },
    };
    let returns = if o.contains_key("cardinality") {
        match o.get("returns") {
            Some(r) => Cow::Borrowed(r),
            None => return Err(format!("method {name} states no returns")),
        }
    } else {
        match opt(o, "returns") {
            Some(r) => Cow::Borrowed(r),
            None => Cow::Owned(Value::Object(Map::new())),
        }
    };
    let param_schemas = match opt(o, "param_schemas") {
        None => None,
        Some(Value::Array(ps)) => Some(
            ps.iter()
                .map(|p| {
                    let Value::Object(po) = p else { return Err("a param schema is not an object".to_string()) };
                    let name = match po.get("name") {
                        Some(Value::String(s)) => s.clone(),
                        _ => return Err("a param schema names no name".to_string()),
                    };
                    Ok(ParamIn { name, deprecation: deprecation(opt(po, "deprecation"))? })
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err("param_schemas is not a list".into()),
    };
    Ok(MethodIn {
        description: opt_str(o, "description")?.unwrap_or_default(),
        params: opt(o, "params"),
        returns,
        error: opt(o, "error"),
        progress: opt(o, "progress"),
        input: opt(o, "input"),
        cardinality,
        param_schemas,
        role: role(opt(o, "role"))?,
        long_description: opt_str(o, "long_description")?,
        grant: opt_str(o, "grant")?,
        target: opt_str(o, "target")?,
        name,
    })
}

/// A plugin schema, read as synapse reads it.
pub(crate) fn plugin(v: &Value) -> Result<PluginIn<'_>, String> {
    let Value::Object(o) = v else { return Err("a schema is not an object".into()) };
    if !matches!(o.get("namespace"), Some(Value::String(_))) {
        return Err("a schema names no namespace".into());
    }
    let methods = match opt(o, "methods") {
        None => vec![],
        Some(Value::Array(ms)) => ms.iter().map(method).collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("methods is not a list".into()),
    };
    let children = match opt(o, "children") {
        None => None,
        Some(Value::Array(cs)) => Some(
            cs.iter()
                .map(|c| match c.get("namespace") {
                    Some(Value::String(ns)) => Ok(ns.clone()),
                    _ => Err("a child names no namespace".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err("children is not a list".into()),
    };
    // AUTH-3's roles: read when they are role → grants, else none
    let roles = match opt(o, "roles") {
        Some(Value::Object(rs)) => rs
            .iter()
            .map(|(k, v)| match v {
                Value::Array(gs) => gs.iter().map(|g| g.as_str().map(str::to_string)).collect::<Option<Vec<_>>>().map(|gs| (k.clone(), gs)),
                _ => None,
            })
            .collect::<Option<BTreeMap<_, _>>>(),
        _ => None,
    };
    Ok(PluginIn {
        hash: opt_str(o, "hash")?.unwrap_or_default(),
        methods,
        children,
        request: opt(o, "request"),
        roles,
    })
}
