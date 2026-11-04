//! SYNAPSE-CC-9: the two walks that hold a schema to IR 2.1's contract.
//!
//! - [`untyped_sites`]: every schema position that is neither a typed schema
//!   nor the JSON type — a bare `{"type":"object"}` (no `properties`, no
//!   `additionalProperties`), a bare `{"type":"array"}` (no `items`), a
//!   `type` list that is neither one type (± `null`) nor the whole JSON set
//!   (`["object","boolean"]`) — and an RPC method with no `returns`
//!   (`<ns>.<method> returns`). synapse refuses each (SYNAPSE-CC-8); a
//!   crate's test asserts the list is empty (SYNAPSE-CC-12). A
//!   `serde_json::Value` is the JSON type (`true`, `{}`, annotations alone,
//!   or `{"type": JSON_TYPES}` as plexus spells it), a type like any other.
//! - [`foreign_keywords`]: every keyword in a type position outside
//!   [`CONTRACT_KEYWORDS`], as `<site>: <keyword>`.
//!
//! Site names are the contract's: `<ns>.<Type>[.<variant>].<field>`,
//! `<ns>.<method>(<param>)`, `<ns>.<method> returns`, with the suffixes `[]`
//! (element), `?` (optional or nullable), `{}` (map value) and `.N` (tuple
//! element). `<ns>` is the plugin's namespace as it names itself (synapse
//! writes the protocol root's as `""`). A variant is named by its tag's
//! string `const` (internally tagged), by its one property (externally
//! tagged), else by its `title`, else by its index. A `$ref` is not followed:
//! every `$defs` entry is walked once, as `<ns>.<Name>`. A parameter the
//! server injects (`x-plexus-source` other than `{"from":"rpc"}`) is no
//! client's to type and is skipped.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::schema::{is_json_type, MethodRole, PluginSchema, CONTRACT_KEYWORDS};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Untyped,
    Foreign,
}

struct Walk<'a> {
    ns: &'a str,
    mode: Mode,
    out: BTreeSet<String>,
}

/// Every untyped site in this plugin's schema (its RPC methods'
/// params, returns, request/response types and input, and its request
/// struct), sorted. Empty is the contract.
pub fn untyped_sites(plugin: &PluginSchema) -> Vec<String> {
    walk_plugin(plugin, Mode::Untyped)
}

/// Every keyword outside the closed list, as `<site>: <keyword>`, sorted.
pub fn foreign_keywords(plugin: &PluginSchema) -> Vec<String> {
    walk_plugin(plugin, Mode::Foreign)
}

/// [`untyped_sites`] for one type's schema (`schema_for!(T)`), its root
/// named `<ns>.<title>`.
pub fn schema_untyped_sites(ns: &str, schema: &schemars::Schema) -> Vec<String> {
    let mut w = Walk { ns, mode: Mode::Untyped, out: BTreeSet::new() };
    w.root(ns, &serde_json::to_value(schema).unwrap_or(Value::Null));
    w.out.into_iter().collect()
}

fn walk_plugin(plugin: &PluginSchema, mode: Mode) -> Vec<String> {
    let ns = plugin.namespace.as_str();
    let mut w = Walk { ns, mode, out: BTreeSet::new() };
    let json = |s: &schemars::Schema| serde_json::to_value(s).unwrap_or(Value::Null);
    for m in &plugin.methods {
        if !matches!(m.role, MethodRole::Rpc) {
            continue;
        }
        let path = format!("{ns}.{}", m.name);
        if let Some(p) = &m.params {
            w.params(&path, &json(p));
        }
        // RETURNS-5: `returns` is always present; the empty schema (any
        // value, what `MethodSchema::new` starts at) is a return no type
        // was given for.
        let returns = json(&m.returns);
        if returns == Value::Bool(true) || returns.as_object().is_some_and(|o| o.is_empty()) {
            w.untyped(&format!("{path} returns"));
        } else {
            w.root(&format!("{path} returns"), &returns);
        }
        for (what, s) in [
            ("error", &m.error),
            ("progress", &m.progress),
            ("request_type", &m.request_type),
            ("response_type", &m.response_type),
            ("input", &m.input),
        ] {
            if let Some(s) = s {
                w.root(&format!("{path} {what}"), &json(s));
            }
        }
    }
    if let Some(req) = &plugin.request {
        w.params(&format!("{ns} request"), req);
    }
    w.out.into_iter().collect()
}

fn is_injected(v: &Value) -> bool {
    match v.get("x-plexus-source") {
        Some(src) => src.get("from").and_then(Value::as_str) != Some("rpc"),
        None => false,
    }
}

fn is_null_schema(v: &Value) -> bool {
    v.get("type").and_then(Value::as_str) == Some("null")
}

fn opt(site: &str) -> String {
    if site.ends_with('?') { site.to_string() } else { format!("{site}?") }
}

impl Walk<'_> {
    fn untyped(&mut self, site: &str) {
        if self.mode == Mode::Untyped {
            self.out.insert(site.to_string());
        }
    }

    fn keywords(&mut self, site: &str, o: &Map<String, Value>) {
        if self.mode == Mode::Foreign {
            for k in o.keys().filter(|k| !CONTRACT_KEYWORDS.contains(&k.as_str())) {
                self.out.insert(format!("{site}: {k}"));
            }
        }
    }

    fn defs(&mut self, v: &Value) {
        for key in ["$defs", "definitions"] {
            if let Some(defs) = v.get(key).and_then(Value::as_object) {
                for (name, d) in defs {
                    self.node(&format!("{}.{name}", self.ns), d);
                }
            }
        }
    }

    /// A document root: a `returns`, a request/response type, a type of its
    /// own. A titled struct or union is the type of that name.
    fn root(&mut self, site: &str, v: &Value) {
        self.defs(v);
        let named = v.get("title").and_then(Value::as_str).filter(|_| {
            v.get("$ref").is_none()
                && (v.get("properties").is_some() || v.get("oneOf").is_some() || v.get("anyOf").is_some())
        });
        match named {
            Some(t) => self.node(&format!("{}.{t}", self.ns), v),
            None => self.node(site, v),
        }
    }

    /// A params object: each property is `<path>(<param>)`.
    fn params(&mut self, path: &str, v: &Value) {
        self.defs(v);
        let Some(o) = v.as_object() else { return self.node(path, v) };
        self.keywords(path, o);
        if let Some(props) = o.get("properties").and_then(Value::as_object) {
            for (k, p) in props.iter().filter(|(_, p)| !is_injected(p)) {
                self.node(&format!("{path}({k})"), p);
            }
        }
    }

    fn node(&mut self, site: &str, v: &Value) {
        if is_json_type(v) {
            if let Value::Object(o) = v {
                self.keywords(site, o);
            }
            return; // the JSON type: a serde_json::Value
        }
        let Value::Object(o) = v else { return };
        self.keywords(site, o);
        if is_injected(v) || o.contains_key("$ref") {
            return;
        }
        let mut site = site.to_string();
        let mut typed = o.contains_key("enum") || o.contains_key("const");
        match o.get("type") {
            Some(Value::String(t)) if t != "object" && t != "array" => typed = true,
            Some(Value::Array(ts)) => {
                let kinds: Vec<&str> = ts.iter().filter_map(Value::as_str).filter(|t| *t != "null").collect();
                if kinds.len() < ts.len() {
                    site = opt(&site);
                }
                match kinds.as_slice() {
                    [] => typed = true,
                    [one] if *one != "object" && *one != "array" => typed = true,
                    [_] => {}
                    _ if !typed => return self.untyped(&site),
                    _ => {}
                }
            }
            _ => {}
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(arr) = o.get(key).and_then(Value::as_array) {
                typed = true;
                let real: Vec<&Value> = arr.iter().filter(|x| !is_null_schema(x)).collect();
                if real.len() == 1 && real.len() < arr.len() {
                    self.node(&opt(&site), real[0]);
                } else {
                    for (i, var) in real.into_iter().enumerate() {
                        self.variant(&site, i, var);
                    }
                }
            }
        }
        if let Some(arr) = o.get("allOf").and_then(Value::as_array) {
            typed = true;
            for x in arr {
                self.node(&site, x);
            }
        }
        if let Some(props) = o.get("properties").and_then(Value::as_object) {
            typed = true;
            let required: BTreeSet<&str> = o
                .get("required")
                .and_then(Value::as_array)
                .map(|r| r.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            for (k, p) in props.iter().filter(|(_, p)| !is_injected(p)) {
                let s = format!("{site}.{k}");
                let s = if required.contains(k.as_str()) { s } else { opt(&s) };
                self.node(&s, p);
            }
        }
        if let Some(items) = o.get("items") {
            typed = true;
            self.node(&format!("{site}[]"), items);
        }
        if let Some(arr) = o.get("prefixItems").and_then(Value::as_array) {
            typed = true;
            for (i, x) in arr.iter().enumerate() {
                self.node(&format!("{site}.{i}"), x);
            }
        }
        match o.get("additionalProperties") {
            Some(ap @ (Value::Object(_) | Value::Bool(true))) if !o.contains_key("properties") => {
                typed = true;
                self.node(&format!("{site}{{}}"), ap);
            }
            _ => {}
        }
        if !typed {
            self.untyped(&site);
        }
    }

    fn variant(&mut self, site: &str, i: usize, var: &Value) {
        if var.get("$ref").is_some() && var.get("properties").is_none() {
            return self.node(site, var); // checks its keywords; not followed
        }
        let props = var.get("properties").and_then(Value::as_object);
        let tag = props.and_then(|ps| {
            ps.values().find_map(|p| {
                p.get("const").and_then(Value::as_str).or_else(|| match p.get("enum").and_then(Value::as_array) {
                    Some(e) if e.len() == 1 => e[0].as_str(),
                    _ => None,
                })
            })
        });
        if let Some(t) = tag {
            return self.node(&format!("{site}.{t}"), var);
        }
        if let Some(ps) = props.filter(|ps| ps.len() == 1) {
            let (k, inner) = ps.iter().next().unwrap();
            if let Some(o) = var.as_object() {
                self.keywords(&format!("{site}.{k}"), o);
            }
            return self.node(&format!("{site}.{k}"), inner);
        }
        let name = var
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| var.get("const").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| i.to_string());
        self.node(&format!("{site}.{name}"), var);
    }
}
