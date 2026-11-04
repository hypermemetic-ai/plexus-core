//! What a service's `ir` method answers ([`DynamicHub::service_ir`]): the
//! IR of the walks from the namespaces asked for, or why not — and what the
//! service keeps of it.
//!
//! [`DynamicHub::service_ir`]: crate::plexus::DynamicHub::service_ir

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;

use super::build::{build, IrBuildError};

/// A service's IR, as `<service>.ir` answers it: IR 3.0 — the document
/// synapse's `buildIRFromSchemas` builds from the same schemas (its
/// `irBackend` the service's namespace, its `irMetadata` `null`). Kept as
/// its JSON, written once.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceIr(pub Arc<RawValue>);

impl ServiceIr {
    /// The IR as a JSON value.
    pub fn to_value(&self) -> Value {
        serde_json::from_str(self.0.get()).unwrap_or(Value::Null)
    }
}

impl PartialEq for ServiceIr {
    fn eq(&self, other: &Self) -> bool {
        self.0.get() == other.0.get()
    }
}

impl JsonSchema for ServiceIr {
    fn schema_name() -> Cow<'static, str> {
        "ServiceIr".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "The service's IR 3.0: every type once (irTypes), each method referring to them (irMethods) — as synapse's buildIRFromSchemas builds it from the same schemas"
        })
    }
}

/// Why a service writes no IR for what was asked. (A title collision is no
/// reason: the walk refuses that activation into the IR's `irRefusals`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IrError {
    /// A namespace asked for is not one the caller's view of the service shows.
    NotFound { namespace: String, message: String },
    /// A schema the service answered is one synapse could not read.
    Unreadable { namespace: String, message: String },
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrError::NotFound { message, .. } | IrError::Unreadable { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for IrError {}

/// The walks' roots for `namespaces` (dotted paths; none, `""` or the
/// service's own namespace: the root): sorted, each once, and none under
/// another named one — its walk reads it already.
pub fn roots(service: &str, namespaces: &[String]) -> Vec<Vec<String>> {
    let mut paths: Vec<Vec<String>> = namespaces
        .iter()
        .map(|n| if n.is_empty() || n == service { vec![] } else { n.split('.').map(str::to_string).collect() })
        .collect();
    if paths.is_empty() {
        return vec![vec![]];
    }
    paths.sort();
    paths.dedup();
    let all = paths.clone();
    paths.retain(|p| !all.iter().any(|q| q != p && p.starts_with(q)));
    paths
}

fn dotted(path: &[String]) -> String {
    path.join(".")
}

/// The answer for `roots` over `schemas` (every `<path>.schema` the walks
/// read, by path): the IR, or why not.
pub fn answer(service: &str, roots: &[Vec<String>], schemas: &BTreeMap<Vec<String>, Value>) -> Result<ServiceIr, IrError> {
    match build(service, roots, schemas) {
        Ok(ir) => {
            let text = serde_json::to_string(&ir.to_json()).expect("an IR serializes");
            Ok(ServiceIr(Arc::from(RawValue::from_string(text).expect("JSON"))))
        }
        Err(e) => {
            let message = e.to_string();
            Err(match e {
                // the walk refuses a title collision into the IR (synapse's
                // pluginIRRefusing): build() never fails so
                IrBuildError::TitleCollision { namespace, .. } => IrError::Unreadable { namespace, message },
                IrBuildError::MissingSchema { path } => IrError::NotFound {
                    message: format!("no namespace {} in this service", if path.is_empty() { service.to_string() } else { dotted(&path) }),
                    namespace: dotted(&path),
                },
                IrBuildError::Unreadable { path, .. } => IrError::Unreadable { namespace: dotted(&path), message },
            })
        }
    }
}

/// At most this many answers are kept; past it they are dropped and built
/// again as they are asked.
const KEPT: usize = 64;

/// What a service keeps of its `ir` answers: by the hash of what the caller
/// sees (the service's hash, or the caller's view's) and the roots asked —
/// the schemas do not change while a service runs, and a change moves the
/// hash.
#[derive(Default)]
pub struct IrCache {
    kept: Mutex<HashMap<(String, Vec<Vec<String>>), Result<ServiceIr, IrError>>>,
}

impl IrCache {
    pub fn get(&self, hash: &str, roots: &[Vec<String>]) -> Option<Result<ServiceIr, IrError>> {
        self.kept.lock().unwrap_or_else(|p| p.into_inner()).get(&(hash.to_string(), roots.to_vec())).cloned()
    }

    pub fn keep(&self, hash: String, roots: Vec<Vec<String>>, answer: Result<ServiceIr, IrError>) {
        let mut kept = self.kept.lock().unwrap_or_else(|p| p.into_inner());
        if kept.len() >= KEPT {
            kept.clear();
        }
        kept.insert((hash, roots), answer);
    }

    /// How many answers are kept.
    pub fn len(&self) -> usize {
        self.kept.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn roots_of_what_is_asked() {
        assert_eq!(roots("svc", &[]), vec![p(&[])]);
        assert_eq!(roots("svc", &p(&["svc"])), vec![p(&[])]);
        assert_eq!(roots("svc", &p(&["beta", "alpha", "beta"])), vec![p(&["alpha"]), p(&["beta"])]);
        assert_eq!(roots("svc", &p(&["alpha.gamma", "alpha"])), vec![p(&["alpha"])]);
        assert_eq!(roots("svc", &p(&["alpha", ""])), vec![p(&[])]);
        assert_eq!(roots("svc", &p(&["alphabet", "alpha"])), vec![p(&["alpha"]), p(&["alphabet"])]);
    }
}
