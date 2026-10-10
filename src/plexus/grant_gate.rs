//! AUTH-2 — the grant gate in dispatch: default deny, every method.
//!
//! A [`DynamicHub`](super::DynamicHub) given a gate
//! ([`DynamicHub::with_gate`](super::DynamicHub::with_gate)) asks it before
//! routing every call: the method's grant (its schema's `grant`, else
//! `<activation>.<method>`), held through a role on the scope its target
//! resolves to (its schema's `target` param, read from the call's params),
//! within the session's ceiling. A hub without a gate never enters this
//! module and dispatches exactly as before.
//!
//! # Decision table (gate set)
//!
//! | call | anonymous | signed in |
//! |---|---|---|
//! | `public` method | runs (empty reach) | runs (its reach) |
//! | introspection: `<ns>.schema`, the hub's `hash` / `hashes` / `schema` | runs | runs |
//! | method with a `target`, value present | `Unauthenticated` | allowed iff a role held on a scope in the value's chain lists the grant, and every ceiling layer allows it there |
//! | method without a target (or the target param absent / null) | `Unauthenticated` | allowed iff the grant is held anywhere (within the ceiling) |
//! | method no schema describes (a nested child path) | `Unauthenticated` | as "without a target", grant = the dotted path |
//!
//! A target whose value is a list is checked element by element; every
//! element must be allowed. Introspection stays open here because the
//! per-caller view of a hub is AUTH-4's (`_info` and every `schema` answered
//! per caller); this gate decides calls, not what is listed.
//!
//! # How a method receives its [`Reach`]
//!
//! The gate's answer — where the grant is held — rides into the method as
//! [`Reach`]: the dispatch runs the routed call inside a task-local scope,
//! and `#[plexus_macros::method]` hands a method that declares a `reach:
//! Reach` parameter (stripped from the schema, like `auth`) the value of
//! [`current_reach`]. Outside a gated dispatch, [`current_reach`] is
//! [`Reach::everywhere`] — what a hub without a gate has always meant. The
//! reach is live: [`Reach::allows`] / [`Reach::current`] ask the gate again
//! as it stands, which is how a stream checks each event (IDENTITY-37).

use plexus_auth_core::grants::{Gate, Grant, Reach, Refusal};
use serde_json::Value;

use super::auth::AuthContext;
use super::plexus::{AuthzDenyReason, PlexusError};
use super::scope_gate::MethodGateInfo;

tokio::task_local! {
    static CURRENT_REACH: Reach;
}

/// The reach of the call being dispatched: what the gate answered for its
/// grant. [`Reach::everywhere`] when no gate decided this call (a hub
/// without a gate, or a call that did not come through a gated dispatch).
///
/// `#[plexus_macros::method]` calls this for a method that declares a
/// `reach: Reach` parameter, before the method's stream is built — read it
/// there, not from inside a stream, which runs outside the dispatch's scope.
pub fn current_reach() -> Reach {
    CURRENT_REACH.try_with(Reach::clone).unwrap_or_else(|_| Reach::everywhere())
}

/// Run `fut` with `reach` as the [`current_reach`].
pub async fn with_reach<F: std::future::Future>(reach: Reach, fut: F) -> F::Output {
    CURRENT_REACH.scope(reach, fut).await
}

/// What the gate decided for a call that may proceed: run it under this
/// reach, or (introspection) without one.
pub(crate) enum Admit {
    Reach(Reach),
    Open,
}

impl From<Refusal> for PlexusError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Unauthenticated => {
                PlexusError::Unauthenticated("sign in first: this method is not public".into())
            }
            Refusal::MissingGrant { grant, scope, roles, held_on } => PlexusError::Forbidden {
                reason: AuthzDenyReason::MissingGrant { grant, scope, roles, held_on },
            },
        }
    }
}

/// The target values a call names: `None` when the param is absent or
/// null; one string per element when it is a list.
fn target_values(params: &Value, param: &str) -> Option<Vec<String>> {
    let v = params.get(param)?;
    let one = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    match v {
        Value::Null => None,
        Value::Array(items) => Some(items.iter().filter_map(one).collect()),
        other => one(other).map(|s| vec![s]),
    }
}

/// Decide one call. `full_path` is the dotted method as dispatched;
/// `hub_ns` the hub's own namespace.
pub(crate) fn decide(
    gate: &Gate,
    hub_ns: &str,
    full_path: &str,
    info: Option<&MethodGateInfo>,
    params: &Value,
    auth: Option<&AuthContext>,
) -> Result<Admit, PlexusError> {
    let (ns, method) = full_path.split_once('.').unwrap_or((full_path, ""));
    let introspection = method == "schema"
        || method.ends_with(".schema")
        || (ns == hub_ns && matches!(method, "hash" | "hashes"));
    if introspection {
        return Ok(Admit::Open);
    }
    let grant = Grant::new(info.and_then(|i| i.grant.clone()).unwrap_or_else(|| full_path.to_string()));
    if info.is_some_and(|i| i.public) {
        return Ok(Admit::Reach(gate.reach_of_public(auth, &grant)));
    }
    let targets = info
        .and_then(|i| i.target.as_deref())
        .and_then(|param| target_values(params, param));
    match targets {
        None => Ok(Admit::Reach(gate.check(auth, &grant, None)?)),
        Some(values) if values.is_empty() => Ok(Admit::Reach(gate.check(auth, &grant, None)?)),
        Some(values) => {
            let mut reach = None;
            for v in &values {
                reach = Some(gate.check(auth, &grant, Some(v))?);
            }
            Ok(Admit::Reach(reach.expect("non-empty")))
        }
    }
}

/// The wire rendering of a refusal's facts, merged into the error stream
/// item (`{"type":"error", …}`) beside its `message` and `code`:
/// `error_kind` always for an auth refusal, and for a missing grant its
/// `grant`, `scope`, `roles` and `held_on`. Additive: a client that reads
/// only `message` sees what it always saw.
pub(crate) fn error_fields(e: &PlexusError) -> Option<serde_json::Map<String, Value>> {
    let mut m = serde_json::Map::new();
    match e {
        PlexusError::Unauthenticated(_) => {
            m.insert("error_kind".into(), "unauthenticated".into());
        }
        PlexusError::Forbidden { reason } => {
            m.insert("error_kind".into(), "forbidden".into());
            match reason {
                AuthzDenyReason::MissingGrant { grant, scope, roles, held_on } => {
                    m.insert("grant".into(), grant.as_str().into());
                    m.insert("scope".into(), scope.as_str().into());
                    m.insert("roles".into(), roles.iter().map(|r| Value::from(r.as_str())).collect());
                    m.insert("held_on".into(), held_on.iter().map(|s| Value::from(s.as_str())).collect());
                }
                AuthzDenyReason::MissingScope { scope } => {
                    m.insert("reason".into(), "missing_scope".into());
                    m.insert("scope".into(), scope.as_str().into());
                }
                AuthzDenyReason::TenantBoundary => {
                    m.insert("reason".into(), "tenant_boundary".into());
                }
                AuthzDenyReason::NotAccepted => {
                    m.insert("reason".into(), "not_accepted".into());
                }
            }
        }
        _ => return None,
    }
    Some(m)
}

/// A refusal as a client reads it back from an error stream item — the
/// typed view of [`error_fields`]' `forbidden` shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForbiddenItem {
    pub grant: String,
    pub scope: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub held_on: Vec<String>,
    pub message: String,
}

impl ForbiddenItem {
    /// The refusal an error item carries, when it is a missing grant.
    pub fn from_item(item: &Value) -> Option<Self> {
        if item.get("type")?.as_str()? != "error" || item.get("error_kind")?.as_str()? != "forbidden" {
            return None;
        }
        item.get("grant")?;
        serde_json::from_value(item.clone()).ok()
    }
}
