//! AUTH-2 — the grant gate in dispatch: default deny, every method.
//!
//! A [`DynamicHub`](super::DynamicHub) given a gate
//! ([`DynamicHub::with_gate`](super::DynamicHub::with_gate)) asks it before
//! routing every call: the method's grant (its schema's `grant`, else
//! `<activation>.<method>`), held through a role on the scope its target
//! resolves to (its schema's `target` param, read from the call's params),
//! within the session's ceiling. A service without a gate never enters this
//! module and dispatches exactly as before.
//!
//! # Decision table (gate set)
//!
//! | call | anonymous | signed in |
//! |---|---|---|
//! | `public` method | runs (empty reach) | runs (its reach) |
//! | introspection: `<ns>.schema`, the service's `hash` / `hashes` / `schema` / `ir` | runs | runs |
//! | method with a `target`, value present | `Unauthenticated` | allowed iff a role held on a scope in the value's chain lists the grant, and every ceiling layer allows it there |
//! | method that acts `everywhere` (KEEL-31) | `Unauthenticated` | allowed iff a role held on `*` lists the grant, and every ceiling layer allows it on `*` — held on a scope is refused, naming `*` |
//! | method without a target (or the target param absent / null) | `Unauthenticated` | allowed iff the grant is held anywhere (within the ceiling) |
//! | method no schema describes (a nested child path) | `Unauthenticated` | as "without a target", grant = the dotted path |
//! | a signed-in grant (AUTH-5: `auth.whoami`, `auth.logout`, `auth.requires`) | `Unauthenticated` | runs (its reach), whatever the roles or ceiling |
//!
//! A target whose value is a list is checked element by element; every
//! element must be allowed.
//!
//! AUTH-13: before any of this, `params` must be an object (or absent):
//! the gate reads a target by name, and a bare value (`"MENGER-1"`, `[…]`)
//! names none — it would be decided as "held anywhere" while the method
//! deserialized it into its only parameter. A target that is neither a
//! scalar nor a list of scalars is refused too. Both are `InvalidParams`
//! (`error_kind: invalid_params`), whoever calls. Introspection stays open here: what it answers
//! is the caller's view (AUTH-4, [`super::view`]) — `_info` and every
//! `schema` answered per caller; this gate decides calls, not what is listed.
//!
//! # How a method receives its [`Reach`]
//!
//! The gate's answer — where the grant is held — rides into the method as
//! [`Reach`]: the dispatch runs the routed call inside its context
//! ([`crate::call`], RETURNS-47) — the stream it answers included — and
//! `#[plexus_macros::method]` hands a method that declares a `reach: Reach`
//! parameter (stripped from the schema, like `auth`) the value of
//! [`current_reach`]. A service without a gate dispatches with
//! [`Reach::everywhere`], said by its dispatch; outside a call
//! [`current_reach`] is an error, never everything (RETURNS-47: it fell back
//! to everywhere). The reach is live: [`Reach::allows`] / [`Reach::current`]
//! ask the gate again as it stands, which is how a stream checks each event
//! (IDENTITY-37).

use plexus_auth_core::grants::{Gate, Grant, Reach, Refusal};
use serde_json::Value;

use super::auth::AuthContext;
use super::plexus::{AuthzDenyReason, PlexusError};
use super::scope_gate::MethodGateInfo;

/// The reach of the call being dispatched: what the gate answered for its
/// grant — [`Reach::everywhere`] on a service without a gate, which its
/// dispatch says. RETURNS-47: **fail closed** — outside a call (code no
/// dispatch runs, a task spawned without its context handed to it,
/// [`crate::call::scope`]), and in a call that came through a hop (its
/// bound is [`crate::call::Hop::allows`]), it is an error
/// (`Unauthenticated`), never everything.
///
/// `#[plexus_macros::method]` calls this for a method that declares a
/// `reach: Reach` parameter, before the method's stream is built; the
/// stream runs in the call's context too, so reading it there answers the
/// same.
pub fn current_reach() -> Result<Reach, PlexusError> {
    let ctx = crate::call::context()?;
    ctx.reach().cloned().ok_or_else(|| crate::call::CallError::ThroughHop.into())
}

/// Run `fut` with `reach` as the [`current_reach`] of the call it runs in:
/// it narrows that call's reach, never widens it and never creates a call.
/// RETURNS-47: refused (`Unauthenticated`) outside a call, and when `reach`
/// holds a scope the call's does not (unless the call's is everywhere) —
/// it used to build an anonymous caller by hand. A test enters a call with
/// `plexus_core::call::test::in_call` (feature `test-util`).
pub async fn with_reach<F: std::future::Future>(reach: Reach, fut: F) -> Result<F::Output, PlexusError> {
    let ctx = crate::call::context()?;
    let current = ctx.reach().ok_or(crate::call::CallError::ThroughHop)?;
    let within = current.is_everywhere() || reach.held_on().iter().all(|s| current.held_on().contains(s));
    if !within {
        return Err(PlexusError::Unauthenticated(
            "with_reach narrows a call's reach; it holds a scope the call does not".into(),
        ));
    }
    Ok(crate::call::scope(ctx.with_reach(reach), fut).await)
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
            Refusal::Ended { reason } => PlexusError::Unauthenticated(reason),
        }
    }
}

/// AUTH-11: the identity a call acts as — `auth` while its sign-in stands
/// ([`Gate::alive`]); once it has ended (signed out, expired, revoked),
/// nobody: the call is decided and dispatched as anonymous, and the second
/// value says why. A socket that signed out sees the anonymous view and
/// reaches only the `public` methods — not `auth.grant`.
pub(crate) fn standing<'a>(gate: &Gate, auth: Option<&'a AuthContext>) -> (Option<&'a AuthContext>, Option<String>) {
    match auth.map(|a| gate.alive(a)) {
        Some(Err(reason)) => (None, Some(reason)),
        _ => (auth, None),
    }
}

/// AUTH-11: an anonymous refusal of a sign-in that ended says so, rather
/// than "sign in first".
pub(crate) fn say_ended(e: PlexusError, ended: Option<&str>) -> PlexusError {
    match (e, ended) {
        (PlexusError::Unauthenticated(_), Some(reason)) => PlexusError::Unauthenticated(reason.to_string()),
        (e, _) => e,
    }
}

/// The target values a call names: `None` when the param is absent or
/// null; one string per element when it is a list. AUTH-13: a value the
/// gate cannot read as a scope — an object, or a list holding anything but
/// scalars — is refused, never skipped (skipped, it would be decided as
/// "no target": held anywhere).
pub(crate) fn target_values(params: &Value, param: &str) -> Result<Option<Vec<String>>, PlexusError> {
    let Some(v) = params.get(param) else { return Ok(None) };
    let one = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    let unreadable = || {
        PlexusError::malformed_param(param, "names what this call acts on: a string, or a list of strings")
    };
    match v {
        Value::Null => Ok(None),
        Value::Array(items) => items.iter().map(|i| one(i).ok_or_else(unreadable)).collect::<Result<_, _>>().map(Some),
        other => one(other).map(|s| Some(vec![s])).ok_or_else(unreadable),
    }
}

/// AUTH-13: under a gate, a call's params are an object (or absent). A
/// bare value names no target, so the gate would decide it as "held
/// anywhere" — while a method of one parameter would take it as that
/// parameter.
fn params_shape(params: &Value) -> Result<(), PlexusError> {
    match params {
        Value::Object(_) | Value::Null => Ok(()),
        _ => Err(PlexusError::invalid_params(
            "params must be an object naming each parameter, e.g. {\"id\": \"…\"}: a gated method takes no bare value",
        )),
    }
}

/// Decide one call. `full_path` is the dotted method as dispatched;
/// `service_ns` the service's own namespace.
pub(crate) fn decide(
    gate: &Gate,
    service_ns: &str,
    full_path: &str,
    info: Option<&MethodGateInfo>,
    params: &Value,
    auth: Option<&AuthContext>,
    signed_in_grants: &std::collections::BTreeSet<String>,
) -> Result<Admit, PlexusError> {
    params_shape(params)?;
    let (ns, method) = full_path.split_once('.').unwrap_or((full_path, ""));
    let introspection = method == "schema"
        || method.ends_with(".schema")
        || (ns == service_ns && matches!(method, "hash" | "hashes" | "ir"));
    if introspection {
        return Ok(Admit::Open);
    }
    let grant = Grant::new(info.and_then(|i| i.grant.clone()).unwrap_or_else(|| full_path.to_string()));
    // KEEL-31: a method that acts on the whole service is decided on `*`,
    // whatever else it says — the rule is the gate's, not the method's.
    if info.is_some_and(|i| i.everywhere) {
        return Ok(Admit::Reach(gate.check_everywhere(auth, &grant)?));
    }
    if info.is_some_and(|i| i.public) {
        return Ok(Admit::Reach(gate.reach_of_public(auth, &grant)));
    }
    // AUTH-5: what every signed-in caller reaches (`auth.whoami`,
    // `auth.logout`, `auth.requires`) — whatever its roles or ceiling, but
    // never anonymously.
    if signed_in_grants.contains(grant.as_str()) {
        if auth.and_then(|a| a.principal()).is_none() {
            return Err(Refusal::Unauthenticated.into());
        }
        return Ok(Admit::Reach(gate.reach_of_public(auth, &grant)));
    }
    let targets = match info.and_then(|i| i.target.as_deref()) {
        Some(param) => target_values(params, param)?,
        None => None,
    };
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

/// KEEL-31: a backstop that does not depend on the macro — each of
/// `methods` in `schema` is marked `everywhere`, or why not. A service
/// whose own whole-service methods lost the mark (built with a macro that
/// dropped the word) refuses to start rather than admit a scoped holder.
pub fn require_everywhere(schema: &super::schema::PluginSchema, methods: &[&str]) -> Result<(), String> {
    let unmarked: Vec<&str> = methods
        .iter()
        .copied()
        .filter(|name| !schema.methods.iter().any(|m| m.name == *name && m.everywhere))
        .collect();
    if unmarked.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}: {} act on the whole service and must be marked `everywhere` in its schema; they are not — \
         built with a plexus-macros that does not know the word (it needs 0.11.1 or later)",
        schema.namespace,
        unmarked.iter().map(|m| format!("{}.{m}", schema.namespace)).collect::<Vec<_>>().join(", "),
    ))
}

/// A refusal as a client reads it back from an error stream item — the
/// typed view of the `forbidden` shape [`super::types::spec_fields`] writes.
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
