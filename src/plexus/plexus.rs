//! DynamicHub - the central routing layer for activations
//!
//! DynamicHub IS an activation that also serves as the registry for other activations.
//! It implements the Plexus RPC protocol for routing and introspection.
//! It uses hub-macro for its methods, with the `call` method using the streaming
//! pattern to forward responses from routed methods.

use super::{
    context::PlexusContext,
    method_enum::MethodEnumSchema,
    schema::{ChildSummary, MethodSchema, PluginSchema, Schema},
    streaming::PlexusStream,
};
use crate::types::Handle;
use async_stream::stream;
use plexus_client::{DenyReason, ParamProblem, RemoteError};
use async_trait::async_trait;
use bitflags::bitflags;
use futures::Stream;
use futures_core::stream::BoxStream;
use jsonrpsee::core::server::Methods;
use jsonrpsee::RpcModule;

/// The JSON-RPC method name used in all plexus subscription notifications.
///
/// Every subscription registered by plexus (`.call`, `.hash`, `.schema`, `_info`)
/// sends notifications with `"method": PLEXUS_NOTIF_METHOD` on the wire.
/// Clients must match against this value when dispatching raw subscription frames.
pub const PLEXUS_NOTIF_METHOD: &str = "result";
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// ============================================================================
// Error Types
// ============================================================================

/// Why the service could not or would not run a call — the server side of the
/// wire's [`RemoteError`].
///
/// Every variant converts to a `RemoteError` (`From<&PlexusError>`), which
/// is what crosses the wire: in an error frame
/// (`PlexusStreamItem::error(metadata, RemoteError::from(&e), recoverable)`)
/// and in the `data` of a JSON-RPC rejection ([`plexus_error_to_jsonrpc`]).
#[derive(Debug, Clone)]
pub enum PlexusError {
    ActivationNotFound(String),
    MethodNotFound { activation: String, method: String },
    /// The call's params did not fit the method (RETURNS-6: structured, was
    /// `InvalidParams(String)`). `param` names the parameter at fault when
    /// the failure is about one; `problem` says what is wrong with it.
    InvalidParams {
        param: Option<String>,
        problem: ParamProblem,
    },
    ExecutionError(String),
    HandleNotSupported(String),
    TransportError(TransportErrorKind),
    Unauthenticated(String),
    /// Layer-2+ denial from the layered denial model (AUTHZ-0 §4, R-5):
    /// the caller is authenticated but the call is not authorized.
    ///
    /// Produced by the scope gate ([`super::scope_gate`]) when a required
    /// scope is unmet. The full wire-side rendering policy is
    /// AUTHZ-PRIVACY-4's (`plexus_error_to_jsonrpc`); this variant only
    /// commits to the typed server-side value.
    Forbidden { reason: AuthzDenyReason },
}

/// Why a [`PlexusError::Forbidden`] denial fired — the layered denial
/// model's typed discriminator (AUTHZ-S01-output §1, R-5).
///
/// No-enumeration posture per AUTHZ-CORE-1/5: each variant carries at most
/// the single fact the caller already failed. The registry's role taxonomy
/// and the method's full requirement set are never rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDenyReason {
    /// Layer 2 (method authorization): the caller's effective scope set
    /// does not satisfy `scope` — the FIRST unmet required scope.
    /// Emitted by the scope gate (R-5 / AUTHZ-CORE-5).
    MissingScope { scope: plexus_auth_core::Scope },
    /// Layer 4 (data isolation): typed here per AUTHZ-S01-output §1 but
    /// NOT emitted by the scope gate — the tenant-scoped storage layer
    /// (AUTHZ-DATA) owns its emission.
    TenantBoundary,
    /// Layer 3 (action context): typed here but NOT emitted by the scope
    /// gate — AUTHLANG-3's action gate owns its emission.
    NotAccepted,
    /// AUTH-2: the grant gate's refusal — the caller does not hold `grant`
    /// on `scope` (within its session's ceiling). Unlike `MissingScope` it
    /// names what was needed and where the caller does hold it (owner,
    /// 2026-10-10: "return the grants required to hit an endpoint"); the
    /// gate gives it only to a signed-in caller — an anonymous one gets
    /// [`PlexusError::Unauthenticated`].
    MissingGrant {
        /// The method's grant, `<activation>.<method>`.
        grant: plexus_auth_core::grants::Grant,
        /// Where it was needed: the target's innermost scope, or `*` for a
        /// method without a target.
        scope: plexus_auth_core::grants::ScopeRef,
        /// The roles that list the grant, `admin` last.
        roles: Vec<plexus_auth_core::RoleName>,
        /// Where the caller holds it.
        held_on: Vec<plexus_auth_core::grants::ScopeRef>,
    },
    /// NEST-16: a child called its service for `method`, which is neither
    /// the standard upward interface nor one of the methods it `needs`.
    NotNeeded {
        /// The method the child called, by its path from the service.
        method: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "error_kind", rename_all = "snake_case")]
pub enum TransportErrorKind {
    ConnectionRefused { host: String, port: u16 },
    ConnectionTimeout { host: String, port: u16 },
    ProtocolError { message: String },
    NetworkError { message: String },
}

impl std::fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportErrorKind::ConnectionRefused { host, port } => {
                write!(f, "Connection refused to {}:{}", host, port)
            }
            TransportErrorKind::ConnectionTimeout { host, port } => {
                write!(f, "Connection timeout to {}:{}", host, port)
            }
            TransportErrorKind::ProtocolError { message } => {
                write!(f, "Protocol error: {}", message)
            }
            TransportErrorKind::NetworkError { message } => {
                write!(f, "Network error: {}", message)
            }
        }
    }
}

impl std::fmt::Display for PlexusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlexusError::ActivationNotFound(name) => write!(f, "Activation not found: {}", name),
            PlexusError::MethodNotFound { activation, method } => {
                write!(f, "Method not found: {}.{}", activation, method)
            }
            // MACRO-15's lines: the parameter's wire name first, so the
            // message names it (spec/05) — `Invalid params: id: <serde's
            // message>`, `Invalid params: missing field: id`.
            PlexusError::InvalidParams { param, problem } => match (param, problem) {
                (Some(p), ParamProblem::Missing) => {
                    write!(f, "Invalid params: missing field: {}", p)
                }
                (None, ParamProblem::Missing) => {
                    write!(f, "Invalid params: a required parameter is missing")
                }
                (Some(p), ParamProblem::Malformed { detail }) => {
                    write!(f, "Invalid params: {}: {}", p, detail)
                }
                (None, ParamProblem::Malformed { detail }) => {
                    write!(f, "Invalid params: {}", detail)
                }
            },
            PlexusError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            PlexusError::HandleNotSupported(activation) => {
                write!(f, "Handle resolution not supported by activation: {}", activation)
            }
            PlexusError::TransportError(kind) => match kind {
                TransportErrorKind::ConnectionRefused { host, port } => {
                    write!(f, "Connection refused to {}:{}", host, port)
                }
                TransportErrorKind::ConnectionTimeout { host, port } => {
                    write!(f, "Connection timeout to {}:{}", host, port)
                }
                TransportErrorKind::ProtocolError { message } => {
                    write!(f, "Protocol error: {}", message)
                }
                TransportErrorKind::NetworkError { message } => {
                    write!(f, "Network error: {}", message)
                }
            }
            PlexusError::Unauthenticated(msg) => write!(f, "Authentication required: {}", msg),
            PlexusError::Forbidden { reason } => match reason {
                // Names ONLY the unmet scope — never the registry's
                // taxonomy or the method's full requirement set
                // (no-enumeration posture, AUTHZ-CORE-1/5).
                AuthzDenyReason::MissingScope { scope } => {
                    write!(f, "Forbidden: missing required scope '{}'", scope)
                }
                AuthzDenyReason::TenantBoundary => write!(f, "Forbidden: tenant boundary"),
                AuthzDenyReason::NotAccepted => write!(f, "Forbidden: call not accepted"),
                // AUTH-2: the wire's `message` for a refusal.
                AuthzDenyReason::MissingGrant { grant, scope, .. } if scope.is_everywhere() => {
                    write!(f, "needs {}", grant)
                }
                AuthzDenyReason::MissingGrant { grant, scope, .. } => {
                    write!(f, "needs {} on {}", grant, scope)
                }
                AuthzDenyReason::NotNeeded { method } => {
                    write!(f, "`{method}` is not among the methods this child needs (its schema's `needs`)")
                }
            },
        }
    }
}

impl std::error::Error for PlexusError {}

impl PlexusError {
    /// `InvalidParams` naming no one parameter: `detail` says what is wrong
    /// (`Invalid params: <detail>`).
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        PlexusError::InvalidParams { param: None, problem: ParamProblem::Malformed { detail: detail.into() } }
    }

    /// `InvalidParams` naming the parameter at fault
    /// (`Invalid params: <param>: <detail>`).
    pub fn malformed_param(param: impl Into<String>, detail: impl Into<String>) -> Self {
        PlexusError::InvalidParams {
            param: Some(param.into()),
            problem: ParamProblem::Malformed { detail: detail.into() },
        }
    }
}

/// RETURNS-6: the server's failure, as the wire carries it.
///
/// | `PlexusError` | `RemoteError` |
/// |---|---|
/// | `ActivationNotFound(name)` | `ActivationNotFound { activation: name }` |
/// | `MethodNotFound { activation, method }` | same |
/// | `InvalidParams { param, problem }` | same |
/// | `ExecutionError(msg)` | `Execution { message: msg }` |
/// | `HandleNotSupported(ns)` | `HandleNotSupported { activation: ns }` |
/// | `TransportError(kind)` — a service forwarding upstream failed | `Execution { message: kind.to_string() }` |
/// | `Unauthenticated(_)` | `Unauthenticated` — the server-side reason stays server-side |
/// | `Forbidden { reason }` | `Forbidden { reason: DenyReason }` |
///
/// `Forbidden` renders at most the single fact the caller already failed
/// (AUTHZ-CORE-1/5): `MissingScope` names the one unmet scope — the fact
/// the 0.6 wire already carried in its `Display` line — and
/// `TenantBoundary` / `NotAccepted` carry nothing.
impl From<&PlexusError> for RemoteError {
    fn from(e: &PlexusError) -> Self {
        match e {
            PlexusError::ActivationNotFound(name) => RemoteError::ActivationNotFound {
                activation: name.clone(),
            },
            PlexusError::MethodNotFound { activation, method } => RemoteError::MethodNotFound {
                activation: activation.clone(),
                method: method.clone(),
            },
            PlexusError::InvalidParams { param, problem } => RemoteError::InvalidParams {
                param: param.clone(),
                problem: problem.clone(),
            },
            PlexusError::ExecutionError(message) => RemoteError::Execution {
                message: message.clone(),
            },
            PlexusError::HandleNotSupported(activation) => RemoteError::HandleNotSupported {
                activation: activation.clone(),
            },
            PlexusError::TransportError(kind) => RemoteError::Execution {
                message: kind.to_string(),
            },
            PlexusError::Unauthenticated(_) => RemoteError::Unauthenticated,
            PlexusError::Forbidden { reason } => RemoteError::Forbidden {
                reason: match reason {
                    AuthzDenyReason::MissingScope { scope } => DenyReason::MissingScope {
                        scope: scope.as_str().to_string(),
                    },
                    AuthzDenyReason::TenantBoundary => DenyReason::TenantBoundary,
                    AuthzDenyReason::NotAccepted => DenyReason::NotAccepted,
                    AuthzDenyReason::NotNeeded { method } => DenyReason::NotNeeded { method: method.clone() },
                    // AUTH-2's refusal, whole: what was needed, where, the
                    // roles listing it and where the caller holds it.
                    AuthzDenyReason::MissingGrant { grant, scope, roles, held_on } => {
                        DenyReason::MissingGrant {
                            grant: grant.as_str().to_string(),
                            scope: scope.as_str().to_string(),
                            roles: roles.iter().map(|r| r.as_str().to_string()).collect(),
                            held_on: held_on.iter().map(|s| s.as_str().to_string()).collect(),
                        }
                    }
                },
            },
        }
    }
}

/// RETURNS-47: a child's call inside its own context (when the parent's call
/// had one), its stream carrying it.
async fn in_child<F>(ctx: Option<crate::call::CallContext>, routed: F) -> Result<PlexusStream, PlexusError>
where
    F: std::future::Future<Output = Result<PlexusStream, PlexusError>>,
{
    match ctx {
        Some(ctx) => in_call(ctx, routed).await,
        None => routed.await,
    }
}

/// RETURNS-47: run a call's routing inside its context, and hand back its
/// stream carrying that context, so the method's stream reads its caller as
/// its first line does ([`crate::call`]).
async fn in_call<F>(ctx: crate::call::CallContext, routed: F) -> Result<PlexusStream, PlexusError>
where
    F: std::future::Future<Output = Result<PlexusStream, PlexusError>>,
{
    let stream = crate::call::scope(ctx.clone(), routed).await?;
    Ok(Box::pin(crate::call::InCall::new(ctx, stream)))
}

/// Get the semantic JSON-RPC error code for a PlexusError.
///
/// Codes:
/// - `-32001`: Authentication required (custom app-level error)
/// - `-32003`: Forbidden — authenticated but not authorized (custom app-level error)
/// - `-32601`: Method/activation not found (standard JSON-RPC)
/// - `-32602`: Invalid parameters (standard JSON-RPC)
/// - `-32000`: Generic server error (execution, transport, handle errors)
fn plexus_error_code(e: &PlexusError) -> i32 {
    match e {
        PlexusError::Unauthenticated(_) => -32001,
        PlexusError::Forbidden { .. } => -32003,
        PlexusError::InvalidParams { .. } => -32602,
        PlexusError::MethodNotFound { .. } | PlexusError::ActivationNotFound(_) => -32601,
        _ => -32000,
    }
}

/// Convert a PlexusError to a JSON-RPC rejection.
///
/// JSON-RPC 2.0 requires `code` and `message`, so they stay: `code` is the
/// semantic code above, `message` the `RemoteError`'s `Display` line. `data`
/// always carries the typed [`RemoteError`] (RETURNS-6):
///
/// ```text
/// {"code": -32601, "message": "method not found: tickets.frob",
///  "data": {"kind": "method_not_found", "activation": "tickets", "method": "frob"}}
/// ```
pub fn plexus_error_to_jsonrpc(e: &PlexusError) -> jsonrpsee::types::ErrorObjectOwned {
    let error = RemoteError::from(e);
    jsonrpsee::types::ErrorObject::owned(plexus_error_code(e), error.to_string(), Some(error))
}

/// The error stream item a failed dispatch sends: `{"type":"error",
/// "metadata", "message", "code", "recoverable"}`, plus — for an auth
/// refusal — AUTH-2's typed fields (`error_kind`, and for a missing grant
/// `grant`, `scope`, `roles`, `held_on`; see
/// [`super::types::spec_fields`]), and RETURNS-6's typed `error` beside them.
pub(crate) fn error_item_raw(ns: &str, e: &PlexusError) -> Option<Box<serde_json::value::RawValue>> {
    serde_json::value::to_raw_value(&error_item(ns, e)).ok()
}

/// AUTH-2: the error stream item a failed dispatch of `ns.call` sends for
/// `e`, as JSON — `{"type":"error","metadata","message","code",
/// "recoverable"}` plus, for an auth refusal, `error_kind` and (a missing
/// grant) `grant`, `scope`, `roles`, `held_on`. Public so a transport that
/// renders dispatch errors itself renders them the same way.
pub fn error_item(ns: &str, e: &PlexusError) -> serde_json::Value {
    // POLYGLOT-5: the typed refusal's fields ride in the item itself, and
    // RETURNS-6's typed `error` beside them.
    let item = super::types::PlexusStreamItem::from_plexus_error(
        super::types::StreamMetadata::new(vec![ns.into()], super::context::PlexusContext::hash()),
        e,
        false,
    );
    serde_json::to_value(&item).unwrap_or(serde_json::Value::Null)
}

// ============================================================================
// Schema Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActivationInfo {
    pub namespace: String,
    pub version: String,
    pub description: String,
    pub methods: Vec<String>,
}

// ============================================================================
// Activation Trait
// ============================================================================

#[async_trait]
pub trait Activation: Send + Sync + 'static {
    type Methods: MethodEnumSchema;

    fn namespace(&self) -> &str;
    fn version(&self) -> &str;
    /// Short description (max 15 words)
    fn description(&self) -> &str { "No description available" }
    /// Long description (optional, for detailed documentation)
    fn long_description(&self) -> Option<&str> { None }
    fn methods(&self) -> Vec<&str>;
    fn method_help(&self, _method: &str) -> Option<String> { None }
    /// Stable activation instance ID for handle routing
    /// By default generates a deterministic UUID from namespace+major_version
    /// Using major version only ensures handles survive minor/patch upgrades (semver)
    fn plugin_id(&self) -> uuid::Uuid {
        let major_version = self.version().split('.').next().unwrap_or("0");
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, format!("{}@{}", self.namespace(), major_version).as_bytes())
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        auth: Option<&super::auth::AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Result<PlexusStream, PlexusError>;
    async fn resolve_handle(&self, _handle: &Handle) -> Result<PlexusStream, PlexusError> {
        Err(PlexusError::HandleNotSupported(self.namespace().to_string()))
    }

    fn into_rpc_methods(self) -> Methods where Self: Sized;

    /// MACRO-20: this activation's static children and theirs, as
    /// `(path, schema)` — the same list as
    /// [`ChildRouter::router_static_child_schemas`], reachable from the
    /// hub's type-erased registry (which holds `Activation`s).
    ///
    /// Default empty; `#[plexus_macros::activation]` emits it for an
    /// activation with static `#[plexus_macros::child]`ren. A
    /// [`DynamicHub`] indexes each child's methods for its gate
    /// (`<activation>.<path>.<method>`, the child's own `target`), merges the
    /// children's `roles(...)` into [`DynamicHub::declared_roles`], and lists
    /// them in `auth.requires` and the caller's view — every grant qualified
    /// by the path (see [`super::children`]).
    fn static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        Vec::new()
    }

    /// NEST-5: this activation's schema without an instance — what a
    /// parent's dynamic `#[child]` publishes as its slot's type
    /// (`MethodRole::DynamicChild { child }`). `None` (the default) for an
    /// activation the macro did not write; `#[plexus_macros::activation]`
    /// emits it (its static namespace, version, description, methods and
    /// roles).
    fn slot_schema() -> Option<PluginSchema>
    where
        Self: Sized,
    {
        None
    }

    /// NEST-16: what this activation calls of the service it is grafted
    /// onto — its schema's `needs`, answered without building the schema
    /// (`#[plexus_macros::activation(parent = …)]` emits it). `None`: it
    /// declares nothing.
    fn needs(&self) -> Option<Vec<super::schema::Need>> {
        None
    }

    /// Return this activation's schema (methods + optional children)
    fn plugin_schema(&self) -> PluginSchema {
        // A method of an activation not built with `#[activation]` is known
        // by its name and help text alone; its hash is that schema's content
        // hash (RETURNS-10), as a macro-built method's is of its whole schema.
        let methods: Vec<MethodSchema> = self.methods().iter().map(|name| {
            let desc = self.method_help(name).unwrap_or_default();
            MethodSchema::new(name.to_string(), desc, String::new()).with_content_hash()
        }).collect();

        if let Some(long_desc) = self.long_description() {
            PluginSchema::leaf_with_long_description(
                self.namespace(),
                self.version(),
                self.description(),
                long_desc,
                methods,
            )
        } else {
            PluginSchema::leaf(
                self.namespace(),
                self.version(),
                self.description(),
                methods,
            )
        }
    }
}

// ============================================================================
// Child Routing for Hub Plugins
// ============================================================================

bitflags! {
    /// Opt-in capability flags advertising which optional `ChildRouter`
    /// operations a router supports.
    ///
    /// The Plexus RPC network is a *graph*, not a tree: children may be
    /// remote, infinite, or deliberately private. Listing and searching
    /// children are therefore opt-in — routers must declare them here
    /// before callers can rely on them.
    ///
    /// # Contract
    ///
    /// | Condition | Expected |
    /// |---|---|
    /// | `capabilities().contains(LIST)` is `true` | `list_children().await` returns `Some(stream)` |
    /// | `capabilities().contains(LIST)` is `false` | `list_children().await` returns `None` |
    /// | `capabilities().contains(SEARCH)` is `true` | `search_children(q).await` returns `Some(stream)` for every `q` |
    /// | `capabilities().contains(SEARCH)` is `false` | `search_children(q).await` returns `None` for every `q` |
    ///
    /// These rules are not runtime-enforced; advertising a capability you
    /// do not implement is a correctness bug in the router.
    ///
    /// # Deprecated (IR-4)
    ///
    /// This bitflags type is superseded by the `MethodRole::DynamicChild {
    /// list_method, search_method }` tag on the corresponding gate method.
    /// Consumers that want to know whether a child router supports list /
    /// search operations should inspect the gate method's role instead of
    /// calling `ChildRouter::capabilities()`. The type stays on the wire for
    /// the 0.5 transition window and is slated for removal in 0.7.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
    #[deprecated(
        since = "0.5",
        note = "Use MethodRole::DynamicChild { list_method, search_method } instead. Removed in 0.7."
    )]
    pub struct ChildCapabilities: u32 {
        /// The router promises `list_children()` returns `Some(stream)`.
        const LIST = 0b0000_0001;
        /// The router promises `search_children(query)` returns
        /// `Some(stream)` for any query.
        const SEARCH = 0b0000_0010;
    }
}

/// Trait for activations that can route to child activations
///
/// Hub activations implement this to support nested method routing.
/// When a method like "mercury.info" is called on a solar activation,
/// this trait enables routing to the mercury child.
///
/// This trait is separate from Activation to avoid associated type issues
/// with dynamic dispatch.
///
/// # Optional capabilities
///
/// In addition to the required `router_namespace` + `get_child` surface,
/// routers may opt in to advertising enumerable and searchable children
/// via [`ChildCapabilities`]. When a flag is set, the corresponding
/// `list_children` / `search_children` method must return `Some(stream)`.
/// The default implementations report no capabilities and return `None`.
#[async_trait]
pub trait ChildRouter: Send + Sync {
    /// Get the namespace of this router (for error messages)
    fn router_namespace(&self) -> &str;

    /// Call a method on this router
    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError>;

    /// Get a child activation instance by name for nested routing
    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>>;

    /// NEST-7: the child or peer named `name`, or why a peer could not be
    /// returned — what routing asks, so a caller gets a typed error item
    /// (`not_grafted`, `unavailable`, `shape_mismatch`, …), never "not
    /// found", for a peer that failed. Default: [`Self::get_child`], which
    /// cannot fail. `#[plexus_macros::activation]` overrides it for an
    /// activation with a `#[plexus_macros::peer]` slot.
    async fn peer_child(&self, name: &str) -> Result<Option<Box<dyn ChildRouter>>, super::peer::PeerError> {
        Ok(self.get_child(name).await)
    }

    /// Which optional operations (list / search) this router supports.
    ///
    /// Defaults to [`ChildCapabilities::empty()`]: a router that only
    /// exposes `get_child` for exact-name lookup.
    #[allow(deprecated)]
    fn capabilities(&self) -> ChildCapabilities {
        ChildCapabilities::empty()
    }

    /// Stream every child name the router is willing to enumerate.
    ///
    /// Returns `None` when the router does not support listing — callers
    /// should check [`ChildRouter::capabilities`] first.
    ///
    /// Routers that implement this **must** set
    /// [`ChildCapabilities::LIST`] in [`ChildRouter::capabilities`].
    async fn list_children(&self) -> Option<BoxStream<'_, String>> {
        None
    }

    /// Stream child names matching the router-defined query semantics.
    ///
    /// Returns `None` when the router does not support searching — callers
    /// should check [`ChildRouter::capabilities`] first.
    ///
    /// Routers that implement this **must** set
    /// [`ChildCapabilities::SEARCH`] in [`ChildRouter::capabilities`].
    async fn search_children(&self, _query: &str) -> Option<BoxStream<'_, String>> {
        None
    }

    // AUTHLANG-3 — three default-implemented methods that the framework's
    // dispatch path (`route_to_child` below) consults. Existing impls keep
    // compiling unchanged: they inherit the defaults below. Hub-level impls
    // (DynamicHub) override them to consult the registry/principal/sink the
    // hub holds.

    /// Look up the forward policy declared for a callee namespace.
    ///
    /// Default: returns `None`, which the framework interprets as
    /// [`plexus_auth_core::IdentityOnly`] — the safe default per
    /// `AUTHLANG-S01-output` §5. Macro-emitted impls (AUTHLANG-4) override
    /// this from the `#[plexus::activation(forward_policy = ...)]`
    /// attribute; the [`DynamicHub`] override consults its
    /// [`ForwardPolicyRegistry`](super::forward_registry::ForwardPolicyRegistry).
    fn forward_policy_for(
        &self,
        _callee_ns: &str,
    ) -> Option<std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>> {
        None
    }

    /// MACRO-20: this router's own schema, when it has one.
    ///
    /// Default `None` (a hand-written router describes nothing). The
    /// `ChildRouter` impl `#[plexus_macros::activation]` emits answers its
    /// activation's [`Activation::plugin_schema`], which is how a parent
    /// describes its static children ([`Self::router_static_child_schemas`]).
    fn router_schema(&self) -> Option<PluginSchema> {
        None
    }

    /// MACRO-20: every static child below this router that describes itself,
    /// as `(path, schema)` — `path` relative to this router, dotted for a
    /// grandchild (`"commits"`, `"commits.audit"`), `schema` the child's own
    /// (its methods' grants and its `roles` relative to it, as its macro
    /// wrote them).
    ///
    /// Default empty. `#[plexus_macros::activation]` emits it for an
    /// activation with static `#[plexus_macros::child]`ren: each child's
    /// [`Self::router_schema`], then its own static children under its name.
    /// A dynamic child (an open name set) is never listed. The hub reads it
    /// through [`Activation::static_child_schemas`] to gate a child's method
    /// by its whole path ([`super::children`]).
    fn router_static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        Vec::new()
    }

    /// Framework-stamped immediate-caller [`plexus_auth_core::Principal`] of
    /// this router.
    ///
    /// Default: [`plexus_auth_core::Principal::Anonymous`]. The dispatch
    /// path passes this into the [`plexus_auth_core::CallSite`] handed to
    /// the policy so policies can implement callee-and-caller-aware
    /// decisions (e.g., "PassThrough only when callee is in `audit.*`").
    /// Hub-level impls override to return the per-connection stamp.
    fn framework_stamped_principal(&self) -> plexus_auth_core::Principal {
        plexus_auth_core::Principal::Anonymous
    }
}

/// Route a method call to a child activation
///
/// This is called from generated code when a hub activation receives
/// a method that doesn't match its local methods. If the method
/// contains a dot (e.g., "mercury.info"), it routes to the child.
///
/// # AUTHLANG-3 dispatch sequence
///
/// Between callee resolution (`get_child`) and the actual dispatch
/// (`router_call`), the framework runs the forwarding-policy step pinned
/// in `plans/AUTHLANG/AUTHLANG-S01-output.md` §3:
///
/// 1. Resolve the policy registered for the callee namespace via
///    [`ChildRouter::forward_policy_for`]; default
///    [`plexus_auth_core::IdentityOnly`] when none is declared.
/// 2. Build a [`plexus_auth_core::CallSite`] from the parent router's
///    framework-stamped principal and the callee's [`MethodPath`].
/// 3. Invoke [`plexus_auth_core::ForwardPolicy::forward`] to obtain a
///    [`plexus_auth_core::ForwardDerivation`].
/// 4. *(deferred — PRIVACY-1)* Emit one `AuditRecord` with
///    `kind: ForwardPolicyApplied` to the configured `AuditSink`.
/// 5. Mint the callee `AuthContext` via the framework-only constructor
///    [`plexus_auth_core::AuthContext::derive_callee_context`]; when it
///    keeps the caller's identity, it keeps the caller's ceiling and
///    sign-in end too, whatever the policy (KEEL-51, [`keep_bounds`]).
/// 6. Dispatch to `child.router_call(...)` with the derived context.
///
/// The policy step is invisible to activation authors per AUTHZ-0
/// principle 1 ("trust is structural, not procedural"). The
/// [`plexus_auth_core::ForwardPolicy::forward`] surface returns
/// *parameters*, never a constructed `AuthContext`; the framework is the
/// only entity that can mint one, per the sealed-type pattern.
pub async fn route_to_child<T: ChildRouter + ?Sized>(
    parent: &T,
    method: &str,
    params: Value,
    auth: Option<&super::auth::AuthContext>,
    raw_ctx: Option<&crate::request::RawRequestContext>,
) -> Result<PlexusStream, PlexusError> {
    // Try to split on first dot for nested routing
    if let Some((child_name, rest)) = method.split_once('.') {
        // NEST-7: a peer that could not be returned is its typed error item.
        let found = match parent.peer_child(child_name).await {
            Ok(found) => found,
            Err(e) => {
                return Ok(e.stream(vec![parent.router_namespace().to_string(), child_name.to_string()]));
            }
        };
        if let Some(child) = found {
            // ── AUTHLANG-3: forwarding-policy dispatch sequence ───────────
            // Steps 1–3, 5–6 per the pinned spike §3. Step 4 (audit
            // emission) is deferred until PRIVACY-1 lands `AuditRecord` /
            // `AuditSink` / `ForwardPolicyApplied`; the TODO below marks
            // the exact insertion point. See run-notes on the ticket.

            // Step 1: resolve the policy registered for the callee
            // namespace; default to IdentityOnly per the spike-pinned safe
            // default (AUTHLANG-S01-output §5).
            let policy: std::sync::Arc<dyn plexus_auth_core::ForwardPolicy> = parent
                .forward_policy_for(child_name)
                .unwrap_or_else(|| {
                    std::sync::Arc::new(plexus_auth_core::IdentityOnly)
                        as std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>
                });

            // Step 2: build the CallSite. The framework-built path string
            // is always a valid MethodPath because the caller already
            // validated the inbound method on its way in; if validation
            // ever fails here it indicates a framework bug, not a user
            // input error.
            let callee_method_str = format!("{}.{}", child_name, rest);
            let callee_method = plexus_auth_core::MethodPath::try_new(callee_method_str.as_str())
                .map_err(|e| PlexusError::ExecutionError(format!(
                    "framework-built MethodPath rejected: {} ({:?})",
                    callee_method_str, e
                )))?;
            let site = plexus_auth_core::CallSite::new(
                parent.framework_stamped_principal(),
                callee_method,
            );

            // Step 3: invoke the policy. When the caller has no
            // AuthContext (anonymous edge), feed the policy the anonymous
            // sealed context so the policy contract is honored uniformly.
            let anonymous_owned;
            let caller_ctx: &super::auth::AuthContext = match auth {
                Some(ctx) => ctx,
                None => {
                    anonymous_owned = super::auth::AuthContext::anonymous();
                    &anonymous_owned
                }
            };
            let derivation = policy.forward(caller_ctx, &site);

            // Step 4 (DEFERRED — PRIVACY-1): emit AuditRecord with
            // kind: ForwardPolicyApplied before dispatch. When PRIVACY-1
            // lands `AuditRecord`, `AuditSink`, and `ForwardPolicyApplied`
            // in `plexus_auth_core`, add a `ChildRouter::audit_sink()`
            // default method (returning a no-op sink) and call:
            //
            //     parent.audit_sink().write(
            //         AuditRecord::for_forward(
            //             &site.callee_method,
            //             &site.caller,
            //             policy.name(),
            //             derivation,
            //             auth.and_then(|c| c.verified_user_id()),
            //         )
            //     ).await;
            //
            // Sink failure must be logged at WARN and NOT propagated
            // (acceptance-criteria row 4 in AUTHLANG-3 §"Required
            // behavior"). Until then, log a structured trace event so
            // operators can confirm the policy step ran:
            tracing::trace!(
                target: "plexus::audit",
                policy = policy.name().as_str(),
                callee_method = %site.callee_method.as_str(),
                derivation_keep_verified_user = derivation.keep_verified_user,
                derivation_keep_roles = derivation.keep_roles,
                derivation_keep_capabilities = derivation.keep_capabilities,
                derivation_keep_metadata = derivation.keep_metadata,
                "forward_policy_applied (audit-record emission stubbed pending PRIVACY-1)"
            );

            // Step 5+6: framework-blessed derivation of the callee sealed
            // AuthContext, and dispatch with it. The policy NEVER sees the
            // constructed value — it returned *parameters*; the framework
            // consumed them via `with_callee_context`, which scopes the
            // callee to the dispatch closure (the raw constructor remains
            // pub(crate) to plexus-auth-core).
            // RETURNS-47 (owner, 2026-11-04: children receive auth): the
            // child's call runs in a context of its own, as the policy
            // derived it — its caller the derived context, its reach the
            // call's when the policy keeps the caller's identity, nowhere
            // when not — so `caller()`, `current_reach()` and `required` in a
            // child answer as the policy says, not as the outer call does.
            let outer = crate::call::context().ok();
            let keeps_identity = derivation.keep_verified_user;
            return match auth {
                Some(caller_ctx) => {
                    caller_ctx
                        .with_callee_context(&derivation, &site.caller, |callee_ctx| async move {
                            let callee_ctx = keep_bounds(callee_ctx, caller_ctx, keeps_identity);
                            let ctx = outer.map(|o| o.for_child(Some(&callee_ctx), keeps_identity));
                            in_child(ctx, child.router_call(rest, params, Some(&callee_ctx), raw_ctx)).await
                        })
                        .await
                }
                None => {
                    let ctx = outer.map(|o| o.for_child(None, keeps_identity));
                    in_child(ctx, child.router_call(rest, params, None, raw_ctx)).await
                }
            };
        }
        return Err(PlexusError::ActivationNotFound(child_name.to_string()));
    }

    // No dot - method simply not found
    Err(PlexusError::MethodNotFound {
        activation: parent.router_namespace().to_string(),
        method: method.to_string(),
    })
}

/// KEEL-51: a context a forward policy derived keeps its caller's bounds —
/// the session's ceiling ([`CEILING_KEY`](plexus_auth_core::grants::CEILING_KEY))
/// and the end of its sign-in
/// ([`EXPIRES_AT_KEY`](plexus_auth_core::auth::EXPIRES_AT_KEY), AUTH-11) —
/// whenever it keeps the caller's identity, whatever else the policy drops.
/// They are bounds, not credentials (BIDIR-1's `hop_identity` keeps them for
/// the same reason): without them a child, and every call back a peer makes
/// on the call (its upcalls are decided on this context), would act as the
/// whole principal, past the ceiling its session was minted under and past
/// its sign-in's end. They are the caller's exactly: a policy can drop
/// metadata, never add to it, so this neither widens nor drops a bound. A
/// context that names nobody (`anonymous`) has no bound to keep.
fn keep_bounds(
    mut callee: super::auth::AuthContext,
    caller: &super::auth::AuthContext,
    keeps_identity: bool,
) -> super::auth::AuthContext {
    if !keeps_identity {
        return callee;
    }
    for key in [plexus_auth_core::grants::CEILING_KEY, plexus_auth_core::auth::EXPIRES_AT_KEY] {
        if let Some(bound) = caller.metadata.get(key) {
            if !callee.metadata.is_object() {
                callee.metadata = Value::Object(serde_json::Map::new());
            }
            callee.metadata[key] = bound.clone();
        }
    }
    callee
}

/// Wrapper to implement ChildRouter for Arc<dyn ChildRouter>
///
/// This allows DynamicHub to return its stored Arc<dyn ChildRouter> from get_child()
struct ArcChildRouter(Arc<dyn ChildRouter>);

#[async_trait]
impl ChildRouter for ArcChildRouter {
    fn router_namespace(&self) -> &str {
        self.0.router_namespace()
    }

    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        self.0.router_call(method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        self.0.get_child(name).await
    }

    async fn peer_child(&self, name: &str) -> Result<Option<Box<dyn ChildRouter>>, super::peer::PeerError> {
        self.0.peer_child(name).await
    }

    #[allow(deprecated)]
    fn capabilities(&self) -> ChildCapabilities {
        self.0.capabilities()
    }

    async fn list_children(&self) -> Option<BoxStream<'_, String>> {
        self.0.list_children().await
    }

    async fn search_children(&self, query: &str) -> Option<BoxStream<'_, String>> {
        self.0.search_children(query).await
    }

    // AUTHLANG-3 — forward the new ChildRouter trait methods through the
    // Arc wrapper so a `DynamicHub` reached via `get_child` keeps its
    // overrides (especially `forward_policy_for`).
    fn forward_policy_for(
        &self,
        callee_ns: &str,
    ) -> Option<std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>> {
        self.0.forward_policy_for(callee_ns)
    }

    fn framework_stamped_principal(&self) -> plexus_auth_core::Principal {
        self.0.framework_stamped_principal()
    }

    fn router_schema(&self) -> Option<PluginSchema> {
        self.0.router_schema()
    }

    fn router_static_child_schemas(&self) -> Vec<(String, PluginSchema)> {
        self.0.router_static_child_schemas()
    }
}

// ============================================================================
// Internal Type-Erased Activation
// ============================================================================

#[async_trait]
#[allow(dead_code)] // Methods exist for completeness but some aren't called post-erasure yet
pub(crate) trait ActivationObject: Send + Sync + 'static {
    fn namespace(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn long_description(&self) -> Option<&str>;
    fn methods(&self) -> Vec<&str>;
    fn method_help(&self, method: &str) -> Option<String>;
    fn plugin_id(&self) -> uuid::Uuid;
    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError>;
    async fn resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError>;
    fn plugin_schema(&self) -> PluginSchema;
    fn static_child_schemas(&self) -> Vec<(String, PluginSchema)>;
    fn schema(&self) -> Schema;
    /// NEST-16: [`Activation::needs`].
    fn needs(&self) -> Option<Vec<super::schema::Need>> {
        None
    }
}

struct ActivationWrapper<A: Activation> {
    inner: A,
}

#[async_trait]
impl<A: Activation> ActivationObject for ActivationWrapper<A> {
    fn namespace(&self) -> &str { self.inner.namespace() }
    fn version(&self) -> &str { self.inner.version() }
    fn description(&self) -> &str { self.inner.description() }
    fn long_description(&self) -> Option<&str> { self.inner.long_description() }
    fn methods(&self) -> Vec<&str> { self.inner.methods() }
    fn method_help(&self, method: &str) -> Option<String> { self.inner.method_help(method) }
    fn plugin_id(&self) -> uuid::Uuid { self.inner.plugin_id() }

    async fn call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        self.inner.call(method, params, auth, raw_ctx).await
    }

    async fn resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError> {
        self.inner.resolve_handle(handle).await
    }

    fn plugin_schema(&self) -> PluginSchema { self.inner.plugin_schema() }

    fn static_child_schemas(&self) -> Vec<(String, PluginSchema)> { self.inner.static_child_schemas() }

    fn needs(&self) -> Option<Vec<super::schema::Need>> { self.inner.needs() }

    fn schema(&self) -> Schema {
        let schema = schemars::schema_for!(A::Methods);
        serde_json::from_value(serde_json::to_value(schema).expect("serialize"))
            .expect("parse schema")
    }
}

// ============================================================================
// Plexus Event Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HashEvent {
    Hash { value: String },
}

/// Event for schema() RPC method - returns plugin schema
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SchemaEvent {
    /// This plugin's schema
    Schema(PluginSchema),
}

/// Lightweight hash information for cache validation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginHashes {
    pub namespace: String,
    pub self_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_hash: Option<String>,
    pub hash: String,
    /// Child plugin hashes (for recursive checking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ChildHashes>>,
}

/// Hash information for a child plugin
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChildHashes {
    pub namespace: String,
    pub hash: String,
}


// ============================================================================
// Activation Registry
// ============================================================================

/// Entry in the activation registry
#[derive(Debug, Clone)]
pub struct PluginEntry {
    /// Stable activation instance ID
    pub id: uuid::Uuid,
    /// Current path/namespace for this activation
    pub path: String,
    /// Activation type (e.g., "cone", "bash", "arbor")
    pub plugin_type: String,
}

/// Registry mapping activation UUIDs to their current paths
///
/// This enables handle routing without path dependency - handles reference
/// activations by their stable UUID, and the registry maps to the current path.
#[derive(Default)]
pub struct PluginRegistry {
    /// Lookup by plugin UUID
    by_id: HashMap<uuid::Uuid, PluginEntry>,
    /// Lookup by current path (for reverse lookup)
    by_path: HashMap<String, uuid::Uuid>,
}

/// Read-only snapshot of the activation registry
///
/// Safe to use outside of DynamicHub locks.
#[derive(Clone)]
pub struct PluginRegistrySnapshot {
    by_id: HashMap<uuid::Uuid, PluginEntry>,
    by_path: HashMap<String, uuid::Uuid>,
}

impl PluginRegistrySnapshot {
    /// Look up an activation's path by its UUID
    pub fn lookup(&self, id: uuid::Uuid) -> Option<&str> {
        self.by_id.get(&id).map(|e| e.path.as_str())
    }

    /// Look up an activation's UUID by its path
    pub fn lookup_by_path(&self, path: &str) -> Option<uuid::Uuid> {
        self.by_path.get(path).copied()
    }

    /// Get an activation entry by its UUID
    pub fn get(&self, id: uuid::Uuid) -> Option<&PluginEntry> {
        self.by_id.get(&id)
    }

    /// List all registered activations
    pub fn list(&self) -> impl Iterator<Item = &PluginEntry> {
        self.by_id.values()
    }

    /// Get the number of registered plugins
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl PluginRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up an activation's path by its UUID
    pub fn lookup(&self, id: uuid::Uuid) -> Option<&str> {
        self.by_id.get(&id).map(|e| e.path.as_str())
    }

    /// Look up an activation's UUID by its path
    pub fn lookup_by_path(&self, path: &str) -> Option<uuid::Uuid> {
        self.by_path.get(path).copied()
    }

    /// Get an activation entry by its UUID
    pub fn get(&self, id: uuid::Uuid) -> Option<&PluginEntry> {
        self.by_id.get(&id)
    }

    /// Register an activation
    pub fn register(&mut self, id: uuid::Uuid, path: String, plugin_type: String) {
        let entry = PluginEntry { id, path: path.clone(), plugin_type };
        self.by_id.insert(id, entry);
        self.by_path.insert(path, id);
    }

    /// NEST-15: forget the activation `id` (an entry the service no longer
    /// serves).
    pub(crate) fn remove(&mut self, id: uuid::Uuid) {
        if let Some(entry) = self.by_id.remove(&id) {
            if self.by_path.get(&entry.path) == Some(&id) {
                self.by_path.remove(&entry.path);
            }
        }
    }

    /// List all registered activations
    pub fn list(&self) -> impl Iterator<Item = &PluginEntry> {
        self.by_id.values()
    }

    /// Get the number of registered plugins
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

// ============================================================================
// DynamicHub (formerly Plexus)
// ============================================================================

/// Build the JSON payload for the `_info` well-known endpoint.
///
/// The shape is `{"backend": "<ns>", "auth_capabilities": {…}}` per
/// AUTHZ-S01-output §2 / AUTHZ-CORE-3. When the backend has not declared its
/// capabilities via [`DynamicHub::with_auth_capabilities`], the field falls
/// back to [`plexus_auth_core::BackendAuthCapabilities::anonymous_default`]
/// (a single `Anonymous` mechanism). The `_info` endpoint itself remains
/// public — no authentication is required to read it.
fn build_info_payload(
    namespace: &str,
    caps: Option<&plexus_auth_core::BackendAuthCapabilities>,
) -> serde_json::Value {
    let advertised = match caps {
        Some(c) => c.clone(),
        None => plexus_auth_core::BackendAuthCapabilities::anonymous_default(),
    };
    serde_json::json!({
        "backend": namespace,
        "auth_capabilities": advertised,
    })
}

/// CA-1 (trak facet `ccc924ad-0e78-4d4b-b71f-0018d249d0bf`): map a schema
/// response stream so every `requires_credential` lacking a `site_hint`
/// gets the hub-derived attach site.
///
/// Only `Data` items whose `content_type` is a schema payload
/// (`*.schema` / `*.method_schema`) are touched; their `content` is decoded
/// as a [`super::SchemaResult`], hint-filled, and re-encoded. Items that do
/// not decode (defensive: a custom activation emitting a non-standard
/// payload under a schema content type) pass through unchanged, as do all
/// non-`Data` items.
fn fill_site_hints_in_schema_stream(
    stream: PlexusStream,
    site: plexus_auth_core::AttachmentSite,
) -> PlexusStream {
    use futures::StreamExt;
    Box::pin(stream.map(move |item| match item {
        super::types::PlexusStreamItem::Data {
            metadata,
            content_type,
            content,
        } if content_type.ends_with(".schema") || content_type.ends_with(".method_schema") => {
            // PERF-7: an encoded content is decoded straight from its bytes.
            let content = match content.decode::<super::SchemaResult>() {
                Ok(mut result) => {
                    result.fill_site_hints(&site);
                    match serde_json::to_value(&result) {
                        Ok(v) => v.into(),
                        Err(_) => content,
                    }
                }
                Err(_) => content,
            };
            super::types::PlexusStreamItem::Data {
                metadata,
                content_type,
                content,
            }
        }
        other => other,
    }))
}

pub(crate) struct DynamicHubInner {
    /// Custom namespace for this hub instance (defaults to "plexus")
    namespace: String,
    /// NEST-15: the service root — its table of peers, by name: each
    /// registered activation, each mounted child, each peer served while the
    /// service serves ([`DynamicHub::root`]). Read as a snapshot (an `Arc`),
    /// changed by swapping one in. PERF-21: ordered, so every list of them —
    /// the service schema's `children` ([`DynamicHub::plugin_children`]),
    /// what the self-description cache keeps, the static children, the
    /// declared roles — is in name order: a function of what the service
    /// serves, the same at every start.
    root: std::sync::RwLock<Arc<super::service_root::Table>>,
    /// NEST-15: told the service's hash each time the root's table changes.
    root_watch: tokio::sync::watch::Sender<String>,
    /// Activation registry mapping UUIDs to paths
    registry: std::sync::RwLock<PluginRegistry>,
    pending_rpc: std::sync::Mutex<Vec<Box<dyn FnOnce() -> Methods + Send>>>,
    /// What this backend advertises at `_info`'s `auth_capabilities` field.
    ///
    /// `None` means the backend has not called
    /// [`DynamicHub::with_auth_capabilities`]; `_info` falls back to
    /// [`plexus_auth_core::BackendAuthCapabilities::anonymous_default`]
    /// (a single `Anonymous` mechanism, no default). This preserves today's
    /// no-auth substrate behavior while signaling "no auth wired" to
    /// capability-aware clients.
    ///
    /// Per AUTHZ-CORE-3 and AUTHZ-S01-output §2.
    auth_capabilities: Option<plexus_auth_core::BackendAuthCapabilities>,
    /// AUTHLANG-3 — per-hub mapping from callee namespace to the
    /// [`plexus_auth_core::ForwardPolicy`] consulted at every
    /// cross-boundary call routed through this hub. Populated declaratively
    /// (by the AUTHLANG-4 macro emission) or imperatively (via
    /// [`DynamicHub::with_forward_policy`]). When the registry has no entry
    /// for a callee namespace, the framework falls back to
    /// [`plexus_auth_core::IdentityOnly`] per the spike-pinned safe
    /// default. See `plans/AUTHLANG/AUTHLANG-S01-output.md` §3.
    forward_policies: super::forward_registry::ForwardPolicyRegistry,
    /// R-5 (AUTHZ-CORE-4 acceptance 8) — the deployment's role→scope
    /// taxonomy, consulted by the scope gate at every dispatch through
    /// [`DynamicHub::route_with_ctx`]. `None` means no registry is
    /// configured: with `default_deny` also off (the default), dispatch
    /// behaves byte-for-byte as before the gate existed.
    scope_registry: Option<Arc<plexus_auth_core::ScopeRegistry>>,
    /// R-5 (AUTHZ-CORE-1) — the default-deny posture. **Ships OFF.**
    ///
    /// Whether / when each backend flips this ON is an open human decision
    /// (R-S01 open question 4); see [`super::scope_gate`] module docs for
    /// the full decision table and the deviation note (runtime builder
    /// option here vs CORE-1's Cargo feature flag).
    default_deny: bool,
    /// Where the scope gate writes its `ScopeCheck` [`AuditRecord`]s
    /// (AUTHZ-CORE-5). Defaults to [`plexus_auth_core::TracingAuditSink`];
    /// override via [`DynamicHub::with_audit_sink`].
    ///
    /// [`AuditRecord`]: plexus_auth_core::AuditRecord
    audit_sink: Arc<dyn plexus_auth_core::AuditSink>,
    /// BIDIR-6: see [`DynamicHub::duplex_gate`].
    duplex_gate: std::sync::OnceLock<super::duplex_gate::DuplexGate>,
    /// Lazily-built index from full dotted method path
    /// (`<activation>.<method>`, hub-own methods under
    /// `<hub-ns>.<method>`) to the gate-relevant schema facts. Built on the
    /// first gated dispatch so the gate never re-walks plugin schemas on the
    /// hot path, and NEST-15: dropped when the root's table changes (an
    /// entry added or removed while the service serves), built again at the
    /// next dispatch.
    /// NEST-5: and the service's slots, so a literal path through a
    /// dynamic child (`solar.earth.info`) finds its slot's entry
    /// (`solar.{planet}.info`).
    gate_index: std::sync::RwLock<Option<Arc<GateIndex>>>,
    /// BIDIR-6: every method path the service knows, and whether it takes an
    /// `Input` (see [`DynamicHub::may_take_input`]). Built once, on the first
    /// call (NEST-15: and again after the root's table changes).
    /// PERF.115-49: FxHash — read on every `{ns}.call`, keyed by the
    /// service's own method paths.
    input_index: std::sync::RwLock<Option<Arc<rustc_hash::FxHashMap<String, bool>>>>,
    /// AUTH-2 — the grant gate: when set, every call is decided by it
    /// before routing (default deny). `None` (the default): dispatch exactly
    /// as before it existed. See [`super::grant_gate`].
    gate: Option<Arc<plexus_auth_core::grants::Gate>>,
    /// AUTH-4/AUTH-5: grants every signed-in caller reaches whatever its
    /// roles or ceiling (the auth activation's `whoami`, `logout`,
    /// `requires`). Empty unless [`DynamicHub::with_auth`] mounted it.
    signed_in_grants: std::collections::BTreeSet<String>,
    /// AUTH-4: the RFC 9728 metadata URL an anonymous `_info` names
    /// (`auth.resource_metadata`). See [`DynamicHub::with_resource_metadata`].
    resource_metadata: Option<String>,
    /// AUTH-5: what each method requires — grant, target, public — kept
    /// for `auth.requires`; present only when the auth activation is
    /// mounted, and fed by every [`DynamicHub::register`].
    auth_catalog: Option<super::auth_activation::Catalog>,
    /// PERF-15: the self-description cache — what the service's schemas
    /// show, and each caller's view of them — that `_info`, `hash`, `hashes`
    /// and every `<ns>.schema` answer from. See [`super::view`].
    describe: super::view::Cache,
    /// RETURNS-40: the `ir` answers kept, by the hash the caller sees and
    /// the namespaces asked. See [`DynamicHub::service_ir`].
    ir_cache: super::ir::IrCache,
    /// NEST-16: what children said through `host.notify`, to whoever in the
    /// service listens ([`DynamicHub::notices`]).
    notices: tokio::sync::broadcast::Sender<super::parent::Notice>,
    /// NEST-21: the service's configuration, made at its first use.
    config: std::sync::OnceLock<super::config::Config>,
}

/// NEST-5: the gate's index — every method path to its gate facts, and the
/// service's slots, through which a literal path finds its slot's entry.
#[derive(Debug, Default)]
pub(crate) struct GateIndex {
    methods: HashMap<String, super::scope_gate::MethodGateInfo>,
    slots: super::slots::Slots,
    /// ONE-7: the paths whose last name its activation gives a method and a
    /// child alike (`dyn.connect`, were `connect` both): no call at or under
    /// one has an address ([`super::grant_gate::dispatched`]).
    ambiguous: std::collections::HashSet<String>,
}

/// KEEL-54: a call's path as its service decides and routes it — made only
/// by [`DynamicHub::call_path`], once a call, from what the caller said.
/// The gate decides it and the router routes it; neither reads the caller's
/// spelling again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CallPath<'m>(&'m str);

impl<'m> CallPath<'m> {
    pub(crate) fn as_str(&self) -> &'m str {
        self.0
    }
}

/// KEEL-54 · **routing never outruns the gate**: the call at `path` runs
/// only under a reach the gate made for `path` itself — for the grant its
/// index entry names (its own, or the slot's it goes through), or for the
/// literal path (a grant written as the path, NEST-5). A reach for any other
/// grant is refused, never run: whatever decided it decided another call.
fn routes_as_decided(index: &GateIndex, path: CallPath<'_>, reach: &plexus_auth_core::grants::Reach) -> Result<(), PlexusError> {
    let named = index.info(path.as_str()).and_then(|i| i.grant.as_deref());
    match reach.grant().map(|g| g.as_str()) {
        Some(decided) if decided == path.as_str() || Some(decided) == named => Ok(()),
        decided => Err(PlexusError::Forbidden {
            reason: AuthzDenyReason::MissingGrant {
                grant: plexus_auth_core::grants::Grant::new(named.unwrap_or(path.as_str())),
                scope: plexus_auth_core::grants::ScopeRef::Everywhere,
                roles: Vec::new(),
                held_on: if decided.is_some() { reach.held_on().to_vec() } else { Vec::new() },
            },
        }),
    }
}

impl GateIndex {
    /// NEST-5: the gate's facts for `method` — its own entry, else its
    /// slot's (`solar.earth.info` → `solar.{planet}.info`).
    fn info(&self, method: &str) -> Option<&super::scope_gate::MethodGateInfo> {
        self.methods.get(method).or_else(|| self.slots.resolve(method).and_then(|k| self.methods.get(&k)))
    }

    /// KEEL-32: the index's key for the path `path` (a method's or a
    /// child's): through a slot, the slot's (`solar.earth.info` →
    /// `solar.{planet}.info`, `solar.earth` → `solar.{planet}`,
    /// `dyn.peer.w` → `dyn.{peer}`); else the path itself.
    fn slot_key(&self, path: &str) -> String {
        if let Some(k) = self.slots.resolve(path) {
            return k;
        }
        // As a child's path: one more segment makes it a method's.
        const PROBE: &str = ".\u{0}";
        match self.slots.resolve(&format!("{path}{PROBE}")) {
            Some(k) => k.strip_suffix(PROBE).map(str::to_string).unwrap_or(k),
            None => path.to_string(),
        }
    }
}


/// DynamicHub - an activation that routes to dynamically registered child activations
///
/// Unlike hub activations with hardcoded children (like Solar),
/// DynamicHub allows registering activations at runtime via `.register()`.
///
/// # Direct Hosting
///
/// For a single activation, host it directly:
/// ```ignore
/// let solar = Arc::new(Solar::new());
/// TransportServer::builder(solar, converter).serve().await?;
/// ```
///
/// # Composition
///
/// For multiple top-level activations, use DynamicHub:
/// ```ignore
/// let hub = DynamicHub::with_namespace("myapp")
///     .register(Solar::new())
///     .register(EchoActivation::new());
/// ```
#[derive(Clone)]
pub struct DynamicHub {
    inner: Arc<DynamicHubInner>,
}

/// RETURNS-40: one snapshot of what a caller is shown, an IR is built from.
struct IrView {
    base: Arc<super::view::Described>,
    /// The caller's view under the grant gate; `None`: the whole service.
    shaped: Option<Arc<super::view::Shaped>>,
    /// The view's hash (the service's own without a gate).
    hash: String,
}

impl IrView {
    fn root(&self) -> PluginSchema {
        match &self.shaped {
            Some(v) => v.service.clone(),
            None => self.base.service.clone(),
        }
    }

    fn top(&self, ns: &str) -> Option<PluginSchema> {
        match &self.shaped {
            Some(v) => v.schema_of(&self.base, ns).filter(|_| ns != v.service.namespace),
            None => self.base.activations.iter().find(|a| a.namespace == ns).cloned(),
        }
    }

    fn shows(&self, ns: &str) -> bool {
        match &self.shaped {
            Some(v) => v.shows(ns),
            None => self.base.activations.iter().any(|a| a.namespace == ns),
        }
    }

    /// Every namespace the snapshot shows, dotted (`""`: the service's own):
    /// the root, each activation shown, and each static child below one —
    /// in a gated view, when the entry that reaches it is shown.
    fn names(&self, service: &str) -> Vec<String> {
        let mut out = vec![String::new()];
        out.extend(self.base.activations.iter().map(|a| a.namespace.clone()).filter(|ns| ns != service && self.shows(ns)));
        for path in self.base.nested() {
            let mut segs = path.split('.');
            let (Some(top), Some(entry)) = (segs.next(), segs.next()) else { continue };
            let reached = self.shows(top)
                && match &self.shaped {
                    Some(v) => v.method_of(&self.base, top, entry).is_some(),
                    None => true,
                };
            if reached {
                out.push(path.to_string());
            }
        }
        out
    }
}

// ============================================================================
// DynamicHub Infrastructure (non-RPC methods)
// ============================================================================

impl DynamicHub {
    /// NEST-11: the service a [`super::service_scope::WeakService`] upgrades to.
    pub(crate) fn from_inner(inner: Arc<DynamicHubInner>) -> Self {
        Self { inner }
    }

    /// KEEL-54: whether `weak` is this service's own handle.
    pub(crate) fn is_inner(&self, weak: &std::sync::Weak<DynamicHubInner>) -> bool {
        std::ptr::eq(weak.as_ptr(), Arc::as_ptr(&self.inner))
    }

    /// Create a new DynamicHub with explicit namespace
    ///
    /// Unlike single activations which have fixed namespaces, DynamicHub is a
    /// composition tool that can be named based on your application. Common choices:
    /// - "hub" - generic default
    /// - "substrate" - for substrate server
    /// - "myapp" - for your application name
    ///
    /// The namespace appears in method calls: `{namespace}.call`, `{namespace}.schema`
    ///
    /// # The root name is a routing namespace, not a label
    ///
    /// Routing resolves the hub root namespace **before** registered
    /// activations, so the root name must differ from the namespace of every
    /// activation you later [`register`](Self::register). A hub root that
    /// shares its name with a child (`DynamicHub::new("echo").register(Echo)`
    /// where `Echo`'s namespace is also `"echo"`) makes every method on that
    /// child unreachable: `echo.<method>` resolves to the hub root and fails
    /// with `Command not found`, and navigators resolve the like-named child
    /// back to the root schema. This is silent at construction and fatal at
    /// call time, so [`register`](Self::register) rejects the collision with
    /// a panic. Pick a distinct root name (e.g. `"echo_hub"`).
    ///
    /// Z2H-8 / HOSTLESS-3 — register-time detection of the root/activation
    /// namespace shadow.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(DynamicHubInner {
                namespace: namespace.into(),
                root: Default::default(),
                root_watch: tokio::sync::watch::Sender::new(String::new()),
                registry: std::sync::RwLock::new(PluginRegistry::new()),
                pending_rpc: std::sync::Mutex::new(Vec::new()),
                auth_capabilities: None,
                forward_policies: super::forward_registry::ForwardPolicyRegistry::new(),
                scope_registry: None,
                default_deny: false,
                audit_sink: Arc::new(plexus_auth_core::TracingAuditSink),
                duplex_gate: std::sync::OnceLock::new(),
                gate_index: Default::default(),
                input_index: Default::default(),
                gate: None,
                signed_in_grants: std::collections::BTreeSet::new(),
                resource_metadata: None,
                auth_catalog: None,
                describe: Default::default(),
                ir_cache: Default::default(),
                notices: tokio::sync::broadcast::Sender::new(64),
                config: std::sync::OnceLock::new(),
            }),
        }
    }

    /// The service's state while it is built — every builder's way in;
    /// panics with `refused` once the service is shared. PERF-15: a change
    /// made here may change what the service describes, so the
    /// self-description cache starts over.
    fn inner_mut(&mut self, refused: &str) -> &mut DynamicHubInner {
        let inner = Arc::get_mut(&mut self.inner).expect(refused);
        inner.describe.reset();
        *inner.gate_index.get_mut().unwrap_or_else(|p| p.into_inner()) = None;
        *inner.input_index.get_mut().unwrap_or_else(|p| p.into_inner()) = None;
        inner
    }


    /// Configure the deployment's [`ScopeRegistry`] — the scope gate's
    /// source of truth for role→scope expansion, public-method
    /// declarations, and per-method scope overlays (R-5 / AUTHZ-CORE-4
    /// acceptance 8).
    ///
    /// Once a registry is configured, every dispatch through this hub
    /// consults the gate: methods whose [`MethodSchema`] carries
    /// `requires_credential` scopes (or that have a registry overlay) are
    /// enforced; `public` methods bypass; methods with no declared
    /// requirement pass through unchanged unless
    /// [`DynamicHub::with_default_deny`] is also set.
    ///
    /// A hub that never calls this (and never sets `default_deny`)
    /// dispatches byte-for-byte as before the gate existed.
    ///
    /// See [`super::scope_gate`] for the full decision table.
    ///
    /// [`ScopeRegistry`]: plexus_auth_core::ScopeRegistry
    /// [`MethodSchema`]: super::schema::MethodSchema
    pub fn with_scope_registry(mut self, registry: plexus_auth_core::ScopeRegistry) -> Self {
        let inner = self.inner_mut("Cannot set scope_registry: DynamicHub has multiple references");
        inner.scope_registry = Some(Arc::new(registry));
        self
    }

    /// Set the default-deny posture (R-5 / AUTHZ-CORE-1). **Ships OFF.**
    ///
    /// With it ON, methods with NO declared requirement are enforced
    /// against the implicit full-path scope
    /// ([`ScopeRegistry::required_scopes_for`]'s implicit rule) — fail
    /// closed, including when no registry is configured at all. With it
    /// OFF (the default), such methods behave exactly as today.
    ///
    /// **Open human decision (R-S01 Q4):** whether / when each backend
    /// flips this ON (inside the ROLES wave's completion gate vs left to
    /// backend epics à la AUTHZ-FLOWS-4) is unresolved. Until that call is
    /// made, no backend should enable it in production.
    ///
    /// Deviation from AUTHZ-CORE-1: this is a runtime builder option, not
    /// the Cargo feature flag CORE-1 pinned — see [`super::scope_gate`]
    /// module docs for the rationale.
    ///
    /// [`ScopeRegistry::required_scopes_for`]: plexus_auth_core::ScopeRegistry::required_scopes_for
    pub fn with_default_deny(mut self, default_deny: bool) -> Self {
        let inner = self.inner_mut("Cannot set default_deny: DynamicHub has multiple references");
        inner.default_deny = default_deny;
        self
    }

    /// Override where the scope gate writes its `ScopeCheck`
    /// [`AuditRecord`]s (AUTHZ-CORE-5). Default:
    /// [`plexus_auth_core::TracingAuditSink`] (`tracing::info!` events on
    /// the `plexus::audit` target).
    ///
    /// The gate awaits the sink's write BEFORE the dispatch responds
    /// ("audit before respond", AUTHZ-S01-output §8). Sink implementors
    /// are responsible for low-latency writes.
    ///
    /// [`AuditRecord`]: plexus_auth_core::AuditRecord
    pub fn with_audit_sink(mut self, sink: Arc<dyn plexus_auth_core::AuditSink>) -> Self {
        let inner = self.inner_mut("Cannot set audit_sink: DynamicHub has multiple references");
        inner.audit_sink = sink;
        self
    }

    /// AUTH-2: put every call through `gate` before routing — default deny.
    ///
    /// With a gate, a call runs only if the caller holds the method's grant
    /// (`MethodSchema.grant`, else `<activation>.<method>`) through a role
    /// on the scope its target param resolves to — or anywhere, for a method
    /// without a target — within the session's ceiling. `public` methods run
    /// for anyone; an anonymous caller reaches nothing else
    /// ([`PlexusError::Unauthenticated`]); a refusal is
    /// [`AuthzDenyReason::MissingGrant`], rendered on the wire as an error
    /// item with `error_kind: "forbidden"`, `grant`, `scope`, `roles`,
    /// `held_on`. The routed call runs with the gate's [`Reach`] as
    /// [`super::grant_gate::current_reach`], which `#[plexus_macros::method]`
    /// hands a method declaring `reach: Reach`.
    ///
    /// A gated hub also stops merging its activations' direct JSON-RPC
    /// methods (`<activation>.<method>` registered beside `<hub>.call`):
    /// they carry no auth and would pass around the gate. Every call goes
    /// through `<hub>.call`.
    ///
    /// A hub that never calls this dispatches exactly as before. R-5's
    /// [`DynamicHub::with_scope_registry`] / [`DynamicHub::with_default_deny`]
    /// still apply after it when configured.
    ///
    /// [`Reach`]: plexus_auth_core::grants::Reach
    pub fn with_gate(mut self, gate: Arc<plexus_auth_core::grants::Gate>) -> Self {
        let inner = self.inner_mut("Cannot set gate: DynamicHub has multiple references");
        inner.gate = Some(gate);
        self
    }

    /// AUTH-2: the configured gate, if any.
    pub fn gate(&self) -> Option<&Arc<plexus_auth_core::grants::Gate>> {
        self.inner.gate.as_ref()
    }

    /// AUTH-4: the RFC 9728 protected-resource metadata URL
    /// (`…/.well-known/oauth-protected-resource`, AUTH-6) an anonymous
    /// caller's `_info` names as `auth.resource_metadata`. Only a gated hub
    /// says it; without a gate `_info` is unchanged.
    pub fn with_resource_metadata(mut self, url: impl Into<String>) -> Self {
        let inner = self.inner_mut("Cannot set resource_metadata: DynamicHub has multiple references");
        inner.resource_metadata = Some(url.into());
        self
    }

    /// AUTH-4/AUTH-5: grants every signed-in caller reaches whatever its
    /// roles or ceiling — admitted by the gate like a `public` method, but
    /// only with a principal, and shown in every caller's view.
    /// [`DynamicHub::with_auth`] sets the auth activation's `whoami`,
    /// `logout` and `requires`; a hub calls this only for a method of its
    /// own of the same kind.
    pub fn with_signed_in_grants<I, S>(mut self, grants: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let inner = self.inner_mut("Cannot set signed_in grants: DynamicHub has multiple references");
        inner.signed_in_grants.extend(grants.into_iter().map(Into::into));
        self
    }

    /// AUTH-5: mount the `auth` activation ([`super::auth_activation::AuthActivation`])
    /// and put every call through a gate built from the same stores — the
    /// one way a service turns login on. `setup` carries what only the
    /// service knows: its [`AuthBackend`] (providers, login flows, sessions,
    /// signup's waiting list), its editable [`RoleStore`] and
    /// [`MembershipStore`], and its scope [`Resolve`]r.
    ///
    /// Call it **after** registering the service's own activations or
    /// before — either way `auth.requires` knows every method (later
    /// registrations are added as they come). It replaces a gate set by
    /// [`DynamicHub::with_gate`].
    ///
    /// [`AuthBackend`]: super::auth_activation::AuthBackend
    /// [`RoleStore`]: super::auth_activation::RoleStore
    /// [`MembershipStore`]: super::auth_activation::MembershipStore
    /// [`Resolve`]: plexus_auth_core::grants::Resolve
    pub fn with_auth(mut self, setup: super::auth_activation::AuthSetup) -> Self {
        let catalog = super::auth_activation::Catalog::default();
        catalog.add(&Activation::plugin_schema(&self));
        for e in self.table().entries.values() {
            catalog.add(&e.object.plugin_schema());
        }
        // MACRO-20: a static child's methods, by their whole path; NEST-5:
        // a typed slot's, by the slot's (`solar.{planet}.info`), and an
        // untyped slot whole (`solar.{planet}`).
        for child in self.described_children() {
            catalog.add(&child);
        }
        let (_, untyped) = self.slot_children();
        catalog.add_slots(&untyped);
        let (auth, gate) = super::auth_activation::AuthActivation::mount(setup, catalog.clone());
        // KEEL-31: refuse to start if the auth activation's whole-service
        // methods lost their mark.
        if let Err(why) = super::grant_gate::require_everywhere(&Activation::plugin_schema(&auth), super::auth_activation::EVERYWHERE) {
            panic!("{why}");
        }
        {
            let inner = self.inner_mut("Cannot mount auth: DynamicHub has multiple references");
            inner.auth_catalog = Some(catalog);
            inner.gate = Some(Arc::new(gate));
        }
        self.register(auth)
            .with_signed_in_grants(super::auth_activation::SIGNED_IN_GRANTS.iter().copied())
    }

    /// AUTH-4: the hub as `caller` may see it — what `_info`, the hub's
    /// `schema` / `hash` / `hashes` and every `<ns>.schema` answer that
    /// caller on a gated hub. Anonymous: the `public` methods only (the
    /// auth activation's door). Signed in: each method whose grant a role
    /// the caller holds lists (within its ceiling), with `held_on`; the
    /// public methods; the signed-in methods (`auth.whoami`, …). Methods
    /// the caller cannot use are absent; activations left with none are
    /// absent. The hub's own methods are in every view.
    ///
    /// Without a gate: the whole hub, as every caller sees it today
    /// ([`ViewKind::Caller`](super::ViewKind::Caller), the hub's own hash).
    /// See [`super::view`].
    ///
    /// PERF-15: answered from the service's self-description cache — built
    /// once per schema generation and, for a gated service, once per view
    /// key (the caller's grants' fingerprint, or anonymous) and grants
    /// generation.
    pub fn view(&self, caller: Option<&super::auth::AuthContext>) -> super::view::View {
        match self.inner.gate.as_ref() {
            None => self.described().whole(),
            Some(_) => {
                let (base, view) = self.shaped(caller);
                view.view(&base)
            }
        }
    }

    /// PERF-15: something this service describes changed after it was built
    /// — a child mounted or gone while it serves, an activation whose schema
    /// changed: what the self-description cache kept is dropped, and the
    /// next `_info`, `hash` or `schema` builds it again. Registering, and
    /// every other change while the service is built, does this by itself.
    pub fn schema_moved(&self) {
        self.inner.describe.schema_moved();
    }

    /// PERF-15: what the service's schemas show whoever asks — its own,
    /// every activation's, every static child's — kept per schema
    /// generation.
    fn described(&self) -> Arc<super::view::Described> {
        let at = self.inner.describe.schema_generation();
        match self.inner.describe.base(at) {
            Some(cell) => cell.get_or_init(|| Arc::new(self.describe_now())).clone(),
            None => Arc::new(self.describe_now()),
        }
    }

    fn describe_now(&self) -> super::view::Described {
        let service = Activation::plugin_schema(self);
        let activations: Vec<PluginSchema> = self.table().entries.values().map(|e| e.object.plugin_schema()).collect();
        // MACRO-20: a static child's entry stays in its parent's view when
        // the caller can use something below it.
        // NEST-5: and a slot's (`solar.planet`) when something in the slot.
        super::view::Described::new(service, activations, self.described_children())
    }

    /// PERF-15: a gated service's view for `caller`, kept per view key and
    /// grants generation, with what it was decided over. The generations
    /// are read before anything they cover, so a write that lands while a
    /// view is built leaves it under the generation before — dropped at the
    /// next ask.
    fn shaped(&self, caller: Option<&super::auth::AuthContext>) -> (Arc<super::view::Described>, Arc<super::view::Shaped>) {
        let gate = self.inner.gate.as_ref().expect("a view is a gated service's");
        let schema_at = self.inner.describe.schema_generation();
        let grants_at = gate.generation().current();
        // AUTH-11: a sign-in that ended sees the anonymous view — asked on
        // every ask, never kept.
        let (caller, _) = super::grant_gate::standing(gate, caller);
        let who = caller.and_then(|c| gate.fingerprint(c));
        let shape = |base: &super::view::Described| {
            Arc::new(super::view::shape(gate, &self.inner.signed_in_grants, who.as_ref(), caller, base))
        };
        match self.inner.describe.view(schema_at, grants_at, &who) {
            Some((base, view)) => {
                let base = base.get_or_init(|| Arc::new(self.describe_now())).clone();
                let view = view.get_or_init(|| shape(&base)).clone();
                (base, view)
            }
            None => {
                let base = Arc::new(self.describe_now());
                let view = shape(&base);
                (base, view)
            }
        }
    }

    /// AUTH-4: `_info`'s content for `caller`. Without a gate, exactly
    /// today's `{backend, auth_capabilities}` whoever asks. With one, also
    /// `view` (`anonymous` | `caller`) and `view_hash`; and, to an
    /// anonymous caller, `auth: {methods: [the public methods' grants],
    /// resource_metadata?}` — how to sign in.
    pub fn info(&self, caller: Option<&super::auth::AuthContext>) -> serde_json::Value {
        if self.inner.gate.is_none() {
            return build_info_payload(self.runtime_namespace(), self.inner.auth_capabilities.as_ref());
        }
        // PERF-15: built once per view, kept with it.
        let (base, view) = self.shaped(caller);
        view.info
            .get_or_init(|| {
                let mut payload = build_info_payload(self.runtime_namespace(), self.inner.auth_capabilities.as_ref());
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("view".into(), view.kind.as_str().into());
                    obj.insert("view_hash".into(), view.hash.clone().into());
                    if view.kind == super::ViewKind::Anonymous {
                        let mut auth = serde_json::Map::new();
                        auth.insert("methods".into(), view.public_methods(&base).into());
                        if let Some(url) = self.inner.resource_metadata.as_ref() {
                            auth.insert("resource_metadata".into(), url.clone().into());
                        }
                        obj.insert("auth".into(), serde_json::Value::Object(auth));
                    }
                }
                payload
            })
            .clone()
    }

    /// AUTH-4: a gated hub's introspection (`<ns>.schema`, the hub's
    /// `hash` / `hashes`, `<ns>.<method>.schema`) answered from the
    /// caller's view: the stream the hub would send, its content replaced
    /// by the view's. `None`: not answered here (a nested child path of a
    /// visible activation) — route it as before.
    async fn introspect_in_view(
        &self,
        path: CallPath<'_>,
        params: &Value,
        auth: Option<&super::auth::AuthContext>,
        raw_ctx: Option<&crate::request::RawRequestContext>,
    ) -> Option<Result<PlexusStream, PlexusError>> {
        let method = path.as_str();
        let (ns, rest) = method.split_once('.')?;
        let hub_ns = self.inner.namespace.as_str();
        // PERF-15: the view, and what it was decided over, from the cache.
        let (base, view) = self.shaped(auth);
        let not_found = || PlexusError::ActivationNotFound(ns.to_string());
        let content: serde_json::Value = match rest {
            "schema" => {
                if !view.shows(ns) {
                    return Some(Err(not_found()));
                }
                let mut result = match params.get("method").and_then(|v| v.as_str()) {
                    Some(name) => match view.method_of(&base, ns, name) {
                        Some(m) => super::SchemaResult::Method(m),
                        None => {
                            return Some(Err(PlexusError::MethodNotFound {
                                activation: ns.to_string(),
                                method: name.to_string(),
                            }))
                        }
                    },
                    None => super::SchemaResult::Plugin(view.schema_of(&base, ns)?),
                };
                if let Some(site) = self.derived_site_hint() {
                    result.fill_site_hints(&site);
                }
                serde_json::to_value(&result).ok()?
            }
            "hash" if ns == hub_ns => serde_json::to_value(HashEvent::Hash { value: view.hash.clone() }).ok()?,
            "hashes" if ns == hub_ns => serde_json::to_value(view.hashes()).ok()?,
            r if r.ends_with(".schema") => {
                let name = r.trim_end_matches(".schema");
                if !view.shows(ns) {
                    // ONE-7: a door below an activation the caller's view
                    // does not show — one peer's (`/dyn.peer.shop.*` reads
                    // `dyn.peer.shop.schema`; a view is one per caller, and
                    // shows a slot only to one who opens it for every name):
                    // KEEL-32's rule decides it, as below.
                    let path = format!("{ns}.{name}");
                    if ns != hub_ns && name.contains('.') && self.crosses_slot(&path) && self.shows_path(&path, auth) {
                        return None;
                    }
                    return Some(Err(not_found()));
                }
                match view.method_of(&base, ns, name) {
                    Some(m) if matches!(m.role, super::MethodRole::Rpc) => {
                        serde_json::to_value(super::SchemaResult::Method(m)).ok()?
                    }
                    // A visible nested child: its own routing answers.
                    Some(_) => return None,
                    // KEEL-32: a path below the activation — a static
                    // child's (`tickets.commits.link`), or a name in a
                    // dynamic or peer slot (NEST-6, NEST-7:
                    // `solar.earth.schema`, `dyn.peer.w.schema`) — is
                    // routed only when the caller holds a method at it or
                    // below it (or the slot whole): routing it runs the
                    // slot's lookup with the name the caller chose. Any
                    // other is not found, never routed.
                    None if ns != hub_ns
                        && (name.contains('.') || base.activations.iter().any(|a| a.namespace == ns && a.methods.iter().any(|m| m.role.is_slot())))
                        && self.shows_path(&format!("{ns}.{name}"), auth) =>
                    {
                        return None
                    }
                    None => {
                        return Some(Err(PlexusError::MethodNotFound {
                            activation: ns.to_string(),
                            method: name.to_string(),
                        }))
                    }
                }
            }
            _ => return None,
        };
        // The stream the service sends today, so content types and metadata
        // stay what clients know; only the content is the view's.
        use futures::StreamExt;
        let with = |content: serde_json::Value| {
            // PERF-7: an encoded item is a `Data` item: its content is
            // replaced whole, whatever it was made as.
            move |item: super::types::PlexusStreamItem| match item {
                super::types::PlexusStreamItem::Data { metadata, content_type, .. } => {
                    super::types::PlexusStreamItem::Data { metadata, content_type, content: content.clone().into() }
                }
                other => other,
            }
        };
        // R-5's scope gate decides introspection on every call, and audits
        // it: routed every time, as before.
        if self.inner.scope_registry.is_some() || self.inner.default_deny {
            let routed = self.route_ungated(path, params.clone(), auth, raw_ctx).await;
            return Some(routed.map(|s| -> PlexusStream { Box::pin(s.map(with(content))) }));
        }
        // PERF-15: that stream's envelope is learned from the first answer
        // routed for this method and params, and kept with what the service
        // describes; after it no activation builds its schema to say it.
        let key = format!("{method}\n{params}");
        if let Some(shell) = base.shell(&key) {
            return Some(Ok(Box::pin(futures::stream::iter(shell.answer(content)))));
        }
        let items: Vec<super::types::PlexusStreamItem> = match self.route_ungated(path, params.clone(), auth, raw_ctx).await {
            Ok(s) => s.collect().await,
            Err(e) => return Some(Err(e)),
        };
        if let Some(shell) = super::view::Shell::of(&items) {
            base.keep_shell(key, shell);
        }
        Some(Ok(Box::pin(futures::stream::iter(items.into_iter().map(with(content))))))
    }

    /// KEEL-54 · **the one path** a call is decided and routed by: what the
    /// caller said, in the service's own-namespace form (`svc.vault.get`,
    /// the form a hop forwards — plexus-wire spec/12) as its bare form
    /// (`vault.get`, spec/02's `method`), so the gate decides exactly the
    /// path the router routes, and the two forms are one call (KEEL-32 made
    /// them one for introspection). One prefix is taken, once: a path whose
    /// first segment below the service is one of the service's own methods
    /// (`svc.call.schema`) is the service's own and stays, and so does
    /// anything else — `svc.svc.vault.get` stays, and names nothing. Nothing
    /// else is rewritten: no case, no dot, no empty segment.
    pub(crate) fn call_path<'m>(&self, method: &'m str) -> CallPath<'m> {
        let Some(rest) = method.strip_prefix(self.inner.namespace.as_str()).and_then(|r| r.strip_prefix('.')) else {
            return CallPath(method);
        };
        match rest.split_once('.') {
            // No entry is named as the service (`RootError::Shadows`): a
            // name given twice is not taken twice.
            Some((first, _)) if !first.is_empty() && first != self.inner.namespace && !self.is_own_method(first) => CallPath(rest),
            _ => CallPath(method),
        }
    }

    /// KEEL-54: whether `name` is one of the service's own methods (`call`,
    /// `hash`, `hashes`, `ir`, `schema`) — what `<ns>.<name>` routes to.
    fn is_own_method(&self, name: &str) -> bool {
        name == "schema" || Activation::methods(self).contains(&name)
    }

    /// KEEL-32: a child's schema request, `<path>.schema` in either form, as
    /// its bare path (`svc.vault.hidden.schema` → `vault.hidden`).
    pub(crate) fn bare_schema_path(&self, method: &str) -> String {
        self.call_path(method).as_str().trim_end_matches(".schema").to_string()
    }

    /// KEEL-32: whether reaching `path` looks a name up in a dynamic or peer
    /// slot (`dyn.peer.w`, `solar.earth`), by the service's index — asked of
    /// no activation.
    pub(crate) fn crosses_slot(&self, path: &str) -> bool {
        self.gate_index().slot_key(path) != path
    }

    /// KEEL-32: whether the caller's view shows the path `path` below an
    /// activation (`vault.hidden`, `vault.hidden.rotate_master_key`,
    /// `solar.earth`, `dyn.peer.w`): the caller holds — as the gate would
    /// admit it, `everywhere` included — a method there or below it, read
    /// from the gate's index through the slots (`solar.earth` →
    /// `solar.{planet}`), or the path itself as a grant (an untyped slot
    /// whole, or `admin`, which holds every grant). Asks nothing of an
    /// activation: no child or peer is looked up to decide it.
    ///
    /// ONE-7: an entry the door decides (an `everywhere` method with no
    /// target, an untyped peer slot) is shown where the caller opens its
    /// door at the literal path asked — the slot's segment as named
    /// (`solar.earth.rotate`), a peer's schema as `<path>.schema`
    /// (`dyn.peer.shop.schema`: `/dyn.peer.shop.*` reads it, `admin on KILN`
    /// does not) — never by its grant held on data.
    fn shows_path(&self, path: &str, auth: Option<&super::auth::AuthContext>) -> bool {
        let Some(gate) = self.inner.gate.as_ref() else { return true };
        let signed_in = auth.and_then(|a| a.principal()).is_some();
        let index = self.gate_index();
        let holds = |grant: &str, public: bool, everywhere: bool, door: Option<&str>| {
            if public || (signed_in && self.inner.signed_in_grants.contains(grant)) {
                return true;
            }
            let Some(a) = auth else { return false };
            let grant = plexus_auth_core::grants::Grant::new(grant);
            if let Some(at) = door {
                let (caller, _) = super::grant_gate::standing(gate, Some(a));
                return match super::grant_gate::dispatched(at, &grant, &index.ambiguous) {
                    Some(call) => gate.check_everywhere_at(caller, &call).is_ok(),
                    None => gate.check_everywhere(caller, &grant).is_ok(),
                };
            }
            let held = gate.held_on(a, &grant);
            if everywhere {
                held.iter().any(plexus_auth_core::grants::ScopeRef::is_everywhere)
            } else {
                !held.is_empty()
            }
        };
        if holds(path, false, false, None) {
            return true;
        }
        let key = index.slot_key(path);
        let below = format!("{key}.");
        index.methods.iter().any(|(at, info)| {
            if !(*at == key || at.starts_with(&below)) {
                return false;
            }
            // The literal path of the entry, as the path asked names it.
            let literal = match at.strip_prefix(key.as_str()) {
                Some("") if info.door => Some(format!("{path}.schema")),
                Some(rest) if info.door => Some(format!("{path}{rest}")),
                _ => None,
            };
            holds(info.grant.as_deref().unwrap_or(at), info.public, info.everywhere, literal.as_deref())
        })
    }

    /// RETURNS-40: the service's IR of the walks from `namespaces` (dotted
    /// paths; none: the whole service) as `caller` sees it — what its `ir`
    /// method answers. Synapse's walk, made in process over **one snapshot**
    /// of what the caller is shown (RETURNS-40 review #2): the service's own
    /// schema and each activation's from that one view (a grant that moves
    /// while the IR is built moves the next view, not this one), a static
    /// child's as its activation answers it, each child summary followed;
    /// under the R-5 scope gate only the schemas the caller's own calls are
    /// answered (#3). Built off the runtime (`spawn_blocking`), once per key
    /// at a time, and kept by the view's hash, the roots and — under the
    /// scope gate — what the caller is answered ([`super::ir::IrCache`],
    /// #4); a refusal is not kept. The IR is [`super::ir::build`]'s, equal
    /// to synapse's `buildIRFromSchemas` over the same schemas.
    pub async fn service_ir(
        &self,
        namespaces: &[String],
        caller: Option<&super::auth::AuthContext>,
    ) -> Result<super::ir::ServiceIr, super::ir::IrError> {
        let roots = super::ir::roots(&self.inner.namespace, namespaces);
        let view = self.ir_view(caller);
        let permitted = match self.inner.scope_registry.is_some() || self.inner.default_deny {
            false => None,
            true => {
                // re-review #4: decided for the names under the roots asked
                // alone, and written to no audit sink — the `ir` call was
                // enforced, and audited, once
                let mut answered = Vec::new();
                for name in view.names(&self.inner.namespace) {
                    let under = roots.iter().any(|r| {
                        let r = r.join(".");
                        r.is_empty() || name == r || name.starts_with(&format!("{r}."))
                    });
                    if under && self.scope_answers(&self.schema_method(&name), caller).await {
                        answered.push(name);
                    }
                }
                Some(answered)
            }
        };
        let key = super::ir::IrKey { view: view.hash.clone(), roots: roots.clone(), permitted: permitted.clone() };
        self.inner
            .ir_cache
            .get_or_build(key, || async {
                let mut schemas: BTreeMap<Vec<String>, Value> = BTreeMap::new();
                let mut todo: Vec<Vec<String>> = roots.clone();
                while let Some(path) = todo.pop() {
                    if schemas.contains_key(&path) || permitted.as_ref().is_some_and(|p| !p.contains(&path.join("."))) {
                        continue;
                    }
                    // KEEL-32: a path below an activation that `<path>.schema`
                    // would refuse the caller is not walked either.
                    if path.len() > 1 && !self.shows_path(&path.join("."), caller) {
                        continue;
                    }
                    // a schema the caller is not answered is one the walk skips
                    let Some(schema) = self.ir_schema(&view, &path, caller).await else { continue };
                    for child in schema.get("children").and_then(Value::as_array).into_iter().flatten() {
                        if let Some(ns) = child.get("namespace").and_then(Value::as_str) {
                            let mut next = path.clone();
                            next.push(ns.to_string());
                            todo.push(next);
                        }
                    }
                    schemas.insert(path, schema);
                }
                let service = self.inner.namespace.clone();
                crate::rt::spawn_blocking(move || super::ir::answer(&service, &roots, &schemas))
                    .await
                    .unwrap_or_else(|e| Err(super::ir::IrError::Unreadable { namespace: String::new(), message: format!("the IR's build failed: {e}") }))
            })
            .await
    }

    /// How many IR builds this service has run — its `ir` answers built
    /// rather than kept.
    pub fn ir_builds(&self) -> usize {
        self.inner.ir_cache.builds()
    }

    /// RETURNS-40: one snapshot of what `caller` is shown — the caller's view
    /// under the grant gate (one [`DynamicHub::shaped`]), the whole service
    /// otherwise.
    fn ir_view(&self, caller: Option<&super::auth::AuthContext>) -> IrView {
        match self.inner.gate {
            Some(_) => {
                let (base, shaped) = self.shaped(caller);
                IrView { hash: shaped.hash.clone(), base, shaped: Some(shaped) }
            }
            None => {
                let base = self.described();
                IrView { hash: base.service.hash.clone(), base, shaped: None }
            }
        }
    }

    /// `<path>.schema` (the service's own `<ns>.schema` at `[]`).
    fn schema_method(&self, dotted: &str) -> String {
        if dotted.is_empty() { format!("{}.schema", self.inner.namespace) } else { format!("{dotted}.schema") }
    }

    /// Whether the R-5 scope gate answers `caller`'s `method` — the gate the
    /// call itself would meet.
    async fn scope_answers(&self, method: &str, caller: Option<&super::auth::AuthContext>) -> bool {
        let registry = self.inner.scope_registry.as_deref().unwrap_or_else(|| super::scope_gate::empty_registry());
        super::scope_gate::answers(registry, self.inner.default_deny, method, self.gate_index().info(method), caller).await
    }

    /// The schema at `path` as the snapshot answers it — what `<path>.schema`
    /// answers the caller: the service's own and each activation's from the
    /// view, a static child's (which no view shapes) as its activation
    /// answers it, asked of the activation as the route asks it.
    async fn ir_schema(&self, view: &IrView, path: &[String], caller: Option<&super::auth::AuthContext>) -> Option<Value> {
        use futures::StreamExt;
        let shown = match path {
            [] => Some(view.root()),
            [ns] => view.top(ns),
            [top, below @ ..] => {
                // asked of its activation as the route asks it past both
                // gates — the scope gate decided this name already, silently
                let activation = self.table().entries.get(top.as_str())?.object.clone();
                let mut stream = activation.call(&format!("{}.schema", below.join(".")), Value::Null, caller, None).await.ok()?;
                if let Some(site) = self.derived_site_hint() {
                    stream = fill_site_hints_in_schema_stream(stream, site);
                }
                let items: Vec<super::types::PlexusStreamItem> = stream.collect().await;
                return items.into_iter().find_map(|item| match item {
                    super::types::PlexusStreamItem::Data { content_type, content, .. } if content_type.ends_with(".schema") => {
                        Some(content.into_value())
                    }
                    _ => None,
                });
            }
        };
        let mut schema = shown?;
        if let Some(site) = self.derived_site_hint() {
            schema.fill_site_hints(&site);
        }
        serde_json::to_value(super::SchemaResult::Plugin(schema)).ok()
    }

    /// RETURNS-40 review #1: `ir`'s `namespaces` refused before any work —
    /// more names than the caller's view of the service has, or a name it
    /// has not (named), is `invalid_params`.
    fn check_ir_names(&self, params: &Value, caller: Option<&super::auth::AuthContext>) -> Result<(), PlexusError> {
        let asked = match params.get("namespaces") {
            None | Some(Value::Null) => return Ok(()),
            Some(Value::Array(a)) => a,
            Some(_) => return Err(PlexusError::malformed_param("namespaces", "a list of namespaces")),
        };
        // the cheap bound first, read with no schema built: no view shows
        // more than the service has — said without the service's size
        // (re-review #3), which the caller's view may not show
        let most = {
            let table = self.table();
            1 + table.entries.len() + table.nested
        };
        if asked.len() > most {
            return Err(PlexusError::malformed_param(
                "namespaces",
                format!("{} namespaces asked; more than this service shows you", asked.len()),
            ));
        }
        let names: std::collections::HashSet<String> = self.ir_view(caller).names(&self.inner.namespace).into_iter().collect();
        if asked.len() > names.len() {
            return Err(PlexusError::malformed_param(
                "namespaces",
                format!("{} namespaces asked; this service shows you {}", asked.len(), names.len()),
            ));
        }
        for n in asked {
            let Some(n) = n.as_str() else { return Err(PlexusError::malformed_param("namespaces", "a list of namespaces")) };
            let known = n == self.inner.namespace || names.contains(n);
            if !known {
                return Err(PlexusError::malformed_param("namespaces", format!("no namespace `{n}` in this service")));
            }
        }
        Ok(())
    }

    /// AUTH-2/AUTH-3: the default roles every registered activation
    /// declares (`#[plexus_macros::activation(roles(...))]`), merged by role
    /// name — what a service seeds its [`Roles`] with
    /// ([`RoleTable::from_lists`]) before an admin's edits.
    ///
    /// [`Roles`]: plexus_auth_core::grants::Roles
    /// [`RoleTable::from_lists`]: plexus_auth_core::grants::RoleTable::from_lists
    pub fn declared_roles(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut out: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
        // MACRO-20: and every static child's, its grants qualified by the
        // path it is reached through (`commits.link` → `tickets.commits.link`).
        // NEST-5: and every typed slot's, by the slot's path.
        let schemas = self.table().entries.values().map(|e| e.object.plugin_schema()).chain(self.described_children()).collect::<Vec<_>>();
        for schema in schemas {
            for (role, grants) in schema.roles {
                let entry = out.entry(role).or_default();
                for g in grants {
                    if !entry.contains(&g) {
                        entry.push(g);
                    }
                }
            }
        }
        out
    }

    /// MACRO-20: every registered activation's static children (and
    /// theirs), each a schema whose namespace is its whole path
    /// (`tickets.commits`) and whose grants and roles are qualified by it —
    /// see [`super::children`]. Empty for a hub whose activations have no
    /// static `#[plexus_macros::child]`.
    pub fn static_children(&self) -> Vec<PluginSchema> {
        self.table()
            .entries
            .values()
            .flat_map(|e| super::children::qualified(&e.object.plugin_schema().namespace, e.object.static_child_schemas()))
            .collect()
    }

    /// Read-only view of the configured [`ScopeRegistry`], if any.
    /// Test-side accessor.
    ///
    /// [`ScopeRegistry`]: plexus_auth_core::ScopeRegistry
    pub fn scope_registry(&self) -> Option<&plexus_auth_core::ScopeRegistry> {
        self.inner.scope_registry.as_deref()
    }

    /// BIDIR-6: what a call with an input half is held to when it is asked
    /// again: the grant and targets the gate decided it on. Read only when a
    /// method with an `Input` opens, so no other call pays for it.
    pub(crate) fn input_terms(&self, method: &str, params: &Value) -> Result<InputTerms, PlexusError> {
        if self.inner.gate.is_none() {
            return Ok(InputTerms { grant: method.to_string(), targets: Vec::new(), recheck: false });
        }
        // KEEL-54: held to the grant of the path the call was decided on.
        let method = self.call_path(method).as_str();
        let index = self.gate_index();
        let info = index.info(method);
        let grant = info.and_then(|i| i.grant.clone()).unwrap_or_else(|| method.to_string());
        let open = info.is_some_and(|i| i.public) || self.inner.signed_in_grants.contains(grant.as_str());
        let targets = match info.and_then(|i| i.target.as_deref()) {
            Some(param) => super::grant_gate::target_values(params, param)?.unwrap_or_default(),
            None => Vec::new(),
        };
        Ok(InputTerms { grant, targets, recheck: !open })
    }

    /// BIDIR-6: the gate over this service's duplex calls, made when the
    /// first one opens (in the runtime, which runs its audit's drain).
    pub(crate) fn duplex_gate(&self) -> &super::duplex_gate::DuplexGate {
        self.inner.duplex_gate.get_or_init(|| match &self.inner.gate {
            Some(gate) => {
                let (audit, drain) = plexus_auth_core::audit::AuditQueue::new(1024, self.inner.audit_sink.clone());
                crate::rt::spawn(drain);
                super::duplex_gate::DuplexGate::new((**gate).clone()).with_audit(audit)
            }
            None => super::duplex_gate::DuplexGate::ungated(),
        })
    }

    /// BIDIR-6: whether `method` (a `{ns}.call`'s dotted path) may take an
    /// `Input`: `false` only for a method this service's schemas show has
    /// none — its own, each activation's, each static child's. A path they do
    /// not show (a dynamic child's) may.
    pub(crate) fn may_take_input(&self, method: &str) -> bool {
        let method = self.call_path(method).as_str();
        // PERF.115-49: answered under the read guard, no `Arc` taken.
        if let Some(index) = self.inner.input_index.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
            return index.get(method).copied().unwrap_or(true);
        }
        let index = {
            {
                let own = Activation::plugin_schema(self).methods.into_iter().map(|m| (format!("{}.{}", self.inner.namespace, m.name), m.input.is_some()));
                let schemas: Vec<PluginSchema> = self.table().entries.values().map(|e| e.object.plugin_schema()).chain(self.static_children()).collect();
                let theirs = schemas.into_iter().flat_map(|schema| {
                    let ns = schema.namespace;
                    schema.methods.into_iter().map(move |m| (format!("{ns}.{}", m.name), m.input.is_some()))
                });
                let index: Arc<rustc_hash::FxHashMap<String, bool>> = Arc::new(own.chain(theirs).collect());
                *self.inner.input_index.write().unwrap_or_else(|p| p.into_inner()) = Some(index.clone());
                index
            }
        };
        index.get(method).copied().unwrap_or(true)
    }

    /// NEST-5: every slot of every registered activation and static child
    /// (to any depth): each typed slot as a schema at its path
    /// (`tickets.{item}`, grants qualified — [`super::slots`]), and each
    /// untyped slot's path.
    pub fn slot_children(&self) -> (Vec<PluginSchema>, Vec<String>) {
        let (mut typed, mut untyped) = (Vec::new(), Vec::new());
        let schemas = self.table().entries.values().map(|e| e.object.plugin_schema()).chain(self.static_children()).collect::<Vec<_>>();
        for schema in schemas {
            super::slots::slot_schemas(&schema, &mut typed, &mut untyped);
        }
        (typed, untyped)
    }

    /// MACRO-20 and NEST-5: every static child and every typed slot, each a
    /// schema whose namespace is its whole path and whose grants are
    /// qualified by it — what the gate, the roles, `auth.requires` and the
    /// caller's view read below an activation.
    pub fn described_children(&self) -> Vec<PluginSchema> {
        let mut out = self.static_children();
        out.extend(self.slot_children().0);
        out
    }

    /// The gate's path→schema-facts index; built once on first gated
    /// dispatch. See the field docs on `DynamicHubInner::gate_index`.
    fn gate_index(&self) -> Arc<GateIndex> {
        if let Some(index) = self.inner.gate_index.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
            return index.clone();
        }
        let index = Arc::new(self.build_gate_index());
        *self.inner.gate_index.write().unwrap_or_else(|p| p.into_inner()) = Some(index.clone());
        index
    }

    fn build_gate_index(&self) -> GateIndex {
        {
            let mut index = HashMap::new();
            // The hub's own methods, addressable as "<hub-ns>.<method>".
            for m in &Activation::plugin_schema(self).methods {
                let mut info = super::scope_gate::MethodGateInfo::from_schema(m);
                // The hub's own methods are granted under its runtime
                // namespace (the macro's static one is "plexus").
                info.grant = Some(format!("{}.{}", self.inner.namespace, m.name));
                index.insert(format!("{}.{}", self.inner.namespace, m.name), info);
            }
            // Each registered activation's methods, addressable as
            // "<activation-ns>.<method>"; MACRO-20: and each static child's,
            // as "<activation-ns>.<path>.<method>", with the child's own
            // target and its grant qualified by the path
            // (`tickets.commits.link`, see `super::children`). A dynamic
            // child (an open name set) has no MethodSchema at this hub's
            // level; the gate treats its paths as schema-less (grant = the
            // dotted path, held on `*` alone — KEEL-54; registry overlay /
            // default_deny still apply).
            // NEST-5: and each typed slot's, as `<parent>.{<slot>}.<method>`
            // with its grant qualified by the slot's path; an untyped slot
            // is one entry, `<parent>.{<slot>}`, granted whole.
            let (typed, untyped) = self.slot_children();
            let activations: Vec<PluginSchema> = self.table().entries.values().map(|e| e.object.plugin_schema()).collect();

            let statics = self.static_children();
            let mut ambiguous = std::collections::HashSet::new();
            for schema in activations.iter().chain(statics.iter()).chain(typed.iter()) {
                for m in &schema.methods {
                    let mut info = super::scope_gate::MethodGateInfo::from_schema(m);
                    info.grant = Some(m.grant_or(&schema.namespace));
                    index.insert(format!("{}.{}", schema.namespace, m.name), info);
                }
                // ONE-7: a name both a method and a child has no address.
                ambiguous.extend(super::grant_gate::named_twice(schema).into_iter().map(|n| format!("{}.{n}", schema.namespace)));
            }
            let slots = super::slots::Slots::of(activations.iter().chain(statics.iter()).chain(typed.iter()), &untyped);
            for path in &untyped {
                // ONE-7: an untyped peer slot is decided at the door of the
                // call into it (KEEL-44); an untyped dynamic child's, held
                // anywhere, as before.
                let door = super::grant_gate::door_shaped(false, None, slots.is_untyped_peer_slot(path));
                index.insert(
                    path.clone(),
                    super::scope_gate::MethodGateInfo { grant: Some(path.clone()), door, ..Default::default() },
                );
            }
            GateIndex { methods: index, slots, ambiguous }
        }
    }

    /// Register a [`plexus_auth_core::ForwardPolicy`] for a callee
    /// namespace.
    ///
    /// AUTHLANG-3 — every cross-boundary call through this hub consults
    /// the registry at dispatch time. When `callee_ns` has no entry, the
    /// framework falls back to [`plexus_auth_core::IdentityOnly`].
    ///
    /// AUTHLANG-4's `#[plexus::activation(forward_policy = ...)]`
    /// attribute is the declarative path; this builder is the imperative
    /// escape hatch used by integration tests and hand-rolled wiring.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use plexus_auth_core::PassThrough;
    /// use std::sync::Arc;
    ///
    /// let hub = DynamicHub::new("my-backend")
    ///     .with_forward_policy("solar", Arc::new(PassThrough));
    /// ```
    pub fn with_forward_policy(
        mut self,
        callee_ns: impl Into<String>,
        policy: std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>,
    ) -> Self {
        let inner = self.inner_mut("Cannot register forward policy: DynamicHub has multiple references");
        inner.forward_policies.register(callee_ns, policy);
        self
    }

    /// Read-only view of the registered forward policies.
    ///
    /// Test-side accessor; production dispatch consults the registry via
    /// the [`ChildRouter::forward_policy_for`] override.
    pub fn forward_policies(&self) -> &super::forward_registry::ForwardPolicyRegistry {
        &self.inner.forward_policies
    }

    /// Declare the backend's authentication capabilities, served at `_info`.
    ///
    /// Backends call this at builder time to advertise which auth mechanisms
    /// they support (Bearer, Cookie, OIDC, Anonymous). Generic clients
    /// (synapse CLI, gamma, generated SDKs) read the advertisement to decide
    /// which authentication flow to drive.
    ///
    /// Without calling this method, `_info` emits the
    /// [`plexus_auth_core::BackendAuthCapabilities::anonymous_default`]
    /// fallback: a single `Anonymous` mechanism, no default. This preserves
    /// today's no-auth substrate behavior.
    ///
    /// Per AUTHZ-CORE-3 / AUTHZ-S01-output §2.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use plexus_core::DynamicHub;
    /// use plexus_auth_core::{
    ///     AuthMechanism, BackendAuthCapabilities, CookieName, MethodPath,
    /// };
    ///
    /// let caps = BackendAuthCapabilities::new(
    ///     vec![AuthMechanism::Cookie {
    ///         cookie: CookieName::try_new("plexus_session").unwrap(),
    ///         login: MethodPath::try_new("auth.login").unwrap(),
    ///         refresh: None,
    ///         logout: None,
    ///     }],
    ///     Some(0),
    /// )
    /// .unwrap();
    ///
    /// let hub = DynamicHub::new("my-backend").with_auth_capabilities(caps);
    /// ```
    pub fn with_auth_capabilities(
        mut self,
        caps: plexus_auth_core::BackendAuthCapabilities,
    ) -> Self {
        let inner = self.inner_mut("Cannot set auth_capabilities: DynamicHub has multiple references");
        inner.auth_capabilities = Some(caps);
        self
    }

    /// Returns the configured [`BackendAuthCapabilities`], or `None` if the
    /// backend has not called [`Self::with_auth_capabilities`].
    ///
    /// Test-side accessor; production code reads the advertisement off `_info`.
    ///
    /// [`BackendAuthCapabilities`]: plexus_auth_core::BackendAuthCapabilities
    pub fn auth_capabilities(&self) -> Option<&plexus_auth_core::BackendAuthCapabilities> {
        self.inner.auth_capabilities.as_ref()
    }

    /// Deprecated: Use new() with explicit namespace instead
    #[deprecated(since = "0.3.0", note = "Use DynamicHub::new(namespace) instead")]
    pub fn with_namespace(namespace: impl Into<String>) -> Self {
        Self::new(namespace)
    }

    /// Get the runtime namespace for this DynamicHub instance
    pub fn runtime_namespace(&self) -> &str {
        &self.inner.namespace
    }

    /// Get access to the activation registry
    pub fn registry(&self) -> std::sync::RwLockReadGuard<'_, PluginRegistry> {
        self.inner.registry.read().unwrap()
    }

    /// Panic if `child_namespace` shadows the hub root namespace.
    ///
    /// Z2H-8 / HOSTLESS-3 — routing resolves the hub root before registered
    /// activations (see [`Self::route_with_ctx`]), so a child activation whose
    /// namespace equals the hub root name is silently unreachable: every
    /// `<ns>.<method>` call resolves to the root (which only has
    /// call/hash/hashes/schema) and navigators resolve the like-named child
    /// back to the root schema. The published echo example shipped exactly
    /// this shape and was dead on arrival. A loud, immediate error at
    /// registration time beats silent unreachability at call time.
    fn assert_no_root_shadow(&self, child_namespace: &str) {
        // KEEL-54 (R5): an entry named as one of the service's own methods
        // would be routed to the method, and its schema collides with it.
        if self.is_own_method(child_namespace) {
            panic!(
                "DynamicHub: an activation named `{child_namespace}` collides with the service's own method `{root}.{child_namespace}` \
                 (its own methods: call, hash, hashes, ir, schema) — it would never be reached. Name it otherwise. [KEEL-54]",
                root = self.inner.namespace,
            );
        }
        if child_namespace == self.inner.namespace {
            panic!(
                "DynamicHub namespace shadow: activation namespace '{child}' collides with the hub root namespace '{root}'. \
                 The hub root name is a routing namespace, not a label — routing resolves the root first, so a like-named \
                 child activation is unreachable (every '{child}.<method>' call resolves to the hub root and fails with \
                 'Command not found', and navigation resolves the child back to the root schema). \
                 Fix: rename the hub root so it differs from every registered activation's namespace, \
                 e.g. DynamicHub::new(\"{root}_hub\").register(...). [Z2H-8 / HOSTLESS-3]",
                child = child_namespace,
                root = self.inner.namespace,
            );
        }
    }

    /// ONE-7: an activation names each method and child once. A method and a
    /// child of one name (`#[method(name = "peer")]` beside `#[peer] fn
    /// peer`) would be one address — `/dyn.peer` would cover the method and
    /// everything mounted at `dyn.peer` alike — so it is refused here, at
    /// build, as a root shadow is (Z2H-8). An entry served while the service
    /// runs is not refused (its error type has no word for it); a call at or
    /// under such a name has no address and is decided on `*` alone
    /// ([`super::grant_gate::dispatched`]).
    fn assert_names_once<A: Activation + ChildRouter>(activation: &A) {
        let own = activation.plugin_schema();
        let statics = super::children::qualified(&own.namespace, activation.static_child_schemas());
        let twice: Vec<String> = std::iter::once(&own)
            .chain(statics.iter())
            .flat_map(|s| super::grant_gate::named_twice(s).into_iter().map(move |n| format!("{}.{n}", s.namespace)))
            .collect();
        if !twice.is_empty() {
            panic!(
                "DynamicHub: {} each name a method and a child alike — one address for both, so a role held on it \
                 would reach both. Name them apart. [ONE-7]",
                twice.join(", ")
            );
        }
    }

    /// Register an activation
    ///
    /// # Panics
    ///
    /// Panics if the activation's namespace equals the hub root namespace —
    /// such a child would be unreachable at call time (Z2H-8 / HOSTLESS-3,
    /// see [`Self::new`]). Also panics if the hub has already been shared
    /// (multiple `Arc` references).
    pub fn register<A: Activation + ChildRouter + Clone + 'static>(self, activation: A) -> Self {
        self.register_entry(activation)
    }

    /// Register a hub activation that supports nested routing
    ///
    /// Hub activations implement `ChildRouter`, enabling direct nested method calls
    /// like `hub.solar.mercury.info` at the RPC layer (no hub.call indirection).
    ///
    /// # Panics
    ///
    /// Same contract as [`Self::register`]: panics on a root/activation
    /// namespace collision (Z2H-8 / HOSTLESS-3).
    #[deprecated(since = "0.5.0", note = "Use register() — it now handles both leaf and hub activations")]
    pub fn register_hub<A: Activation + ChildRouter + Clone + 'static>(self, activation: A) -> Self {
        self.register_entry(activation)
    }

    /// NEST-15: `activation` as an entry of the root's table.
    pub(crate) fn entry_of<A: Activation + ChildRouter + Clone + 'static>(activation: A) -> super::service_root::Entry {
        let router = Arc::new(activation.clone());
        super::service_root::Entry { object: Arc::new(ActivationWrapper { inner: activation }), router }
    }

    /// [`register`](Self::register): an entry of the root's table, at build,
    /// with its direct RPC methods (a service without a grant gate serves
    /// `<ns>.<method>` beside `<ns>.call`).
    fn register_entry<A: Activation + ChildRouter + Clone + 'static>(mut self, activation: A) -> Self {
        let namespace = activation.namespace().to_string();
        self.assert_no_root_shadow(&namespace);
        Self::assert_names_once(&activation);
        let activation_for_rpc = activation.clone();
        let entry = Self::entry_of(activation);
        let inner = self.inner_mut("Cannot register: DynamicHub has multiple references");
        Self::index_entry(inner.registry.get_mut().unwrap_or_else(|p| p.into_inner()), inner.auth_catalog.as_ref(), &namespace, &entry);
        let table = Arc::make_mut(inner.root.get_mut().unwrap_or_else(|p| p.into_inner()));
        if let Some(old) = table.entries.insert(namespace, entry.clone()) {
            table.nested -= old.object.static_child_schemas().len();
        }
        // RETURNS-40: the cheap bound on `ir`'s names, counted here, once
        table.nested += entry.object.static_child_schemas().len();
        inner.pending_rpc.lock().unwrap()
            .push(Box::new(move || activation_for_rpc.into_rpc_methods()));
        self
    }

    /// What every entry is known by besides the table: its id in the
    /// activation registry, and — AUTH-5 — its methods in `auth.requires`
    /// (registered before the auth activation was mounted or after).
    fn index_entry(
        registry: &mut PluginRegistry,
        catalog: Option<&super::auth_activation::Catalog>,
        namespace: &str,
        entry: &super::service_root::Entry,
    ) {
        registry.register(entry.object.plugin_id(), namespace.to_string(), namespace.to_string());
        if let Some(catalog) = catalog {
            let schema = entry.object.plugin_schema();
            // MACRO-20: and its static children's methods, by their whole path.
            let statics = super::children::qualified(&schema.namespace, entry.object.static_child_schemas());
            // NEST-5: and its slots — a typed slot's methods by the slot's
            // path, an untyped slot whole.
            let (mut typed, mut untyped) = (Vec::new(), Vec::new());
            for s in std::iter::once(&schema).chain(statics.iter()) {
                super::slots::slot_schemas(s, &mut typed, &mut untyped);
            }
            for child in statics.iter().chain(typed.iter()) {
                catalog.add(child);
            }
            catalog.add_slots(&untyped);
            catalog.add(&schema);
        }
    }

    /// NEST-15: the service root — its table of peers, read and changed
    /// while the service serves.
    pub fn root(&self) -> super::service_root::ServiceRoot {
        super::service_root::ServiceRoot { hub: self.clone() }
    }

    /// NEST-15: the root's table now (a snapshot).
    pub(crate) fn table(&self) -> Arc<super::service_root::Table> {
        self.inner.root.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// NEST-15: told the service's hash each time the root's table changes.
    pub(crate) fn watch_root(&self) -> tokio::sync::watch::Receiver<String> {
        self.inner.root_watch.subscribe()
    }

    /// NEST-15: serve `entry` as `name` while the service serves — refused
    /// for the service's own name, a name not one segment, or (unless
    /// `replace`) a name taken. Answers whether an entry was replaced.
    pub(crate) fn insert_entry(&self, name: String, entry: super::service_root::Entry, replace: bool) -> Result<bool, super::service_root::RootError> {
        super::service_root::check_name(&name)?;
        // KEEL-54 (R5): nor one of the service's own methods.
        if name == self.inner.namespace || self.is_own_method(&name) {
            return Err(super::service_root::RootError::Shadows { name });
        }
        // NEST-16: a graft is checked against the service it joins.
        if let Some(needs) = entry.object.needs() {
            self.check_needs(&name, &needs).map_err(super::service_root::RootError::Needs)?;
        }
        let before = self.compute_hash();
        let replaced = self.change_table(|table| {
            if !replace && table.entries.contains_key(&name) {
                return Err(super::service_root::RootError::Taken { name: name.clone() });
            }
            let nested = entry.object.static_child_schemas().len();
            let old = table.entries.insert(name.clone(), entry.clone());
            if let Some(old) = old.as_ref() {
                table.nested -= old.object.static_child_schemas().len();
            }
            table.nested += nested;
            Ok(old.is_some())
        })?;
        Self::index_entry(&mut self.inner.registry.write().unwrap_or_else(|p| p.into_inner()), self.inner.auth_catalog.as_ref(), &name, &entry);
        self.table_moved(before);
        Ok(replaced)
    }

    /// NEST-21: the service's configuration — a capability handle (every
    /// clone the same store), made in memory at its first use unless
    /// [`DynamicHub::with_config`] gave one. Hand it to what reads or sets
    /// a setting; serve it with [`DynamicHub::with_config_service`].
    pub fn config(&self) -> super::config::Config {
        self.inner.config.get_or_init(super::config::Config::new).clone()
    }

    /// NEST-21: keep the configuration in `config` (one with a file, or one
    /// a host built before the service). Before the service is shared.
    pub fn with_config(mut self, config: super::config::Config) -> Self {
        let inner = self.inner_mut("Cannot set config: DynamicHub has multiple references");
        inner.config = std::sync::OnceLock::from(config);
        self
    }

    /// NEST-21: serve the service's configuration as the `config`
    /// activation ([`super::config::ConfigActivation`]): admin's, each key
    /// on its own grant.
    pub fn with_config_service(self) -> Self {
        let config = self.config();
        // KEEL-31: refuse to start if a setting's writes lost their mark.
        if let Err(why) = super::config::require_everywhere() {
            panic!("{why}");
        }
        self.register(super::config::ConfigActivation::new(config))
    }

    /// NEST-16: what children say through `host.notify` from now on (the
    /// last 64 kept for a slow listener; older ones dropped for it).
    pub fn notices(&self) -> tokio::sync::broadcast::Receiver<super::parent::Notice> {
        self.inner.notices.subscribe()
    }

    /// NEST-16: say `notice` to whoever listens; answers how many do.
    pub fn notify(&self, notice: super::parent::Notice) -> u64 {
        self.inner.notices.send(notice).map(|n| n as u64).unwrap_or(0)
    }

    /// NEST-16: the method this service serves at `path` (`shop.items`,
    /// `shop.ui.slots.list`, `<service>.schema`): its shape hash
    /// ([`super::peer::Interface::method_hash`]) and its grant. Every
    /// registered activation, mounted child, static child and typed slot's
    /// method; `None` for anything else.
    pub fn method_at(&self, path: &str) -> Option<(String, String)> {
        let own = Activation::plugin_schema(self);
        if let Some(m) = path.strip_prefix(&format!("{}.", self.inner.namespace)).and_then(|m| own.methods.iter().find(|x| x.name == m)) {
            return Some((super::peer::Interface::method_hash(m), path.to_string()));
        }
        let (at, name) = path.rsplit_once('.')?;
        let activations: Vec<PluginSchema> = self.table().entries.values().map(|e| e.object.plugin_schema()).collect();
        let statics = self.static_children();
        let typed = self.slot_children().0;
        activations
            .iter()
            .chain(statics.iter())
            .chain(typed.iter())
            .filter(|s| s.namespace == at)
            .flat_map(|s| s.methods.iter().map(move |m| (s, m)))
            .find(|(_, m)| m.name == name && matches!(m.role, super::schema::MethodRole::Rpc))
            .map(|(s, m)| (super::peer::Interface::method_hash(m), m.grant_or(&s.namespace)))
    }

    /// NEST-16: the grant the gate holds a call to `path` to (its index's,
    /// kept until the service changes).
    pub(crate) fn grant_at(&self, path: &str) -> Option<String> {
        self.gate_index().info(self.call_path(path).as_str()).and_then(|i| i.grant.clone())
    }

    /// NEST-16: check a graft's `needs` against what this service serves,
    /// each by its shape hash.
    pub fn check_needs(&self, child: &str, needs: &[super::schema::Need]) -> Result<(), super::parent::NeedsMiss> {
        // A need below an untyped slot (`dyn.peer.w.weather.forecast`) is
        // reachable when the slot is; its shape is the peer's, unknown here.
        super::parent::check_needs(child, &self.inner.namespace, needs, |p| {
            self.method_at(p).map(|(h, _)| h).or_else(|| self.gate_index().slots.resolve(p).map(|_| String::new()))
        })
    }

    /// NEST-16: check every entry that declares `needs` against the rest of
    /// the service — what serving a service does first (a static graft whose
    /// parent is not there is refused before anything is served).
    pub fn check_grafts(&self) -> Result<(), Vec<super::parent::NeedsMiss>> {
        let misses: Vec<_> = self
            .table()
            .entries
            .iter()
            .filter_map(|(name, e)| e.object.needs().map(|n| (name.clone(), n)))
            .filter_map(|(name, needs)| self.check_needs(&name, &needs).err())
            .collect();
        if misses.is_empty() { Ok(()) } else { Err(misses) }
    }

    /// NEST-15: stop serving `name`; answers whether it was served.
    pub(crate) fn remove_entry(&self, name: &str) -> bool {
        let before = self.compute_hash();
        let gone = self.change_table(|table| {
            let old = table.entries.remove(name);
            if let Some(old) = old.as_ref() {
                table.nested -= old.object.static_child_schemas().len();
            }
            old
        });
        let Some(old) = gone else { return false };
        self.inner.registry.write().unwrap_or_else(|p| p.into_inner()).remove(old.object.plugin_id());
        if let Some(catalog) = self.inner.auth_catalog.as_ref() {
            catalog.remove_under(name);
        }
        self.table_moved(before);
        true
    }

    /// One change of the root's table, made on a copy and swapped in.
    fn change_table<R>(&self, change: impl FnOnce(&mut super::service_root::Table) -> R) -> R {
        let mut root = self.inner.root.write().unwrap_or_else(|p| p.into_inner());
        let mut table = (**root).clone();
        let out = change(&mut table);
        *root = Arc::new(table);
        out
    }

    /// NEST-15: the root's table changed while the service serves: what was
    /// described and indexed is dropped, the service's hash moves — in the
    /// `plexus_hash` items carry when it was this service's — and watchers
    /// are told.
    fn table_moved(&self, before: String) {
        *self.inner.gate_index.write().unwrap_or_else(|p| p.into_inner()) = None;
        *self.inner.input_index.write().unwrap_or_else(|p| p.into_inner()) = None;
        self.inner.describe.schema_moved();
        let after = self.compute_hash();
        PlexusContext::moved(&before, &after);
        self.inner.root_watch.send_replace(after);
    }

    /// List all methods across all activations
    pub fn list_methods(&self) -> Vec<String> {
        let mut methods = Vec::new();

        // Include hub's own methods
        for m in Activation::methods(self) {
            methods.push(format!("{}.{}", self.inner.namespace, m));
        }

        // Include registered activation methods
        for (ns, e) in &self.table().entries {
            let act = &e.object;
            for m in act.methods() {
                methods.push(format!("{}.{}", ns, m));
            }
        }
        methods.sort();
        methods
    }

    /// List all activations (including this hub itself)
    pub fn list_activations_info(&self) -> Vec<ActivationInfo> {
        let mut activations = Vec::new();

        // Include this hub itself
        activations.push(ActivationInfo {
            namespace: Activation::namespace(self).to_string(),
            version: Activation::version(self).to_string(),
            description: Activation::description(self).to_string(),
            methods: Activation::methods(self).iter().map(|s| s.to_string()).collect(),
        });

        // Include registered activations
        for e in self.table().entries.values() {
            let a = &e.object;
            activations.push(ActivationInfo {
                namespace: a.namespace().to_string(),
                version: a.version().to_string(),
                description: a.description().to_string(),
                methods: a.methods().iter().map(|s| s.to_string()).collect(),
            });
        }

        activations
    }

    /// Compute hash for cache invalidation
    ///
    /// Returns the hash from the recursive plugin schema. This hash changes
    /// whenever any method definition or child plugin changes — and,
    /// PERF-21, only then: the children are listed by namespace, so every
    /// start of the same build computes the same hash (the `plexus_hash`
    /// every item carries, [`PlexusContext::init`]).
    pub fn compute_hash(&self) -> String {
        // PERF-15: from what the service describes, kept per schema generation.
        self.described().service.hash.clone()
    }

    /// PERF-15: the service's own `hash` answer for `caller` — the caller's
    /// view's on a gated service (AUTH-4), the service's own otherwise —
    /// from the cache.
    fn own_hash(&self, caller: Option<&super::auth::AuthContext>) -> String {
        match self.inner.gate {
            Some(_) => self.shaped(caller).1.hash.clone(),
            None => self.described().service.hash.clone(),
        }
    }

    /// PERF-15: the service's own schema as `caller` sees it — the
    /// `{ns}.schema` answer before its site hints — from the cache.
    fn own_schema(&self, caller: Option<&super::auth::AuthContext>) -> PluginSchema {
        match self.inner.gate {
            Some(_) => self.shaped(caller).1.service.clone(),
            None => self.described().service.clone(),
        }
    }

    /// Route a call to the appropriate activation
    pub async fn route(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>) -> Result<PlexusStream, PlexusError> {
        self.route_with_ctx(method, params, auth, None).await
    }

    /// Route a call to the appropriate activation, with optional raw HTTP request context.
    ///
    /// NEST-11: the call is routed knowing its service — the outermost
    /// service a call entered — so a child mounted below it
    /// ([`RemoteChild`](super::RemoteChild)) can take the calls its far side
    /// makes back under a forwarded call through this service's own routing
    /// and gate ([`super::service_scope`]).
    pub async fn route_with_ctx(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        if super::service_scope::entered() {
            return self.route_entered(method, params, auth, raw_ctx).await;
        }
        super::service_scope::scope(self.downgrade(), self.route_entered(method, params, auth, raw_ctx)).await
    }

    /// NEST-11: a weak handle to this service — what a child mounted below
    /// it keeps, so a child never keeps its service alive.
    pub fn downgrade(&self) -> super::service_scope::WeakService {
        super::service_scope::WeakService::new(Arc::downgrade(&self.inner))
    }

    /// NEST-11: a schema the service answers for one of its own children
    /// outside any call (a child asking, at its start, for the shape of what
    /// it will call): the service's whole description at `method` (a
    /// `….schema` path), as the service itself sees it — no caller's view.
    pub(crate) async fn schema_for_child(&self, method: &str, params: Value) -> Result<PlexusStream, PlexusError> {
        let path = self.call_path(method);
        let (_, name) = self.parse_method(path.as_str())?;
        if !Self::is_schema_query(name) {
            return Err(PlexusError::Unauthenticated(format!(
                "`{method}` is not a schema: outside a call, a child asks its service only for a schema"
            )));
        }
        // KEEL-32: decided by the mount before it gets here (`may_read_schema`);
        // it runs with no reach, never everywhere.
        let ctx = crate::call::CallContext::admitted(None, plexus_auth_core::grants::Reach::nowhere());
        let routed = self.route_ungated(path, params, None, None);
        super::service_scope::scope(self.downgrade(), in_call(ctx, routed)).await
    }

    /// [`DynamicHub::route_with_ctx`], inside its service's scope.
    ///
    /// KEEL-54: the caller's spelling is read once, here, into the one
    /// [`CallPath`] the gate decides and the router routes.
    async fn route_entered(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        let path = self.call_path(method);
        // AUTH-2 grant gate: only when configured — a hub without one pays
        // this one branch and dispatches as before.
        if let Some(gate) = self.inner.gate.as_ref() {
            // KEEL-59: the generation the call is decided at, read before it
            // is: a move from here on is a call held asked again.
            let seen = gate.generation().current();
            // AUTH-11: a sign-in that ended proves no one, on every method.
            let (auth, ended) = super::grant_gate::standing(gate, auth);
            let index = self.gate_index();
            let method = path.as_str();
            // ONE-7 (review M1): the untyped peer slot this path goes
            // through, if it does — a literal door's shape opens the
            // peer's name.
            let peer_slot = match index.methods.get(method) {
                Some(_) => None,
                None => index.info(method).filter(|s| s.door).and_then(|s| s.grant.clone()),
            };
            let decide = |info| super::grant_gate::decide(gate, &self.inner.namespace, method, info, &params, auth, &self.inner.signed_in_grants, &index.ambiguous);
            let admit = match index.methods.get(method) {
                Some(info) => decide(Some(info)),
                // NEST-5: a path through a slot is decided on the slot's
                // grant; a grant written as its literal path still decides
                // first (the slot grant is additive).
                None => match index.info(method) {
                    // KEEL-31: a slot's method that acts everywhere is
                    // decided on `*` by its literal path too.
                    Some(slot) => {
                        // KEEL-54 (R1): and on the slot method's target, as
                        // the slot's own entry would be — a grant held by
                        // its literal name is still checked where the call
                        // acts, never "held anywhere".
                        let literal = super::scope_gate::MethodGateInfo { everywhere: slot.everywhere, target: slot.target.clone(), ..Default::default() };
                        // ONE-7 (review M1): through an untyped peer slot,
                        // the literal grant held at the call's address — a
                        // role listing the peer's method (or admin) on
                        // `/dyn.peer.vault.*`, `/dyn.*` — is that method's
                        // own door, before the slot's whole grant, which
                        // opens the peer's ordinary methods only.
                        let literal_door = super::scope_gate::MethodGateInfo { door: true, ..Default::default() };
                        decide(Some(&literal))
                            .or_else(|e| if slot.door { decide(Some(&literal_door)).or(Err(e)) } else { Err(e) })
                            .or_else(|_| decide(Some(slot)))
                    }
                    // KEEL-54: a path no schema of this service describes,
                    // and no slot holds, names nothing the gate can read a
                    // target from — so it is never "held anywhere" on a
                    // grant made up from its spelling, which `admin` on any
                    // data scope holds. It is decided as a whole-service
                    // call is (KEEL-31): its literal grant held on `*`, by a
                    // role on `*` that lists it (or admin on `*`), within a
                    // ceiling that allows it on `*`. Introspection answers
                    // from the caller's view, as before.
                    None => decide(Some(&super::scope_gate::MethodGateInfo { everywhere: true, ..Default::default() })),
                },
            }
            .map_err(|e| super::grant_gate::say_ended(e, ended.as_deref()))?;
            return match admit {
                // AUTH-4: introspection answers from the caller's view.
                // RETURNS-47: in a context too — the caller's reach for the
                // path, as the gate gives a public method's — never none.
                // KEEL-32: the own-namespace form is the bare form
                // (`call_path`).
                super::grant_gate::Admit::Open => {
                    let grant = plexus_auth_core::grants::Grant::new(method.to_string());
                    // PERF.115-49: boxed — the introspection path's future is
                    // the largest, and inline every call's future was its size.
                    Box::pin(in_call(crate::call::CallContext::introspection(auth, Arc::clone(gate), grant), async {
                        match self.introspect_in_view(path, &params, auth, raw_ctx).await {
                            Some(answer) => answer,
                            None => self.route_ungated(path, params, auth, raw_ctx).await,
                        }
                    }))
                    .await
                }
                super::grant_gate::Admit::Reach(reach, door, held) => {
                    // KEEL-54: the call runs only where it was decided — the
                    // reach is for this path's own grant (its entry's, its
                    // slot's, or its literal path's), or nothing runs.
                    // A backstop: no input reaches it today — every arm
                    // above decides `path` itself, for its entry's, its
                    // slot's or its literal grant. It stands against a
                    // future arm or a second reading of the path; the unit
                    // test `keel54_routing::a_reach_for_another_grant_never_runs_the_call`
                    // is its only cover. Do not remove it as dead code.
                    routes_as_decided(&index, path, &reach)?;
                    let ctx = crate::call::CallContext::admitted_by_gate(auth, reach);
                    // ONE-7: the call a door admitted, kept with the call —
                    // what a hop carries across for exactly that call.
                    let ctx = match door {
                        Some(call) => ctx.at_door(call, peer_slot.as_deref()),
                        None => ctx,
                    };
                    // KEEL-59: a signed-in caller's call, on a grant not
                    // everyone holds, is held to this decision while it runs
                    // (`held`); any other runs as before.
                    // One await for both: the future's state stays the size
                    // it was (two awaits of the routed call made it ~400
                    // bytes larger, PERF's `call.one_item`).
                    let held = held.filter(|_| auth.is_some());
                    let stream = crate::call::scope(ctx.clone(), self.route_ungated(path, params, auth, raw_ctx)).await?;
                    Ok(match held {
                        Some(targets) => super::held::held(ctx, self.clone(), seen, targets, stream),
                        None => Box::pin(crate::call::InCall::new(ctx, stream)),
                    })
                }
            };
        }
        // RETURNS-47: no gate — the call is admitted everywhere, said here
        // rather than assumed by `current_reach` (which fails closed). A
        // service without a gate reached from inside a call (a nested
        // service, a method calling its parent) keeps that call's reach and
        // hop, as the task-local reach always carried through, with this
        // call's identity.
        let ctx = match crate::call::context() {
            Ok(outer) => outer.with_auth(auth),
            Err(_) => crate::call::CallContext::admitted(auth, plexus_auth_core::grants::Reach::everywhere()),
        };
        in_call(ctx, self.route_ungated(path, params, auth, raw_ctx)).await
    }

    /// KEEL-54: what routing answers a path it has nowhere to send, said
    /// without routing it: no dot — not `namespace.method`; a first segment
    /// no entry is (and not the service's own) — `Activation not found`;
    /// else `Method not found` there.
    fn not_found(&self, path: CallPath<'_>) -> PlexusError {
        let (ns, rest) = match self.parse_method(path.as_str()) {
            Ok(split) => split,
            Err(e) => return e,
        };
        if ns != self.inner.namespace && !self.table().entries.contains_key(ns) {
            return PlexusError::ActivationNotFound(ns.to_string());
        }
        PlexusError::MethodNotFound { activation: ns.to_string(), method: rest.to_string() }
    }

    /// Everything [`DynamicHub::route_with_ctx`] does after the grant gate.
    ///
    /// KEEL-54: it routes the path the gate decided ([`CallPath`]) as the
    /// gate's index names it: the service's own namespace to the service's
    /// own methods alone (`svc.hash`, `svc.call`, `svc.<method>.schema`),
    /// every other first segment to its entry. It never takes `svc.` off
    /// again: the macro's fallback below the service's own methods into an
    /// entry would be a second reading of a path the gate decided as one.
    async fn route_ungated(&self, path: CallPath<'_>, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        let method = path.as_str();
        // R-5 scope gate (AUTHZ-CORE-1 + CORE-5). Inactive unless a
        // ScopeRegistry is configured or default_deny is set — a hub with
        // neither pays exactly this one branch and dispatches as before
        // the gate existed (the hard backward-safety constraint).
        if self.inner.scope_registry.is_some() || self.inner.default_deny {
            let registry = self
                .inner
                .scope_registry
                .as_deref()
                .unwrap_or_else(|| super::scope_gate::empty_registry());
            // PERF.115-49: boxed — configured by no tenant; inline, its
            // future was part of every call's.
            Box::pin(super::scope_gate::enforce(
                registry,
                self.inner.default_deny,
                &self.inner.audit_sink,
                method,
                self.gate_index().info(method),
                auth,
                raw_ctx.and_then(|ctx| ctx.peer.map(|peer| peer.ip())),
            ))
            .await?;
        }

        let (namespace, method_name) = self.parse_method(method)?;

        // RETURNS-40 review #1: `ir`'s names, before any work
        if namespace == self.inner.namespace && method_name == "ir" {
            self.check_ir_names(&params, auth)?;
        }

        // NEST-15: routing is `peer(name)` from the root down — the
        // service's own name answers the root itself (its `call`, `hash`,
        // `schema`, `ir`), every other name the root's table; the entry
        // routes the rest of the path below it.
        let stream = if namespace == self.inner.namespace {
            // KEEL-54: the service's own methods, and their schemas — never
            // a path below them routed on into an entry.
            let own = match method_name.split_once('.') {
                None => self.is_own_method(method_name),
                Some((first, "schema")) => first != "schema" && self.is_own_method(first),
                Some(_) => false,
            };
            if !own {
                return Err(self.not_found(path));
            }
            Activation::call(self, method_name, params, auth, raw_ctx).await?
        } else {
            let entry = self.table().entries.get(namespace).map(|e| e.object.clone())
                .ok_or_else(|| PlexusError::ActivationNotFound(namespace.to_string()))?;

            entry.call(method_name, params, auth, raw_ctx).await?
        };

        // CA-1 (trak facet ccc924ad): schema responses leaving this hub get
        // their `requires_credential.site_hint` filled from the backend's
        // advertised auth capabilities. Backends that never call
        // `with_auth_capabilities` (or advertise anonymous-only) derive no
        // site, and the stream passes through untouched — byte-identical to
        // pre-CA-1 emissions.
        if Self::is_schema_query(method_name) {
            if let Some(site) = self.derived_site_hint() {
                return Ok(fill_site_hints_in_schema_stream(stream, site));
            }
        }
        Ok(stream)
    }

    /// Whether a routed `method_name` (the part after the first dot) is a
    /// schema query: `"schema"` (`<ns>.schema`, with or without a `method`
    /// param) or a nested `"<child...>.schema"` path routed into a child
    /// activation.
    fn is_schema_query(method_name: &str) -> bool {
        method_name == "schema" || method_name.ends_with(".schema")
    }

    /// CA-1: the [`AttachmentSite`] implied by this backend's advertised
    /// auth capabilities, or `None` when no capabilities are configured or
    /// none of the advertised mechanisms implies a site.
    ///
    /// [`AttachmentSite`]: plexus_auth_core::AttachmentSite
    pub fn derived_site_hint(&self) -> Option<plexus_auth_core::AttachmentSite> {
        self.inner
            .auth_capabilities
            .as_ref()
            .and_then(|caps| caps.implied_attachment_site())
    }

    /// Resolve a handle using the activation registry
    ///
    /// Looks up the activation by its UUID in the registry.
    pub async fn do_resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError> {
        let path = self.inner.registry.read().unwrap()
            .lookup(handle.plugin_id)
            .map(|s| s.to_string())
            .ok_or_else(|| PlexusError::ActivationNotFound(handle.plugin_id.to_string()))?;

        let activation = self.table().entries.get(&path).map(|e| e.object.clone())
            .ok_or_else(|| PlexusError::ActivationNotFound(path.clone()))?;
        activation.resolve_handle(handle).await
    }

    /// Get activation schema
    pub fn get_activation_schema(&self, namespace: &str) -> Option<Schema> {
        self.table().entries.get(namespace).map(|e| e.object.schema())
    }

    /// Get a snapshot of the activation registry (safe to use outside locks)
    pub fn registry_snapshot(&self) -> PluginRegistrySnapshot {
        let guard = self.inner.registry.read().unwrap();
        PluginRegistrySnapshot {
            by_id: guard.by_id.clone(),
            by_path: guard.by_path.clone(),
        }
    }

    /// Look up an activation path by its UUID
    pub fn lookup_plugin(&self, id: uuid::Uuid) -> Option<String> {
        self.inner.registry.read().unwrap().lookup(id).map(|s| s.to_string())
    }

    /// Look up an activation UUID by its path
    pub fn lookup_plugin_by_path(&self, path: &str) -> Option<uuid::Uuid> {
        self.inner.registry.read().unwrap().lookup_by_path(path)
    }

    /// Get activation schemas for all activations (including this hub itself)
    pub fn list_plugin_schemas(&self) -> Vec<PluginSchema> {
        let mut schemas = Vec::new();

        // Include this hub itself
        schemas.push(Activation::plugin_schema(self));

        // Include registered activations
        for e in self.table().entries.values() {
            schemas.push(e.object.plugin_schema());
        }

        schemas
    }

    /// Deprecated: use list_plugin_schemas instead
    #[deprecated(note = "Use list_plugin_schemas instead")]
    pub fn list_full_schemas(&self) -> Vec<PluginSchema> {
        self.list_plugin_schemas()
    }

    /// Get help for a method
    pub fn get_method_help(&self, method: &str) -> Option<String> {
        let (namespace, method_name) = self.parse_method(method).ok()?;
        let table = self.table();
        table.entries.get(namespace)?.object.method_help(method_name)
    }

    fn parse_method<'a>(&self, method: &'a str) -> Result<(&'a str, &'a str), PlexusError> {
        let parts: Vec<&str> = method.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(PlexusError::InvalidParams {
                param: Some("method".into()),
                problem: ParamProblem::Malformed {
                    detail: format!("expected `namespace.method`, got `{}`", method),
                },
            });
        }
        Ok((parts[0], parts[1]))
    }

    /// Get child activation summaries: one per registered activation, in
    /// namespace order (PERF-21) — the service schema's `children`, which
    /// its `hash` and every caller's view hash digest in this order.
    /// Called by `#[plexus_macros::activation]` when its `hub` flag is set.
    pub fn plugin_children(&self) -> Vec<ChildSummary> {
        self.table().entries.values()
            .map(|e| {
                let schema = e.object.plugin_schema();
                ChildSummary {
                    namespace: schema.namespace,
                    description: schema.description,
                    hash: schema.hash,
                }
            })
            .collect()
    }

    /// Convert to RPC module
    pub fn into_rpc_module(self) -> Result<RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let mut module = RpcModule::new(());

        // NEST-16: a static graft whose parent's methods are not served
        // here, or moved, is refused before anything is served.
        if let Err(misses) = self.check_grafts() {
            panic!("{}", misses.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "));
        }
        PlexusContext::init(self.compute_hash());

        // Register hub methods with runtime namespace using dot notation (e.g., "plexus.call" or "hub.call")
        // Note: we leak these strings to get 'static lifetime required by jsonrpsee
        let ns = self.runtime_namespace();
        let call_method: &'static str = Box::leak(format!("{}.call", ns).into_boxed_str());
        let call_unsub: &'static str = Box::leak(format!("{}.call_unsub", ns).into_boxed_str());
        let hash_method: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let hash_unsub: &'static str = Box::leak(format!("{}.hash_unsub", ns).into_boxed_str());
        let schema_method: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let schema_unsub: &'static str = Box::leak(format!("{}.schema_unsub", ns).into_boxed_str());
        let hash_content_type: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let schema_content_type: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let ns_static: &'static str = Box::leak(ns.to_string().into_boxed_str());

        // Register {ns}.call subscription
        let plexus_for_call = self.clone();
        module.register_subscription(
            call_method,
            PLEXUS_NOTIF_METHOD,
            call_unsub,
            move |params, pending, _ctx, ext| {
                let plexus = plexus_for_call.clone();
                // AUTH-4: a gated hub reads the connection's identity (as
                // arc_into_rpc_module always has); a hub without a gate
                // dispatches anonymously here, as before.
                let identified = plexus.inner.gate.is_some();
                serve_call(plexus, params, pending, ext, ns_static, identified)
            }
        )?;

        register_input_methods(&mut module, ns_static)?;

        // Register {ns}.hash subscription
        let plexus_for_hash = self.clone();
        module.register_subscription(
            hash_method,
            PLEXUS_NOTIF_METHOD,
            hash_unsub,
            move |_params, pending, _ctx, ext| {
                let plexus = plexus_for_hash.clone();
                Box::pin(async move {
                    // AUTH-4: a gated hub's hash is the caller's view's.
                    let auth = ext.get::<std::sync::Arc<super::auth::AuthContext>>().map(|a| a.as_ref());
                    let value = plexus.own_hash(auth);
                    let stream = async_stream::stream! {
                        yield HashEvent::Hash { value };
                    };
                    let wrapped = super::streaming::wrap_stream(stream, hash_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            }
        )?;

        // Register {ns}.schema subscription
        let plexus_for_schema = self.clone();
        module.register_subscription(
            schema_method,
            PLEXUS_NOTIF_METHOD,
            schema_unsub,
            move |params, pending, _ctx, ext| {
                let plexus = plexus_for_schema.clone();
                Box::pin(async move {
                    let p: SchemaParams = params.parse().unwrap_or_default();
                    // AUTH-4: a gated hub answers from the caller's view.
                    let auth = ext.get::<std::sync::Arc<super::auth::AuthContext>>().map(|a| a.as_ref());
                    let mut plugin_schema = plexus.own_schema(auth);
                    // CA-1: hub-derived site hints on the hub's own schema.
                    if let Some(site) = plexus.derived_site_hint() {
                        plugin_schema.fill_site_hints(&site);
                    }

                    let result = if let Some(ref name) = p.method {
                        plugin_schema.methods.iter()
                            .find(|m| m.name == *name)
                            .map(|m| super::SchemaResult::Method(m.clone()))
                            .ok_or_else(|| jsonrpsee::types::ErrorObject::owned(
                                -32602,
                                format!("Method '{}' not found", name),
                                None::<()>,
                            ))?
                    } else {
                        super::SchemaResult::Plugin(plugin_schema)
                    };

                    let stream = async_stream::stream! { yield result; };
                    let wrapped = super::streaming::wrap_stream(stream, schema_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            }
        )?;

        // Register _info well-known endpoint (no namespace prefix).
        // Returns backend name + auth_capabilities (AUTHZ-CORE-3) as a
        // single-item stream with automatic Done event. Backends that have not
        // called with_auth_capabilities get the anonymous-default fallback so
        // capability-aware clients can still discover the auth surface.
        let info_payload = build_info_payload(
            self.runtime_namespace(),
            self.inner.auth_capabilities.as_ref(),
        );
        // AUTH-4: a gated hub answers `_info` per caller; without a gate the
        // payload is built once, as before.
        let plexus_for_info = self.inner.gate.is_some().then(|| self.clone());
        module.register_subscription(
            "_info",
            PLEXUS_NOTIF_METHOD,
            "_info_unsub",
            move |_params, pending, _ctx, ext| {
                let payload = match plexus_for_info.as_ref() {
                    Some(hub) => hub.info(ext.get::<std::sync::Arc<super::auth::AuthContext>>().map(|a| a.as_ref())),
                    None => info_payload.clone(),
                };
                Box::pin(async move {
                    // Create a single-item stream with the info response
                    let info_stream = futures::stream::once(async move { payload });

                    // Wrap to auto-append Done event
                    let wrapped = super::streaming::wrap_stream(
                        info_stream,
                        "_info",
                        vec![]
                    );

                    // Pipe to subscription (handles Done automatically)
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            }
        )?;

        // Add all registered activation RPC methods — unless a grant gate
        // is set (AUTH-2): those direct methods carry no auth and would pass
        // around it, so a gated hub is reached only through `<ns>.call`.
        let pending = std::mem::take(&mut *self.inner.pending_rpc.lock().unwrap());
        if self.inner.gate.is_none() {
            for factory in pending {
                module.merge(factory())?;
            }
        }

        // CHILD-WIRE: for each registered child router with capability bits set,
        // register {ns}.list_children / {ns}.search_children as subscriptions.
        // Per-activation namespaced (not top-level _list_children).
        // KEEL-33: not on a gated service — they would run beside the gate.
        if self.inner.gate.is_none() {
            for (ns, e) in self.table().entries.iter() {
                register_child_capability_methods(&mut module, ns, e.router.clone())?;
            }
        }

        Ok(module)
    }

    /// V2-57: serve one `{ns}.call` exactly as this service's own `{ns}.call`
    /// does: routed as the connection's caller (the `AuthContext` the upgrade
    /// put in `ext`), a method with an `Input` taking its input half from
    /// `pending` (BIDIR-6), each item piped, a dispatch error sent as an
    /// item. For a host that registers `{ns}.call` itself to check its own
    /// limits first (menger's call layer): it removes the module's
    /// `{ns}.call`, registers its own, and hands each call it admits here.
    /// Routing with [`route`](Self::route) instead runs outside the call's
    /// seam, so an `Input` method answers that the transport carries none.
    /// `ns` is the service's runtime namespace, the error items' source.
    pub fn serve_call(
        &self,
        params: jsonrpsee::types::Params<'static>,
        pending: jsonrpsee::PendingSubscriptionSink,
        ext: http::Extensions,
        ns: &'static str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = jsonrpsee::core::SubscriptionResult> + Send>> {
        serve_call(self.clone(), params, pending, ext, ns, true)
    }

    /// Convert Arc<DynamicHub> to RPC module while keeping the Arc alive
    ///
    /// Unlike `into_rpc_module`, this keeps the Arc<DynamicHub> reference alive,
    /// which is necessary when activations hold Weak<DynamicHub> references that
    /// need to remain upgradeable.
    pub fn arc_into_rpc_module(hub: Arc<Self>) -> Result<RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let mut module = RpcModule::new(());

        // NEST-16: a static graft whose parent's methods are not served
        // here, or moved, is refused before anything is served.
        if let Err(misses) = hub.check_grafts() {
            panic!("{}", misses.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "));
        }
        PlexusContext::init(hub.compute_hash());

        // Register hub methods with runtime namespace using dot notation (e.g., "plexus.call" or "hub.call")
        // Note: we leak these strings to get 'static lifetime required by jsonrpsee
        let ns = hub.runtime_namespace();
        let call_method: &'static str = Box::leak(format!("{}.call", ns).into_boxed_str());
        let call_unsub: &'static str = Box::leak(format!("{}.call_unsub", ns).into_boxed_str());
        let hash_method: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let hash_unsub: &'static str = Box::leak(format!("{}.hash_unsub", ns).into_boxed_str());
        let schema_method: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let schema_unsub: &'static str = Box::leak(format!("{}.schema_unsub", ns).into_boxed_str());
        let hash_content_type: &'static str = Box::leak(format!("{}.hash", ns).into_boxed_str());
        let schema_content_type: &'static str = Box::leak(format!("{}.schema", ns).into_boxed_str());
        let ns_static: &'static str = Box::leak(ns.to_string().into_boxed_str());

        // Register {ns}.call subscription - clone Arc to keep reference alive
        let hub_for_call = hub.clone();
        module.register_subscription(
            call_method,
            call_method,
            call_unsub,
            move |params, pending, _ctx, ext| {
                let hub = hub_for_call.clone();
                let hub = (*hub).clone();
                serve_call(hub, params, pending, ext, ns_static, true)
            }
        )?;

        register_input_methods(&mut module, ns_static)?;

        // Register {ns}.hash subscription
        let hub_for_hash = hub.clone();
        module.register_subscription(
            hash_method,
            PLEXUS_NOTIF_METHOD,
            hash_unsub,
            move |_params, pending, _ctx, ext| {
                let hub = hub_for_hash.clone();
                Box::pin(async move {
                    // AUTH-4: a gated hub's hash is the caller's view's.
                    let auth = ext.get::<std::sync::Arc<super::auth::AuthContext>>().map(|a| a.as_ref());
                    let value = hub.own_hash(auth);
                    let stream = async_stream::stream! {
                        yield HashEvent::Hash { value };
                    };
                    let wrapped = super::streaming::wrap_stream(stream, hash_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            }
        )?;

        // Register {ns}.schema subscription
        let hub_for_schema = hub.clone();
        module.register_subscription(
            schema_method,
            PLEXUS_NOTIF_METHOD,
            schema_unsub,
            move |params, pending, _ctx, ext| {
                let hub = hub_for_schema.clone();
                Box::pin(async move {
                    let p: SchemaParams = params.parse().unwrap_or_default();
                    // AUTH-4: a gated hub answers from the caller's view.
                    let auth = ext.get::<std::sync::Arc<super::auth::AuthContext>>().map(|a| a.as_ref());
                    let mut plugin_schema = hub.own_schema(auth);
                    // CA-1: hub-derived site hints on the hub's own schema.
                    if let Some(site) = hub.derived_site_hint() {
                        plugin_schema.fill_site_hints(&site);
                    }

                    let result = if let Some(ref name) = p.method {
                        plugin_schema.methods.iter()
                            .find(|m| m.name == *name)
                            .map(|m| super::SchemaResult::Method(m.clone()))
                            .ok_or_else(|| jsonrpsee::types::ErrorObject::owned(
                                -32602,
                                format!("Method '{}' not found", name),
                                None::<()>,
                            ))?
                    } else {
                        super::SchemaResult::Plugin(plugin_schema)
                    };

                    let stream = async_stream::stream! {
                        yield result;
                    };
                    let wrapped = super::streaming::wrap_stream(stream, schema_content_type, vec![ns_static.into()]);
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            }
        )?;

        // Register _info well-known endpoint (no namespace prefix).
        // Returns backend name + auth_capabilities (AUTHZ-CORE-3) as a
        // single-item stream with automatic Done event. Same payload shape as
        // the sibling registration in into_rpc_module.
        let info_payload = build_info_payload(
            hub.runtime_namespace(),
            hub.inner.auth_capabilities.as_ref(),
        );
        // AUTH-4: a gated hub answers `_info` per caller; without a gate the
        // payload is built once, as before.
        let hub_for_info = hub.inner.gate.is_some().then(|| hub.clone());
        module.register_subscription(
            "_info",
            PLEXUS_NOTIF_METHOD,
            "_info_unsub",
            move |_params, pending, _ctx, ext| {
                let payload = match hub_for_info.as_ref() {
                    Some(hub) => hub.info(ext.get::<std::sync::Arc<super::auth::AuthContext>>().map(|a| a.as_ref())),
                    None => info_payload.clone(),
                };
                Box::pin(async move {
                    // Create a single-item stream with the info response
                    let info_stream = futures::stream::once(async move { payload });

                    // Wrap to auto-append Done event
                    let wrapped = super::streaming::wrap_stream(
                        info_stream,
                        "_info",
                        vec![]
                    );

                    // Pipe to subscription (handles Done automatically)
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            }
        )?;

        // Register pending RPC methods from activations
        // AUTH-2: not under a grant gate — see `into_rpc_module`.
        let mut pending = std::mem::take(&mut *hub.inner.pending_rpc.lock().unwrap());
        if hub.inner.gate.is_some() {
            pending.clear();
        }
        tracing::trace!(factories = pending.len(), "merging activation RPC factories");
        for (idx, factory) in pending.into_iter().enumerate() {
            tracing::trace!(factory_idx = idx, "calling factory to get Methods");
            let methods = factory();
            let method_count = methods.method_names().count();
            tracing::trace!(factory_idx = idx, methods = method_count, "factory returned Methods; merging into module");
            module.merge(methods)?;
            tracing::trace!(factory_idx = idx, "successfully merged factory methods");
        }
        tracing::trace!("all activations merged successfully");

        // CHILD-WIRE: for each registered child router with capability bits set,
        // register {ns}.list_children / {ns}.search_children as subscriptions.
        // KEEL-33: not on a gated service — they would run beside the gate.
        if hub.inner.gate.is_none() {
            for (ns, e) in hub.table().entries.iter() {
                register_child_capability_methods(&mut module, ns, e.router.clone())?;
            }
        }

        Ok(module)
    }
}

/// CHILD-WIRE: register per-activation namespaced `<ns>.list_children` and
/// `<ns>.search_children` as subscription methods when the router advertises
/// the corresponding capability bits.
///
/// Each name returned by `ChildRouter::list_children` / `search_children` is
/// emitted as a `data` envelope with `content_type` set to the method name
/// (`"list_children"` or `"search_children"`) and `content` carrying the name
/// string. Termination is `done`. Mirrors the standard `wrap_stream` shape
/// used by every other framework subscription.
///
/// Activations that advertise neither bit produce no registrations — calling
/// the methods returns standard `methodNotFound`. That's the wire-level
/// signal that the activation doesn't support enumeration / search.
///
/// KEEL-33: registered only on a service **without a gate**. They run the
/// router's list or search function with no grant decided — that function
/// may be no method at all (a plain `fn`), so it has no grant of its own to
/// decide them by. On a gated service the list method, when it is a method,
/// is reached as any method is: through `{ns}.call`, by its own grant; and
/// the names a caller may see are its view's.
///
/// RETURNS-47: the context such a call runs in, so a dynamic child's list
/// or search method reads its caller as any method does: everywhere, as a
/// service without a gate admits every call.
fn listing_context(ext: &jsonrpsee::Extensions) -> crate::call::CallContext {
    let auth = ext.get::<Arc<super::auth::AuthContext>>().map(|a| a.as_ref());
    crate::call::CallContext::admitted(auth, plexus_auth_core::grants::Reach::everywhere())
}

#[allow(deprecated)] // ChildCapabilities is deprecated by IR-4 but still the wire-level signal
fn register_child_capability_methods(
    module: &mut RpcModule<()>,
    namespace: &str,
    router: Arc<dyn ChildRouter>,
) -> Result<(), jsonrpsee::core::RegisterMethodError> {
    let caps = router.capabilities();
    if caps.is_empty() {
        return Ok(());
    }

    let ns_static: &'static str = Box::leak(namespace.to_string().into_boxed_str());

    if caps.contains(ChildCapabilities::LIST) {
        let list_method: &'static str =
            Box::leak(format!("{}.list_children", namespace).into_boxed_str());
        let list_unsub: &'static str =
            Box::leak(format!("{}.list_children_unsub", namespace).into_boxed_str());
        let router_for_list = router.clone();
        module.register_subscription(
            list_method,
            PLEXUS_NOTIF_METHOD,
            list_unsub,
            move |_params, pending, _ctx, ext| {
                let router = router_for_list.clone();
                let ctx = listing_context(&ext);
                Box::pin(async move {
                    // Collect names eagerly so the BoxStream's borrow on the
                    // router doesn't outlive list_children's call. For v1 this
                    // matches the typical pattern (small finite child sets like
                    // Solar's eight planets). A future variant could keep the
                    // Arc-borrow alive across the stream by binding the BoxStream
                    // to the Arc directly — out of scope here.
                    let collected: Vec<String> = crate::call::scope(ctx, async {
                        match router.list_children().await {
                            Some(mut s) => {
                                use futures::StreamExt;
                                let mut acc = Vec::new();
                                while let Some(name) = s.next().await {
                                    acc.push(name);
                                }
                                acc
                            }
                            None => Vec::new(),
                        }
                    })
                    .await;
                    let stream = async_stream::stream! {
                        for name in collected {
                            yield name;
                        }
                    };
                    let wrapped = super::streaming::wrap_stream(
                        stream,
                        "list_children",
                        vec![ns_static.into()],
                    );
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            },
        )?;
    }

    if caps.contains(ChildCapabilities::SEARCH) {
        let search_method: &'static str =
            Box::leak(format!("{}.search_children", namespace).into_boxed_str());
        let search_unsub: &'static str =
            Box::leak(format!("{}.search_children_unsub", namespace).into_boxed_str());
        let router_for_search = router.clone();
        module.register_subscription(
            search_method,
            PLEXUS_NOTIF_METHOD,
            search_unsub,
            move |params, pending, _ctx, ext| {
                let router = router_for_search.clone();
                let ctx = listing_context(&ext);
                Box::pin(async move {
                    let p: SearchChildrenParams = params.parse()?;
                    let collected: Vec<String> = crate::call::scope(ctx, async {
                        match router.search_children(&p.query).await {
                            Some(mut s) => {
                                use futures::StreamExt;
                                let mut acc = Vec::new();
                                while let Some(name) = s.next().await {
                                    acc.push(name);
                                }
                                acc
                            }
                            None => Vec::new(),
                        }
                    })
                    .await;
                    let stream = async_stream::stream! {
                        for name in collected {
                            yield name;
                        }
                    };
                    let wrapped = super::streaming::wrap_stream(
                        stream,
                        "search_children",
                        vec![ns_static.into()],
                    );
                    pipe_stream_to_subscription(pending, wrapped, &ext).await
                })
            },
        )?;
    }

    Ok(())
}

/// Params for `<ns>.search_children`
#[derive(Debug, serde::Deserialize)]
struct SearchChildrenParams {
    query: String,
}

/// Params for {ns}.call
#[derive(Debug, serde::Deserialize)]
pub(crate) struct CallParams {
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Option<Value>,
}

/// BIDIR-6: [`DynamicHub::input_terms`]' answer.
pub(crate) struct InputTerms {
    pub(crate) grant: String,
    pub(crate) targets: Vec<String>,
    pub(crate) recheck: bool,
}

/// Params for {ns}.schema (SYNAPSE-CC-9: the published type)
use super::schema::SchemaParams;

/// `{ns}.call`: route the call, then pipe what it answers.
///
/// The call's future is boxed here, and is its one allocation of that size,
/// so it is chosen before it is made: a method the service knows has no
/// `Input` is routed and piped as it was before BIDIR-6,
/// holding nothing of the input half (the seam inline in one future for both
/// was 1,024 bytes more a call, and the params kept beside it 176 more);
/// any other ([`DynamicHub::may_take_input`]) is [`serve_seamed`]. A
/// dispatch error is sent as a stream item on the
/// accepted subscription: this preserves its message and code, where
/// returning it from a subscription handler has jsonrpsee wrap it as generic
/// -32603.
fn serve_call(
    service: DynamicHub,
    params: jsonrpsee::types::Params<'static>,
    pending: jsonrpsee::PendingSubscriptionSink,
    ext: http::Extensions,
    ns: &'static str,
    identified: bool,
) -> CallFuture {
    // Read here, not in the future: the choice of future is made on it, and
    // the plain one then holds neither the params' text nor the method name.
    let call: CallParams = match params.parse() {
        Ok(call) => call,
        Err(e) => return Box::pin(async move { Err(e.into()) }),
    };
    if service.may_take_input(&call.method) {
        return Box::pin(serve_seamed(service, call, params, pending, ext, ns, identified));
    }
    let CallParams { method, params: args } = call;
    Box::pin(async move {
        let caller = if identified { ext.get::<Arc<super::auth::AuthContext>>().map(|a| a.as_ref()) } else { None };
        match service.route(&method, args.unwrap_or_default(), caller).await {
            Ok(stream) => pipe_stream_to_subscription(pending, stream, &ext).await,
            Err(e) => {
                let sink = pending.accept().await?;
                if let Some(raw) = error_item_raw(ns, &e) {
                    let _ = sink.send(raw).await;
                }
                Ok(())
            }
        }
    })
}

/// A `{ns}.call`'s future, boxed: one allocation a call, the size of the
/// path it takes.
type CallFuture = std::pin::Pin<Box<dyn std::future::Future<Output = jsonrpsee::core::SubscriptionResult> + Send>>;

/// [`serve_call`] for a method that may take an `Input`: the route runs
/// inside [`super::input::CALL`], holding the unaccepted subscription and the
/// extensions, and a method with an `Input` parameter takes them there
/// (BIDIR-6); one without leaves them.
async fn serve_seamed(
    service: DynamicHub,
    call: CallParams,
    params: jsonrpsee::types::Params<'static>,
    pending: jsonrpsee::PendingSubscriptionSink,
    ext: http::Extensions,
    ns: &'static str,
    identified: bool,
) -> jsonrpsee::core::SubscriptionResult {
    let caller = if identified { ext.get::<Arc<super::auth::AuthContext>>().cloned() } else { None };
    let seen = service.inner.gate.as_ref().map_or(0, |g| g.generation().current());
    let opened = Arc::new(std::sync::Mutex::new(None::<super::input::Opened>));
    let take = || opened.lock().unwrap_or_else(|e| e.into_inner()).take();
    let mut scoped = std::pin::pin!(super::input::CALL.scope(
        std::cell::RefCell::new(super::input::Seam { service: service.clone(), params, pending: Some(pending), ext, seen, opened: opened.clone(), refused: None }),
        service.route(&call.method, call.params.unwrap_or_default(), caller.as_deref()),
    ));
    // The route runs until it answers, or until the method has opened its
    // input half: a handler may read its input before it returns its stream,
    // so from the open the pipe runs (credit, items, cancel) beside the
    // route still resolving.
    let answered = std::future::poll_fn(|cx| match std::future::Future::poll(scoped.as_mut(), cx) {
        std::task::Poll::Ready(answer) => std::task::Poll::Ready(Some(answer)),
        std::task::Poll::Pending if opened.lock().unwrap_or_else(|e| e.into_inner()).is_some() => std::task::Poll::Ready(None),
        std::task::Poll::Pending => std::task::Poll::Pending,
    })
    .await;
    let Some(answer) = answered else {
        let super::input::Opened { sink, duplex } = take().expect("opened, the route still resolving");
        let mut routing = std::pin::pin!(async { scoped.as_mut().await.map_err(|e| error_item(ns, &e)) });
        return Box::pin(super::wire::pipe_duplex(sink, super::wire::Output::Routing(routing.as_mut()), duplex)).await;
    };
    let super::input::Seam { pending, ext, refused, .. } = scoped.as_mut().take_value().expect("the scope ran to its end").into_inner();
    match (answer, take()) {
        // Boxed: a call with no input half does not carry its room.
        (Ok(stream), Some(opened)) => Box::pin(super::wire::pipe_duplex(opened.sink, super::wire::Output::Ready(stream), opened.duplex)).await,
        (Ok(stream), None) => {
            let pending = pending.expect("only an open takes it, and an open is `opened`");
            pipe_stream_to_subscription(pending, stream, &ext).await
        }
        (Err(e), opened) => {
            let sink = match (opened, pending) {
                (Some(opened), _) => opened.sink,
                (None, Some(pending)) => pending.accept().await?,
                (None, None) => return Ok(()),
            };
            let raw = match refused {
                Some(item) => serde_json::value::to_raw_value(&item).ok(),
                None => error_item_raw(ns, &e),
            };
            if let Some(raw) = raw {
                let _ = sink.send(raw).await;
            }
            Ok(())
        }
    }
}

/// BIDIR-6: `{ns}.input` and `{ns}.end` in the method table, for a client
/// that sends them as requests and wants an answer (`true`: it reached the
/// call; `false`: a resend, or the half has closed). The notification, which
/// is what a client normally sends, is taken on the socket's reader before
/// the table. Sync methods, so a request is run in place, in order.
fn register_input_methods(module: &mut RpcModule<()>, ns: &'static str) -> Result<(), jsonrpsee::core::RegisterMethodError> {
    use super::input::{Delivered, InputTable};
    use jsonrpsee::types::ErrorObjectOwned;

    fn answer(delivered: Delivered) -> Result<bool, ErrorObjectOwned> {
        match delivered {
            Delivered::Taken => Ok(true),
            Delivered::Dropped | Delivered::Refused => Ok(false),
            Delivered::NotThisCall => Err(ErrorObjectOwned::owned(
                -32003,
                "not_this_call: input comes from the connection that opened the call",
                Some(serde_json::json!({"error_kind": "not_this_call"})),
            )),
            Delivered::Malformed => Err(ErrorObjectOwned::owned(-32602, "invalid params: subscription, seq and items", None::<()>)),
        }
    }
    fn table(ext: &http::Extensions) -> Result<&Arc<InputTable>, ErrorObjectOwned> {
        ext.get::<super::wire::FrameSink>()
            .and_then(super::wire::FrameSink::inputs)
            .ok_or_else(|| ErrorObjectOwned::owned(-32601, "this transport carries no input half: call over a WebSocket", None::<()>))
    }

    let input_method: &'static str = Box::leak(format!("{ns}.input").into_boxed_str());
    let end_method: &'static str = Box::leak(format!("{ns}.end").into_boxed_str());
    module.register_method(input_method, move |params, _ctx, ext| {
        let frame = bytes::Bytes::copy_from_slice(params.as_str().unwrap_or("null").as_bytes());
        answer(table(ext)?.input(ns, &frame, &frame))
    })?;
    module.register_method(end_method, move |params, _ctx, ext| answer(table(ext)?.end(ns, params.as_str().unwrap_or("null").as_bytes())))?;
    Ok(())
}

/// Pipe a call's stream to its subscription: accept it, then
/// [`super::wire::pipe`] — each item encoded once and written as one frame
/// (PERF-7), on the transport's own frames when the call's extensions
/// carry them.
///
/// Notifications are sent with the `notif_method_name` each
/// `register_subscription` call set.
///
/// The pipe watches the sink's close (an unsubscribe, a lost socket),
/// dropping the stream at once.
async fn pipe_stream_to_subscription(
    pending: jsonrpsee::PendingSubscriptionSink,
    stream: PlexusStream,
    ext: &http::Extensions,
) -> jsonrpsee::core::SubscriptionResult {
    let sink = pending.accept().await?;
    super::wire::pipe(sink, stream, ext).await
}

// ============================================================================
// DynamicHub RPC Methods (via plexus-macros)
// ============================================================================

#[plexus_macros::activation(
    namespace = "plexus",
    version = "1.0.0",
    description = "Central routing and introspection",
    hub,
    namespace_fn = "runtime_namespace"
)]
#[allow(deprecated)]
impl DynamicHub {
    /// Route a call to a registered activation
    #[plexus_macros::method(
        description = "Route a call to a registered activation",
        params(
            method = "The method to call (format: namespace.method)",
            params = "Parameters to pass to the method (optional, defaults to {})"
        )
    )]
    async fn call(
        &self,
        method: String,
        params: Option<Value>,
    ) -> impl Stream<Item = super::types::PlexusStreamItem> + Send + 'static {
        use super::context::PlexusContext;
        use super::types::{PlexusStreamItem, StreamMetadata};

        // KEEL-54 (R2): a service registered as an entry of another is
        // reached by its path (`inner.leaf.read`), which the outer gate
        // decides. Its own `call`, run inside a call the outer gate
        // admitted on `inner.call` alone, would route as this service —
        // ungated here, with the outer call's reach — past every check the
        // path would meet. Refused, decided where it runs: whatever mounted
        // it, in whatever order its gate was set.
        let outer = super::service_scope::current().filter(|w| !w.is(self)).and_then(|w| w.upgrade());
        let result = match outer {
            Some(outer) if outer.inner.gate.is_some() => Err(PlexusError::Forbidden {
                reason: AuthzDenyReason::MissingGrant {
                    grant: plexus_auth_core::grants::Grant::new(format!("{}.call", self.inner.namespace)),
                    scope: plexus_auth_core::grants::ScopeRef::Everywhere,
                    roles: Vec::new(),
                    held_on: Vec::new(),
                },
            }),
            _ => self.route(&method, params.unwrap_or_default(), None).await,
        };

        match result {
            Ok(plexus_stream) => {
                // Forward the routed stream directly - it already contains PlexusStreamItems
                plexus_stream
            }
            Err(e) => {
                // Return error as a PlexusStreamItem stream
                let metadata = StreamMetadata::new(
                    vec![self.inner.namespace.clone()],
                    PlexusContext::hash(),
                );
                Box::pin(futures::stream::once(async move {
                    PlexusStreamItem::from_plexus_error(metadata, &e, false)
                }))
            }
        }
    }

    /// Get Plexus RPC server configuration hash (from the recursive schema)
    ///
    /// This hash changes whenever any method or child activation changes.
    /// It's computed from the method hashes rolled up through the schema tree.
    #[plexus_macros::method(description = "Get plexus configuration hash (from the recursive schema)\n\n This hash changes whenever any method or child plugin changes.\n It's computed from the method hashes rolled up through the schema tree.")]
    async fn hash(&self) -> impl Stream<Item = HashEvent> + Send + 'static {
        let schema = Activation::plugin_schema(self);
        stream! { yield HashEvent::Hash { value: schema.hash }; }
    }

    /// Get plugin hashes for cache validation (lightweight alternative to full schema)
    #[plexus_macros::method(description = "Get plugin hashes for cache validation")]
    #[allow(deprecated)]
    async fn hashes(&self) -> impl Stream<Item = PluginHashes> + Send + 'static {
        let schema = Activation::plugin_schema(self);

        stream! {
            yield PluginHashes {
                namespace: schema.namespace.clone(),
                self_hash: schema.self_hash.clone(),
                children_hash: schema.children_hash.clone(),
                hash: schema.hash.clone(),
                children: schema.children.as_ref().map(|kids| {
                    kids.iter()
                        .map(|c| ChildHashes {
                            namespace: c.namespace.clone(),
                            hash: c.hash.clone(),
                        })
                        .collect()
                }),
            };
        }
    }

    /// RETURNS-40: the service's IR — IR 3.0, every type once and each
    /// method referring to them — of the namespaces asked (none: the whole
    /// service), as the caller sees the service. The one way to ask for
    /// several schemas; `<ns>.schema` answers one. Equal to what synapse
    /// builds from the same raw schemas.
    #[plexus_macros::method(
        description = "The service's IR (3.0): every type once, each method referring to them — of the namespaces asked, or the whole service",
        params(namespaces = "The namespaces (dotted paths) to describe; none: the whole service")
    )]
    async fn ir(
        &self,
        auth: Option<&super::auth::AuthContext>,
        namespaces: Option<Vec<String>>,
    ) -> Result<super::ir::ServiceIr, super::ir::IrError> {
        self.service_ir(&namespaces.unwrap_or_default(), auth).await
    }

    // Note: schema() method is auto-generated by hub-macro for all activations
}

// ============================================================================
// HubContext Implementation for Weak<DynamicHub>
// ============================================================================

use super::hub_context::HubContext;
use std::sync::Weak;

/// HubContext implementation for Weak<DynamicHub>
///
/// This enables activations to receive a weak reference to their parent DynamicHub,
/// allowing them to resolve handles and route calls through the hub without
/// creating reference cycles.
#[async_trait]
impl HubContext for Weak<DynamicHub> {
    async fn resolve_handle(&self, handle: &Handle) -> Result<PlexusStream, PlexusError> {
        let hub = self.upgrade().ok_or_else(|| {
            PlexusError::ExecutionError("Parent hub has been dropped".to_string())
        })?;
        hub.do_resolve_handle(handle).await
    }

    async fn call(&self, method: &str, params: serde_json::Value) -> Result<PlexusStream, PlexusError> {
        let hub = self.upgrade().ok_or_else(|| {
            PlexusError::ExecutionError("Parent hub has been dropped".to_string())
        })?;
        hub.route(method, params, None).await
    }

    fn is_valid(&self) -> bool {
        self.upgrade().is_some()
    }
}

/// ChildRouter implementation for DynamicHub
///
/// This enables nested routing through registered activations.
/// e.g., hub.call("solar.mercury.info") routes to solar → mercury → info
#[async_trait]
impl ChildRouter for DynamicHub {
    fn router_namespace(&self) -> &str {
        &self.inner.namespace
    }

    async fn router_call(&self, method: &str, params: Value, auth: Option<&super::auth::AuthContext>, raw_ctx: Option<&crate::request::RawRequestContext>) -> Result<PlexusStream, PlexusError> {
        // DynamicHub routes via its registered activations
        // Method format: "activation.method" or "activation.child.method"
        self.route_with_ctx(method, params, auth, raw_ctx).await
    }

    async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
        // Look up registered activations that implement ChildRouter
        self.table().entries.get(name).map(|e| e.router.clone())
            .map(|router| {

                // Clone the Arc and wrap in Box for the trait object
                Box::new(ArcChildRouter(router.clone())) as Box<dyn ChildRouter>
            })
    }

    /// AUTHLANG-3 — consult the hub's
    /// [`ForwardPolicyRegistry`](super::forward_registry::ForwardPolicyRegistry).
    fn forward_policy_for(
        &self,
        callee_ns: &str,
    ) -> Option<std::sync::Arc<dyn plexus_auth_core::ForwardPolicy>> {
        self.inner.forward_policies.get(callee_ns)
    }

    // `framework_stamped_principal` retains the trait default
    // (`Principal::Anonymous`) for now. AUTHLANG-3 wires the dispatch path
    // to read this; populating it with the per-connection stamp lands
    // when the principal-minting service (post-AUTHZ-0 / future
    // CRED-CORE) is wired into the WS upgrade path. The current
    // anonymous return value is correct under today's no-auth substrate.
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_hub_implements_activation() {
        fn assert_activation<T: Activation>() {}
        assert_activation::<DynamicHub>();
    }

    #[test]
    fn dynamic_hub_methods() {
        let hub = DynamicHub::new("test");
        let methods = hub.methods();
        assert!(methods.contains(&"call"));
        assert!(methods.contains(&"hash"));
        assert!(methods.contains(&"schema"));
        // list_activations was removed - use schema() instead
    }

    #[test]
    fn dynamic_hub_hash_stable() {
        let h1 = DynamicHub::new("test");
        let h2 = DynamicHub::new("test");
        assert_eq!(h1.compute_hash(), h2.compute_hash());
    }

    #[test]
    fn dynamic_hub_is_hub() {
        use crate::activations::health::Health;
        let hub = DynamicHub::new("test").register(Health::new());
        let schema = hub.plugin_schema();

        // DynamicHub should be a hub (has children)
        assert!(schema.is_hub(), "dynamic hub should be a hub");
        assert!(!schema.is_leaf(), "dynamic hub should not be a leaf");

        // Should have children (as summaries)
        let children = schema.children.expect("dynamic hub should have children");
        assert!(!children.is_empty(), "dynamic hub should have at least one child");

        // Health should be in the children summaries
        let health = children.iter().find(|c| c.namespace == "health").expect("should have health child");
        assert!(!health.hash.is_empty(), "health should have a hash");
    }

    /// Z2H-8 / HOSTLESS-3 — a hub root that shares its name with a registered
    /// activation's namespace is rejected loudly at registration time instead
    /// of producing a silently unreachable child (the shipped echo example's
    /// exact failure shape).
    #[test]
    #[should_panic(expected = "activation namespace 'health' collides with the hub root namespace 'health'")]
    fn dynamic_hub_rejects_root_namespace_shadow() {
        use crate::activations::health::Health;
        let _hub = DynamicHub::new("health").register(Health::new());
    }

    /// Z2H-8 / HOSTLESS-3 — the deprecated register_hub path enforces the
    /// same collision contract.
    #[test]
    #[should_panic(expected = "activation namespace 'health' collides with the hub root namespace 'health'")]
    fn dynamic_hub_register_hub_rejects_root_namespace_shadow() {
        use crate::activations::health::Health;
        let _hub = DynamicHub::new("health").register_hub(Health::new());
    }

    /// Z2H-8 — the shadow error names both colliding strings and suggests the
    /// fix (rename the hub root), so the failure is actionable without
    /// reading plexus-core source.
    #[test]
    fn dynamic_hub_shadow_error_names_collision_and_fix() {
        use crate::activations::health::Health;
        let result = std::panic::catch_unwind(|| {
            let _hub = DynamicHub::new("health").register(Health::new());
        });
        let err = result.expect_err("shadow registration must panic");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .expect("panic payload should be a string");
        assert!(msg.contains("'health'"), "must name the colliding namespace: {msg}");
        assert!(msg.contains("hub root namespace"), "must name the root side: {msg}");
        assert!(msg.contains("rename the hub root"), "must suggest the fix: {msg}");
        assert!(msg.contains("Z2H-8"), "must cite the ticket: {msg}");
    }

    /// Z2H-8 — non-colliding registration is unaffected by shadow detection:
    /// the child registers, routes, and appears in the schema.
    #[test]
    fn dynamic_hub_non_colliding_registration_unaffected() {
        use crate::activations::health::Health;
        let hub = DynamicHub::new("health_hub").register(Health::new());
        assert_eq!(hub.runtime_namespace(), "health_hub");
        let schema = hub.plugin_schema();
        let children = schema.children.expect("hub should have children");
        assert!(
            children.iter().any(|c| c.namespace == "health"),
            "health child must be registered"
        );
        assert!(hub.list_methods().iter().any(|m| m.starts_with("health.")));
    }

    #[test]
    fn dynamic_hub_schema_structure() {
        use crate::activations::health::Health;
        let hub = DynamicHub::new("test").register(Health::new());
        let schema = hub.plugin_schema();

        // Pretty print the schema
        let json = serde_json::to_string_pretty(&schema).unwrap();
        println!("DynamicHub schema:\n{}", json);

        // Verify structure
        assert_eq!(schema.namespace, "test");
        assert!(schema.methods.iter().any(|m| m.name == "call"));
        assert!(schema.children.is_some());
    }

    // ========================================================================
    // INVARIANT: Handle routing - resolves to correct plugin
    // ========================================================================

    #[tokio::test]
    async fn invariant_resolve_handle_unknown_activation() {
        use crate::activations::health::Health;
        use crate::types::Handle;
        use uuid::Uuid;

        let hub = DynamicHub::new("test").register(Health::new());

        // Handle for an unregistered activation (random UUID)
        let unknown_plugin_id = Uuid::new_v4();
        let handle = Handle::new(unknown_plugin_id, "1.0.0", "some_method");

        let result = hub.do_resolve_handle(&handle).await;

        match result {
            Err(PlexusError::ActivationNotFound(_)) => {
                // Expected - activation not found
            }
            Err(other) => panic!("Expected ActivationNotFound, got {:?}", other),
            Ok(_) => panic!("Expected error for unknown activation"),
        }
    }

    #[tokio::test]
    async fn invariant_resolve_handle_unsupported() {
        use crate::activations::health::Health;
        use crate::types::Handle;

        let hub = DynamicHub::new("test").register(Health::new());

        // Handle for health activation (which doesn't support handle resolution)
        let handle = Handle::new(Health::PLUGIN_ID, "1.0.0", "check");

        let result = hub.do_resolve_handle(&handle).await;

        match result {
            Err(PlexusError::HandleNotSupported(name)) => {
                assert_eq!(name, "health");
            }
            Err(other) => panic!("Expected HandleNotSupported, got {:?}", other),
            Ok(_) => panic!("Expected error for unsupported handle"),
        }
    }

    #[tokio::test]
    async fn invariant_resolve_handle_routes_by_plugin_id() {
        use crate::activations::health::Health;
        use crate::activations::echo::EchoActivation;
        use crate::types::Handle;
        use uuid::Uuid;

        let health = Health::new();
        let echo = EchoActivation::new();
        let health_plugin_id = health.plugin_id();
        let echo_plugin_id = echo.plugin_id();

        let hub = DynamicHub::new("test")
            .register(health)
            .register(echo);

        // Health handle → health activation
        let health_handle = Handle::new(health_plugin_id, "1.0.0", "check");
        match hub.do_resolve_handle(&health_handle).await {
            Err(PlexusError::HandleNotSupported(name)) => assert_eq!(name, "health"),
            Err(other) => panic!("health handle should route to health activation, got {:?}", other),
            Ok(_) => panic!("health handle should return HandleNotSupported"),
        }

        // Echo handle → echo activation
        let echo_handle = Handle::new(echo_plugin_id, "1.0.0", "echo");
        match hub.do_resolve_handle(&echo_handle).await {
            Err(PlexusError::HandleNotSupported(name)) => assert_eq!(name, "echo"),
            Err(other) => panic!("echo handle should route to echo activation, got {:?}", other),
            Ok(_) => panic!("echo handle should return HandleNotSupported"),
        }

        // Unknown handle → ActivationNotFound (random UUID not registered)
        let unknown_handle = Handle::new(Uuid::new_v4(), "1.0.0", "method");
        match hub.do_resolve_handle(&unknown_handle).await {
            Err(PlexusError::ActivationNotFound(_)) => { /* expected */ },
            Err(other) => panic!("unknown handle should return ActivationNotFound, got {:?}", other),
            Ok(_) => panic!("unknown handle should return ActivationNotFound"),
        }
    }

    #[test]
    fn invariant_handle_plugin_id_determines_routing() {
        use crate::activations::health::Health;
        use crate::activations::echo::EchoActivation;
        use crate::types::Handle;

        let health = Health::new();
        let echo = EchoActivation::new();

        // Same meta, different activations → different routing targets (by plugin_id)
        let health_handle = Handle::new(health.plugin_id(), "1.0.0", "check")
            .with_meta(vec!["msg-123".into(), "user".into()]);
        let echo_handle = Handle::new(echo.plugin_id(), "1.0.0", "echo")
            .with_meta(vec!["msg-123".into(), "user".into()]);

        // Different plugin_ids ensure different routing
        assert_ne!(health_handle.plugin_id, echo_handle.plugin_id);
    }

    // ========================================================================
    // Plugin Registry Tests
    // ========================================================================

    #[test]
    fn plugin_registry_basic_operations() {
        let mut registry = PluginRegistry::new();
        let id = uuid::Uuid::new_v4();

        // Register an activation
        registry.register(id, "test_plugin".to_string(), "test".to_string());

        // Lookup by ID
        assert_eq!(registry.lookup(id), Some("test_plugin"));

        // Lookup by path
        assert_eq!(registry.lookup_by_path("test_plugin"), Some(id));

        // Get entry
        let entry = registry.get(id).expect("should have entry");
        assert_eq!(entry.path, "test_plugin");
        assert_eq!(entry.plugin_type, "test");
    }

    #[test]
    fn plugin_registry_populated_on_register() {
        use crate::activations::health::Health;

        let hub = DynamicHub::new("test").register(Health::new());

        let registry = hub.registry();
        assert!(!registry.is_empty(), "registry should not be empty after registration");

        // Health activation should be registered
        let health_id = registry.lookup_by_path("health");
        assert!(health_id.is_some(), "health should be registered by path");

        // Should be able to look up path by ID
        let health_uuid = health_id.unwrap();
        assert_eq!(registry.lookup(health_uuid), Some("health"));
    }

    #[test]
    fn plugin_registry_deterministic_uuid() {
        use crate::activations::health::Health;

        // Same activation registered twice should produce same UUID
        let health1 = Health::new();
        let health2 = Health::new();

        assert_eq!(health1.plugin_id(), health2.plugin_id(),
            "same activation type should have deterministic UUID");

        // UUID should be based on namespace+major_version (semver compatibility)
        let expected = uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_OID,
            b"health@1"
        );
        assert_eq!(health1.plugin_id(), expected,
            "plugin_id should be deterministic from namespace@major_version");
    }

    // ========================================================================
    // CHILD-2: ChildRouter capabilities + opt-in list/search
    // ========================================================================

    /// A minimal `ChildRouter` that overrides only the required methods.
    /// Exercises default implementations of `capabilities`, `list_children`
    /// and `search_children`.
    struct MinimalRouter;

    #[async_trait]
    impl ChildRouter for MinimalRouter {
        fn router_namespace(&self) -> &str {
            "minimal"
        }

        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&super::super::auth::AuthContext>,
            _raw_ctx: Option<&crate::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Err(PlexusError::MethodNotFound {
                activation: "minimal".into(),
                method: "none".into(),
            })
        }

        async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
            None
        }
    }

    #[tokio::test]
    async fn child_router_defaults_report_no_capabilities_and_none_streams() {
        let router = MinimalRouter;

        assert_eq!(
            router.capabilities(),
            ChildCapabilities::empty(),
            "default capabilities should be empty"
        );
        assert!(
            router.list_children().await.is_none(),
            "default list_children should be None"
        );
        assert!(
            router.search_children("anything").await.is_none(),
            "default search_children should be None"
        );
    }

    /// A `ChildRouter` that opts in to both LIST and SEARCH.
    struct ListingRouter {
        names: Vec<String>,
    }

    #[async_trait]
    impl ChildRouter for ListingRouter {
        fn router_namespace(&self) -> &str {
            "listing"
        }

        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&super::super::auth::AuthContext>,
            _raw_ctx: Option<&crate::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Err(PlexusError::MethodNotFound {
                activation: "listing".into(),
                method: "none".into(),
            })
        }

        async fn get_child(&self, name: &str) -> Option<Box<dyn ChildRouter>> {
            if self.names.iter().any(|n| n == name) {
                // Return the same type to keep the test simple; we only care
                // that the override compiles and is reachable.
                Some(Box::new(ListingRouter { names: vec![] }))
            } else {
                None
            }
        }

        fn capabilities(&self) -> ChildCapabilities {
            ChildCapabilities::LIST | ChildCapabilities::SEARCH
        }

        async fn list_children(&self) -> Option<BoxStream<'_, String>> {
            let stream = futures::stream::iter(self.names.iter().cloned());
            Some(Box::pin(stream))
        }

        async fn search_children(&self, query: &str) -> Option<BoxStream<'_, String>> {
            let q = query.to_string();
            let stream = futures::stream::iter(
                self.names
                    .iter()
                    .filter(move |n| n.contains(&q))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            Some(Box::pin(stream))
        }
    }

    #[tokio::test]
    async fn child_router_overrides_report_capabilities_and_yield_streams() {
        use futures::StreamExt;

        let router = ListingRouter {
            names: vec!["alpha".into(), "beta".into(), "alphabet".into()],
        };

        // Capabilities
        let caps = router.capabilities();
        assert!(caps.contains(ChildCapabilities::LIST));
        assert!(caps.contains(ChildCapabilities::SEARCH));
        assert_eq!(caps, ChildCapabilities::LIST | ChildCapabilities::SEARCH);

        // list_children yields the full, non-empty, finite sequence.
        let list_stream = router
            .list_children()
            .await
            .expect("LIST capability set — expected Some(stream)");
        let listed: Vec<String> = list_stream.collect().await;
        assert_eq!(listed, vec!["alpha".to_string(), "beta".into(), "alphabet".into()]);

        // search_children filters by the query string.
        let search_stream = router
            .search_children("alpha")
            .await
            .expect("SEARCH capability set — expected Some(stream)");
        let matched: Vec<String> = search_stream.collect().await;
        assert_eq!(matched, vec!["alpha".to_string(), "alphabet".into()]);
    }

    // ========================================================================
    // CHILD-WIRE: per-activation namespaced wire exposure for
    // <ns>.list_children / <ns>.search_children
    //
    // These tests exercise `register_child_capability_methods` directly with
    // hand-built fixtures, then drive the resulting RpcModule through the
    // in-process subscription path. Mirrors the existing
    // `auth_capabilities_info` integration pattern but verifies the
    // child-router wire registration instead of the _info payload.
    // ========================================================================

    /// Like `EnumerableRouter` above but with configurable capability bits +
    /// a fixed name set. Used to drive CHILD-WIRE registration through
    /// different capability combinations.
    struct WireFixture {
        names: Vec<String>,
        caps: ChildCapabilities,
    }

    #[async_trait]
    impl ChildRouter for WireFixture {
        fn router_namespace(&self) -> &str {
            "wirefixture"
        }
        async fn router_call(
            &self,
            _method: &str,
            _params: Value,
            _auth: Option<&super::super::auth::AuthContext>,
            _raw_ctx: Option<&crate::request::RawRequestContext>,
        ) -> Result<PlexusStream, PlexusError> {
            Err(PlexusError::MethodNotFound {
                activation: "wirefixture".into(),
                method: "none".into(),
            })
        }
        async fn get_child(&self, _name: &str) -> Option<Box<dyn ChildRouter>> {
            None
        }
        fn capabilities(&self) -> ChildCapabilities {
            self.caps
        }
        async fn list_children(&self) -> Option<futures_core::stream::BoxStream<'_, String>> {
            if !self.caps.contains(ChildCapabilities::LIST) {
                return None;
            }
            Some(Box::pin(futures::stream::iter(self.names.clone())))
        }
        async fn search_children(
            &self,
            query: &str,
        ) -> Option<futures_core::stream::BoxStream<'_, String>> {
            if !self.caps.contains(ChildCapabilities::SEARCH) {
                return None;
            }
            let q = query.to_lowercase();
            let filtered: Vec<String> = self
                .names
                .iter()
                .filter(|n| n.to_lowercase().contains(&q))
                .cloned()
                .collect();
            Some(Box::pin(futures::stream::iter(filtered)))
        }
    }

    fn build_module_for(router: WireFixture, ns: &str) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        let arc: Arc<dyn ChildRouter> = Arc::new(router);
        register_child_capability_methods(&mut module, ns, arc).expect("register");
        module
    }

    #[tokio::test]
    async fn child_wire_registers_both_methods_when_both_bits_set() {
        let module = build_module_for(
            WireFixture {
                names: vec!["alpha".into(), "beta".into()],
                caps: ChildCapabilities::LIST | ChildCapabilities::SEARCH,
            },
            "fixture",
        );
        let names: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
        assert!(
            names.contains(&"fixture.list_children".to_string()),
            "expected fixture.list_children, got: {:?}",
            names
        );
        assert!(
            names.contains(&"fixture.search_children".to_string()),
            "expected fixture.search_children, got: {:?}",
            names
        );
    }

    #[tokio::test]
    async fn child_wire_registers_nothing_when_no_bits_set() {
        let module = build_module_for(
            WireFixture {
                names: vec!["alpha".into()],
                caps: ChildCapabilities::empty(),
            },
            "fixture",
        );
        let names: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
        assert!(
            !names.contains(&"fixture.list_children".to_string()),
            "fixture.list_children should NOT be registered when cap absent"
        );
        assert!(
            !names.contains(&"fixture.search_children".to_string()),
            "fixture.search_children should NOT be registered when cap absent"
        );
    }

    #[tokio::test]
    async fn child_wire_registers_only_list_when_only_list_bit() {
        let module = build_module_for(
            WireFixture {
                names: vec!["alpha".into()],
                caps: ChildCapabilities::LIST,
            },
            "fixture",
        );
        let names: Vec<String> = module.method_names().map(|s| s.to_string()).collect();
        assert!(names.contains(&"fixture.list_children".to_string()));
        assert!(!names.contains(&"fixture.search_children".to_string()));
    }

    // Live wire-call behavior (subscription stream content, methodNotFound on
    // unregistered names, error envelopes) is verified end-to-end against
    // running substrate Solar — that's the canonical integration gate per
    // the CHILD-WIRE acceptance criteria. The unit-level introspection
    // tests above assert the registration shape; the substrate verification
    // asserts the live behavior. Splitting it that way avoids forcing the
    // unit test to construct a working RpcSubscriptionSink, which is not
    // straightforward in the bare jsonrpsee API.
}

#[cfg(test)]
mod keel54_routing {
    //! KEEL-54, layer 3: routing never outruns the gate — each piece alone,
    //! with nothing before it to normalize or refuse the path.
    use super::*;
    use crate::activations::health::Health;
    use plexus_auth_core::grants::{Gate, Grant, Membership, Memberships, Reach, Resolve, RoleTable, ScopeRef};
    use serde_json::json;

    const ADMIN: &str = "key:adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad";

    struct AdminEverywhere;
    impl Memberships for AdminEverywhere {
        fn held(&self, who: &plexus_auth_core::identity::Principal) -> Vec<Membership> {
            vec![Membership { principal: who.clone(), role: plexus_auth_core::RoleName::new("admin"), scope: ScopeRef::Everywhere }]
        }
    }
    struct Anywhere;
    impl Resolve for Anywhere {
        fn chain(&self, _: &str) -> Option<Vec<ScopeRef>> {
            Some(vec![ScopeRef::Everywhere])
        }
    }

    fn service() -> DynamicHub {
        DynamicHub::new("svc").register(Health::new())
    }

    async fn routed(svc: &DynamicHub, path: &'static str) -> Result<PlexusStream, PlexusError> {
        let ctx = crate::call::CallContext::admitted(None, Reach::everywhere());
        crate::call::scope(ctx, svc.route_ungated(CallPath(path), json!({}), None, None)).await
    }

    /// The service's own name routes to the service's own methods alone:
    /// the macro's fallback below them (`svc.health.check` into `health`)
    /// is never reached, whatever the gate before it decided.
    #[tokio::test]
    async fn the_router_sends_the_services_own_name_to_its_own_methods_alone() {
        let svc = service();
        for path in ["svc.health.check", "svc.svc.health.check", "svc.hash.check", "svc.call.check", "svc.schema.schema"] {
            assert!(matches!(routed(&svc, path).await, Err(PlexusError::MethodNotFound { .. })), "{path}");
        }
        for path in ["svc.hash", "svc.schema", "svc.call.schema", "health.check"] {
            assert!(routed(&svc, path).await.is_ok(), "{path}");
        }
    }

    /// The call runs only under a reach made for its own path's grant.
    #[test]
    fn a_reach_for_another_grant_never_runs_the_call() {
        let svc = service();
        let index = svc.gate_index();
        let gate = Gate::new(Arc::new(AdminEverywhere), Arc::new(RoleTable::from_lists([("viewer", ["health.check"])])), Arc::new(Anywhere));
        let admin = crate::plexus::AuthContext::for_principal(&ADMIN.parse().unwrap(), "s", vec![], Value::Null);
        let reach = |grant: &str| gate.check(Some(&admin), &Grant::new(grant), None).unwrap();
        assert!(routes_as_decided(&index, CallPath("health.check"), &reach("health.check")).is_ok());
        assert!(routes_as_decided(&index, CallPath("svc.hash"), &reach("svc.hash")).is_ok());
        for (path, decided) in [("health.check", "svc.health.check"), ("svc.hash", "health.other"), ("health.check", "health")] {
            assert!(matches!(routes_as_decided(&index, CallPath(path), &reach(decided)), Err(PlexusError::Forbidden { .. })), "{path} on {decided}");
        }
        assert!(routes_as_decided(&index, CallPath("health.check"), &Reach::everywhere()).is_err(), "a reach no gate made");
    }

    /// Layer 1 alone: the one prefix taken, once, and nothing else rewritten.
    #[test]
    fn the_caller_s_spelling_is_read_once() {
        let svc = service();
        let cases = [
            ("svc.health.check", "health.check"),
            ("health.check", "health.check"),
            ("svc.hash", "svc.hash"),
            ("svc.call.schema", "svc.call.schema"),
            ("svc.svc.health.check", "svc.svc.health.check"),
            ("svc..health.check", "svc..health.check"),
            ("SVC.health.check", "SVC.health.check"),
            ("svc.Health.check", "Health.check"),
            ("svc.health", "svc.health"),
            ("svcx.health.check", "svcx.health.check"),
            (".svc.health.check", ".svc.health.check"),
        ];
        for (said, path) in cases {
            assert_eq!(svc.call_path(said).as_str(), path, "{said}");
        }
    }
}
